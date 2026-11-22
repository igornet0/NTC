//! Active and passive local-network discovery: ARP, ICMP, mDNS, reverse DNS,
//! OUI vendor lookup.

use anyhow::Result;
use chrono::{DateTime, Utc};
use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;
use tokio::sync::Semaphore;
use tracing::{debug, info, warn};

pub const MDNS_SERVICES: &[&str] = &[
    "_http._tcp.local.",
    "_https._tcp.local.",
    "_ipp._tcp.local.",
    "_printer._tcp.local.",
    "_workstation._tcp.local.",
    "_smb._tcp.local.",
    "_afpovertcp._tcp.local.",
    "_googlecast._tcp.local.",
    "_airplay._tcp.local.",
    "_raop._tcp.local.",
    "_hap._tcp.local.",
    "_spotify-connect._tcp.local.",
    "_sonos._tcp.local.",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredDevice {
    pub ip: IpAddr,
    pub mac: Option<String>,
    pub hostname: Option<String>,
    pub vendor: Option<String>,
    pub discovery_methods: Vec<String>,
    pub last_seen: DateTime<Utc>,
}

impl DiscoveredDevice {
    pub fn new(ip: IpAddr) -> Self {
        Self {
            ip,
            mac: None,
            hostname: None,
            vendor: None,
            discovery_methods: Vec::new(),
            last_seen: Utc::now(),
        }
    }

    pub fn add_method(&mut self, method: &str) {
        if !self.discovery_methods.iter().any(|m| m == method) {
            self.discovery_methods.push(method.to_string());
        }
        self.last_seen = Utc::now();
    }
}

#[derive(Debug, Clone)]
pub struct DiscoveryOptions {
    pub max_hosts_per_subnet: usize,
    pub ping_timeout: Duration,
    pub max_concurrency: usize,
    pub enable_mdns: bool,
    pub mdns_timeout: Duration,
    pub enable_icmp: bool,
}

impl Default for DiscoveryOptions {
    fn default() -> Self {
        Self {
            max_hosts_per_subnet: 512,
            ping_timeout: Duration::from_secs(1),
            max_concurrency: 128,
            enable_mdns: true,
            mdns_timeout: Duration::from_secs(4),
            enable_icmp: true,
        }
    }
}

pub async fn discover_network(
    subnets: &[Ipv4Net],
    options: &DiscoveryOptions,
) -> Result<Vec<DiscoveredDevice>> {
    let mut map: HashMap<IpAddr, DiscoveredDevice> = HashMap::new();

    for (ip, mac) in read_arp_table() {
        let entry = map.entry(ip).or_insert_with(|| DiscoveredDevice::new(ip));
        if entry.mac.is_none() {
            entry.mac = mac;
        }
        entry.add_method("arp");
    }
    debug!("ARP table yielded {} entries", map.len());

    if options.enable_icmp {
        for subnet in subnets {
            let hosts = enumerate_hosts(subnet, options.max_hosts_per_subnet);
            let alive = ping_sweep(&hosts, options).await;
            for ip in alive {
                let entry = map.entry(ip).or_insert_with(|| DiscoveredDevice::new(ip));
                entry.add_method("icmp");
            }
        }
    }

    if options.enable_mdns {
        let mdns = mdns_discover(options.mdns_timeout).await;
        for (ip, hostname) in mdns {
            let entry = map.entry(ip).or_insert_with(|| DiscoveredDevice::new(ip));
            if entry.hostname.is_none() {
                entry.hostname = hostname;
            }
            entry.add_method("mdns");
        }
    }

    // Try to learn MAC addresses for mDNS/ICMP-only hosts from a fresh ARP snapshot.
    let arp2 = read_arp_table();
    for (ip, mac) in arp2 {
        if let Some(entry) = map.get_mut(&ip) {
            if entry.mac.is_none() {
                entry.mac = mac;
            }
        }
    }

    let mut devices: Vec<DiscoveredDevice> = map.into_values().collect();

    for device in &mut devices {
        if device.hostname.is_none() {
            device.hostname = reverse_dns(device.ip).await;
        }
        if device.vendor.is_none() {
            if let Some(mac) = &device.mac {
                device.vendor = oui_lookup(mac);
            }
        }
    }

    devices.sort_by(|a, b| a.ip.to_string().cmp(&b.ip.to_string()));
    info!("discovered {} device(s)", devices.len());
    Ok(devices)
}

fn enumerate_hosts(subnet: &Ipv4Net, max: usize) -> Vec<Ipv4Addr> {
    let network = u32::from(subnet.network());
    let broadcast = u32::from(subnet.broadcast());
    let mut hosts = Vec::new();
    let mut ip = network.saturating_add(1);
    while ip < broadcast && hosts.len() < max {
        hosts.push(Ipv4Addr::from(ip));
        ip = ip.saturating_add(1);
    }
    hosts
}

async fn ping_sweep(hosts: &[Ipv4Addr], options: &DiscoveryOptions) -> Vec<IpAddr> {
    use std::sync::Arc;
    use surge_ping::{Client, Config, PingIdentifier, PingSequence};

    if hosts.is_empty() {
        return Vec::new();
    }

    let client = match Client::new(&Config::default()) {
        Ok(c) => Arc::new(c),
        Err(e) => {
            warn!("ICMP socket unavailable (root or CAP_NET_RAW required): {e}");
            return Vec::new();
        }
    };

    let sem = Arc::new(Semaphore::new(options.max_concurrency));
    let mut handles = Vec::with_capacity(hosts.len());
    let base_id = std::process::id() as u16;

    for (i, ip) in hosts.iter().enumerate() {
        let client = client.clone();
        let sem = sem.clone();
        let ip = *ip;
        let timeout = options.ping_timeout;
        let id = base_id.wrapping_add(i as u16);

        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.ok()?;
            let mut pinger = client.pinger(IpAddr::V4(ip), PingIdentifier(id)).await;
            pinger.timeout(timeout);
            let payload = [0u8; 32];
            match pinger.ping(PingSequence(0), &payload).await {
                Ok(_) => Some(IpAddr::V4(ip)),
                Err(_) => None,
            }
        }));
    }

    let mut alive = Vec::new();
    for h in handles {
        if let Ok(Some(ip)) = h.await {
            alive.push(ip);
        }
    }
    debug!("ICMP ping sweep: {}/{} alive", alive.len(), hosts.len());
    alive
}

async fn mdns_discover(timeout: Duration) -> Vec<(IpAddr, Option<String>)> {
    use mdns_sd::{ServiceDaemon, ServiceEvent};

    let daemon = match ServiceDaemon::new() {
        Ok(d) => d,
        Err(e) => {
            warn!("mDNS daemon failed to start: {e}");
            return Vec::new();
        }
    };

    let mut receivers = Vec::new();
    for svc in MDNS_SERVICES {
        if let Ok(rx) = daemon.browse(svc) {
            receivers.push(rx);
        }
    }

    let mut results: Vec<(IpAddr, Option<String>)> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let deadline = tokio::time::Instant::now() + timeout;

    while tokio::time::Instant::now() < deadline {
        for rx in &receivers {
            while let Ok(event) = rx.try_recv() {
                if let ServiceEvent::ServiceResolved(info) = event {
                    let hostname = Some(info.get_hostname().to_string());
                    for addr in info.get_addresses() {
                        if seen.insert(*addr) {
                            results.push((*addr, hostname.clone()));
                        }
                    }
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let _ = daemon.shutdown();
    results
}

async fn reverse_dns(ip: IpAddr) -> Option<String> {
    tokio::task::spawn_blocking(move || dns_lookup::lookup_addr(&ip).ok())
        .await
        .ok()
        .flatten()
}

fn read_arp_table() -> Vec<(IpAddr, Option<String>)> {
    let mut out: Vec<(IpAddr, Option<String>)> = Vec::new();

    #[cfg(target_os = "linux")]
    {
        if let Ok(content) = std::fs::read_to_string("/proc/net/arp") {
            for line in content.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() < 4 {
                    continue;
                }
                if let Ok(ip) = parts[0].parse::<IpAddr>() {
                    let mac = parts[3];
                    if mac != "00:00:00:00:00:00" && mac != "ff:ff:ff:ff:ff:ff" {
                        out.push((ip, Some(mac.to_string())));
                    } else {
                        out.push((ip, None));
                    }
                }
            }
        }
    }

    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        if let Ok(o) = std::process::Command::new("arp").arg("-an").output() {
            let text = String::from_utf8_lossy(&o.stdout);
            for line in text.lines() {
                if let Some(open) = line.find('(') {
                    if let Some(close_rel) = line[open + 1..].find(')') {
                        let ip_str = &line[open + 1..open + 1 + close_rel];
                        if let Ok(ip) = ip_str.parse::<IpAddr>() {
                            let mac = line
                                .split(" at ")
                                .nth(1)
                                .and_then(|s| s.split_whitespace().next())
                                .filter(|s| *s != "(incomplete)" && *s != "ff:ff:ff:ff:ff:ff")
                                .map(|s| s.to_string());
                            out.push((ip, mac));
                        }
                    }
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        if let Ok(o) = std::process::Command::new("arp").arg("-a").output() {
            let text = String::from_utf8_lossy(&o.stdout);
            for line in text.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    if let Ok(ip) = parts[0].parse::<IpAddr>() {
                        let mac = parts[1].replace('-', ":").to_ascii_lowercase();
                        if mac != "ff:ff:ff:ff:ff:ff" && mac != "00:00:00:00:00:00" {
                            out.push((ip, Some(mac)));
                        }
                    }
                }
            }
        }
    }

    out
}

/// Compact curated OUI lookup table covering the most common consumer/enterprise
/// vendors encountered on LANs. Extend as needed.
const OUI_TABLE: &[(&str, &str)] = &[
    ("00:1A:2B", "VMware"),
    ("00:0C:29", "VMware"),
    ("00:50:56", "VMware"),
    ("00:05:69", "VMware"),
    ("00:15:5D", "Microsoft (Hyper-V)"),
    ("00:16:3E", "Xen"),
    ("08:00:27", "VirtualBox"),
    ("00:1C:42", "Parallels"),
    ("AC:DE:48", "Apple"),
    ("00:1C:B3", "Apple"),
    ("00:1E:C2", "Apple"),
    ("00:23:DF", "Apple"),
    ("3C:22:FB", "Apple"),
    ("F0:18:98", "Apple"),
    ("B8:27:EB", "Raspberry Pi"),
    ("DC:A6:32", "Raspberry Pi"),
    ("E4:5F:01", "Raspberry Pi"),
    ("28:CD:C1", "Raspberry Pi"),
    ("24:0A:C4", "Espressif"),
    ("84:F3:EB", "Espressif"),
    ("3C:71:BF", "Espressif"),
    ("18:B4:30", "Nest Labs"),
    ("44:65:0D", "Amazon"),
    ("68:54:FD", "Amazon"),
    ("74:C2:46", "Amazon"),
    ("FC:65:DE", "Amazon (Ring)"),
    ("3C:5A:B4", "Google"),
    ("44:07:0B", "Google"),
    ("F4:F5:D8", "Google"),
    ("54:60:09", "Google"),
    ("00:17:88", "Philips Hue"),
    ("00:0C:E7", "MikroTik"),
    ("00:1D:0F", "MikroTik"),
    ("4C:5E:0C", "MikroTik"),
    ("6C:3B:6B", "MikroTik"),
    ("CC:2D:E0", "MikroTik"),
    ("D4:CA:6D", "MikroTik"),
    ("2C:C8:1B", "MikroTik"),
    ("74:4D:28", "MikroTik"),
    ("B8:69:F4", "MikroTik"),
    ("DC:2C:6E", "MikroTik"),
    ("18:FD:74", "MikroTik"),
    ("00:1A:A1", "Cisco"),
    ("00:1D:7E", "Cisco"),
    ("00:24:36", "Cisco"),
    ("00:26:5A", "Cisco"),
    ("00:09:0F", "Cisco"),
    ("00:0B:5F", "Cisco"),
    ("00:0C:30", "Cisco"),
    ("00:0F:23", "Cisco"),
    ("00:1C:F0", "D-Link"),
    ("00:23:69", "D-Link"),
    ("00:24:B2", "D-Link"),
    ("14:D6:4D", "D-Link"),
    ("84:C9:B2", "D-Link"),
    ("00:14:BF", "Linksys"),
    ("00:16:B6", "Linksys"),
    ("00:18:39", "Linksys"),
    ("00:1A:70", "Linksys"),
    ("04:18:D6", "TP-Link"),
    ("18:A6:F7", "TP-Link"),
    ("30:B5:C2", "TP-Link"),
    ("50:C7:BF", "TP-Link"),
    ("54:C8:0F", "TP-Link"),
    ("5C:63:BF", "TP-Link"),
    ("60:32:B1", "TP-Link"),
    ("68:FF:7B", "TP-Link"),
    ("70:4F:57", "TP-Link"),
    ("98:DA:C4", "TP-Link"),
    ("A4:2B:B0", "TP-Link"),
    ("B0:4E:26", "TP-Link"),
    ("C0:25:E9", "TP-Link"),
    ("CC:32:E5", "TP-Link"),
    ("E4:C3:2A", "TP-Link"),
    ("F4:F2:6D", "TP-Link"),
    ("00:0F:CC", "ASUS"),
    ("00:1C:10", "ASUS"),
    ("08:60:6E", "ASUS"),
    ("2C:56:DC", "ASUS"),
    ("38:D5:47", "ASUS"),
    ("40:16:7E", "ASUS"),
    ("50:46:5D", "ASUS"),
    ("74:D0:2B", "ASUS"),
    ("9C:5C:8E", "ASUS"),
    ("AC:22:0B", "ASUS"),
    ("BC:EE:7B", "ASUS"),
    ("D8:50:E6", "ASUS"),
    ("F8:32:E4", "ASUS"),
    ("00:1F:33", "Netgear"),
    ("20:0C:C8", "Netgear"),
    ("28:C6:8E", "Netgear"),
    ("44:94:FC", "Netgear"),
    ("4C:60:DE", "Netgear"),
    ("6C:B0:CE", "Netgear"),
    ("9C:3D:CF", "Netgear"),
    ("A0:40:A0", "Netgear"),
    ("B0:7F:B9", "Netgear"),
    ("C0:3F:0E", "Netgear"),
    ("DC:EF:09", "Netgear"),
    ("E4:F4:C6", "Netgear"),
    ("00:E0:FC", "Huawei"),
    ("F0:27:65", "Huawei"),
    ("3C:A9:F4", "Intel"),
    ("00:1B:21", "Intel"),
    ("8C:16:45", "Intel"),
    ("F4:8E:38", "Dell"),
    ("00:14:22", "Dell"),
    ("00:21:9B", "Dell"),
    ("18:66:DA", "Dell"),
    ("00:1B:63", "Apple"),
    ("00:1F:F3", "Apple"),
    ("A4:83:E7", "Apple"),
    ("DC:2B:2A", "Apple"),
    ("E0:B9:BA", "Apple"),
    ("F0:DB:E2", "Apple"),
    ("00:16:CB", "Apple"),
    ("00:1E:52", "Apple"),
    ("00:22:41", "Apple"),
    ("00:25:00", "Apple"),
    ("00:26:B0", "Apple"),
    ("00:50:E4", "Apple"),
];

fn oui_lookup(mac: &str) -> Option<String> {
    let prefix: String = mac
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .take(6)
        .collect::<String>()
        .to_ascii_uppercase();
    if prefix.len() != 6 {
        return None;
    }
    let formatted = format!(
        "{}:{}:{}",
        &prefix[0..2],
        &prefix[2..4],
        &prefix[4..6]
    );
    OUI_TABLE
        .iter()
        .find(|(p, _)| *p == formatted)
        .map(|(_, v)| v.to_string())
}

