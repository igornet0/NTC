//! Core network primitives: interfaces, gateways, DNS, subnets.
//!
//! The goal of this crate is to gather the minimal set of local network facts
//! required by every other NTC component.

use anyhow::{Context, Result};
use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr};
use tracing::{debug, info};

pub const DEFAULT_PING_TIMEOUT_SECS: u64 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InterfaceType {
    Ethernet,
    Wireless,
    Loopback,
    Virtual,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterface {
    pub name: String,
    pub index: u32,
    pub mac: Option<String>,
    pub ipv4: Vec<Ipv4Net>,
    pub ipv6: Vec<String>,
    pub interface_type: InterfaceType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Gateway {
    pub ip: IpAddr,
    pub interface: Option<String>,
    pub mac: Option<String>,
    pub is_default: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubnetInfo {
    pub cidr: String,
    pub network: Ipv4Addr,
    pub broadcast: Ipv4Addr,
    pub first_host: Option<Ipv4Addr>,
    pub last_host: Option<Ipv4Addr>,
    pub host_count: u64,
    pub interface: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInfo {
    pub interfaces: Vec<NetworkInterface>,
    pub gateways: Vec<Gateway>,
    pub dns_servers: Vec<IpAddr>,
    pub subnets: Vec<SubnetInfo>,
}

pub fn list_interfaces() -> Result<Vec<NetworkInterface>> {
    use network_interface::{NetworkInterface as Nif, NetworkInterfaceConfig};

    let list = Nif::show().context("failed to enumerate network interfaces")?;
    let mut out = Vec::with_capacity(list.len());

    for iface in list {
        let mut ipv4 = Vec::new();
        let mut ipv6 = Vec::new();
        for addr in &iface.addr {
            match addr {
                network_interface::NifAddr::V4(v4) => {
                    if let Ok(net) = Ipv4Net::with_netmask(v4.ip, v4.netmask) {
                        ipv4.push(net);
                    }
                }
                network_interface::NifAddr::V6(v6) => {
                    ipv6.push(v6.ip.to_string());
                }
                _ => {}
            }
        }

        let itype = classify_interface(&iface.name);
        let mac = iface.mac_addr.as_ref().map(|m| m.to_string());

        out.push(NetworkInterface {
            name: iface.name.clone(),
            index: iface.index,
            mac,
            ipv4,
            ipv6,
            interface_type: itype,
        });
    }

    info!("discovered {} interfaces", out.len());
    Ok(out)
}

fn classify_interface(name: &str) -> InterfaceType {
    let n = name.to_ascii_lowercase();
    if n == "lo" || n == "lo0" || n.starts_with("lo") && !n.starts_with("loop") {
        return InterfaceType::Loopback;
    }
    if n.contains("loopback") {
        return InterfaceType::Loopback;
    }
    if n.starts_with("wl") || n.starts_with("wlan") || n.starts_with("wifi")
        || n.contains("wi-fi") || n.contains("wireless")
    {
        return InterfaceType::Wireless;
    }
    // macOS primary Wi-Fi interface is usually en0; we cannot reliably distinguish
    // it from Ethernet by name, so we leave en0 as Other->Ethernet in that case.
    if n.starts_with("eth") || n.starts_with("eno") || n.starts_with("enp")
        || n.starts_with("ens") || n.starts_with("en")
    {
        return InterfaceType::Ethernet;
    }
    if n.starts_with("utun") || n.starts_with("tun") || n.starts_with("tap")
        || n.starts_with("docker") || n.starts_with("veth") || n.starts_with("br-")
        || n.starts_with("virbr") || n.starts_with("bridge")
    {
        return InterfaceType::Virtual;
    }
    InterfaceType::Other
}

pub fn discover_gateways() -> Result<Vec<Gateway>> {
    let mut gateways = Vec::new();

    match default_net::get_default_gateway() {
        Ok(gw) => {
            for ip in gw.ipv4 {
                gateways.push(Gateway {
                    ip: IpAddr::V4(ip),
                    interface: None,
                    mac: None,
                    is_default: true,
                });
            }
        }
        Err(e) => {
            debug!("default-net gateway detection failed: {e}");
        }
    }

    if gateways.is_empty() {
        gateways.extend(discover_gateways_shell());
    }

    info!("discovered {} gateway(s)", gateways.len());
    Ok(gateways)
}

fn discover_gateways_shell() -> Vec<Gateway> {
    let mut out = Vec::new();

    #[cfg(target_os = "linux")]
    {
        if let Ok(o) = std::process::Command::new("ip").args(["route", "show", "default"]).output() {
            let text = String::from_utf8_lossy(&o.stdout);
            for line in text.lines() {
                let mut it = line.split_whitespace();
                while let Some(tok) = it.next() {
                    if tok == "via" {
                        if let Some(next) = it.next() {
                            if let Ok(ip) = next.parse::<IpAddr>() {
                                out.push(Gateway { ip, interface: None, mac: None, is_default: true });
                            }
                        }
                    }
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Ok(o) = std::process::Command::new("route").args(["-n", "get", "default"]).output() {
            let text = String::from_utf8_lossy(&o.stdout);
            for line in text.lines() {
                if let Some(rest) = line.trim().strip_prefix("gateway:") {
                    if let Ok(ip) = rest.trim().parse::<IpAddr>() {
                        out.push(Gateway { ip, interface: None, mac: None, is_default: true });
                    }
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        if let Ok(o) = std::process::Command::new("ipconfig").output() {
            let text = String::from_utf8_lossy(&o.stdout);
            let mut in_default = false;
            for line in text.lines() {
                let trimmed = line.trim();
                if trimmed.to_ascii_lowercase().contains("default gateway") {
                    in_default = true;
                    continue;
                }
                if in_default {
                    if let Ok(ip) = trimmed.parse::<IpAddr>() {
                        out.push(Gateway { ip, interface: None, mac: None, is_default: true });
                        in_default = false;
                    }
                }
            }
        }
    }

    out
}

pub fn discover_dns_servers() -> Vec<IpAddr> {
    let mut result = Vec::new();

    #[cfg(unix)]
    {
        result.extend(parse_resolv_conf());
    }

    #[cfg(windows)]
    {
        result.extend(parse_windows_dns());
    }

    // dedupe while preserving order
    let mut seen = std::collections::HashSet::new();
    result.retain(|ip| seen.insert(*ip));
    info!("discovered {} DNS server(s)", result.len());
    result
}

#[cfg(unix)]
fn parse_resolv_conf() -> Vec<IpAddr> {
    let mut out = Vec::new();
    if let Ok(content) = std::fs::read_to_string("/etc/resolv.conf") {
        for line in content.lines() {
            let line = line.trim();
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            if let Some(rest) = line.strip_prefix("nameserver") {
                if let Some(addr) = rest.split_whitespace().next() {
                    if let Ok(ip) = addr.parse() {
                        out.push(ip);
                    }
                }
            }
        }
    }
    out
}

#[cfg(windows)]
fn parse_windows_dns() -> Vec<IpAddr> {
    let mut out = Vec::new();
    if let Ok(o) = std::process::Command::new("ipconfig").arg("/all").output() {
        let text = String::from_utf8_lossy(&o.stdout);
        let mut in_dns = false;
        for line in text.lines() {
            let trimmed = line.trim();
            let lower = trimmed.to_ascii_lowercase();
            if lower.starts_with("dns servers") {
                in_dns = true;
                if let Some(rest) = trimmed.split(':').nth(1) {
                    if let Ok(ip) = rest.trim().parse() {
                        out.push(ip);
                    }
                }
                continue;
            }
            if in_dns {
                if trimmed.is_empty() || trimmed.contains(':') {
                    in_dns = false;
                    continue;
                }
                if let Ok(ip) = trimmed.parse() {
                    out.push(ip);
                }
            }
        }
    }
    out
}

pub fn subnets_from_interfaces(ifaces: &[NetworkInterface]) -> Vec<SubnetInfo> {
    let mut out = Vec::new();
    for iface in ifaces {
        if iface.interface_type == InterfaceType::Loopback {
            continue;
        }
        for net in &iface.ipv4 {
            let network = net.network();
            let broadcast = net.broadcast();
            let prefix = net.prefix_len();
            let host_count: u64 = if prefix >= 31 {
                1u64 << (32 - prefix)
            } else {
                (1u64 << (32 - prefix)) - 2
            };
            let (first_host, last_host) = if prefix <= 30 {
                (
                    Some(Ipv4Addr::from(u32::from(network) + 1)),
                    Some(Ipv4Addr::from(u32::from(broadcast) - 1)),
                )
            } else {
                (None, None)
            };
            out.push(SubnetInfo {
                cidr: net.to_string(),
                network,
                broadcast,
                first_host,
                last_host,
                host_count,
                interface: iface.name.clone(),
            });
        }
    }
    out
}

pub async fn collect() -> Result<NetworkInfo> {
    let interfaces = list_interfaces()?;
    let gateways = discover_gateways().unwrap_or_default();
    let dns_servers = discover_dns_servers();
    let subnets = subnets_from_interfaces(&interfaces);

    Ok(NetworkInfo {
        interfaces,
        gateways,
        dns_servers,
        subnets,
    })
}

