//! Device fingerprinting: TCP port scan, service guess, banner grabbing,
//! device-type inference.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tracing::debug;

pub const COMMON_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 67, 68, 80, 110, 111, 123, 135, 137, 138, 139, 143, 161, 162, 179, 389, 443,
    445, 465, 500, 514, 515, 548, 554, 587, 623, 631, 636, 873, 902, 993, 995, 1080, 1433, 1521,
    1883, 1900, 2049, 3000, 3306, 3389, 5000, 5001, 5060, 5222, 5353, 5432, 5555, 5900, 6379,
    7000, 8000, 8006, 8080, 8081, 8123, 8200, 8291, 8443, 8883, 8888, 9000, 9090, 9100, 9200,
    10000, 11211, 27017, 32400, 49152, 62078,
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortInfo {
    pub port: u16,
    pub protocol: String,
    pub service: Option<String>,
    pub state: String,
    pub banner: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceFingerprint {
    pub ip: IpAddr,
    pub open_ports: Vec<PortInfo>,
    pub os_guess: Option<String>,
    pub device_type: String,
    pub http_title: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub ports: Vec<u16>,
    pub connect_timeout: Duration,
    pub banner_timeout: Duration,
    pub max_concurrency: usize,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            ports: COMMON_PORTS.to_vec(),
            connect_timeout: Duration::from_millis(600),
            banner_timeout: Duration::from_millis(800),
            max_concurrency: 64,
        }
    }
}

pub async fn fingerprint(ip: IpAddr, options: &ScanOptions) -> Result<DeviceFingerprint> {
    let open_ports = tcp_scan(ip, options).await;
    let http_title = if open_ports.iter().any(|p| matches!(p.port, 80 | 8080 | 8000 | 8888 | 443 | 8443)) {
        fetch_http_title(ip, &open_ports).await
    } else {
        None
    };
    let os_guess = guess_os(&open_ports);
    let device_type = classify_device(&open_ports, http_title.as_deref());

    debug!("{}: {} open port(s), type={}", ip, open_ports.len(), device_type);
    Ok(DeviceFingerprint {
        ip,
        open_ports,
        os_guess,
        device_type,
        http_title,
    })
}

async fn tcp_scan(ip: IpAddr, options: &ScanOptions) -> Vec<PortInfo> {
    let sem = std::sync::Arc::new(Semaphore::new(options.max_concurrency));
    let mut handles = Vec::with_capacity(options.ports.len());

    for &port in &options.ports {
        let sem = sem.clone();
        let connect_timeout = options.connect_timeout;
        let banner_timeout = options.banner_timeout;
        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.ok()?;
            let addr = SocketAddr::new(ip, port);
            let stream = tokio::time::timeout(connect_timeout, TcpStream::connect(addr))
                .await
                .ok()?
                .ok()?;
            let banner = grab_banner(&stream, port, banner_timeout).await;
            Some(PortInfo {
                port,
                protocol: "tcp".to_string(),
                service: service_for_port(port).map(|s| s.to_string()),
                state: "open".to_string(),
                banner,
            })
        }));
    }

    let mut open = Vec::new();
    for h in handles {
        if let Ok(Some(p)) = h.await {
            open.push(p);
        }
    }
    open.sort_by_key(|p| p.port);
    open
}

async fn grab_banner(stream: &TcpStream, port: u16, timeout: Duration) -> Option<String> {
    let mut s = stream;
    let mut buf = [0u8; 512];

    if let Ok(Ok(n)) = tokio::time::timeout(Duration::from_millis(250), s.read(&mut buf)).await {
        if n > 0 {
            return Some(String::from_utf8_lossy(&buf[..n]).trim().to_string());
        }
    }

    let probe: Option<&[u8]> = match port {
        80 | 8080 | 8000 | 8888 => Some(b"HEAD / HTTP/1.0\r\nHost: probe\r\n\r\n"),
        443 | 8443 => None,
        22 => None,
        _ => Some(b"\r\n"),
    };
    if let Some(p) = probe {
        if s.write_all(p).await.is_err() {
            return None;
        }
        if let Ok(Ok(n)) = tokio::time::timeout(timeout, s.read(&mut buf)).await {
            if n > 0 {
                let text = String::from_utf8_lossy(&buf[..n]);
                return Some(text.lines().next()?.to_string());
            }
        }
    }
    None
}

async fn fetch_http_title(ip: IpAddr, open_ports: &[PortInfo]) -> Option<String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .danger_accept_invalid_certs(true)
        .build()
        .ok()?;

    let mut candidates = Vec::new();
    if open_ports.iter().any(|p| p.port == 80) {
        candidates.push(format!("http://{ip}"));
    }
    if open_ports.iter().any(|p| p.port == 8080) {
        candidates.push(format!("http://{ip}:8080"));
    }
    if open_ports.iter().any(|p| p.port == 443) {
        candidates.push(format!("https://{ip}"));
    }
    if open_ports.iter().any(|p| p.port == 8443) {
        candidates.push(format!("https://{ip}:8443"));
    }

    for url in candidates {
        if let Ok(resp) = client.get(&url).send().await {
            if let Ok(body) = resp.text().await {
                if let Some(t) = extract_title(&body) {
                    return Some(t);
                }
            }
        }
    }
    None
}

fn extract_title(body: &str) -> Option<String> {
    let lower = body.to_ascii_lowercase();
    let start = lower.find("<title")?;
    let after = body[start..].find('>')? + start + 1;
    let end = lower[after..].find("</title>")? + after;
    let t = body[after..end].trim();
    if t.is_empty() {
        None
    } else {
        Some(t.chars().take(200).collect())
    }
}

fn service_for_port(port: u16) -> Option<&'static str> {
    Some(match port {
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 | 587 => "smtp",
        53 => "dns",
        80 => "http",
        110 => "pop3",
        111 => "rpcbind",
        135 => "msrpc",
        139 | 445 => "smb",
        143 => "imap",
        161 => "snmp",
        389 => "ldap",
        443 => "https",
        515 => "lpd",
        548 => "afp",
        554 => "rtsp",
        631 => "ipp",
        636 => "ldaps",
        993 => "imaps",
        995 => "pop3s",
        1433 => "mssql",
        1883 => "mqtt",
        2049 => "nfs",
        3306 => "mysql",
        3389 => "rdp",
        5060 => "sip",
        5432 => "postgresql",
        5353 => "mdns",
        5900 => "vnc",
        6379 => "redis",
        8000 | 8006 | 8080 | 8081 | 8888 => "http-alt",
        8443 => "https-alt",
        9100 => "jetdirect",
        32400 => "plex",
        62078 => "iphone-sync",
        _ => return None,
    })
}

fn guess_os(open_ports: &[PortInfo]) -> Option<String> {
    let has = |p: u16| open_ports.iter().any(|x| x.port == p);
    if has(135) && (has(139) || has(445)) {
        return Some("Windows".to_string());
    }
    if has(548) || has(62078) {
        return Some("Apple".to_string());
    }
    if has(22) && has(111) {
        return Some("Unix-like".to_string());
    }
    if has(445) {
        return Some("Windows or Samba".to_string());
    }
    if has(22) {
        return Some("Unix-like (SSH enabled)".to_string());
    }
    None
}

fn classify_device(open_ports: &[PortInfo], http_title: Option<&str>) -> String {
    let has = |p: u16| open_ports.iter().any(|x| x.port == p);
    let title_lower = http_title.map(|t| t.to_ascii_lowercase()).unwrap_or_default();

    if has(631) || has(515) || has(9100) {
        return "printer".to_string();
    }
    if has(62078) {
        return "iphone".to_string();
    }
    if has(32400) {
        return "media-server".to_string();
    }
    if has(1883) || has(8883) {
        return "iot-hub".to_string();
    }
    if title_lower.contains("router") || title_lower.contains("gateway")
        || title_lower.contains("tp-link") || title_lower.contains("asus")
        || title_lower.contains("mikrotik") || title_lower.contains("netgear")
        || title_lower.contains("d-link") || title_lower.contains("openwrt")
    {
        return "router".to_string();
    }
    if has(3389) || (has(135) && has(445)) {
        return "workstation-windows".to_string();
    }
    if has(548) && (has(22) || has(445)) {
        return "workstation-mac".to_string();
    }
    if has(22) && has(80) {
        return "server".to_string();
    }
    if has(22) {
        return "unix-host".to_string();
    }
    if has(80) || has(443) {
        return "web-device".to_string();
    }
    if open_ports.is_empty() {
        return "unknown".to_string();
    }
    "network-device".to_string()
}

