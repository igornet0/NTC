//! Simple HTTP/HTTPS probe for router web UIs.

use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::net::TcpStream;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpProbeResult {
    pub url: String,
    pub status: u16,
    pub title: Option<String>,
    pub server: Option<String>,
    pub open_ports: Vec<u16>,
}

pub async fn probe(ip: IpAddr, timeout: Duration) -> Option<HttpProbeResult> {
    let mut open_ports = Vec::new();
    for port in [80u16, 443, 8080, 8443] {
        let addr = SocketAddr::new(ip, port);
        if tokio::time::timeout(Duration::from_millis(500), TcpStream::connect(addr))
            .await
            .ok()
            .and_then(|r| r.ok())
            .is_some()
        {
            open_ports.push(port);
        }
    }

    let client = match reqwest::Client::builder()
        .timeout(timeout)
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::limited(3))
        .build()
    {
        Ok(c) => c,
        Err(_) => return None,
    };

    let mut candidates = Vec::new();
    if open_ports.contains(&80) {
        candidates.push(format!("http://{}", ip));
    }
    if open_ports.contains(&443) {
        candidates.push(format!("https://{}", ip));
    }
    if open_ports.contains(&8080) {
        candidates.push(format!("http://{}:8080", ip));
    }
    if open_ports.contains(&8443) {
        candidates.push(format!("https://{}:8443", ip));
    }
    if candidates.is_empty() {
        return None;
    }

    for url in candidates {
        match client.get(&url).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let server = resp
                    .headers()
                    .get("server")
                    .and_then(|h| h.to_str().ok())
                    .map(|s| s.to_string());
                let body = match resp.text().await {
                    Ok(b) => b,
                    Err(_) => continue,
                };
                let title = extract_title(&body);
                return Some(HttpProbeResult {
                    url,
                    status,
                    title,
                    server,
                    open_ports,
                });
            }
            Err(_) => continue,
        }
    }

    Some(HttpProbeResult {
        url: format!("http://{}", ip),
        status: 0,
        title: None,
        server: None,
        open_ports,
    })
}

fn extract_title(body: &str) -> Option<String> {
    let lower = body.to_ascii_lowercase();
    let start = lower.find("<title")?;
    let after_open = body[start..].find('>')? + start + 1;
    let end = lower[after_open..].find("</title>")? + after_open;
    let t = body[after_open..end].trim();
    if t.is_empty() {
        None
    } else {
        Some(t.chars().take(200).collect())
    }
}

