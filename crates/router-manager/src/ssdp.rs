//! Minimal SSDP (UPnP discovery) client.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tracing::debug;

pub const SSDP_ADDR: &str = "239.255.255.250:1900";

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SsdpDevice {
    pub ip: Option<IpAddr>,
    pub location: Option<String>,
    pub server: Option<String>,
    pub st: Option<String>,
    pub usn: Option<String>,
    pub friendly_name: Option<String>,
    pub manufacturer: Option<String>,
    pub model_name: Option<String>,
    pub model_number: Option<String>,
    pub device_type: Option<String>,
}

pub async fn discover(timeout: Duration) -> Result<Vec<SsdpDevice>> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.set_multicast_ttl_v4(2)?;

    let searches = [
        "ssdp:all",
        "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
        "urn:schemas-upnp-org:device:InternetGatewayDevice:2",
        "urn:schemas-upnp-org:device:WANDevice:1",
        "upnp:rootdevice",
    ];

    for st in searches {
        let msg = format!(
            "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: {st}\r\n\r\n"
        );
        socket
            .send_to(msg.as_bytes(), SSDP_ADDR)
            .await
            .with_context(|| format!("send SSDP M-SEARCH for {st}"))?;
    }

    let mut buf = [0u8; 8192];
    let mut by_location: HashMap<String, SsdpDevice> = HashMap::new();
    let deadline = tokio::time::Instant::now() + timeout;

    loop {
        match tokio::time::timeout_at(deadline, socket.recv_from(&mut buf)).await {
            Ok(Ok((n, src))) => {
                let text = String::from_utf8_lossy(&buf[..n]);
                if let Some(dev) = parse_response(&text, Some(src.ip())) {
                    let key = dev.location.clone().unwrap_or_else(|| dev.ip.map(|i| i.to_string()).unwrap_or_default());
                    by_location.entry(key).or_insert(dev);
                }
            }
            _ => break,
        }
    }

    let mut devices: Vec<SsdpDevice> = by_location.into_values().collect();

    for dev in devices.iter_mut() {
        if let Some(loc) = &dev.location {
            if let Ok(xml) = fetch_location(loc).await {
                enrich_from_xml(dev, &xml);
            }
        }
    }

    debug!("SSDP: {} device(s)", devices.len());
    Ok(devices)
}

fn parse_response(text: &str, src: Option<IpAddr>) -> Option<SsdpDevice> {
    let mut headers: HashMap<String, String> = HashMap::new();
    for line in text.lines() {
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    if !text.starts_with("HTTP/1.1 200") && !text.starts_with("NOTIFY") {
        return None;
    }
    Some(SsdpDevice {
        ip: src,
        location: headers.get("location").cloned(),
        server: headers.get("server").cloned(),
        st: headers.get("st").cloned(),
        usn: headers.get("usn").cloned(),
        ..Default::default()
    })
}

async fn fetch_location(url: &str) -> Result<String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .danger_accept_invalid_certs(true)
        .build()?;
    let resp = client.get(url).send().await?.text().await?;
    Ok(resp)
}

fn enrich_from_xml(dev: &mut SsdpDevice, xml: &str) {
    if let Some(v) = extract_tag(xml, "friendlyName") {
        dev.friendly_name = Some(v);
    }
    if let Some(v) = extract_tag(xml, "manufacturer") {
        dev.manufacturer = Some(v);
    }
    if let Some(v) = extract_tag(xml, "modelName") {
        dev.model_name = Some(v);
    }
    if let Some(v) = extract_tag(xml, "modelNumber") {
        dev.model_number = Some(v);
    }
    if let Some(v) = extract_tag(xml, "deviceType") {
        dev.device_type = Some(v);
    }
}

fn extract_tag(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    Some(xml[start..end].trim().to_string())
}

