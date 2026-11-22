//! Cross-platform Wi-Fi scanning using native platform utilities.
//!
//! - Linux:   nmcli (NetworkManager), fallback to iw
//! - macOS:   airport utility (deprecated but still present on many versions)
//! - Windows: netsh wlan show networks mode=bssid

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::process::Command;
use tracing::debug;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WifiNetwork {
    pub ssid: String,
    pub bssid: Option<String>,
    pub channel: Option<u32>,
    pub frequency_mhz: Option<u32>,
    pub signal_dbm: Option<i32>,
    pub signal_percent: Option<u8>,
    pub security: String,
    pub encryption: Option<String>,
}

pub fn scan() -> Result<Vec<WifiNetwork>> {
    #[cfg(target_os = "linux")]
    {
        return scan_linux();
    }
    #[cfg(target_os = "macos")]
    {
        return scan_macos();
    }
    #[cfg(target_os = "windows")]
    {
        return scan_windows();
    }
    #[allow(unreachable_code)]
    bail!("Wi-Fi scanning not implemented for this platform")
}

// ---------- Linux ----------

#[cfg(target_os = "linux")]
fn scan_linux() -> Result<Vec<WifiNetwork>> {
    if let Ok(nets) = scan_nmcli() {
        if !nets.is_empty() {
            return Ok(nets);
        }
    }
    scan_iw()
}

#[cfg(target_os = "linux")]
fn scan_nmcli() -> Result<Vec<WifiNetwork>> {
    let out = Command::new("nmcli")
        .args(["-t", "-f", "SSID,BSSID,CHAN,SIGNAL,SECURITY", "device", "wifi", "list"])
        .output()
        .context("run nmcli")?;
    if !out.status.success() {
        bail!("nmcli exited with {}", out.status);
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut result = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let fields = split_escaped(line, ':');
        if fields.len() < 5 {
            continue;
        }
        let ssid = fields[0].trim().to_string();
        if ssid.is_empty() {
            continue;
        }
        let bssid = Some(fields[1].replace("\\", "").trim().to_string());
        let channel = fields[2].trim().parse::<u32>().ok();
        let signal = fields[3].trim().parse::<i32>().ok();
        let security = fields[4].trim().to_string();
        result.push(WifiNetwork {
            ssid,
            bssid,
            channel,
            frequency_mhz: channel.map(channel_to_freq_mhz),
            signal_dbm: signal.map(percent_to_dbm),
            signal_percent: signal.map(|s| s.clamp(0, 100) as u8),
            security,
            encryption: None,
        });
    }
    Ok(result)
}

#[cfg(target_os = "linux")]
fn split_escaped(line: &str, sep: char) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut escape = false;
    for c in line.chars() {
        if escape {
            cur.push(c);
            escape = false;
        } else if c == '\\' {
            escape = true;
            cur.push(c);
        } else if c == sep {
            out.push(std::mem::take(&mut cur));
        } else {
            cur.push(c);
        }
    }
    out.push(cur);
    out
}

#[cfg(target_os = "linux")]
fn scan_iw() -> Result<Vec<WifiNetwork>> {
    // Find first wireless interface
    let ifaces_out = Command::new("iw").arg("dev").output();
    let iface = match ifaces_out {
        Ok(o) if o.status.success() => {
            let text = String::from_utf8_lossy(&o.stdout);
            let mut name = None;
            for line in text.lines() {
                if let Some(rest) = line.trim().strip_prefix("Interface ") {
                    name = Some(rest.trim().to_string());
                    break;
                }
            }
            name
        }
        _ => None,
    };
    let iface = match iface {
        Some(n) => n,
        None => bail!("no wireless interface found (iw unavailable)"),
    };

    let out = Command::new("iw")
        .args(["dev", &iface, "scan"])
        .output()
        .context("run iw scan")?;
    let text = String::from_utf8_lossy(&out.stdout);
    let mut result = Vec::new();
    let mut cur: Option<WifiNetwork> = None;

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("BSS ") {
            if let Some(n) = cur.take() {
                result.push(n);
            }
            let bssid = trimmed
                .split_whitespace()
                .nth(1)
                .map(|s| s.split('(').next().unwrap_or(s).to_ascii_lowercase());
            cur = Some(WifiNetwork {
                ssid: String::new(),
                bssid,
                channel: None,
                frequency_mhz: None,
                signal_dbm: None,
                signal_percent: None,
                security: String::new(),
                encryption: None,
            });
        } else if let Some(n) = cur.as_mut() {
            if let Some(rest) = trimmed.strip_prefix("SSID: ") {
                n.ssid = rest.to_string();
            } else if let Some(rest) = trimmed.strip_prefix("freq: ") {
                if let Ok(f) = rest.trim().parse::<f32>() {
                    n.frequency_mhz = Some(f as u32);
                    n.channel = Some(freq_to_channel(f as u32));
                }
            } else if let Some(rest) = trimmed.strip_prefix("signal: ") {
                if let Some(db) = rest.split_whitespace().next() {
                    if let Ok(v) = db.parse::<f32>() {
                        n.signal_dbm = Some(v as i32);
                    }
                }
            } else if trimmed.starts_with("RSN:") || trimmed.starts_with("WPA:") {
                if n.security.is_empty() {
                    n.security = trimmed.trim_end_matches(':').to_string();
                }
            }
        }
    }
    if let Some(n) = cur.take() {
        result.push(n);
    }
    result.retain(|n| !n.ssid.is_empty());
    debug!("iw scan returned {} network(s)", result.len());
    Ok(result)
}

// ---------- macOS ----------

#[cfg(target_os = "macos")]
fn scan_macos() -> Result<Vec<WifiNetwork>> {
    let airport = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport";
    let out = Command::new(airport).arg("-s").output().context("run airport -s")?;
    if !out.status.success() {
        bail!("airport exited with {} (utility removed in recent macOS; run a privileged scan manually)", out.status);
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut result = Vec::new();
    let mut lines = text.lines();
    let _header = lines.next();
    for line in lines {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 7 {
            continue;
        }
        // Format: SSID BSSID RSSI CHANNEL HT CC SECURITY
        let ssid = parts[0].to_string();
        let bssid = Some(parts[1].to_ascii_lowercase());
        let rssi = parts[2].parse::<i32>().ok();
        let channel_str = parts[3];
        let (channel, freq) = parse_airport_channel(channel_str);
        let security = parts.last().map(|s| s.to_string()).unwrap_or_default();
        result.push(WifiNetwork {
            ssid,
            bssid,
            channel,
            frequency_mhz: freq,
            signal_dbm: rssi,
            signal_percent: rssi.map(dbm_to_percent),
            security,
            encryption: None,
        });
    }
    Ok(result)
}

#[cfg(target_os = "macos")]
fn parse_airport_channel(s: &str) -> (Option<u32>, Option<u32>) {
    // e.g. "6", "6,+1", "44,80"
    let first = s.split(',').next().unwrap_or(s);
    if let Ok(ch) = first.parse::<u32>() {
        (Some(ch), Some(channel_to_freq_mhz(ch)))
    } else {
        (None, None)
    }
}

// ---------- Windows ----------

#[cfg(target_os = "windows")]
fn scan_windows() -> Result<Vec<WifiNetwork>> {
    let out = Command::new("netsh")
        .args(["wlan", "show", "networks", "mode=bssid"])
        .output()
        .context("run netsh wlan")?;
    if !out.status.success() {
        bail!("netsh exited with {}", out.status);
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut result: Vec<WifiNetwork> = Vec::new();
    let mut cur: Option<WifiNetwork> = None;

    for line in text.lines() {
        let trimmed = line.trim();
        if is_label(trimmed, "SSID") && !is_label(trimmed, "BSSID") {
            if let Some(n) = cur.take() {
                result.push(n);
            }
            let value = trimmed.splitn(2, ':').nth(1).unwrap_or("").trim().to_string();
            if value.is_empty() {
                continue;
            }
            cur = Some(WifiNetwork {
                ssid: value,
                bssid: None,
                channel: None,
                frequency_mhz: None,
                signal_dbm: None,
                signal_percent: None,
                security: String::new(),
                encryption: None,
            });
        } else if let Some(n) = cur.as_mut() {
            if is_label(trimmed, "Authentication") || trimmed.contains("Проверка подлинности") {
                n.security = trimmed.splitn(2, ':').nth(1).unwrap_or("").trim().to_string();
            } else if is_label(trimmed, "BSSID") {
                let v = trimmed.splitn(2, ':').skip(1).collect::<Vec<_>>().join(":");
                n.bssid = Some(v.trim().to_ascii_lowercase());
            } else if is_label(trimmed, "Signal") || trimmed.contains("Сигнал") {
                if let Some(pct) = trimmed.split(':').nth(1) {
                    let pct = pct.trim().trim_end_matches('%').trim();
                    if let Ok(v) = pct.parse::<i32>() {
                        n.signal_percent = Some(v.clamp(0, 100) as u8);
                        n.signal_dbm = Some(percent_to_dbm(v));
                    }
                }
            } else if is_label(trimmed, "Channel") || trimmed.contains("Канал") {
                if let Some(ch) = trimmed.split(':').nth(1) {
                    if let Ok(v) = ch.trim().parse::<u32>() {
                        n.channel = Some(v);
                        n.frequency_mhz = Some(channel_to_freq_mhz(v));
                    }
                }
            } else if is_label(trimmed, "Encryption") || trimmed.contains("Шифрование") {
                n.encryption = Some(trimmed.splitn(2, ':').nth(1).unwrap_or("").trim().to_string());
            }
        }
    }
    if let Some(n) = cur.take() {
        result.push(n);
    }
    Ok(result)
}

#[cfg(target_os = "windows")]
fn is_label(line: &str, label: &str) -> bool {
    line.starts_with(label) && line.contains(':')
}

// ---------- helpers ----------

fn channel_to_freq_mhz(channel: u32) -> u32 {
    match channel {
        1..=13 => 2407 + channel * 5,
        14 => 2484,
        32..=177 => 5000 + channel * 5,
        _ => 0,
    }
}

fn freq_to_channel(freq: u32) -> u32 {
    if freq == 2484 {
        14
    } else if freq < 2484 {
        (freq - 2407) / 5
    } else {
        (freq - 5000) / 5
    }
}

fn percent_to_dbm(percent: i32) -> i32 {
    (percent / 2) - 100
}

fn dbm_to_percent(dbm: i32) -> u8 {
    ((dbm + 100) * 2).clamp(0, 100) as u8
}

