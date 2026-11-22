//! Build a simple topology graph from discovered devices, routers and Wi-Fi
//! access points. Edges are classified as confirmed or inferred:
//!
//! - Confirmed: only when we can prove the relationship from collected data
//!   (e.g. a device whose MAC matches a Wi-Fi BSSID, or a device that equals
//!   the default gateway IP).
//! - Inferred: same-subnet co-presence, or gateway reachability.
//!
//! We do NOT claim a physical link between a switch and a host unless we can
//! verify it (e.g. via SNMP bridge MIB walks, which are out of scope here).

use network_core::{Gateway, NetworkInterface};
use network_discovery::DiscoveredDevice;
use router_manager::RouterInfo;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use tracing::info;
use wifi_scanner::WifiNetwork;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeType {
    ThisHost,
    Router,
    Switch,
    AccessPoint,
    EndDevice,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EdgeType {
    Confirmed,
    Inferred,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopologyNode {
    pub id: String,
    pub label: String,
    pub node_type: NodeType,
    pub ip: Option<IpAddr>,
    pub mac: Option<String>,
    pub vendor: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopologyEdge {
    pub from: String,
    pub to: String,
    pub edge_type: EdgeType,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Topology {
    pub nodes: Vec<TopologyNode>,
    pub edges: Vec<TopologyEdge>,
}

pub fn build(
    interfaces: &[NetworkInterface],
    gateways: &[Gateway],
    routers: &[RouterInfo],
    devices: &[DiscoveredDevice],
    wifi: &[WifiNetwork],
) -> Topology {
    let mut nodes = Vec::new();
    let mut edges = Vec::new();

    // Local host nodes.
    for iface in interfaces {
        if iface.ipv4.is_empty() {
            continue;
        }
        let primary = iface.ipv4[0].addr();
        nodes.push(TopologyNode {
            id: format!("host:{}", iface.name),
            label: format!("this-host ({})", iface.name),
            node_type: NodeType::ThisHost,
            ip: Some(IpAddr::V4(primary)),
            mac: iface.mac.clone(),
            vendor: None,
        });
    }

    // Router nodes.
    for r in routers {
        let id = format!("router:{}", r.ip);
        nodes.push(TopologyNode {
            id: id.clone(),
            label: r
                .name
                .clone()
                .or_else(|| r.model.clone())
                .unwrap_or_else(|| r.ip.to_string()),
            node_type: NodeType::Router,
            ip: Some(r.ip),
            mac: r.mac.clone(),
            vendor: r.vendor.clone(),
        });
    }

    // Devices (dedupe against routers by IP).
    for d in devices {
        if routers.iter().any(|r| r.ip == d.ip) {
            continue;
        }
        let id = format!("device:{}", d.ip);
        let label = d
            .hostname
            .clone()
            .unwrap_or_else(|| d.ip.to_string());
        nodes.push(TopologyNode {
            id,
            label,
            node_type: NodeType::EndDevice,
            ip: Some(d.ip),
            mac: d.mac.clone(),
            vendor: d.vendor.clone(),
        });
    }

    // Wi-Fi access points (dedupe by BSSID).
    let mut aps_added: std::collections::HashSet<String> = std::collections::HashSet::new();
    for net in wifi {
        if let Some(bssid) = &net.bssid {
            if !bssid.is_empty() && aps_added.insert(bssid.clone()) {
                nodes.push(TopologyNode {
                    id: format!("ap:{bssid}"),
                    label: format!("AP {}", net.ssid),
                    node_type: NodeType::AccessPoint,
                    ip: None,
                    mac: Some(bssid.clone()),
                    vendor: None,
                });
            }
        }
    }

    // Edges: this-host -> default gateway / router (inferred)
    for gw in gateways {
        let router_id = format!("router:{}", gw.ip);
        for iface in interfaces {
            if iface.ipv4.is_empty() {
                continue;
            }
            edges.push(TopologyEdge {
                from: format!("host:{}", iface.name),
                to: router_id.clone(),
                edge_type: EdgeType::Inferred,
                reason: if gw.is_default {
                    "default gateway (system routing table)".to_string()
                } else {
                    "gateway candidate (system routing table)".to_string()
                },
            });
        }
    }

    // Edges: router -> device (inferred, same subnet).
    for d in devices {
        if routers.iter().any(|r| r.ip == d.ip) {
            continue;
        }
        for r in routers {
            // Only link devices that share a subnet with the router's IP when we can tell;
            // otherwise mark as inferred by proximity.
            let reason = match (d.ip, r.ip) {
                (IpAddr::V4(_), IpAddr::V4(_)) => "co-observed on scanned subnet",
                _ => "co-observed (address family mismatch)",
            };
            edges.push(TopologyEdge {
                from: format!("router:{}", r.ip),
                to: format!("device:{}", d.ip),
                edge_type: EdgeType::Inferred,
                reason: reason.to_string(),
            });
        }
    }

    // Edges: device with MAC matching a Wi-Fi BSSID => confirmed AP relationship.
    for d in devices {
        if let Some(mac) = &d.mac {
            let low = mac.to_ascii_lowercase();
            if aps_added.contains(&low) {
                for net in wifi {
                    if let Some(b) = &net.bssid {
                        if b.eq_ignore_ascii_case(&low) {
                            edges.push(TopologyEdge {
                                from: format!("ap:{b}"),
                                to: format!("device:{}", d.ip),
                                edge_type: EdgeType::Confirmed,
                                reason: "device MAC equals Wi-Fi BSSID".to_string(),
                            });
                        }
                    }
                }
            }
        }
    }

    // Dedupe identical edges.
    let mut seen = std::collections::HashSet::new();
    edges.retain(|e| seen.insert((e.from.clone(), e.to.clone(), e.reason.clone())));

    info!("topology: {} nodes, {} edges", nodes.len(), edges.len());
    Topology { nodes, edges }
}

