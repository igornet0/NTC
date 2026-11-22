//! Router discovery via SSDP/UPnP, HTTP probing and SNMP v2c GET.

pub mod http_probe;
pub mod snmp;
pub mod ssdp;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::time::Duration;
use tracing::{debug, info};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouterInfo {
    pub ip: IpAddr,
    pub mac: Option<String>,
    pub vendor: Option<String>,
    pub model: Option<String>,
    pub name: Option<String>,
    pub device_type: String,
    pub discovery: Vec<String>,
    pub open_ports: Vec<u16>,
    pub http_title: Option<String>,
    pub web_url: Option<String>,
    pub snmp: Option<snmp::SnmpInfo>,
    pub ssdp: Option<ssdp::SsdpDevice>,
    pub is_default_gateway: bool,
}

impl RouterInfo {
    pub fn new(ip: IpAddr) -> Self {
        Self {
            ip,
            mac: None,
            vendor: None,
            model: None,
            name: None,
            device_type: "unknown".to_string(),
            discovery: Vec::new(),
            open_ports: Vec::new(),
            http_title: None,
            web_url: None,
            snmp: None,
            ssdp: None,
            is_default_gateway: false,
        }
    }

    pub fn add_method(&mut self, method: &str) {
        if !self.discovery.iter().any(|m| m == method) {
            self.discovery.push(method.to_string());
        }
    }
}

#[derive(Debug, Clone)]
pub struct RouterDiscoveryOptions {
    pub snmp_community: String,
    pub timeout: Duration,
    pub try_snmp: bool,
    pub try_ssdp: bool,
    pub try_http: bool,
}

impl Default for RouterDiscoveryOptions {
    fn default() -> Self {
        Self {
            snmp_community: "public".to_string(),
            timeout: Duration::from_secs(2),
            try_snmp: true,
            try_ssdp: true,
            try_http: true,
        }
    }
}

pub async fn discover_routers(
    gateway_ips: &[IpAddr],
    default_gateway: Option<IpAddr>,
    options: &RouterDiscoveryOptions,
) -> Result<Vec<RouterInfo>> {
    let mut routers: Vec<RouterInfo> = Vec::new();

    // Seed with gateways.
    for ip in gateway_ips {
        let mut r = RouterInfo::new(*ip);
        r.add_method("gateway");
        r.device_type = "router".to_string();
        r.is_default_gateway = Some(*ip) == default_gateway;
        routers.push(r);
    }

    // SSDP enrichment: match responders by IP.
    if options.try_ssdp {
        match ssdp::discover(options.timeout).await {
            Ok(devices) => {
                for d in devices {
                    if let Some(ip) = d.ip {
                        if let Some(r) = routers.iter_mut().find(|r| r.ip == ip) {
                            if r.vendor.is_none() {
                                r.vendor = d.manufacturer.clone();
                            }
                            if r.model.is_none() {
                                r.model = d.model_name.clone();
                            }
                            if r.name.is_none() {
                                r.name = d.friendly_name.clone();
                            }
                            r.add_method("ssdp");
                            r.ssdp = Some(d);
                        }
                    }
                }
            }
            Err(e) => debug!("SSDP discovery failed: {e}"),
        }
    }

    for r in routers.iter_mut() {
        if options.try_snmp {
            match snmp::query(r.ip, &options.snmp_community, options.timeout).await {
                Ok(info) => {
                    r.add_method("snmp");
                    if let Some(n) = &info.sys_name {
                        if r.name.is_none() {
                            r.name = Some(n.clone());
                        }
                    }
                    if let Some(desc) = &info.sys_descr {
                        if r.model.is_none() {
                            r.model = Some(summarize_sysdescr(desc));
                        }
                    }
                    r.snmp = Some(info);
                }
                Err(e) => debug!("SNMP query to {} failed: {e}", r.ip),
            }
        }

        if options.try_http {
            if let Some(probe) = http_probe::probe(r.ip, options.timeout).await {
                r.add_method("http");
                if let Some(t) = probe.title {
                    if !t.is_empty() {
                        r.http_title = Some(t.clone());
                        if r.model.is_none() {
                            r.model = Some(t);
                        }
                    }
                }
                r.web_url = Some(probe.url);
                if !probe.open_ports.is_empty() {
                    r.open_ports = probe.open_ports;
                }
            }
        }
    }

    info!("discovered {} router candidates", routers.len());
    Ok(routers)
}

fn summarize_sysdescr(descr: &str) -> String {
    // First line, truncated.
    let first = descr.lines().next().unwrap_or(descr).trim();
    first.chars().take(120).collect()
}

