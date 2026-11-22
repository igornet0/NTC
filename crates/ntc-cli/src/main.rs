use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use ipnet::Ipv4Net;
use network_core::{NetworkInfo, SubnetInfo};
use network_discovery::{discover_network, DiscoveryOptions};
use network_storage::{ScanRecord, Storage};
use network_topology::{build as build_topology, Topology};
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;
use tracing::{info, warn};

#[derive(Parser)]
#[command(name = "ntc", version, about = "NTC — Network Analyzer", long_about = None)]
struct Cli {
    #[arg(long, global = true, default_value = "info")]
    log_level: String,
    #[arg(long, global = true, default_value = "ntc.db")]
    db: PathBuf,
    #[arg(long, global = true, help = "Emit machine-readable JSON")]
    json: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// List local network interfaces with IP, MAC and subnet.
    Interfaces,
    /// Show default gateway(s).
    Gateway,
    /// Show system DNS servers.
    Dns,
    /// Full local network scan (subnet discovery + devices + routers + topology).
    Scan {
        #[arg(long, default_value_t = 30)]
        timeout: u64,
        #[arg(long, default_value_t = 512, help = "Max hosts per subnet to probe")]
        max_hosts: usize,
        #[arg(long, default_value = "public")]
        snmp_community: String,
        #[arg(long, help = "Skip ICMP ping sweep")]
        no_icmp: bool,
        #[arg(long, help = "Skip mDNS")]
        no_mdns: bool,
        #[arg(long, help = "Skip Wi-Fi scan")]
        no_wifi: bool,
    },
    /// Discover Wi-Fi networks.
    Wifi,
    /// Discover routers (SSDP/HTTP/SNMP).
    Routers {
        #[arg(long, default_value_t = 15)]
        timeout: u64,
        #[arg(long, default_value = "public")]
        community: String,
    },
    /// Fingerprint a device (port scan + service inference).
    Fingerprint {
        ip: String,
        #[arg(long, default_value_t = 600)]
        connect_timeout_ms: u64,
    },
    /// Print list of saved scans.
    History,
    /// Dump a saved scan as JSON to stdout.
    Show { id: i64 },
    /// Export a saved scan to a JSON file.
    Export { id: i64, file: PathBuf },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| cli.log_level.clone());
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(filter))
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();

    match cli.command {
        Command::Interfaces => cmd_interfaces(cli.json).await,
        Command::Gateway => cmd_gateway(cli.json).await,
        Command::Dns => cmd_dns(cli.json).await,
        Command::Scan {
            timeout,
            max_hosts,
            snmp_community,
            no_icmp,
            no_mdns,
            no_wifi,
        } => cmd_scan(&cli, timeout, max_hosts, snmp_community, !no_icmp, !no_mdns, !no_wifi).await,
        Command::Wifi => cmd_wifi(cli.json).await,
        Command::Routers { timeout, community } => cmd_routers(&cli, timeout, community).await,
        Command::Fingerprint { ip, connect_timeout_ms } => {
            cmd_fingerprint(cli.json, ip, connect_timeout_ms).await
        }
        Command::History => cmd_history(&cli).await,
        Command::Show { id } => cmd_show(&cli, id).await,
        Command::Export { id, file } => cmd_export(&cli, id, file).await,
    }
}

async fn cmd_interfaces(json: bool) -> Result<()> {
    let ifaces = network_core::list_interfaces()?;
    if json {
        println!("{}", serde_json::to_string_pretty(&ifaces)?);
    } else {
        for i in &ifaces {
            println!(
                "{:<20} {:?} mac={} ipv4=[{}]",
                i.name,
                i.interface_type,
                i.mac.as_deref().unwrap_or("-"),
                i.ipv4.iter().map(|n| n.to_string()).collect::<Vec<_>>().join(", ")
            );
        }
    }
    Ok(())
}

async fn cmd_gateway(json: bool) -> Result<()> {
    let gws = network_core::discover_gateways()?;
    if json {
        println!("{}", serde_json::to_string_pretty(&gws)?);
    } else if gws.is_empty() {
        println!("no gateway detected");
    } else {
        for g in &gws {
            println!("{}{}", g.ip, if g.is_default { " (default)" } else { "" });
        }
    }
    Ok(())
}

async fn cmd_dns(json: bool) -> Result<()> {
    let dns = network_core::discover_dns_servers();
    if json {
        println!("{}", serde_json::to_string_pretty(&dns)?);
    } else if dns.is_empty() {
        println!("no DNS server detected");
    } else {
        for d in &dns {
            println!("{d}");
        }
    }
    Ok(())
}

async fn cmd_wifi(json: bool) -> Result<()> {
    match wifi_scanner::scan() {
        Ok(nets) => {
            if json {
                println!("{}", serde_json::to_string_pretty(&nets)?);
            } else if nets.is_empty() {
                println!("no networks found");
            } else {
                for n in &nets {
                    println!(
                        "{:<32} bssid={:<18} ch={:<4} sig={}% ({} dBm) sec={}",
                        n.ssid,
                        n.bssid.as_deref().unwrap_or("-"),
                        n.channel.map(|c| c.to_string()).unwrap_or_else(|| "-".into()),
                        n.signal_percent.map(|s| s.to_string()).unwrap_or_else(|| "-".into()),
                        n.signal_dbm.map(|s| s.to_string()).unwrap_or_else(|| "-".into()),
                        if n.security.is_empty() { "open" } else { &n.security },
                    );
                }
            }
        }
        Err(e) => {
            warn!("Wi-Fi scan failed: {e}");
            println!("Wi-Fi scan failed: {e}");
        }
    }
    Ok(())
}

async fn cmd_routers(cli: &Cli, timeout: u64, community: String) -> Result<()> {
    let gws = network_core::discover_gateways()?;
    let gw_ips: Vec<IpAddr> = gws.iter().map(|g| g.ip).collect();
    let default_gw = gws.iter().find(|g| g.is_default).map(|g| g.ip);
    let opts = router_manager::RouterDiscoveryOptions {
        snmp_community: community,
        timeout: Duration::from_secs(2),
        ..Default::default()
    };
    let routers = router_manager::discover_routers(&gw_ips, default_gw, &opts).await?;
    let _ = timeout;
    if cli.json {
        println!("{}", serde_json::to_string_pretty(&routers)?);
    } else if routers.is_empty() {
        println!("no routers detected");
    } else {
        for r in &routers {
            println!(
                "{} {:<10} name={} vendor={} model={} methods=[{}]",
                r.ip,
                r.device_type,
                r.name.as_deref().unwrap_or("-"),
                r.vendor.as_deref().unwrap_or("-"),
                r.model.as_deref().unwrap_or("-"),
                r.discovery.join(",")
            );
        }
    }
    Ok(())
}

async fn cmd_fingerprint(json: bool, ip: String, connect_timeout_ms: u64) -> Result<()> {
    let ip: IpAddr = ip.parse().context("parse IP")?;
    let opts = device_fingerprint::ScanOptions {
        connect_timeout: Duration::from_millis(connect_timeout_ms),
        ..Default::default()
    };
    let fp = device_fingerprint::fingerprint(ip, &opts).await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&fp)?);
    } else {
        println!("{}: {}", fp.ip, fp.device_type);
        if let Some(os) = &fp.os_guess {
            println!("  os   : {os}");
        }
        if let Some(t) = &fp.http_title {
            println!("  http : {t}");
        }
        for p in &fp.open_ports {
            println!(
                "  port : {:>5}/tcp  {:<12} {}{}",
                p.port,
                p.service.as_deref().unwrap_or("-"),
                p.state,
                p.banner
                    .as_deref()
                    .map(|b| format!("  banner: {}", b.lines().next().unwrap_or(b)))
                    .unwrap_or_default()
            );
        }
    }
    Ok(())
}

async fn cmd_scan(
    cli: &Cli,
    timeout: u64,
    max_hosts: usize,
    snmp_community: String,
    enable_icmp: bool,
    enable_mdns: bool,
    enable_wifi: bool,
) -> Result<()> {
    let started_at = chrono::Utc::now();
    info!("starting scan");

    let network = network_core::collect().await?;

    let subnets: Vec<Ipv4Net> = network
        .subnets
        .iter()
        .filter_map(|s: &SubnetInfo| s.cidr.parse::<Ipv4Net>().ok())
        .filter(|n| n.prefix_len() <= 24)
        .collect();

    let discovery_opts = DiscoveryOptions {
        max_hosts_per_subnet: max_hosts,
        ping_timeout: Duration::from_secs(1),
        max_concurrency: 128,
        enable_mdns,
        mdns_timeout: Duration::from_secs(4),
        enable_icmp,
    };
    let devices = discover_network(&subnets, &discovery_opts).await?;

    let gw_ips: Vec<IpAddr> = network.gateways.iter().map(|g| g.ip).collect();
    let default_gw = network.gateways.iter().find(|g| g.is_default).map(|g| g.ip);
    let router_opts = router_manager::RouterDiscoveryOptions {
        snmp_community,
        timeout: Duration::from_secs(2),
        ..Default::default()
    };
    let routers = router_manager::discover_routers(&gw_ips, default_gw, &router_opts).await?;

    let wifi = if enable_wifi {
        match wifi_scanner::scan() {
            Ok(v) => v,
            Err(e) => {
                warn!("Wi-Fi scan failed: {e}");
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };

    let topology = build_topology(&network.interfaces, &network.gateways, &routers, &devices, &wifi);

    let finished_at = chrono::Utc::now();
    let hostname = hostname_string();
    let record = ScanRecord {
        started_at,
        finished_at,
        hostname,
        network,
        devices,
        routers,
        wifi,
        topology: Some(topology.clone()),
    };

    let storage = Storage::open(&cli.db)?;
    let id = storage.save_scan(&record)?;
    info!("scan #{id} saved to {}", cli.db.display());

    if cli.json {
        println!("{}", serde_json::to_string_pretty(&record)?);
    } else {
        print_scan_summary(&record, &topology);
    }
    Ok(())
}

fn print_scan_summary(record: &ScanRecord, topology: &Topology) {
    println!("scan finished in {:?}", record.finished_at - record.started_at);
    println!(
        "interfaces: {}",
        record
            .network
            .interfaces
            .iter()
            .map(|i| i.name.clone())
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!(
        "subnets   : {}",
        record
            .network
            .subnets
            .iter()
            .map(|s| s.cidr.clone())
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!("routers   : {}", record.routers.len());
    for r in &record.routers {
        println!(
            "  {} {:<12} {}",
            r.ip,
            r.device_type,
            r.name.as_deref().or(r.model.as_deref()).unwrap_or("-")
        );
    }
    println!("devices   : {}", record.devices.len());
    for d in &record.devices {
        println!(
            "  {:<15} {:<17} {}",
            d.ip,
            d.mac.as_deref().unwrap_or("-"),
            d.hostname.as_deref().or(d.vendor.as_deref()).unwrap_or("-")
        );
    }
    println!("wifi      : {} network(s)", record.wifi.len());
    println!(
        "topology  : {} nodes, {} edges",
        topology.nodes.len(),
        topology.edges.len()
    );
}

async fn cmd_history(cli: &Cli) -> Result<()> {
    let storage = Storage::open(&cli.db)?;
    let scans = storage.list_scans()?;
    if cli.json {
        println!("{}", serde_json::to_string_pretty(&scans)?);
    } else if scans.is_empty() {
        println!("no scans saved in {}", cli.db.display());
    } else {
        for s in &scans {
            println!(
                "#{:<4} {}  devices={} routers={}",
                s.id,
                s.started_at.to_rfc3339(),
                s.device_count,
                s.router_count
            );
        }
    }
    Ok(())
}

async fn cmd_show(cli: &Cli, id: i64) -> Result<()> {
    let storage = Storage::open(&cli.db)?;
    match storage.load_scan(id)? {
        Some(rec) => println!("{}", serde_json::to_string_pretty(&rec)?),
        None => println!("scan #{id} not found"),
    }
    Ok(())
}

async fn cmd_export(cli: &Cli, id: i64, file: PathBuf) -> Result<()> {
    let storage = Storage::open(&cli.db)?;
    match storage.load_scan(id)? {
        Some(rec) => {
            let json = serde_json::to_string_pretty(&rec)?;
            std::fs::write(&file, json)?;
            println!("scan #{id} exported to {}", file.display());
        }
        None => println!("scan #{id} not found"),
    }
    Ok(())
}

fn hostname_string() -> Option<String> {
    if let Ok(o) = std::process::Command::new("hostname").output() {
        if o.status.success() {
            let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
            if !s.is_empty() {
                return Some(s);
            }
        }
    }
    std::env::var("COMPUTERNAME").ok()
}

