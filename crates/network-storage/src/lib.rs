//! SQLite persistence for scan snapshots.
//!
//! A scan record stores the full snapshot serialized as JSON so that the schema
//! remains stable even as new fields are added. Query-oriented indexes are kept
//! on top of the scan table.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use network_core::NetworkInfo;
use network_discovery::DiscoveredDevice;
use network_topology::Topology;
use router_manager::RouterInfo;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::{Arc, Mutex};
use tracing::{debug, info};
use wifi_scanner::WifiNetwork;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRecord {
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    pub hostname: Option<String>,
    pub network: NetworkInfo,
    pub devices: Vec<DiscoveredDevice>,
    pub routers: Vec<RouterInfo>,
    pub wifi: Vec<WifiNetwork>,
    pub topology: Option<Topology>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub id: i64,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    pub device_count: usize,
    pub router_count: usize,
}

#[derive(Clone)]
pub struct Storage {
    conn: Arc<Mutex<Connection>>,
}

impl Storage {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).ok();
            }
        }
        let conn = Connection::open(path).with_context(|| format!("open SQLite {}", path.display()))?;
        conn.pragma_update(None, "journal_mode", "WAL").ok();
        let storage = Storage { conn: Arc::new(Mutex::new(conn)) };
        storage.init_schema()?;
        info!("storage ready at {}", path.display());
        Ok(storage)
    }

    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        let storage = Storage { conn: Arc::new(Mutex::new(conn)) };
        storage.init_schema()?;
        Ok(storage)
    }

    fn init_schema(&self) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                started_at TEXT NOT NULL,
                finished_at TEXT NOT NULL,
                hostname TEXT,
                device_count INTEGER NOT NULL,
                router_count INTEGER NOT NULL,
                payload TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS scans_finished_idx ON scans(finished_at);
            "#,
        )?;
        Ok(())
    }

    pub fn save_scan(&self, scan: &ScanRecord) -> Result<i64> {
        let payload = serde_json::to_string(scan)?;
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO scans (started_at, finished_at, hostname, device_count, router_count, payload) VALUES (?, ?, ?, ?, ?, ?)",
            params![
                scan.started_at.to_rfc3339(),
                scan.finished_at.to_rfc3339(),
                scan.hostname,
                scan.devices.len() as i64,
                scan.routers.len() as i64,
                payload,
            ],
        )?;
        let id = conn.last_insert_rowid();
        debug!("stored scan {id}");
        Ok(id)
    }

    pub fn list_scans(&self) -> Result<Vec<ScanSummary>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, started_at, finished_at, device_count, router_count FROM scans ORDER BY id DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            let started: String = row.get(1)?;
            let finished: String = row.get(2)?;
            Ok(ScanSummary {
                id: row.get(0)?,
                started_at: DateTime::parse_from_rfc3339(&started)
                    .map(|d| d.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                finished_at: DateTime::parse_from_rfc3339(&finished)
                    .map(|d| d.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                device_count: row.get::<_, i64>(3)? as usize,
                router_count: row.get::<_, i64>(4)? as usize,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    pub fn load_scan(&self, id: i64) -> Result<Option<ScanRecord>> {
        let conn = self.conn.lock().unwrap();
        let payload: Option<String> = conn
            .query_row("SELECT payload FROM scans WHERE id = ?1", [id], |row| row.get(0))
            .optional()?;
        match payload {
            Some(json) => Ok(Some(serde_json::from_str(&json)?)),
            None => Ok(None),
        }
    }
}

