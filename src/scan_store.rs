//! SQLite-backed scan result persistence.
//!
//! The public methods are async wrappers around blocking rusqlite work. The
//! blocking methods stay private so callers cannot accidentally run database
//! I/O on the GUI or async executor path.

use std::path::PathBuf;

use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

use crate::error::ScanError;
use crate::types::{
    Device, DeviceStatus, Finding, FindingCategory, FindingConfidence, FindingSeverity,
    FindingSource, Port, PortState,
};

const SCHEMA_VERSION: i64 = 2;
const MAX_PAGE_LIMIT: u32 = 500;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScanSessionStatus {
    Running,
    Completed,
    Cancelled,
    Error,
}

impl ScanSessionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Cancelled => "cancelled",
            Self::Error => "error",
        }
    }

    fn from_str(value: &str) -> Result<Self, ScanError> {
        match value {
            "running" => Ok(Self::Running),
            "completed" => Ok(Self::Completed),
            "cancelled" => Ok(Self::Cancelled),
            "error" => Ok(Self::Error),
            other => Err(ScanError::ScanStoreError(format!(
                "Unknown scan session status '{}'",
                other
            ))),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct StoredScanConfig {
    pub timeout_ms: u64,
    pub scan_ports: bool,
    pub ports: Vec<u16>,
    pub max_concurrent_hosts: Option<u32>,
    pub max_concurrent_ports: Option<u32>,
    pub discovery_methods: Option<Vec<String>>,
    pub retry_count: Option<u8>,
    pub scan_type: String,
    pub timing_template: Option<String>,
    pub web_audit_enabled: bool,
    pub active_checks_enabled: bool,
}

/// Unified scan session input type.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanSession {
    pub id: String,
    pub cidr: String,
    pub total_hosts: u32,
    pub config: StoredScanConfig,
    pub started_at: i64,
}

/// Backward-compatible alias for code that still references `NewScanSession`.
#[deprecated(note = "Use ScanSession instead")]
pub type NewScanSession = ScanSession;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanSessionSummary {
    pub id: String,
    pub cidr: String,
    pub status: ScanSessionStatus,
    pub total_hosts: u32,
    pub scanned_hosts: u32,
    pub device_count: u32,
    pub finding_count: u32,
    pub started_at: i64,
    pub updated_at: i64,
    pub completed_at: Option<i64>,
    pub duration_ms: Option<u64>,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredDeviceSummary {
    pub scan_id: String,
    pub ip: String,
    pub mac: String,
    pub hostname: Option<String>,
    pub vendor: Option<String>,
    pub os: Option<String>,
    pub status: String,
    pub port_count: u32,
    pub open_port_count: u32,
    pub finding_count: u32,
    pub last_seen: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Page<T> {
    pub items: Vec<T>,
    pub total: u32,
    pub limit: u32,
    pub offset: u32,
}

/// Summarized view of a persisted finding for paginated UI lists.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FindingSummary {
    pub scan_id: String,
    pub finding_id: String,
    pub device_ip: String,
    pub category: FindingCategory,
    pub source: FindingSource,
    pub severity: FindingSeverity,
    pub title: String,
    pub port: Option<u16>,
    pub service: Option<String>,
    pub cvss_score: Option<f64>,
    pub epss_probability: Option<f64>,
    pub risk_score: f64,
    pub timestamp: i64,
}

#[derive(Debug, Clone)]
pub struct ScanStore {
    db_path: PathBuf,
}

impl ScanStore {
    pub fn new(config_dir: PathBuf) -> Self {
        Self {
            db_path: config_dir.join("scan_results.db"),
        }
    }

    pub async fn initialize(&self) -> Result<(), ScanError> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || store.initialize_blocking())
            .await
            .map_err(|e| ScanError::ScanStoreError(format!("Scan store init task failed: {}", e)))?
    }

    pub async fn create_scan_session(&self, session: ScanSession) -> Result<String, ScanError> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || store.create_session_blocking(&session))
            .await
            .map_err(|e| {
                ScanError::ScanStoreError(format!("Scan session create task failed: {}", e))
            })?
    }

    /// Upsert device metadata and snapshot.
    ///
    /// This does **not** authoritatively replace ports or findings; use
    /// [`ScanStore::upsert_port`] and [`ScanStore::insert_finding`] for those.
    pub async fn upsert_device(&self, scan_id: String, device: Device) -> Result<(), ScanError> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || store.upsert_device_blocking(&scan_id, &device))
            .await
            .map_err(|e| {
                ScanError::ScanStoreError(format!("Scan device upsert task failed: {}", e))
            })?
    }

    /// Upsert a single port for a device.
    pub async fn upsert_port(
        &self,
        scan_id: String,
        device_ip: String,
        port: Port,
    ) -> Result<(), ScanError> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || store.upsert_port_blocking(&scan_id, &device_ip, &port))
            .await
            .map_err(|e| {
                ScanError::ScanStoreError(format!("Scan port upsert task failed: {}", e))
            })?
    }

    /// Insert a single finding.
    pub async fn insert_finding(&self, scan_id: String, finding: Finding) -> Result<(), ScanError> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || store.insert_finding_blocking(&scan_id, &finding))
            .await
            .map_err(|e| {
                ScanError::ScanStoreError(format!("Scan finding insert task failed: {}", e))
            })?
    }

    pub async fn update_progress(
        &self,
        scan_id: String,
        scanned_hosts: u32,
        total_hosts: u32,
    ) -> Result<(), ScanError> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || {
            store.update_progress_blocking(&scan_id, scanned_hosts, total_hosts)
        })
        .await
        .map_err(|e| {
            ScanError::ScanStoreError(format!("Scan progress update task failed: {}", e))
        })?
    }

    pub async fn complete_scan_session(
        &self,
        scan_id: String,
        status: ScanSessionStatus,
        duration_ms: Option<u64>,
        error_message: Option<String>,
    ) -> Result<(), ScanError> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || {
            store.complete_session_blocking(&scan_id, status, duration_ms, error_message.as_deref())
        })
        .await
        .map_err(|e| {
            ScanError::ScanStoreError(format!("Scan session complete task failed: {}", e))
        })?
    }

    pub async fn list_sessions(
        &self,
        limit: u32,
        offset: u32,
    ) -> Result<Page<ScanSessionSummary>, ScanError> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || store.list_sessions_blocking(limit, offset))
            .await
            .map_err(|e| {
                ScanError::ScanStoreError(format!("Scan session list task failed: {}", e))
            })?
    }

    pub async fn list_devices_page(
        &self,
        scan_id: String,
        limit: u32,
        offset: u32,
    ) -> Result<Page<StoredDeviceSummary>, ScanError> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || store.list_devices_blocking(&scan_id, limit, offset))
            .await
            .map_err(|e| {
                ScanError::ScanStoreError(format!("Scan device list task failed: {}", e))
            })?
    }

    pub async fn get_device(
        &self,
        scan_id: String,
        ip: String,
    ) -> Result<Option<Device>, ScanError> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || store.get_device_blocking(&scan_id, &ip))
            .await
            .map_err(|e| {
                ScanError::ScanStoreError(format!("Scan device load task failed: {}", e))
            })?
    }

    pub async fn delete_session(&self, scan_id: String) -> Result<(), ScanError> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || store.delete_session_blocking(&scan_id))
            .await
            .map_err(|e| {
                ScanError::ScanStoreError(format!("Scan session delete task failed: {}", e))
            })?
    }

    pub async fn list_findings_page(
        &self,
        scan_id: String,
        severity_filter: Option<FindingSeverity>,
        limit: u32,
        offset: u32,
    ) -> Result<Page<FindingSummary>, ScanError> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || {
            store.list_findings_page_blocking(&scan_id, severity_filter, limit, offset)
        })
        .await
        .map_err(|e| ScanError::ScanStoreError(format!("Scan findings list task failed: {}", e)))?
    }

    fn open_connection(&self) -> Result<Connection, ScanError> {
        if let Some(parent) = self.db_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                ScanError::ScanStoreError(format!("Failed to create scan store directory: {}", e))
            })?;
        }

        let conn = Connection::open(&self.db_path).map_err(|e| {
            ScanError::ScanStoreError(format!("Failed to open scan store database: {}", e))
        })?;

        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        Ok(conn)
    }

    fn initialize_blocking(&self) -> Result<(), ScanError> {
        let conn = self.open_connection()?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS scan_sessions (
                id TEXT PRIMARY KEY,
                cidr TEXT NOT NULL,
                status TEXT NOT NULL,
                total_hosts INTEGER NOT NULL,
                scanned_hosts INTEGER NOT NULL DEFAULT 0,
                device_count INTEGER NOT NULL DEFAULT 0,
                finding_count INTEGER NOT NULL DEFAULT 0,
                config_json TEXT NOT NULL,
                started_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                completed_at INTEGER,
                duration_ms INTEGER,
                error_message TEXT
            );

            CREATE TABLE IF NOT EXISTS scan_devices (
                scan_id TEXT NOT NULL,
                ip TEXT NOT NULL,
                mac TEXT NOT NULL,
                hostname TEXT,
                vendor TEXT,
                os TEXT,
                status TEXT NOT NULL,
                port_count INTEGER NOT NULL DEFAULT 0,
                open_port_count INTEGER NOT NULL DEFAULT 0,
                finding_count INTEGER NOT NULL DEFAULT 0,
                last_seen INTEGER NOT NULL,
                device_json TEXT NOT NULL,
                updated_at INTEGER NOT NULL,
                PRIMARY KEY (scan_id, ip),
                FOREIGN KEY (scan_id) REFERENCES scan_sessions(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS scan_ports (
                scan_id TEXT NOT NULL,
                device_ip TEXT NOT NULL,
                number INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                service TEXT,
                state TEXT NOT NULL,
                port_json TEXT NOT NULL,
                PRIMARY KEY (scan_id, device_ip, number, protocol),
                FOREIGN KEY (scan_id, device_ip) REFERENCES scan_devices(scan_id, ip) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS scan_findings (
                scan_id TEXT NOT NULL,
                finding_id TEXT NOT NULL,
                device_ip TEXT NOT NULL,
                source TEXT NOT NULL,
                severity TEXT NOT NULL,
                confidence TEXT NOT NULL,
                title TEXT NOT NULL,
                port INTEGER,
                service TEXT,
                timestamp INTEGER NOT NULL,
                finding_json TEXT NOT NULL,
                PRIMARY KEY (scan_id, finding_id),
                FOREIGN KEY (scan_id, device_ip) REFERENCES scan_devices(scan_id, ip) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS scan_services (
                scan_id TEXT NOT NULL,
                device_ip TEXT NOT NULL,
                port INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                name TEXT,
                product TEXT,
                version TEXT,
                info TEXT,
                service_json TEXT NOT NULL,
                PRIMARY KEY (scan_id, device_ip, port, protocol),
                FOREIGN KEY (scan_id, device_ip) REFERENCES scan_devices(scan_id, ip) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS scan_web_audits (
                scan_id TEXT NOT NULL,
                device_ip TEXT NOT NULL,
                port INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                url TEXT NOT NULL,
                audit_json TEXT NOT NULL,
                PRIMARY KEY (scan_id, device_ip, port, protocol, url),
                FOREIGN KEY (scan_id, device_ip) REFERENCES scan_devices(scan_id, ip) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS scan_metadata (
                scan_id TEXT NOT NULL,
                key TEXT NOT NULL,
                value_json TEXT NOT NULL,
                PRIMARY KEY (scan_id, key),
                FOREIGN KEY (scan_id) REFERENCES scan_sessions(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_scan_sessions_started_at
                ON scan_sessions(started_at DESC);
            CREATE INDEX IF NOT EXISTS idx_scan_devices_scan_id
                ON scan_devices(scan_id, ip);
            CREATE INDEX IF NOT EXISTS idx_scan_findings_scan_id
                ON scan_findings(scan_id, severity);
            CREATE INDEX IF NOT EXISTS idx_scan_services_scan_id
                ON scan_services(scan_id, device_ip);
            CREATE INDEX IF NOT EXISTS idx_scan_web_audits_scan_id
                ON scan_web_audits(scan_id, device_ip);",
        )
        .map_err(|e| ScanError::ScanStoreError(format!("Failed to initialize schema: {}", e)))?;

        conn.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        Ok(())
    }

    fn create_session_blocking(&self, session: &ScanSession) -> Result<String, ScanError> {
        self.initialize_blocking()?;
        let conn = self.open_connection()?;
        let config_json = serde_json::to_string(&session.config).map_err(|e| {
            ScanError::SerializationError(format!("Failed to serialize scan config: {}", e))
        })?;

        conn.execute(
            "INSERT INTO scan_sessions
                (id, cidr, status, total_hosts, scanned_hosts, device_count, finding_count,
                 config_json, started_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, 0, 0, 0, ?5, ?6, ?6)",
            params![
                session.id,
                session.cidr,
                ScanSessionStatus::Running.as_str(),
                session.total_hosts,
                config_json,
                session.started_at,
            ],
        )
        .map_err(|e| ScanError::ScanStoreError(format!("Failed to create scan session: {}", e)))?;

        Ok(session.id.clone())
    }

    fn upsert_device_blocking(&self, scan_id: &str, device: &Device) -> Result<(), ScanError> {
        let conn = self.open_connection()?;
        let tx = conn.unchecked_transaction().map_err(|e| {
            ScanError::ScanStoreError(format!("Failed to start device transaction: {}", e))
        })?;

        let now = chrono::Utc::now().timestamp();
        let device_json = serde_json::to_string(device).map_err(|e| {
            ScanError::SerializationError(format!("Failed to serialize device: {}", e))
        })?;
        let port_count = usize_to_u32(device.ports.len(), "port count")?;
        let open_port_count = usize_to_u32(
            device
                .ports
                .iter()
                .filter(|port| port.state == PortState::Open)
                .count(),
            "open port count",
        )?;
        let finding_count = usize_to_u32(device.findings.len(), "finding count")?;

        // Upsert only the device-level metadata and snapshot. Ports and findings
        // are managed through standalone upsert_port / insert_finding calls.
        tx.execute(
            "INSERT INTO scan_devices
                (scan_id, ip, mac, hostname, vendor, os, status, port_count, open_port_count,
                 finding_count, last_seen, device_json, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
             ON CONFLICT(scan_id, ip) DO UPDATE SET
                mac = excluded.mac,
                hostname = excluded.hostname,
                vendor = excluded.vendor,
                os = excluded.os,
                status = excluded.status,
                port_count = excluded.port_count,
                open_port_count = excluded.open_port_count,
                finding_count = excluded.finding_count,
                last_seen = excluded.last_seen,
                device_json = excluded.device_json,
                updated_at = excluded.updated_at",
            params![
                scan_id,
                device.ip,
                device.mac,
                device.hostname,
                device.vendor,
                device.os,
                device_status_to_str(&device.status),
                port_count,
                open_port_count,
                finding_count,
                device.last_seen,
                device_json,
                now,
            ],
        )
        .map_err(|e| ScanError::ScanStoreError(format!("Failed to upsert scan device: {}", e)))?;

        refresh_session_counts(&tx, scan_id)?;
        tx.commit().map_err(|e| {
            ScanError::ScanStoreError(format!("Failed to commit device transaction: {}", e))
        })?;
        Ok(())
    }

    fn upsert_port_blocking(
        &self,
        scan_id: &str,
        device_ip: &str,
        port: &Port,
    ) -> Result<(), ScanError> {
        let conn = self.open_connection()?;
        let tx = conn.unchecked_transaction().map_err(|e| {
            ScanError::ScanStoreError(format!("Failed to start port transaction: {}", e))
        })?;

        ensure_device_exists(&tx, scan_id, device_ip)?;

        let port_json = serde_json::to_string(port).map_err(|e| {
            ScanError::SerializationError(format!("Failed to serialize port: {}", e))
        })?;
        tx.execute(
            "INSERT INTO scan_ports
                (scan_id, device_ip, number, protocol, service, state, port_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(scan_id, device_ip, number, protocol) DO UPDATE SET
                service = excluded.service,
                state = excluded.state,
                port_json = excluded.port_json",
            params![
                scan_id,
                device_ip,
                port.number,
                port.protocol,
                port.service,
                port_state_to_str(&port.state),
                port_json,
            ],
        )
        .map_err(|e| ScanError::ScanStoreError(format!("Failed to upsert scan port: {}", e)))?;

        refresh_device_counts(&tx, scan_id, device_ip)?;
        refresh_session_counts(&tx, scan_id)?;
        tx.commit().map_err(|e| {
            ScanError::ScanStoreError(format!("Failed to commit port transaction: {}", e))
        })?;
        Ok(())
    }

    fn insert_finding_blocking(&self, scan_id: &str, finding: &Finding) -> Result<(), ScanError> {
        let conn = self.open_connection()?;
        let tx = conn.unchecked_transaction().map_err(|e| {
            ScanError::ScanStoreError(format!("Failed to start finding transaction: {}", e))
        })?;

        ensure_device_exists(&tx, scan_id, &finding.ip)?;
        upsert_finding_on_connection(&tx, scan_id, finding)?;
        merge_finding_into_device_snapshot(&tx, scan_id, finding)?;
        refresh_device_counts(&tx, scan_id, &finding.ip)?;
        refresh_session_counts(&tx, scan_id)?;
        tx.commit().map_err(|e| {
            ScanError::ScanStoreError(format!("Failed to commit finding transaction: {}", e))
        })?;
        Ok(())
    }

    fn update_progress_blocking(
        &self,
        scan_id: &str,
        scanned_hosts: u32,
        total_hosts: u32,
    ) -> Result<(), ScanError> {
        let conn = self.open_connection()?;
        let rows = conn
            .execute(
                "UPDATE scan_sessions
                 SET scanned_hosts = ?2, total_hosts = ?3, updated_at = ?4
                 WHERE id = ?1",
                params![
                    scan_id,
                    scanned_hosts,
                    total_hosts,
                    chrono::Utc::now().timestamp()
                ],
            )
            .map_err(|e| {
                ScanError::ScanStoreError(format!("Failed to update scan progress: {}", e))
            })?;

        if rows == 0 {
            return Err(ScanError::ScanStoreError(format!(
                "Scan session '{}' not found",
                scan_id
            )));
        }
        Ok(())
    }

    fn complete_session_blocking(
        &self,
        scan_id: &str,
        status: ScanSessionStatus,
        duration_ms: Option<u64>,
        error_message: Option<&str>,
    ) -> Result<(), ScanError> {
        let conn = self.open_connection()?;
        refresh_session_counts(&conn, scan_id)?;
        let now = chrono::Utc::now().timestamp();
        let rows = conn
            .execute(
                "UPDATE scan_sessions
                 SET status = ?2, completed_at = ?3, duration_ms = ?4,
                     error_message = ?5, updated_at = ?3
                 WHERE id = ?1",
                params![
                    scan_id,
                    status.as_str(),
                    now,
                    duration_ms.map(|value| value as i64),
                    error_message,
                ],
            )
            .map_err(|e| {
                ScanError::ScanStoreError(format!("Failed to complete scan session: {}", e))
            })?;

        if rows == 0 {
            return Err(ScanError::ScanStoreError(format!(
                "Scan session '{}' not found",
                scan_id
            )));
        }
        Ok(())
    }

    fn list_sessions_blocking(
        &self,
        limit: u32,
        offset: u32,
    ) -> Result<Page<ScanSessionSummary>, ScanError> {
        self.initialize_blocking()?;
        let conn = self.open_connection()?;
        let limit = clamp_limit(limit);
        let total = count_rows(&conn, "SELECT COUNT(*) FROM scan_sessions", [])?;
        let mut stmt = conn
            .prepare(
                "SELECT id, cidr, status, total_hosts, scanned_hosts, device_count, finding_count,
                        started_at, updated_at, completed_at, duration_ms, error_message
                 FROM scan_sessions
                 ORDER BY started_at DESC
                 LIMIT ?1 OFFSET ?2",
            )
            .map_err(|e| {
                ScanError::ScanStoreError(format!("Failed to prepare session list: {}", e))
            })?;

        let rows = stmt
            .query_map(params![limit, offset], |row| {
                let status: String = row.get(2)?;
                let duration_ms: Option<i64> = row.get(10)?;
                Ok(ScanSessionSummary {
                    id: row.get(0)?,
                    cidr: row.get(1)?,
                    status: ScanSessionStatus::from_str(&status).map_err(to_sql_error)?,
                    total_hosts: i64_to_u32(row.get(3)?, "total hosts").map_err(to_sql_error)?,
                    scanned_hosts: i64_to_u32(row.get(4)?, "scanned hosts")
                        .map_err(to_sql_error)?,
                    device_count: i64_to_u32(row.get(5)?, "device count").map_err(to_sql_error)?,
                    finding_count: i64_to_u32(row.get(6)?, "finding count")
                        .map_err(to_sql_error)?,
                    started_at: row.get(7)?,
                    updated_at: row.get(8)?,
                    completed_at: row.get(9)?,
                    duration_ms: duration_ms.and_then(|value| u64::try_from(value).ok()),
                    error_message: row.get(11)?,
                })
            })
            .map_err(|e| ScanError::ScanStoreError(format!("Failed to list sessions: {}", e)))?;

        let mut items = Vec::new();
        for row in rows {
            items.push(row.map_err(|e| {
                ScanError::ScanStoreError(format!("Failed to read session row: {}", e))
            })?);
        }

        Ok(Page {
            items,
            total,
            limit,
            offset,
        })
    }

    fn list_devices_blocking(
        &self,
        scan_id: &str,
        limit: u32,
        offset: u32,
    ) -> Result<Page<StoredDeviceSummary>, ScanError> {
        self.initialize_blocking()?;
        let conn = self.open_connection()?;
        let limit = clamp_limit(limit);
        let total = count_rows(
            &conn,
            "SELECT COUNT(*) FROM scan_devices WHERE scan_id = ?1",
            params![scan_id],
        )?;
        let mut stmt = conn
            .prepare(
                "SELECT scan_id, ip, mac, hostname, vendor, os, status, port_count,
                        open_port_count, finding_count, last_seen
                 FROM scan_devices
                 WHERE scan_id = ?1
                 ORDER BY ip
                 LIMIT ?2 OFFSET ?3",
            )
            .map_err(|e| {
                ScanError::ScanStoreError(format!("Failed to prepare device list: {}", e))
            })?;

        let rows = stmt
            .query_map(params![scan_id, limit, offset], |row| {
                Ok(StoredDeviceSummary {
                    scan_id: row.get(0)?,
                    ip: row.get(1)?,
                    mac: row.get(2)?,
                    hostname: row.get(3)?,
                    vendor: row.get(4)?,
                    os: row.get(5)?,
                    status: row.get(6)?,
                    port_count: i64_to_u32(row.get(7)?, "port count").map_err(to_sql_error)?,
                    open_port_count: i64_to_u32(row.get(8)?, "open port count")
                        .map_err(to_sql_error)?,
                    finding_count: i64_to_u32(row.get(9)?, "finding count")
                        .map_err(to_sql_error)?,
                    last_seen: row.get(10)?,
                })
            })
            .map_err(|e| ScanError::ScanStoreError(format!("Failed to list devices: {}", e)))?;

        let mut items = Vec::new();
        for row in rows {
            items.push(row.map_err(|e| {
                ScanError::ScanStoreError(format!("Failed to read device row: {}", e))
            })?);
        }

        Ok(Page {
            items,
            total,
            limit,
            offset,
        })
    }

    fn get_device_blocking(&self, scan_id: &str, ip: &str) -> Result<Option<Device>, ScanError> {
        self.initialize_blocking()?;
        let conn = self.open_connection()?;

        let device_json: Option<String> = conn
            .query_row(
                "SELECT device_json FROM scan_devices WHERE scan_id = ?1 AND ip = ?2",
                params![scan_id, ip],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| ScanError::ScanStoreError(format!("Failed to load device: {}", e)))?;

        let Some(device_json) = device_json else {
            return Ok(None);
        };

        let mut device: Device = serde_json::from_str(&device_json)?;
        device.ports = load_ports_for_device(&conn, scan_id, ip)?;
        device.findings = load_findings_for_device(&conn, scan_id, ip)?;
        Ok(Some(device))
    }

    fn delete_session_blocking(&self, scan_id: &str) -> Result<(), ScanError> {
        self.initialize_blocking()?;
        let conn = self.open_connection()?;
        let rows = conn
            .execute("DELETE FROM scan_sessions WHERE id = ?1", params![scan_id])
            .map_err(|e| {
                ScanError::ScanStoreError(format!("Failed to delete scan session: {}", e))
            })?;

        if rows == 0 {
            return Err(ScanError::ScanStoreError(format!(
                "Scan session '{}' not found",
                scan_id
            )));
        }
        Ok(())
    }

    fn list_findings_page_blocking(
        &self,
        scan_id: &str,
        severity_filter: Option<FindingSeverity>,
        limit: u32,
        offset: u32,
    ) -> Result<Page<FindingSummary>, ScanError> {
        self.initialize_blocking()?;
        let conn = self.open_connection()?;
        let limit = clamp_limit(limit);

        let severity_str = severity_filter.as_ref().map(finding_severity_to_str);

        let total = if let Some(sev) = &severity_str {
            count_rows(
                &conn,
                "SELECT COUNT(*) FROM scan_findings WHERE scan_id = ?1 AND severity = ?2",
                params![scan_id, sev],
            )?
        } else {
            count_rows(
                &conn,
                "SELECT COUNT(*) FROM scan_findings WHERE scan_id = ?1",
                params![scan_id],
            )?
        };

        let map_row = |row: &rusqlite::Row| -> Result<FindingSummary, rusqlite::Error> {
            let finding_json: String = row.get(0)?;
            let finding: Finding = serde_json::from_str(&finding_json).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Text,
                    Box::new(ScanError::SerializationError(format!(
                        "Failed to deserialize finding: {}",
                        e
                    ))),
                )
            })?;
            let risk_score = crate::reporting::risk::finding_risk_score(&finding);
            Ok(FindingSummary {
                scan_id: scan_id.to_string(),
                finding_id: finding.id,
                device_ip: finding.ip,
                category: finding.category,
                source: finding.source,
                severity: finding.severity,
                title: finding.title,
                port: finding.port,
                service: finding.service,
                cvss_score: finding.cvss_score,
                epss_probability: finding.epss_probability,
                risk_score,
                timestamp: finding.timestamp,
            })
        };

        let mut items = Vec::new();

        if let Some(sev) = severity_str {
            let mut stmt = conn.prepare(
                "SELECT finding_json FROM scan_findings WHERE scan_id = ?1 AND severity = ?2 ORDER BY severity ASC, timestamp DESC LIMIT ?3 OFFSET ?4",
            ).map_err(|e| ScanError::ScanStoreError(format!("Failed to prepare findings list: {}", e)))?;
            let rows = stmt
                .query_map(params![scan_id, sev, limit, offset], map_row)
                .map_err(|e| {
                    ScanError::ScanStoreError(format!("Failed to list findings: {}", e))
                })?;
            for row in rows {
                items.push(row.map_err(|e| {
                    ScanError::ScanStoreError(format!("Failed to read finding row: {}", e))
                })?);
            }
        } else {
            let mut stmt = conn.prepare(
                "SELECT finding_json FROM scan_findings WHERE scan_id = ?1 ORDER BY severity ASC, timestamp DESC LIMIT ?2 OFFSET ?3",
            ).map_err(|e| ScanError::ScanStoreError(format!("Failed to prepare findings list: {}", e)))?;
            let rows = stmt
                .query_map(params![scan_id, limit, offset], map_row)
                .map_err(|e| {
                    ScanError::ScanStoreError(format!("Failed to list findings: {}", e))
                })?;
            for row in rows {
                items.push(row.map_err(|e| {
                    ScanError::ScanStoreError(format!("Failed to read finding row: {}", e))
                })?);
            }
        }

        Ok(Page {
            items,
            total,
            limit,
            offset,
        })
    }
}

fn ensure_device_exists(
    conn: &Connection,
    scan_id: &str,
    device_ip: &str,
) -> Result<(), ScanError> {
    let exists: bool = conn
        .query_row(
            "SELECT 1 FROM scan_devices WHERE scan_id = ?1 AND ip = ?2",
            params![scan_id, device_ip],
            |_| Ok(true),
        )
        .optional()
        .map_err(|e| ScanError::ScanStoreError(format!("Failed to check device existence: {}", e)))?
        .is_some();

    if !exists {
        return Err(ScanError::ScanStoreError(format!(
            "Device '{}' does not exist in scan '{}'",
            device_ip, scan_id
        )));
    }
    Ok(())
}

fn load_ports_for_device(
    conn: &Connection,
    scan_id: &str,
    ip: &str,
) -> Result<Vec<Port>, ScanError> {
    let mut stmt = conn
        .prepare(
            "SELECT port_json FROM scan_ports
             WHERE scan_id = ?1 AND device_ip = ?2
             ORDER BY number, protocol",
        )
        .map_err(|e| ScanError::ScanStoreError(format!("Failed to prepare ports load: {}", e)))?;
    let rows = stmt
        .query_map(params![scan_id, ip], |row| {
            let json: String = row.get(0)?;
            serde_json::from_str(&json).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Text,
                    Box::new(ScanError::DeserializationError(format!(
                        "Failed to deserialize port: {}",
                        e
                    ))),
                )
            })
        })
        .map_err(|e| ScanError::ScanStoreError(format!("Failed to query ports: {}", e)))?;

    let mut ports = Vec::new();
    for row in rows {
        ports.push(
            row.map_err(|e| ScanError::ScanStoreError(format!("Failed to read port row: {}", e)))?,
        );
    }
    Ok(ports)
}

fn load_findings_for_device(
    conn: &Connection,
    scan_id: &str,
    ip: &str,
) -> Result<Vec<Finding>, ScanError> {
    let mut stmt = conn
        .prepare(
            "SELECT finding_json FROM scan_findings
             WHERE scan_id = ?1 AND device_ip = ?2
             ORDER BY timestamp DESC",
        )
        .map_err(|e| {
            ScanError::ScanStoreError(format!("Failed to prepare findings load: {}", e))
        })?;
    let rows = stmt
        .query_map(params![scan_id, ip], |row| {
            let json: String = row.get(0)?;
            serde_json::from_str(&json).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Text,
                    Box::new(ScanError::DeserializationError(format!(
                        "Failed to deserialize finding: {}",
                        e
                    ))),
                )
            })
        })
        .map_err(|e| ScanError::ScanStoreError(format!("Failed to query findings: {}", e)))?;

    let mut findings = Vec::new();
    for row in rows {
        findings.push(row.map_err(|e| {
            ScanError::ScanStoreError(format!("Failed to read finding row: {}", e))
        })?);
    }
    Ok(findings)
}

fn upsert_finding_on_connection(
    conn: &Connection,
    scan_id: &str,
    finding: &Finding,
) -> Result<(), ScanError> {
    let finding_json = serde_json::to_string(finding).map_err(|e| {
        ScanError::SerializationError(format!("Failed to serialize finding: {}", e))
    })?;
    conn.execute(
        "INSERT INTO scan_findings
            (scan_id, finding_id, device_ip, source, severity, confidence, title, port,
             service, timestamp, finding_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
         ON CONFLICT(scan_id, finding_id) DO UPDATE SET
            device_ip = excluded.device_ip,
            source = excluded.source,
            severity = excluded.severity,
            confidence = excluded.confidence,
            title = excluded.title,
            port = excluded.port,
            service = excluded.service,
            timestamp = excluded.timestamp,
            finding_json = excluded.finding_json",
        params![
            scan_id,
            finding.id,
            finding.ip,
            finding_source_to_str(&finding.source),
            finding_severity_to_str(&finding.severity),
            finding_confidence_to_str(&finding.confidence),
            finding.title,
            finding.port,
            finding.service,
            finding.timestamp,
            finding_json,
        ],
    )
    .map_err(|e| ScanError::ScanStoreError(format!("Failed to upsert scan finding: {}", e)))?;
    Ok(())
}

fn merge_finding_into_device_snapshot(
    conn: &Connection,
    scan_id: &str,
    finding: &Finding,
) -> Result<(), ScanError> {
    let device_json: Option<String> = conn
        .query_row(
            "SELECT device_json FROM scan_devices WHERE scan_id = ?1 AND ip = ?2",
            params![scan_id, finding.ip],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| {
            ScanError::ScanStoreError(format!("Failed to load device for finding merge: {}", e))
        })?;

    let Some(device_json) = device_json else {
        return Ok(());
    };

    let mut device: Device = serde_json::from_str(&device_json)?;
    device.findings.retain(|existing| existing.id != finding.id);
    device.findings.push(finding.clone());
    let merged_json = serde_json::to_string(&device).map_err(|e| {
        ScanError::SerializationError(format!("Failed to serialize merged device: {}", e))
    })?;

    conn.execute(
        "UPDATE scan_devices
         SET device_json = ?3, updated_at = ?4
         WHERE scan_id = ?1 AND ip = ?2",
        params![
            scan_id,
            finding.ip,
            merged_json,
            chrono::Utc::now().timestamp(),
        ],
    )
    .map_err(|e| {
        ScanError::ScanStoreError(format!("Failed to update device finding snapshot: {}", e))
    })?;
    Ok(())
}

fn refresh_device_counts(
    conn: &Connection,
    scan_id: &str,
    device_ip: &str,
) -> Result<(), ScanError> {
    let port_count = count_rows(
        conn,
        "SELECT COUNT(*) FROM scan_ports WHERE scan_id = ?1 AND device_ip = ?2",
        params![scan_id, device_ip],
    )?;
    let open_port_count = count_rows(
        conn,
        "SELECT COUNT(*) FROM scan_ports WHERE scan_id = ?1 AND device_ip = ?2 AND state = 'open'",
        params![scan_id, device_ip],
    )?;
    let finding_count = count_rows(
        conn,
        "SELECT COUNT(*) FROM scan_findings WHERE scan_id = ?1 AND device_ip = ?2",
        params![scan_id, device_ip],
    )?;

    conn.execute(
        "UPDATE scan_devices
         SET port_count = ?3, open_port_count = ?4, finding_count = ?5, updated_at = ?6
         WHERE scan_id = ?1 AND ip = ?2",
        params![
            scan_id,
            device_ip,
            port_count,
            open_port_count,
            finding_count,
            chrono::Utc::now().timestamp(),
        ],
    )
    .map_err(|e| ScanError::ScanStoreError(format!("Failed to refresh device counts: {}", e)))?;
    Ok(())
}

fn refresh_session_counts(conn: &Connection, scan_id: &str) -> Result<(), ScanError> {
    conn.execute(
        "UPDATE scan_sessions
         SET device_count = (SELECT COUNT(*) FROM scan_devices WHERE scan_id = ?1),
             finding_count = (SELECT COUNT(*) FROM scan_findings WHERE scan_id = ?1),
             updated_at = ?2
         WHERE id = ?1",
        params![scan_id, chrono::Utc::now().timestamp()],
    )
    .map_err(|e| ScanError::ScanStoreError(format!("Failed to refresh scan counts: {}", e)))?;
    Ok(())
}

fn count_rows<P>(conn: &Connection, sql: &str, params: P) -> Result<u32, ScanError>
where
    P: rusqlite::Params,
{
    let count: i64 = conn
        .query_row(sql, params, |row| row.get(0))
        .map_err(|e| ScanError::ScanStoreError(format!("Failed to count rows: {}", e)))?;
    i64_to_u32(count, "row count")
}

pub fn clamp_limit(limit: u32) -> u32 {
    limit.clamp(1, MAX_PAGE_LIMIT)
}

fn usize_to_u32(value: usize, name: &str) -> Result<u32, ScanError> {
    u32::try_from(value)
        .map_err(|_| ScanError::ScanStoreError(format!("{} exceeds supported range", name)))
}

fn i64_to_u32(value: i64, name: &str) -> Result<u32, ScanError> {
    u32::try_from(value)
        .map_err(|_| ScanError::ScanStoreError(format!("Invalid {} value {}", name, value)))
}

fn to_sql_error(error: ScanError) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(error))
}

fn device_status_to_str(status: &DeviceStatus) -> &'static str {
    match status {
        DeviceStatus::Online => "online",
        DeviceStatus::Offline => "offline",
        DeviceStatus::Unknown => "unknown",
    }
}

fn port_state_to_str(state: &PortState) -> &'static str {
    match state {
        PortState::Open => "open",
        PortState::Closed => "closed",
        PortState::Filtered => "filtered",
    }
}

fn finding_source_to_str(source: &FindingSource) -> &'static str {
    match source {
        FindingSource::Cve => "cve",
        FindingSource::ActiveCheck => "active_check",
        FindingSource::WebAudit => "web_audit",
    }
}

fn finding_severity_to_str(severity: &FindingSeverity) -> &'static str {
    match severity {
        FindingSeverity::Critical => "critical",
        FindingSeverity::High => "high",
        FindingSeverity::Medium => "medium",
        FindingSeverity::Low => "low",
        FindingSeverity::Info => "info",
    }
}

fn finding_confidence_to_str(confidence: &FindingConfidence) -> &'static str {
    match confidence {
        FindingConfidence::Confirmed => "confirmed",
        FindingConfidence::High => "high",
        FindingConfidence::Medium => "medium",
        FindingConfidence::Low => "low",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{
        Device, DeviceStatus, FindingConfidence, FindingSeverity, FindingSource, Port,
    };

    fn store(dir: &std::path::Path) -> ScanStore {
        ScanStore::new(dir.to_path_buf())
    }

    fn session(id: &str) -> ScanSession {
        ScanSession {
            id: id.to_string(),
            cidr: "192.168.1.0/24".to_string(),
            total_hosts: 256,
            started_at: 1000,
            config: StoredScanConfig {
                timeout_ms: 1000,
                scan_ports: true,
                ports: vec![22, 80],
                max_concurrent_hosts: Some(25),
                max_concurrent_ports: Some(100),
                discovery_methods: Some(vec!["tcp_probe".to_string()]),
                retry_count: Some(1),
                scan_type: "connect".to_string(),
                timing_template: Some("normal".to_string()),
                web_audit_enabled: false,
                active_checks_enabled: false,
            },
        }
    }

    fn device(ip: &str) -> Device {
        Device {
            ip: ip.to_string(),
            mac: "AA:BB:CC:DD:EE:FF".to_string(),
            hostname: Some("host.local".to_string()),
            vendor: Some("TestVendor".to_string()),
            os: Some("TestOS".to_string()),
            status: DeviceStatus::Online,
            ports: vec![Port {
                number: 22,
                protocol: "tcp".to_string(),
                service: Some("ssh".to_string()),
                state: PortState::Open,
            }],
            last_seen: 1000,
            banner_results: Vec::new(),
            active_checks: Vec::new(),
            web_audits: Vec::new(),
            findings: vec![Finding {
                id: format!("finding-{}", ip),
                scan_id: String::new(),
                source: FindingSource::ActiveCheck,
                severity: FindingSeverity::High,
                confidence: FindingConfidence::Confirmed,
                title: "Finding".to_string(),
                description: "A test finding".to_string(),
                ip: ip.to_string(),
                port: Some(22),
                service: Some("ssh".to_string()),
                evidence: Some("evidence".to_string()),
                cve: None,
                timestamp: 1000,
                category: FindingCategory::ActiveCheck,
                cvss_score: Some(7.5),
                epss_probability: Some(0.25),
                remediation: Some("Fix it".to_string()),
            }],
        }
    }

    #[tokio::test]
    async fn lifecycle_roundtrip_persists_devices_findings_and_progress() {
        let tmp = tempfile::tempdir().expect("create tempdir");
        let store = store(tmp.path());

        store.initialize().await.expect("initialize");
        store
            .create_scan_session(session("scan-1"))
            .await
            .expect("create");
        store
            .upsert_device("scan-1".to_string(), device("192.168.1.10"))
            .await
            .expect("upsert device");
        store
            .update_progress("scan-1".to_string(), 10, 256)
            .await
            .expect("progress");
        store
            .complete_scan_session(
                "scan-1".to_string(),
                ScanSessionStatus::Completed,
                Some(1500),
                None,
            )
            .await
            .expect("complete");

        let sessions = store.list_sessions(50, 0).await.expect("sessions");
        assert_eq!(sessions.total, 1);
        assert_eq!(sessions.items[0].status, ScanSessionStatus::Completed);
        assert_eq!(sessions.items[0].scanned_hosts, 10);

        let loaded = store
            .get_device("scan-1".to_string(), "192.168.1.10".to_string())
            .await
            .expect("get device")
            .expect("device exists");
        assert_eq!(loaded.ip, "192.168.1.10");
        // Ports/findings are managed relationally, so the standalone path test covers them.
    }

    #[tokio::test]
    async fn standalone_port_and_finding_persistence() {
        let tmp = tempfile::tempdir().expect("create tempdir");
        let store = store(tmp.path());
        store
            .create_scan_session(session("scan-port"))
            .await
            .expect("create");

        let mut dev = device("192.168.1.20");
        dev.ports.clear();
        dev.findings.clear();
        store
            .upsert_device("scan-port".to_string(), dev)
            .await
            .expect("upsert device");

        let port = Port {
            number: 443,
            protocol: "tcp".to_string(),
            service: Some("https".to_string()),
            state: PortState::Open,
        };
        store
            .upsert_port(
                "scan-port".to_string(),
                "192.168.1.20".to_string(),
                port.clone(),
            )
            .await
            .expect("upsert port");

        let finding = Finding {
            id: "standalone-finding".to_string(),
            scan_id: String::new(),
            source: FindingSource::Cve,
            severity: FindingSeverity::Critical,
            confidence: FindingConfidence::High,
            title: "Standalone CVE".to_string(),
            description: "desc".to_string(),
            ip: "192.168.1.20".to_string(),
            port: Some(443),
            service: Some("https".to_string()),
            evidence: None,
            cve: Some(crate::types::CveFindingDetails {
                cve_id: "CVE-2026-0001".to_string(),
                affected_software: "soft".to_string(),
                affected_versions: vec!["<1".to_string()],
                cvss_score: 9.8,
            }),
            timestamp: 2000,
            category: FindingCategory::Cve,
            cvss_score: Some(9.8),
            epss_probability: Some(0.9),
            remediation: Some("Patch".to_string()),
        };
        store
            .insert_finding("scan-port".to_string(), finding.clone())
            .await
            .expect("insert finding");

        let summary_page = store
            .list_devices_page("scan-port".to_string(), 50, 0)
            .await
            .expect("list summaries");
        assert_eq!(summary_page.total, 1);
        assert_eq!(summary_page.items[0].port_count, 1);
        assert_eq!(summary_page.items[0].open_port_count, 1);
        assert_eq!(summary_page.items[0].finding_count, 1);

        let loaded = store
            .get_device("scan-port".to_string(), "192.168.1.20".to_string())
            .await
            .expect("get device")
            .expect("device exists");
        assert_eq!(loaded.ports.len(), 1);
        assert_eq!(loaded.ports[0].number, 443);
        assert_eq!(loaded.findings.len(), 1);
        assert_eq!(loaded.findings[0].id, "standalone-finding");

        let findings_page = store
            .list_findings_page("scan-port".to_string(), None, 10, 0)
            .await
            .expect("list findings");
        assert_eq!(findings_page.total, 1);
        assert!(findings_page.items[0].risk_score > 0.0);
    }

    #[tokio::test]
    async fn paging_is_clamped_and_offset_is_respected() {
        let tmp = tempfile::tempdir().expect("create tempdir");
        let store = store(tmp.path());
        store
            .create_scan_session(session("scan-2"))
            .await
            .expect("create");

        for idx in 0..3 {
            let mut dev = device(&format!("192.168.1.{}", idx + 1));
            dev.ports.clear();
            dev.findings.clear();
            store
                .upsert_device("scan-2".to_string(), dev)
                .await
                .expect("upsert");
        }

        let page = store
            .list_devices_page("scan-2".to_string(), 1000, 1)
            .await
            .expect("list");
        assert_eq!(page.limit, MAX_PAGE_LIMIT);
        assert_eq!(page.total, 3);
        assert_eq!(page.items.len(), 2);
    }

    #[tokio::test]
    async fn deleting_session_cascades_children() {
        let tmp = tempfile::tempdir().expect("create tempdir");
        let store = store(tmp.path());
        store
            .create_scan_session(session("scan-3"))
            .await
            .expect("create");
        let mut dev = device("192.168.1.20");
        dev.ports.clear();
        dev.findings.clear();
        store
            .upsert_device("scan-3".to_string(), dev)
            .await
            .expect("upsert");
        store
            .upsert_port(
                "scan-3".to_string(),
                "192.168.1.20".to_string(),
                Port {
                    number: 22,
                    protocol: "tcp".to_string(),
                    service: Some("ssh".to_string()),
                    state: PortState::Open,
                },
            )
            .await
            .expect("upsert port");

        store
            .delete_session("scan-3".to_string())
            .await
            .expect("delete");

        let devices = store
            .list_devices_page("scan-3".to_string(), 50, 0)
            .await
            .expect("list devices");
        assert_eq!(devices.total, 0);
        assert!(devices.items.is_empty());
    }

    #[tokio::test]
    async fn list_findings_page_returns_paginated_results() {
        let tmp = tempfile::tempdir().expect("create tempdir");
        let store = store(tmp.path());
        store
            .create_scan_session(session("scan-findings"))
            .await
            .expect("create");
        let mut dev = device("192.168.1.10");
        dev.ports.clear();
        dev.findings.clear();
        store
            .upsert_device("scan-findings".to_string(), dev)
            .await
            .expect("upsert");
        store
            .insert_finding(
                "scan-findings".to_string(),
                device("192.168.1.10").findings[0].clone(),
            )
            .await
            .expect("insert finding");

        let page = store
            .list_findings_page("scan-findings".to_string(), None, 10, 0)
            .await
            .expect("list findings");
        assert_eq!(page.total, 1);
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].device_ip, "192.168.1.10");
        assert!(page.items[0].risk_score > 0.0);

        let filtered = store
            .list_findings_page(
                "scan-findings".to_string(),
                Some(FindingSeverity::Low),
                10,
                0,
            )
            .await
            .expect("list filtered findings");
        assert_eq!(filtered.total, 0);
        assert!(filtered.items.is_empty());
    }

    #[tokio::test]
    async fn finding_with_new_fields_roundtrips() {
        let tmp = tempfile::tempdir().expect("create tempdir");
        let store = store(tmp.path());
        store
            .create_scan_session(session("scan-fields"))
            .await
            .expect("create");

        let mut dev = device("192.168.1.50");
        dev.ports.clear();
        dev.findings.clear();
        store
            .upsert_device("scan-fields".to_string(), dev)
            .await
            .expect("upsert");

        let finding = Finding {
            id: "finding-fields".to_string(),
            scan_id: String::new(),
            source: FindingSource::Cve,
            severity: FindingSeverity::Critical,
            confidence: FindingConfidence::High,
            title: "CVE finding".to_string(),
            description: "desc".to_string(),
            ip: "192.168.1.50".to_string(),
            port: Some(443),
            service: Some("https".to_string()),
            evidence: None,
            cve: Some(crate::types::CveFindingDetails {
                cve_id: "CVE-2026-9999".to_string(),
                affected_software: "soft".to_string(),
                affected_versions: vec!["<1".to_string()],
                cvss_score: 9.8,
            }),
            timestamp: 2000,
            category: FindingCategory::Cve,
            cvss_score: Some(9.8),
            epss_probability: Some(0.9),
            remediation: Some("Patch".to_string()),
        };
        store
            .insert_finding("scan-fields".to_string(), finding.clone())
            .await
            .expect("insert");

        let loaded = store
            .get_device("scan-fields".to_string(), "192.168.1.50".to_string())
            .await
            .expect("get device")
            .expect("device exists");
        let loaded_finding = loaded
            .findings
            .iter()
            .find(|f| f.id == "finding-fields")
            .expect("finding exists");
        assert_eq!(loaded_finding.category, FindingCategory::Cve);
        assert_eq!(loaded_finding.cvss_score, Some(9.8));
        assert_eq!(loaded_finding.epss_probability, Some(0.9));
        assert_eq!(loaded_finding.remediation.as_deref(), Some("Patch"));

        let page = store
            .list_findings_page("scan-fields".to_string(), None, 10, 0)
            .await
            .expect("list findings");
        let summary = page.items.into_iter().next().expect("summary exists");
        assert_eq!(summary.category, FindingCategory::Cve);
        assert_eq!(summary.cvss_score, Some(9.8));
        assert_eq!(summary.epss_probability, Some(0.9));
        assert!(summary.risk_score > 0.0);
    }
}
