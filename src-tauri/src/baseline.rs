//! Baseline snapshot and differential comparison module.
//!
//! Provides SQLite-backed storage for network baselines and
//! comparison logic to detect changes between scans.

use std::collections::HashMap;
use std::path::PathBuf;

use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};

use crate::error::ScanError;
use crate::types::{Device, Port, PortState};

/// A saved network baseline snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Baseline {
    /// Unique identifier
    pub id: String,
    /// Human-readable name
    pub name: String,
    /// Optional description
    pub description: Option<String>,
    /// Devices captured in this baseline
    pub devices: Vec<Device>,
    /// CIDR that was scanned
    pub scan_cidr: String,
    /// Unix timestamp when the baseline was created
    pub created_at: i64,
}

/// Result of comparing a baseline against current scan results.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BaselineDiff {
    /// ID of the baseline compared against
    pub baseline_id: String,
    /// Name of the baseline
    pub baseline_name: String,
    /// Hosts present in current scan but not in baseline
    pub new_hosts: Vec<Device>,
    /// Hosts present in baseline but not in current scan
    pub removed_hosts: Vec<Device>,
    /// Ports that changed state between baseline and current
    pub changed_ports: Vec<PortChange>,
    /// New services detected (banner results)
    pub new_services: Vec<crate::network::banner::BannerResult>,
    /// Timestamp when the comparison was performed
    pub scan_timestamp: i64,
}

/// A port state change between baseline and current scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PortChange {
    /// IP address of the device
    pub ip: String,
    /// Hostname if available
    pub hostname: Option<String>,
    /// The port that changed
    pub port: Port,
    /// Previous port state (None if port didn't exist in baseline)
    pub previous_state: Option<PortState>,
    /// Current port state
    pub current_state: PortState,
}

/// SQLite-backed baseline storage.
pub struct BaselineStore {
    db_path: PathBuf,
}

impl BaselineStore {
    /// Create a new baseline store with the given database path.
    pub fn new(config_dir: PathBuf) -> Self {
        Self {
            db_path: config_dir.join("baselines.db"),
        }
    }

    /// Initialize the database schema.
    fn init_schema(conn: &Connection) -> Result<(), ScanError> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS baselines (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                scan_cidr TEXT NOT NULL,
                devices_json TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );",
        )
        .map_err(|e| {
            ScanError::NetworkError(format!("Failed to initialize baseline schema: {}", e))
        })?;
        Ok(())
    }

    /// Open a connection to the database, creating it if necessary.
    fn open_connection(&self) -> Result<Connection, ScanError> {
        // Ensure parent directory exists
        if let Some(parent) = self.db_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                ScanError::NetworkError(format!(
                    "Failed to create baseline directory: {}",
                    e
                ))
            })?;
        }

        let conn = Connection::open(&self.db_path).map_err(|e| {
            ScanError::NetworkError(format!("Failed to open baseline database: {}", e))
        })?;

        Self::init_schema(&conn)?;
        Ok(conn)
    }

    /// Save a baseline to the database.
    ///
    /// This is a blocking operation and should be called via `spawn_blocking`.
    pub fn save_blocking(&self, baseline: &Baseline) -> Result<String, ScanError> {
        let conn = self.open_connection()?;

        let devices_json = serde_json::to_string(&baseline.devices).map_err(|e| {
            ScanError::NetworkError(format!("Failed to serialize baseline devices: {}", e))
        })?;

        conn.execute(
            "INSERT OR REPLACE INTO baselines (id, name, description, scan_cidr, devices_json, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                baseline.id,
                baseline.name,
                baseline.description,
                baseline.scan_cidr,
                devices_json,
                baseline.created_at,
            ],
        )
        .map_err(|e| {
            ScanError::NetworkError(format!("Failed to save baseline: {}", e))
        })?;

        Ok(baseline.id.clone())
    }

    /// Get all baselines from the database.
    pub fn get_all_blocking(&self) -> Result<Vec<Baseline>, ScanError> {
        let conn = self.open_connection()?;

        let mut stmt = conn
            .prepare("SELECT id, name, description, scan_cidr, devices_json, created_at FROM baselines ORDER BY created_at DESC")
            .map_err(|e| {
                ScanError::NetworkError(format!("Failed to prepare baseline query: {}", e))
            })?;

        let baselines = stmt
            .query_map([], |row| {
                let id: String = row.get(0)?;
                let name: String = row.get(1)?;
                let description: Option<String> = row.get(2)?;
                let scan_cidr: String = row.get(3)?;
                let devices_json: String = row.get(4)?;
                let created_at: i64 = row.get(5)?;

                Ok((id, name, description, scan_cidr, devices_json, created_at))
            })
            .map_err(|e| {
                ScanError::NetworkError(format!("Failed to query baselines: {}", e))
            })?
            .filter_map(|r| r.ok())
            .map(|(id, name, description, scan_cidr, devices_json, created_at)| {
                let devices: Vec<Device> =
                    serde_json::from_str(&devices_json).unwrap_or_default();
                Baseline {
                    id,
                    name,
                    description,
                    devices,
                    scan_cidr,
                    created_at,
                }
            })
            .collect();

        Ok(baselines)
    }

    /// Delete a baseline by ID.
    pub fn delete_blocking(&self, id: &str) -> Result<(), ScanError> {
        let conn = self.open_connection()?;

        let rows = conn
            .execute("DELETE FROM baselines WHERE id = ?1", params![id])
            .map_err(|e| {
                ScanError::NetworkError(format!("Failed to delete baseline: {}", e))
            })?;

        if rows == 0 {
            return Err(ScanError::NetworkError(format!(
                "Baseline with ID '{}' not found",
                id
            )));
        }

        Ok(())
    }

    /// Get a single baseline by ID.
    pub fn get_by_id_blocking(&self, id: &str) -> Result<Baseline, ScanError> {
        let conn = self.open_connection()?;

        let mut stmt = conn
            .prepare("SELECT id, name, description, scan_cidr, devices_json, created_at FROM baselines WHERE id = ?1")
            .map_err(|e| {
                ScanError::NetworkError(format!("Failed to prepare baseline query: {}", e))
            })?;

        let result = stmt
            .query_row(params![id], |row| {
                let id: String = row.get(0)?;
                let name: String = row.get(1)?;
                let description: Option<String> = row.get(2)?;
                let scan_cidr: String = row.get(3)?;
                let devices_json: String = row.get(4)?;
                let created_at: i64 = row.get(5)?;

                Ok((id, name, description, scan_cidr, devices_json, created_at))
            })
            .map_err(|e| {
                ScanError::NetworkError(format!("Failed to get baseline '{}': {}", id, e))
            })?;

        let (id, name, description, scan_cidr, devices_json, created_at) = result;
        let devices: Vec<Device> =
            serde_json::from_str(&devices_json).unwrap_or_default();

        Ok(Baseline {
            id,
            name,
            description,
            devices,
            scan_cidr,
            created_at,
        })
    }
}

/// Compute the difference between a baseline and current scan results.
///
/// Compares devices by IP address and detects:
/// - New hosts (in current but not in baseline)
/// - Removed hosts (in baseline but not in current)
/// - Port state changes
/// - New services (banner results)
pub fn compute_diff(baseline: &Baseline, current_devices: &[Device]) -> BaselineDiff {
    let baseline_map: HashMap<&str, &Device> = baseline
        .devices
        .iter()
        .map(|d| (d.ip.as_str(), d))
        .collect();

    let current_map: HashMap<&str, &Device> = current_devices
        .iter()
        .map(|d| (d.ip.as_str(), d))
        .collect();

    // Find new hosts
    let new_hosts: Vec<Device> = current_devices
        .iter()
        .filter(|d| !baseline_map.contains_key(d.ip.as_str()))
        .cloned()
        .collect();

    // Find removed hosts
    let removed_hosts: Vec<Device> = baseline
        .devices
        .iter()
        .filter(|d| !current_map.contains_key(d.ip.as_str()))
        .cloned()
        .collect();

    // Find port changes for hosts present in both
    let mut changed_ports = Vec::new();
    for (ip, current_device) in &current_map {
        if let Some(baseline_device) = baseline_map.get(ip) {
            let baseline_ports: HashMap<u16, &Port> = baseline_device
                .ports
                .iter()
                .map(|p| (p.number, p))
                .collect();

            for current_port in &current_device.ports {
                let previous_state = baseline_ports
                    .get(&current_port.number)
                    .map(|p| p.state.clone());

                // Check if state changed or port is new
                let state_changed = match &previous_state {
                    Some(prev) => *prev != current_port.state,
                    None => true, // New port
                };

                if state_changed {
                    changed_ports.push(PortChange {
                        ip: ip.to_string(),
                        hostname: current_device.hostname.clone(),
                        port: current_port.clone(),
                        previous_state,
                        current_state: current_port.state.clone(),
                    });
                }
            }

            // Check for ports that existed in baseline but not in current
            let current_port_numbers: Vec<u16> =
                current_device.ports.iter().map(|p| p.number).collect();

            for baseline_port in &baseline_device.ports {
                if !current_port_numbers.contains(&baseline_port.number) {
                    changed_ports.push(PortChange {
                        ip: ip.to_string(),
                        hostname: baseline_device.hostname.clone(),
                        port: baseline_port.clone(),
                        previous_state: Some(baseline_port.state.clone()),
                        current_state: PortState::Filtered, // Assume filtered if not found
                    });
                }
            }
        }
    }

    // Collect new services from banner results
    let new_services: Vec<crate::network::banner::BannerResult> = current_devices
        .iter()
        .flat_map(|d| d.banner_results.iter().cloned())
        .collect();

    BaselineDiff {
        baseline_id: baseline.id.clone(),
        baseline_name: baseline.name.clone(),
        new_hosts,
        removed_hosts,
        changed_ports,
        new_services,
        scan_timestamp: chrono::Utc::now().timestamp(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{DeviceStatus, Port, PortState};

    fn make_device(ip: &str, ports: Vec<Port>) -> Device {
        Device {
            ip: ip.to_string(),
            mac: String::new(),
            hostname: None,
            vendor: None,
            status: DeviceStatus::Online,
            ports,
            last_seen: 1000,
            banner_results: Vec::new(),
        }
    }

    fn make_port(number: u16, state: PortState) -> Port {
        Port {
            number,
            protocol: "tcp".to_string(),
            service: None,
            state,
        }
    }

    #[test]
    fn test_compute_diff_no_changes() {
        let devices = vec![
            make_device("192.168.1.1", vec![make_port(80, PortState::Open)]),
        ];

        let baseline = Baseline {
            id: "test".to_string(),
            name: "Test".to_string(),
            description: None,
            devices: devices.clone(),
            scan_cidr: "192.168.1.0/24".to_string(),
            created_at: 1000,
        };

        let diff = compute_diff(&baseline, &devices);
        assert!(diff.new_hosts.is_empty());
        assert!(diff.removed_hosts.is_empty());
        assert!(diff.changed_ports.is_empty());
    }

    #[test]
    fn test_compute_diff_new_host() {
        let baseline_devices = vec![
            make_device("192.168.1.1", vec![make_port(80, PortState::Open)]),
        ];
        let current_devices = vec![
            make_device("192.168.1.1", vec![make_port(80, PortState::Open)]),
            make_device("192.168.1.2", vec![make_port(22, PortState::Open)]),
        ];

        let baseline = Baseline {
            id: "test".to_string(),
            name: "Test".to_string(),
            description: None,
            devices: baseline_devices,
            scan_cidr: "192.168.1.0/24".to_string(),
            created_at: 1000,
        };

        let diff = compute_diff(&baseline, &current_devices);
        assert_eq!(diff.new_hosts.len(), 1);
        assert_eq!(diff.new_hosts[0].ip, "192.168.1.2");
        assert!(diff.removed_hosts.is_empty());
    }

    #[test]
    fn test_compute_diff_removed_host() {
        let baseline_devices = vec![
            make_device("192.168.1.1", vec![make_port(80, PortState::Open)]),
            make_device("192.168.1.2", vec![make_port(22, PortState::Open)]),
        ];
        let current_devices = vec![
            make_device("192.168.1.1", vec![make_port(80, PortState::Open)]),
        ];

        let baseline = Baseline {
            id: "test".to_string(),
            name: "Test".to_string(),
            description: None,
            devices: baseline_devices,
            scan_cidr: "192.168.1.0/24".to_string(),
            created_at: 1000,
        };

        let diff = compute_diff(&baseline, &current_devices);
        assert!(diff.new_hosts.is_empty());
        assert_eq!(diff.removed_hosts.len(), 1);
        assert_eq!(diff.removed_hosts[0].ip, "192.168.1.2");
    }

    #[test]
    fn test_compute_diff_port_changed() {
        let baseline_devices = vec![
            make_device("192.168.1.1", vec![make_port(80, PortState::Open)]),
        ];
        let current_devices = vec![
            make_device("192.168.1.1", vec![make_port(80, PortState::Closed)]),
        ];

        let baseline = Baseline {
            id: "test".to_string(),
            name: "Test".to_string(),
            description: None,
            devices: baseline_devices,
            scan_cidr: "192.168.1.0/24".to_string(),
            created_at: 1000,
        };

        let diff = compute_diff(&baseline, &current_devices);
        assert_eq!(diff.changed_ports.len(), 1);
        assert_eq!(diff.changed_ports[0].previous_state, Some(PortState::Open));
        assert_eq!(diff.changed_ports[0].current_state, PortState::Closed);
    }

    #[test]
    fn test_baseline_store_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let store = BaselineStore::new(tmp.path().to_path_buf());

        let baseline = Baseline {
            id: "test-id".to_string(),
            name: "Test Baseline".to_string(),
            description: Some("A test baseline".to_string()),
            devices: vec![
                make_device("192.168.1.1", vec![make_port(80, PortState::Open)]),
            ],
            scan_cidr: "192.168.1.0/24".to_string(),
            created_at: 1000,
        };

        // Save
        let result = store.save_blocking(&baseline);
        assert!(result.is_ok());

        // Get all
        let all = store.get_all_blocking().unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].id, "test-id");
        assert_eq!(all[0].name, "Test Baseline");
        assert_eq!(all[0].devices.len(), 1);

        // Get by ID
        let fetched = store.get_by_id_blocking("test-id").unwrap();
        assert_eq!(fetched.id, "test-id");
        assert_eq!(fetched.scan_cidr, "192.168.1.0/24");

        // Delete
        let delete_result = store.delete_blocking("test-id");
        assert!(delete_result.is_ok());

        let all_after_delete = store.get_all_blocking().unwrap();
        assert!(all_after_delete.is_empty());
    }

    #[test]
    fn test_baseline_serialization() {
        let baseline = Baseline {
            id: "test".to_string(),
            name: "Test".to_string(),
            description: None,
            devices: vec![],
            scan_cidr: "192.168.1.0/24".to_string(),
            created_at: 1000,
        };

        let json = serde_json::to_string(&baseline).unwrap();
        assert!(json.contains("\"scanCidr\""));
        assert!(json.contains("\"createdAt\""));
    }
}
