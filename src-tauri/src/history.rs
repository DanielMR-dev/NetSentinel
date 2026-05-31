//! Scan history persistence layer.
//!
//! Stores completed scan results as a JSON file on disk so users can
//! review past scans. History is capped at 100 entries; the oldest
//! entries are evicted when the limit is exceeded.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::error::ScanError;
use crate::types::Device;

/// Maximum number of history entries retained on disk.
const MAX_HISTORY_ENTRIES: usize = 100;

/// A saved scan history entry.
///
/// Serialized with `camelCase` field names to match the frontend
/// TypeScript interface.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ScanHistoryEntry {
    pub id: String,
    pub scan_id: String,
    pub cidr: String,
    pub device_count: u32,
    pub duration_ms: u64,
    pub status: String,
    pub devices: Vec<Device>,
    pub timestamp: i64,
}

/// Manages reading and writing scan history to a JSON file on disk.
///
/// The store is stateless — each operation loads from disk, mutates,
/// and writes back. This avoids the need for shared mutable state and
/// keeps the implementation simple and deadlock-free.
pub struct HistoryStore {
    file_path: PathBuf,
}

impl HistoryStore {
    /// Create a new `HistoryStore` rooted at the given config directory.
    ///
    /// The history file will be stored at `{config_dir}/scan_history.json`.
    pub fn new(config_dir: PathBuf) -> Self {
        Self {
            file_path: config_dir.join("scan_history.json"),
        }
    }

    /// Load all history entries from disk.
    ///
    /// Returns an empty `Vec` if the file does not exist. Entries are
    /// returned sorted by timestamp descending (newest first).
    pub async fn load(&self) -> Result<Vec<ScanHistoryEntry>, ScanError> {
        if !self.file_path.exists() {
            debug!("History file does not exist, returning empty list");
            return Ok(Vec::new());
        }

        let content = tokio::fs::read_to_string(&self.file_path)
            .await
            .map_err(|e| {
                ScanError::HistoryError(format!(
                    "Failed to read history file '{}': {}",
                    self.file_path.display(),
                    e
                ))
            })?;

        if content.trim().is_empty() {
            debug!("History file is empty, returning empty list");
            return Ok(Vec::new());
        }

        let mut entries: Vec<ScanHistoryEntry> = serde_json::from_str(&content).map_err(|e| {
            ScanError::HistoryError(format!("Failed to parse history JSON: {}", e))
        })?;

        // Sort by timestamp descending (newest first)
        entries.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

        debug!("Loaded {} history entries from disk", entries.len());
        Ok(entries)
    }

    /// Save the given entries to disk, overwriting the existing file.
    ///
    /// Creates the parent directory if it does not exist.
    pub async fn save(&self, entries: &[ScanHistoryEntry]) -> Result<(), ScanError> {
        // Ensure parent directory exists
        if let Some(parent) = self.file_path.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(|e| {
                ScanError::HistoryError(format!(
                    "Failed to create history directory '{}': {}",
                    parent.display(),
                    e
                ))
            })?;
        }

        let json = serde_json::to_string_pretty(entries).map_err(|e| {
            ScanError::HistoryError(format!("Failed to serialize history JSON: {}", e))
        })?;

        tokio::fs::write(&self.file_path, json.as_bytes())
            .await
            .map_err(|e| {
                ScanError::HistoryError(format!(
                    "Failed to write history file '{}': {}",
                    self.file_path.display(),
                    e
                ))
            })?;

        debug!("Saved {} history entries to disk", entries.len());
        Ok(())
    }

    /// Add a new entry to the history store.
    ///
    /// If the store exceeds `MAX_HISTORY_ENTRIES` after insertion, the
    /// oldest entries (by timestamp) are evicted.
    pub async fn add_entry(&self, entry: ScanHistoryEntry) -> Result<(), ScanError> {
        info!(
            id = %entry.id,
            scan_id = %entry.scan_id,
            cidr = %entry.cidr,
            "Adding scan history entry"
        );

        let mut entries = self.load().await?;
        entries.push(entry);

        // Sort by timestamp descending so we can truncate the oldest
        entries.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

        // Evict oldest entries beyond the cap
        if entries.len() > MAX_HISTORY_ENTRIES {
            let evicted_count = entries.len() - MAX_HISTORY_ENTRIES;
            warn!(
                evicted_count,
                "History exceeded {} entries, evicting oldest", MAX_HISTORY_ENTRIES
            );
            entries.truncate(MAX_HISTORY_ENTRIES);
        }

        self.save(&entries).await
    }

    /// Delete a single history entry by its ID.
    ///
    /// Returns an error if no entry with the given ID exists.
    pub async fn delete_entry(&self, id: &str) -> Result<(), ScanError> {
        info!(id = %id, "Deleting scan history entry");

        let mut entries = self.load().await?;
        let original_len = entries.len();
        entries.retain(|e| e.id != id);

        if entries.len() == original_len {
            return Err(ScanError::HistoryError(format!(
                "History entry with ID '{}' not found",
                id
            )));
        }

        self.save(&entries).await
    }

    /// Delete all history entries.
    pub async fn clear(&self) -> Result<(), ScanError> {
        info!("Clearing all scan history");
        self.save(&[]).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Device, DeviceStatus};

    /// Helper to create a test entry with a given id and timestamp.
    fn make_entry(id: &str, timestamp: i64) -> ScanHistoryEntry {
        ScanHistoryEntry {
            id: id.to_string(),
            scan_id: format!("scan-{}", id),
            cidr: "192.168.1.0/24".to_string(),
            device_count: 3,
            duration_ms: 1500,
            status: "completed".to_string(),
            devices: vec![Device {
                ip: "192.168.1.1".to_string(),
                mac: "AA:BB:CC:DD:EE:FF".to_string(),
                hostname: Some("router.local".to_string()),
                vendor: Some("TestVendor".to_string()),
                status: DeviceStatus::Online,
                ports: Vec::new(),
                last_seen: timestamp,
                banner_results: Vec::new(),
            }],
            timestamp,
        }
    }

    /// Helper to create a HistoryStore in a temporary directory.
    fn make_store(dir: &std::path::Path) -> HistoryStore {
        HistoryStore::new(dir.to_path_buf())
    }

    #[tokio::test]
    async fn test_load_nonexistent_file_returns_empty() {
        let tmp = tempfile::tempdir().expect("create tempdir");
        let store = make_store(tmp.path());

        let entries = store.load().await.expect("load should succeed");
        assert!(entries.is_empty(), "Expected empty vec for missing file");
    }

    #[tokio::test]
    async fn test_add_entry_and_load_roundtrip() {
        let tmp = tempfile::tempdir().expect("create tempdir");
        let store = make_store(tmp.path());

        let entry = make_entry("entry-1", 1000);
        store.add_entry(entry).await.expect("add_entry should succeed");

        let loaded = store.load().await.expect("load should succeed");
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].id, "entry-1");
        assert_eq!(loaded[0].scan_id, "scan-entry-1");
        assert_eq!(loaded[0].cidr, "192.168.1.0/24");
        assert_eq!(loaded[0].device_count, 3);
        assert_eq!(loaded[0].duration_ms, 1500);
    }

    #[tokio::test]
    async fn test_delete_entry_removes_correct_entry() {
        let tmp = tempfile::tempdir().expect("create tempdir");
        let store = make_store(tmp.path());

        store
            .add_entry(make_entry("a", 1000))
            .await
            .expect("add a");
        store
            .add_entry(make_entry("b", 2000))
            .await
            .expect("add b");
        store
            .add_entry(make_entry("c", 3000))
            .await
            .expect("add c");

        store.delete_entry("b").await.expect("delete b");

        let loaded = store.load().await.expect("load");
        assert_eq!(loaded.len(), 2);
        assert!(loaded.iter().all(|e| e.id != "b"));
    }

    #[tokio::test]
    async fn test_delete_nonexistent_entry_returns_error() {
        let tmp = tempfile::tempdir().expect("create tempdir");
        let store = make_store(tmp.path());

        store
            .add_entry(make_entry("a", 1000))
            .await
            .expect("add a");

        let result = store.delete_entry("nonexistent").await;
        assert!(result.is_err(), "Should error on nonexistent entry");
    }

    #[tokio::test]
    async fn test_clear_removes_all_entries() {
        let tmp = tempfile::tempdir().expect("create tempdir");
        let store = make_store(tmp.path());

        store
            .add_entry(make_entry("a", 1000))
            .await
            .expect("add a");
        store
            .add_entry(make_entry("b", 2000))
            .await
            .expect("add b");

        store.clear().await.expect("clear");

        let loaded = store.load().await.expect("load");
        assert!(loaded.is_empty(), "Expected empty after clear");
    }

    #[tokio::test]
    async fn test_100_entry_limit() {
        let tmp = tempfile::tempdir().expect("create tempdir");
        let store = make_store(tmp.path());

        // Add 110 entries
        for i in 0..110 {
            store
                .add_entry(make_entry(&format!("entry-{}", i), i as i64))
                .await
                .expect("add entry");
        }

        let loaded = store.load().await.expect("load");
        assert_eq!(
            loaded.len(),
            MAX_HISTORY_ENTRIES,
            "Should be capped at {}",
            MAX_HISTORY_ENTRIES
        );

        // The oldest entries (lowest timestamps) should have been evicted.
        // Entries 10..110 should remain (timestamps 10..109).
        let min_timestamp = loaded.iter().map(|e| e.timestamp).min().expect("min");
        assert_eq!(
            min_timestamp, 10,
            "Oldest retained entry should have timestamp 10"
        );
    }

    #[tokio::test]
    async fn test_load_returns_sorted_descending() {
        let tmp = tempfile::tempdir().expect("create tempdir");
        let store = make_store(tmp.path());

        // Add entries out of order
        store
            .add_entry(make_entry("old", 1000))
            .await
            .expect("add old");
        store
            .add_entry(make_entry("new", 3000))
            .await
            .expect("add new");
        store
            .add_entry(make_entry("mid", 2000))
            .await
            .expect("add mid");

        let loaded = store.load().await.expect("load");
        assert_eq!(loaded.len(), 3);
        assert_eq!(loaded[0].id, "new", "Newest should be first");
        assert_eq!(loaded[1].id, "mid", "Middle should be second");
        assert_eq!(loaded[2].id, "old", "Oldest should be last");
    }

    #[tokio::test]
    async fn test_serde_camel_case() {
        let entry = make_entry("test-1", 1000);
        let json = serde_json::to_string(&entry).expect("serialize");

        // Verify camelCase field names
        assert!(json.contains("\"scanId\""), "Should contain scanId");
        assert!(json.contains("\"deviceCount\""), "Should contain deviceCount");
        assert!(json.contains("\"durationMs\""), "Should contain durationMs");

        // Verify snake_case is NOT present
        assert!(!json.contains("\"scan_id\""), "Should not contain scan_id");
        assert!(
            !json.contains("\"device_count\""),
            "Should not contain device_count"
        );
        assert!(
            !json.contains("\"duration_ms\""),
            "Should not contain duration_ms"
        );
    }
}
