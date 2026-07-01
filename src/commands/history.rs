//! Scan history commands.
//!
//! Provides functions for saving, loading, deleting, and clearing
//! scan history entries.

use crate::commands::settings::get_config_dir;
use crate::error::ScanError;
use crate::history::{HistoryStore, ScanHistoryEntry};
use crate::history_adapter;
use crate::network::sanitize;
use crate::scan_store::{ScanSessionSummary, StoredDeviceSummary};
use crate::types::Device;

/// Save a completed scan to history.
pub async fn save_scan_history(entry: ScanHistoryEntry) -> Result<(), ScanError> {
    // Validate inputs
    let _validated_id = sanitize::validate_id(&entry.id)?;
    let _validated_cidr = sanitize::validate_cidr(&entry.cidr)?;

    let config_dir = get_config_dir()?;
    let store = HistoryStore::new(config_dir);
    store.add_entry(entry).await
}

/// Save a completed scan session summary to history, creating a lightweight entry
/// that links back to the `ScanStore` session for paginated device details.
pub async fn save_scan_history_from_session(
    summary: ScanSessionSummary,
) -> Result<ScanHistoryEntry, ScanError> {
    history_adapter::save_history_from_session(&summary).await
}

/// Get all saved scan history entries, sorted by timestamp descending
/// (newest first).
pub async fn get_scan_history() -> Result<Vec<ScanHistoryEntry>, ScanError> {
    let config_dir = get_config_dir()?;
    let store = HistoryStore::new(config_dir);
    store.load().await
}

/// Load a paginated page of device summaries for a history entry.
pub async fn get_history_devices_page(
    scan_store_id: String,
    limit: u32,
    offset: u32,
) -> Result<crate::scan_store::Page<StoredDeviceSummary>, ScanError> {
    let _id = sanitize::validate_id(&scan_store_id)?;
    history_adapter::load_history_devices_page(&scan_store_id, limit.max(1), offset).await
}

/// Load full device detail for a single IP from a history entry's scan store session.
pub async fn get_history_device_detail(
    scan_store_id: String,
    ip: String,
) -> Result<Option<Device>, ScanError> {
    let _id = sanitize::validate_id(&scan_store_id)?;
    if ip.trim().is_empty() {
        return Err(ScanError::InvalidInput(
            "Device IP must not be empty".to_string(),
        ));
    }
    history_adapter::get_history_device_detail(&scan_store_id, &ip).await
}

/// Delete a single history entry by ID.
pub async fn delete_scan_history_entry(id: String) -> Result<(), ScanError> {
    let validated_id = sanitize::validate_id(&id)?;

    let config_dir = get_config_dir()?;
    let store = HistoryStore::new(config_dir);
    store.delete_entry(&validated_id).await
}

/// Delete all history entries.
pub async fn clear_scan_history() -> Result<(), ScanError> {
    let config_dir = get_config_dir()?;
    let store = HistoryStore::new(config_dir);
    store.clear().await
}
