//! Scan history Tauri commands.
//!
//! Provides IPC endpoints for saving, loading, deleting, and clearing
//! scan history entries.

use crate::commands::settings::get_config_dir;
use crate::error::ScanError;
use crate::history::{HistoryStore, ScanHistoryEntry};

/// Save a completed scan to history.
#[tauri::command]
pub async fn save_scan_history(entry: ScanHistoryEntry) -> Result<(), ScanError> {
    let config_dir = get_config_dir()?;
    let store = HistoryStore::new(config_dir);
    store.add_entry(entry).await
}

/// Get all saved scan history entries, sorted by timestamp descending
/// (newest first).
#[tauri::command]
pub async fn get_scan_history() -> Result<Vec<ScanHistoryEntry>, ScanError> {
    let config_dir = get_config_dir()?;
    let store = HistoryStore::new(config_dir);
    store.load().await
}

/// Delete a single history entry by ID.
#[tauri::command]
pub async fn delete_scan_history_entry(id: String) -> Result<(), ScanError> {
    let config_dir = get_config_dir()?;
    let store = HistoryStore::new(config_dir);
    store.delete_entry(&id).await
}

/// Delete all history entries.
#[tauri::command]
pub async fn clear_scan_history() -> Result<(), ScanError> {
    let config_dir = get_config_dir()?;
    let store = HistoryStore::new(config_dir);
    store.clear().await
}
