//! Baseline-related commands.
//!
//! Provides functions for saving, loading, deleting, and comparing
//! network baselines.

use std::sync::Arc;

use crate::baseline::{Baseline, BaselineDiff, BaselineStore, compute_diff};
use crate::commands::settings::get_config_dir;
use crate::error::ScanError;
use crate::network::sanitize;
use crate::state::SharedScanState;

/// Save a network baseline snapshot.
pub async fn save_baseline(baseline: Baseline) -> Result<String, ScanError> {
    // Validate inputs
    let _name = sanitize::validate_name(&baseline.name)?;
    let _cidr = sanitize::validate_cidr(&baseline.scan_cidr)?;
    let _id = sanitize::validate_id(&baseline.id)?;

    let config_dir = get_config_dir()?;
    let store = BaselineStore::new(config_dir);

    // SQLite operations are blocking — use spawn_blocking
    let result = tokio::task::spawn_blocking(move || store.save_blocking(&baseline))
        .await
        .map_err(|e| ScanError::BaselineError(format!("Baseline save task failed: {}", e)))?;

    result
}

/// Get all saved baselines.
pub async fn get_baselines() -> Result<Vec<Baseline>, ScanError> {
    let config_dir = get_config_dir()?;
    let store = BaselineStore::new(config_dir);

    tokio::task::spawn_blocking(move || store.get_all_blocking())
        .await
        .map_err(|e| ScanError::BaselineError(format!("Baseline query task failed: {}", e)))?
}

/// Delete a baseline by ID.
pub async fn delete_baseline(id: String) -> Result<(), ScanError> {
    let validated_id = sanitize::validate_id(&id)?;

    let config_dir = get_config_dir()?;
    let store = BaselineStore::new(config_dir);

    tokio::task::spawn_blocking(move || store.delete_blocking(&validated_id))
        .await
        .map_err(|e| ScanError::BaselineError(format!("Baseline delete task failed: {}", e)))?
}

/// Compare a baseline against current scan results.
pub async fn compare_baseline(
    id: String,
    state: Arc<SharedScanState>,
) -> Result<BaselineDiff, ScanError> {
    let validated_id = sanitize::validate_id(&id)?;

    let config_dir = get_config_dir()?;
    let store = BaselineStore::new(config_dir);

    // Load the baseline
    let baseline = tokio::task::spawn_blocking(move || store.get_by_id_blocking(&validated_id))
        .await
        .map_err(|e| ScanError::BaselineError(format!("Baseline load task failed: {}", e)))??;

    // Get current devices from shared state
    let current_devices = state.get_devices().await;

    // Compute diff (CPU-bound, but fast enough to run inline)
    let diff = compute_diff(&baseline, &current_devices);

    Ok(diff)
}
