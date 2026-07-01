//! Baseline-related commands.
//!
//! Provides functions for saving, loading, deleting, and comparing
//! network baselines.

use std::sync::Arc;

use crate::baseline::{compute_diff, Baseline, BaselineDiff, BaselineStore};
use crate::commands::settings::get_config_dir;
use crate::error::ScanError;
use crate::network::sanitize;
use crate::scan_store::{ScanStore, StoredDeviceSummary};
use crate::state::SharedScanState;
use crate::types::Device;

/// Page size used when materializing a baseline snapshot from `ScanStore`.
const BASELINE_PAGE_SIZE: u32 = 100;

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

/// Materialize the full device list for a scan store session using paginated reads.
async fn materialize_scan_store_devices(scan_id: &str) -> Result<Vec<Device>, ScanError> {
    let config_dir = get_config_dir()?;
    let scan_store = ScanStore::new(config_dir);

    let mut devices = Vec::new();
    let mut offset = 0u32;

    loop {
        let page = scan_store
            .list_devices_page(scan_id.to_string(), BASELINE_PAGE_SIZE, offset)
            .await?;

        if page.items.is_empty() {
            break;
        }

        let page_len = page.items.len() as u32;
        for summary in page.items {
            if let Some(device) = scan_store
                .get_device(scan_id.to_string(), summary.ip.clone())
                .await?
            {
                devices.push(device);
            }
        }

        let loaded = offset + page_len;
        if loaded >= page.total {
            break;
        }
        offset = loaded;
    }

    Ok(devices)
}

/// Save a baseline using devices persisted for a scan store session.
pub async fn save_baseline_from_scan_store(
    scan_id: String,
    name: String,
    description: Option<String>,
    scan_cidr: String,
) -> Result<String, ScanError> {
    let validated_scan_id = sanitize::validate_id(&scan_id)?;
    let _name = sanitize::validate_name(&name)?;
    let _cidr = sanitize::validate_cidr(&scan_cidr)?;

    let devices = materialize_scan_store_devices(&validated_scan_id).await?;

    let baseline = Baseline {
        id: uuid::Uuid::new_v4().to_string(),
        name,
        description,
        devices,
        scan_cidr,
        created_at: chrono::Utc::now().timestamp(),
    };

    let config_dir = get_config_dir()?;
    let store = BaselineStore::new(config_dir);
    tokio::task::spawn_blocking(move || store.save_blocking(&baseline))
        .await
        .map_err(|e| ScanError::BaselineError(format!("Baseline save task failed: {}", e)))?
}

/// Compare a baseline against devices persisted for a scan store session.
pub async fn compare_baseline_with_scan_store(
    baseline_id: String,
    scan_id: String,
) -> Result<BaselineDiff, ScanError> {
    let validated_baseline_id = sanitize::validate_id(&baseline_id)?;
    let validated_scan_id = sanitize::validate_id(&scan_id)?;

    let config_dir = get_config_dir()?;
    let baseline_store = BaselineStore::new(config_dir.clone());
    let baseline = tokio::task::spawn_blocking(move || {
        baseline_store.get_by_id_blocking(&validated_baseline_id)
    })
    .await
    .map_err(|e| ScanError::BaselineError(format!("Baseline load task failed: {}", e)))??;

    let current_devices = materialize_scan_store_devices(&validated_scan_id).await?;

    Ok(compute_diff(&baseline, &current_devices))
}

/// Re-exported page type alias for callers that need to page through scan store devices.
pub type DeviceSummaryPage = crate::scan_store::Page<StoredDeviceSummary>;
