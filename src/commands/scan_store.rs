//! Command wrappers for SQLite-backed scan result persistence.

use crate::commands::settings::get_config_dir;
use crate::error::ScanError;
use crate::network::sanitize;
use crate::scan_store::{
    clamp_limit, NewScanSession, Page, ScanSessionStatus, ScanSessionSummary, ScanStore,
    StoredDeviceSummary,
};
use crate::types::{Device, Finding};

fn create_scan_store() -> Result<ScanStore, ScanError> {
    Ok(ScanStore::new(get_config_dir()?))
}

pub async fn initialize_scan_store() -> Result<(), ScanError> {
    create_scan_store()?.initialize().await
}

pub async fn begin_scan_session(session: NewScanSession) -> Result<String, ScanError> {
    let _id = sanitize::validate_id(&session.id)?;
    let _cidr = sanitize::validate_cidr(&session.cidr)?;
    if session.total_hosts == 0 {
        return Err(ScanError::InvalidInput(
            "Scan session total_hosts must be greater than zero".to_string(),
        ));
    }
    create_scan_store()?.begin_session(session).await
}

pub async fn upsert_scan_device(scan_id: String, device: Device) -> Result<(), ScanError> {
    let _id = sanitize::validate_id(&scan_id)?;
    if device.ip.trim().is_empty() {
        return Err(ScanError::InvalidInput(
            "Cannot persist device without an IP address".to_string(),
        ));
    }
    create_scan_store()?.upsert_device(scan_id, device).await
}

pub async fn upsert_scan_finding(scan_id: String, finding: Finding) -> Result<(), ScanError> {
    let _id = sanitize::validate_id(&scan_id)?;
    if finding.id.trim().is_empty() || finding.ip.trim().is_empty() {
        return Err(ScanError::InvalidInput(
            "Cannot persist finding without an ID and IP address".to_string(),
        ));
    }
    create_scan_store()?.upsert_finding(scan_id, finding).await
}

pub async fn update_scan_progress(
    scan_id: String,
    scanned_hosts: u32,
    total_hosts: u32,
) -> Result<(), ScanError> {
    let _id = sanitize::validate_id(&scan_id)?;
    if total_hosts == 0 {
        return Err(ScanError::InvalidInput(
            "Scan progress total_hosts must be greater than zero".to_string(),
        ));
    }
    create_scan_store()?
        .update_progress(scan_id, scanned_hosts.min(total_hosts), total_hosts)
        .await
}

pub async fn complete_scan_session(
    scan_id: String,
    status: ScanSessionStatus,
    duration_ms: Option<u64>,
    error_message: Option<String>,
) -> Result<(), ScanError> {
    let _id = sanitize::validate_id(&scan_id)?;
    create_scan_store()?
        .complete_session(scan_id, status, duration_ms, error_message)
        .await
}

pub async fn list_scan_sessions(
    limit: u32,
    offset: u32,
) -> Result<Page<ScanSessionSummary>, ScanError> {
    create_scan_store()?
        .list_sessions(clamp_limit(limit), offset)
        .await
}

pub async fn list_scan_devices(
    scan_id: String,
    limit: u32,
    offset: u32,
) -> Result<Page<StoredDeviceSummary>, ScanError> {
    let _id = sanitize::validate_id(&scan_id)?;
    create_scan_store()?
        .list_devices(scan_id, clamp_limit(limit), offset)
        .await
}

pub async fn get_stored_scan_device(
    scan_id: String,
    ip: String,
) -> Result<Option<Device>, ScanError> {
    let _id = sanitize::validate_id(&scan_id)?;
    if ip.trim().is_empty() {
        return Err(ScanError::InvalidInput(
            "Device IP must not be empty".to_string(),
        ));
    }
    create_scan_store()?.get_device(scan_id, ip).await
}

pub async fn load_scan_devices(scan_id: String) -> Result<Vec<Device>, ScanError> {
    let _id = sanitize::validate_id(&scan_id)?;
    create_scan_store()?.load_all_devices(scan_id).await
}

pub async fn delete_scan_session(scan_id: String) -> Result<(), ScanError> {
    let _id = sanitize::validate_id(&scan_id)?;
    create_scan_store()?.delete_session(scan_id).await
}
