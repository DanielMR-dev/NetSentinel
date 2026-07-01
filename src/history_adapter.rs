//! Adapter between `ScanStore` sessions and the `HistoryStore` JSON entries.
//!
//! History entries no longer embed full device vectors. This module provides
//! helpers to create lightweight history summaries from a completed scan
//! session and to load device details on demand via paginated `ScanStore`
//! APIs.

use crate::commands::settings::get_config_dir;
use crate::error::ScanError;
use crate::history::{HistoryStore, ScanHistoryEntry};
use crate::scan_store::{ScanSessionSummary, ScanStore, StoredDeviceSummary};
use crate::types::{Device, Port};

/// Create a `ScanHistoryEntry` from a completed scan session summary.
///
/// The entry stores the `scan_store_id` link so device details can be loaded
/// paginated on demand.
pub fn history_entry_from_session(summary: &ScanSessionSummary) -> ScanHistoryEntry {
    ScanHistoryEntry {
        id: uuid::Uuid::new_v4().to_string(),
        scan_id: summary.id.clone(),
        scan_store_id: Some(summary.id.clone()),
        cidr: summary.cidr.clone(),
        device_count: summary.device_count,
        duration_ms: summary.duration_ms.unwrap_or(0),
        status: summary.status.as_str().to_string(),
        timestamp: summary.completed_at.unwrap_or(summary.started_at),
    }
}

/// Load a paginated page of device summaries for a history entry's scan store session.
pub async fn load_history_devices_page(
    scan_store_id: &str,
    limit: u32,
    offset: u32,
) -> Result<crate::scan_store::Page<StoredDeviceSummary>, ScanError> {
    let config_dir = get_config_dir()?;
    ScanStore::new(config_dir)
        .list_devices_page(scan_store_id.to_string(), limit, offset)
        .await
}

/// Load full device detail for a single IP from a history entry's scan store session.
pub async fn get_history_device_detail(
    scan_store_id: &str,
    ip: &str,
) -> Result<Option<Device>, ScanError> {
    let config_dir = get_config_dir()?;
    ScanStore::new(config_dir)
        .get_device(scan_store_id.to_string(), ip.to_string())
        .await
}

/// Convenience function that persists a completed scan session summary to history.
pub async fn save_history_from_session(
    summary: &ScanSessionSummary,
) -> Result<ScanHistoryEntry, ScanError> {
    let entry = history_entry_from_session(summary);
    let config_dir = get_config_dir()?;
    HistoryStore::new(config_dir)
        .add_entry(entry.clone())
        .await?;
    Ok(entry)
}

/// Summarize an open port for display in history device previews.
pub fn format_port_preview(port: &Port) -> String {
    match &port.service {
        Some(service) => format!("{}/{} ({})", port.number, port.protocol, service),
        None => format!("{}/{}", port.number, port.protocol),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan_store::ScanSessionStatus;

    #[test]
    fn history_entry_derived_from_session_summary() {
        let summary = ScanSessionSummary {
            id: "scan-abc".to_string(),
            cidr: "10.0.0.0/24".to_string(),
            status: ScanSessionStatus::Completed,
            total_hosts: 256,
            scanned_hosts: 256,
            device_count: 12,
            finding_count: 3,
            started_at: 1000,
            updated_at: 2000,
            completed_at: Some(2500),
            duration_ms: Some(1500),
            error_message: None,
        };

        let entry = history_entry_from_session(&summary);
        assert_eq!(entry.scan_id, "scan-abc");
        assert_eq!(entry.scan_store_id, Some("scan-abc".to_string()));
        assert_eq!(entry.cidr, "10.0.0.0/24");
        assert_eq!(entry.device_count, 12);
        assert_eq!(entry.duration_ms, 1500);
        assert_eq!(entry.status, "completed");
        assert_eq!(entry.timestamp, 2500);
    }

    #[test]
    fn format_port_preview_includes_service_when_present() {
        let port = Port {
            number: 443,
            protocol: "tcp".to_string(),
            service: Some("https".to_string()),
            state: crate::types::PortState::Open,
        };
        assert_eq!(format_port_preview(&port), "443/tcp (https)");
    }

    #[test]
    fn format_port_preview_omits_missing_service() {
        let port = Port {
            number: 9999,
            protocol: "tcp".to_string(),
            service: None,
            state: crate::types::PortState::Open,
        };
        assert_eq!(format_port_preview(&port), "9999/tcp");
    }
}
