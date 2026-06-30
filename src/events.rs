//! Event bridge system for the Iced Frotend
//!
//! Defines the unified event types that flow from the backend scanning engine
//! to the Iced GUI via `tokio::sync::mpsc` channels. This replaces the Tauri
//! event emission system (`app_handle.emit(...)`) with a direct channel-based
//! approach suitable for in-process communication.

use serde::{Deserialize, Serialize};

use crate::network::banner::BannerResult;
use crate::network::cve::CveMatch;
use crate::network::privileges::PrivilegeStatus;
use crate::types::{Device, Finding};

/// Events sent from the backend scanning engine to the Iced UI
///
/// There are received by the Iced subscription and converted into Iced `Message` types.
/// variants for the application to process.
#[derive(Debug, Clone)]
pub enum AppEvent {
    // --------- Scan Lifecycle Events ----------
    /// A new device was discovered during the scan
    DeviceFound(Device),

    /// Progress update with scanned/total counts and current target
    ScanProgress {
        scanned: u32,
        total: u32,
        current_target: String,
    },

    /// Scan has completed (successfully, cancelled, or with error)
    ScanComplete {
        scan_id: String,
        device_count: u32,
        duration_ms: u64,
        status: String,
        /// Snapshot of discovered devices at completion, used for automatic
        /// history persistence.
        devices: Vec<Device>,
    },

    /// A log message from the scanning engine.
    ScanLog {
        level: String,
        message: String,
        target: Option<String>,
        timestamp: i64,
    },

    // ---- Banner / CVE events ----
    /// A service banner was grabbed from an open port
    BannerFound(BannerResult),

    /// A CVE match was found for a grabbed banner.
    CveAlert(CveMatch),

    /// A normalized security finding was found.
    FindingFound(Finding),

    /// A batch of normalized security findings was discovered.
    FindingsDiscovered(Vec<Finding>),

    // ---- Privilege Events ----
    /// Privilege status report (emmited at startup and on-demmand)
    PrivilegeStatus(PrivilegeStatus),

    /// A command triggered from an external IPC tool
    IpcCommand(String),

    /// A security alert triggered from an external IPC tool
    SecurityAlert {
        source_tool: String,
        severity: String,
        title: String,
        description: String,
        target_artifact: String,
        timestamp: i64,
    },
}

/// Scan events used by the scanning engine for streaming progess.
///
/// This is the core event type passed through `tokio::sync::mpsc::UnboundedSender`
/// from the scan task to the UI layer
#[derive(Debug, Clone)]
pub enum ScanEvent {
    /// A device was discovered
    DeviceFound(Device),

    /// Progress update (0.0 to 1.0)
    Progress(f32),

    /// A log message from the scan engine.
    Log {
        level: String,
        message: String,
        target: Option<String>,
        timestamp: i64,
    },

    /// A banner was grabbed.
    BannerFound(BannerResult),

    /// A CVE alert was triggered.
    CveAlert(CveMatch),

    /// A normalized security finding was found.
    FindingFound(Finding),

    /// Scan finished (Ok on success, Err with reason on failure/cancellation).
    Finished(Result<ScanSummary, String>),
}

/// Summary data emitted when a scan completes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub scan_id: String,
    pub device_count: u32,
    pub duration_ms: u64,
    pub status: String,
}

/// Helper to create and `AppEvent` log entry.
pub fn log_event(level: &str, message: &str, target: Option<&str>) -> AppEvent {
    AppEvent::ScanLog {
        level: level.to_string(),
        message: message.to_string(),
        target: target.map(|s| s.to_string()),
        timestamp: chrono::Utc::now().timestamp(),
    }
}
