//! Command modules for the NetSentinel backend.
//!
//! Each submodule exposes plain `pub async fn` functions that operate on
//! `Arc<SharedScanState>` directly, replacing the old Tauri `#[command]`
//! and `State<>` patterns.

pub mod baseline;
pub mod device;
pub mod export;
pub mod history;
pub mod network;
pub mod platform;
pub mod privilege;
pub mod scan;
pub mod scan_pipeline;
pub mod scan_store;
pub mod scheduler;
pub mod settings;

use serde::Serialize;

/// Device information returned by `get_device_info`
#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct DeviceInfo {
    pub hostname: String,
    pub os_name: String,
    pub os_version: String,
    pub uptime: String,
}

/// Network information returned by `get_network_info`
#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct NetworkInfo {
    pub ip_address: String,
    pub mac_address: String,
    pub gateway: String,
    pub network_name: String,
}

/// Formats system uptime into a human-readable string
pub fn format_uptime(uptime_secs: u64) -> String {
    let minutes = (uptime_secs / 60) % 60;
    let hours = (uptime_secs / 3600) % 24;
    let days = uptime_secs / 86400;

    match days {
        0 => format!("{} hours, {} minutes", hours, minutes),
        1 => format!("1 day, {} hours, {} minutes", hours, minutes),
        _ => format!("{} days, {} hours, {} minutes", days, hours, minutes),
    }
}

// Re-export device commands
pub use device::get_device_info;

// Re-export network commands
pub use network::get_network_info;

// Re-export platform capabilities command
pub use platform::get_platform_capabilities;

// Re-export scan commands
pub use scan::{get_scan_results, pause_scan, resume_scan, start_scan, stop_scan};

// Re-export scan store commands
pub use scan_store::{
    complete_scan_session, create_scan_session, delete_scan_session, get_stored_scan_device,
    initialize_scan_store, insert_scan_finding, list_scan_devices, list_scan_findings_page,
    list_scan_sessions, update_scan_progress, upsert_scan_device, upsert_scan_port,
};

// Re-export scan store summary types
pub use crate::scan_store::FindingSummary;

// Re-export export commands
pub use export::export_audit_report;

// Re-export settings commands
pub use settings::{
    delete_profile, get_default_settings, get_settings_profiles, load_settings, save_profile,
    save_settings,
};

// Re-export history commands
pub use history::{
    clear_scan_history, delete_scan_history_entry, get_history_device_detail,
    get_history_devices_page, get_scan_history, save_scan_history, save_scan_history_from_session,
};

// Re-export baseline commands
pub use baseline::{
    compare_baseline, compare_baseline_with_scan_store, delete_baseline, get_baselines,
    save_baseline, save_baseline_from_scan_store,
};

// Re-export privilege command
pub use privilege::check_privilege_status;
