//! NetSentinel library root.
//!
//! Re-exports all public modules and types needed by the Iced frontend.

pub mod baseline;
pub mod commands;
pub mod error;
pub mod events;
pub mod history;
pub mod network;
pub mod settings;
pub mod state;
pub mod types;
pub mod ui;
pub mod ipc;

// ── Re-exports for convenient access ────────────────────────────────────

pub use commands::{
    baseline::{save_baseline, get_baselines, delete_baseline, compare_baseline},
    device::get_device_info,
    export::export_audit_report,
    history::{save_scan_history, get_scan_history, delete_scan_history_entry, clear_scan_history},
    network::get_network_info,
    platform::get_platform_capabilities,
    privilege::check_privilege_status,
    scan::{start_scan, stop_scan, pause_scan, resume_scan, get_scan_results},
    settings::{
        get_settings_profiles, save_profile, delete_profile, load_settings, save_settings,
        get_default_settings,
    },
    DeviceInfo, NetworkInfo,
};

pub use error::ScanError;
pub use events::{AppEvent, ScanEvent, ScanSummary};
pub use history::ScanHistoryEntry;
pub use network::cve::update_cve_database;
pub use network::privileges::PrivilegeStatus;
pub use settings::SettingsProfile;
pub use state::SharedScanState;
