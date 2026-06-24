//! NetSentinel library root.
//!
//! Re-exports all public modules and types needed by the Iced frontend.

pub mod baseline;
pub mod commands;
pub mod error;
pub mod events;
pub mod history;
pub mod ipc;
pub mod network;
pub mod reporting;
pub mod settings;
pub mod state;
pub mod types;
pub mod ui;

// ── Re-exports for convenient access ────────────────────────────────────

pub use commands::{
    baseline::{compare_baseline, delete_baseline, get_baselines, save_baseline},
    device::get_device_info,
    export::export_audit_report,
    history::{clear_scan_history, delete_scan_history_entry, get_scan_history, save_scan_history},
    network::get_network_info,
    platform::get_platform_capabilities,
    privilege::check_privilege_status,
    scan::{get_scan_results, pause_scan, resume_scan, start_scan, stop_scan},
    settings::{
        delete_profile, get_default_settings, get_settings_profiles, load_settings, save_profile,
        save_settings,
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
