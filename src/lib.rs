//! NetSentinel library root.
//!
//! Re-exports all public modules and types needed by the Iced frontend.

pub mod baseline;
pub mod commands;
pub mod error;
pub mod events;
pub mod history;
pub mod history_adapter;
pub mod ipc;
pub mod network;
pub mod reporting;
pub mod scan_store;
pub mod settings;
pub mod state;
pub mod types;
pub mod ui;

// ── Re-exports for convenient access ────────────────────────────────────

pub use commands::{
    baseline::{
        compare_baseline, compare_baseline_with_scan_store, delete_baseline, get_baselines,
        save_baseline, save_baseline_from_scan_store,
    },
    device::get_device_info,
    export::export_audit_report,
    history::{
        clear_scan_history, delete_scan_history_entry, get_history_device_detail,
        get_history_devices_page, get_scan_history, save_scan_history,
        save_scan_history_from_session,
    },
    network::get_network_info,
    platform::get_platform_capabilities,
    privilege::check_privilege_status,
    scan::{get_scan_results, pause_scan, resume_scan, start_scan, stop_scan},
    scan_store::{
        complete_scan_session, create_scan_session, delete_scan_session, get_stored_scan_device,
        initialize_scan_store, insert_scan_finding, list_scan_devices, list_scan_sessions,
        update_scan_progress, upsert_scan_device, upsert_scan_port,
    },
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
pub use scan_store::{
    FindingSummary, Page, ScanSession, ScanSessionStatus, ScanSessionSummary, ScanStore,
    StoredDeviceSummary, StoredScanConfig,
};
pub use settings::SettingsProfile;
pub use state::SharedScanState;
pub use types::FindingCategory;
