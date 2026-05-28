mod commands;
mod error;
mod network;
mod settings;
mod state;
mod types;

use std::sync::Arc;

pub use commands::{
    get_device_info, get_network_info, start_scan, stop_scan, pause_scan, resume_scan,
    get_scan_results, get_platform_capabilities, CommandError, DeviceInfo, NetworkInfo,
};
pub use commands::settings::{
    get_settings_profiles, save_profile, delete_profile, load_settings, save_settings,
    get_default_settings,
};
pub use error::ScanError;
pub use settings::SettingsProfile;
pub use state::SharedScanState;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let shared_state = Arc::new(SharedScanState::new());

    if let Err(e) = tauri::Builder::default()
        .plugin(
            tauri_plugin_log::Builder::default()
                .level(log::LevelFilter::Info)
                .build(),
        )
        .manage(shared_state)
        .invoke_handler(tauri::generate_handler![
            get_device_info,
            get_network_info,
            get_platform_capabilities,
            start_scan,
            stop_scan,
            pause_scan,
            resume_scan,
            get_scan_results,
            get_settings_profiles,
            save_profile,
            delete_profile,
            load_settings,
            save_settings,
            get_default_settings,
        ])
        .run(tauri::generate_context!())
    {
        eprintln!("Fatal error starting NetSentinel: {}", e);
        std::process::exit(1);
    }
}