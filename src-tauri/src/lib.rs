mod commands;
mod error;
mod network;
mod state;
mod types;

use std::sync::Arc;

pub use commands::{
    get_device_info, get_network_info, start_scan, stop_scan, pause_scan, resume_scan,
    get_scan_results, CommandError, DeviceInfo, NetworkInfo,
};
pub use error::ScanError;
pub use state::SharedScanState;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let shared_state = Arc::new(SharedScanState::new());

    tauri::Builder::default()
        .plugin(
            tauri_plugin_log::Builder::default()
                .level(log::LevelFilter::Info)
                .build(),
        )
        .manage(shared_state)
        .invoke_handler(tauri::generate_handler![
            get_device_info,
            get_network_info,
            start_scan,
            stop_scan,
            pause_scan,
            resume_scan,
            get_scan_results,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}