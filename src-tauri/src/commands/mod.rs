mod device;
mod network;
mod scan;

use serde::Serialize;
use thiserror::Error;

/// Custom error type for Tauri commands
#[derive(Error, Debug, Serialize)]
pub enum CommandError {
    #[error("Failed to retrieve system information: {0}")]
    SystemError(String),

    #[error("No network interface found")]
    NoNetworkInterface,

    #[error("Failed to format uptime: {0}")]
    FormatError(String),
}

/// Device information returned by get_device_info command
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceInfo {
    pub hostname: String,
    pub os_name: String,
    pub os_version: String,
    pub uptime: String,
}

/// Network information returned by get_network_info command
#[derive(Serialize)]
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

// Re-export scan commands
pub use scan::{start_scan, stop_scan, pause_scan, resume_scan, get_scan_results};