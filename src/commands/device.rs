use log::info;
use sysinfo::System;

use crate::commands::{format_uptime, CommandError, DeviceInfo};

/// Get device information (hostname, OS name, OS version, uptime)
#[tauri::command]
pub async fn get_device_info() -> Result<DeviceInfo, CommandError> {
    let _sys = System::new_all();

    let hostname = System::host_name()
        .unwrap_or_else(|| "unknown".to_string());

    let os_name = System::name()
        .unwrap_or_else(|| "unknown".to_string());

    let os_version = System::os_version()
        .unwrap_or_else(|| "unknown".to_string());

    let uptime_secs = System::uptime();
    let uptime = format_uptime(uptime_secs);

    info!(
        "Device info retrieved: hostname={}, os_name={}, os_version={}, uptime_secs={}",
        hostname, os_name, os_version, uptime_secs
    );

    Ok(DeviceInfo {
        hostname,
        os_name,
        os_version,
        uptime,
    })
}