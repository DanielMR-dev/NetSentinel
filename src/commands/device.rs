//! Device information command.
//!
//! Provides `get_device_info` as a plain async function that retrieves
//! hostname, OS name, OS version, and uptime from the local system.

use sysinfo::System;
use tracing::info;

use crate::commands::{format_uptime, DeviceInfo};

/// Error type for device information retrieval.
#[derive(thiserror::Error, Debug)]
pub enum DeviceError {
    #[error("Failed to retrieve device information: {0}")]
    InfoError(String),
}

/// Get device information (hostname, OS name, OS version, uptime).
pub async fn get_device_info() -> Result<DeviceInfo, DeviceError> {
    let _sys = System::new_all();

    let hostname = System::host_name().unwrap_or_else(|| "unknown".to_string());

    let os_name = System::name().unwrap_or_else(|| "unknown".to_string());

    let os_version = System::os_version().unwrap_or_else(|| "unknown".to_string());

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
