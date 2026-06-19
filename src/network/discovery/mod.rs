//! Network discovery module for finding devices on the local network.
//!
//! This module provides multiple discovery methods:
//! - `arp_table`: Read the system's ARP table for cached entries
//! - `tcp_probe`: TCP port probing as a fallback when ARP is unavailable

pub mod arp_table;
pub mod arp_sweep;
pub mod tcp_probe;

use tauri::Emitter;

use crate::error::ScanError;
use crate::types::{Device, DeviceFoundEvent};

/// Maximum concurrent TCP probes during discovery
const MAX_CONCURRENT_PROBES: usize = 50;

/// Discover devices using the system's ARP table (preferred method).
/// Falls back to TCP probing if ARP table is empty.
pub async fn discover_devices(
    app: &tauri::AppHandle,
) -> Result<Vec<Device>, ScanError> {
    // First, try to read ARP table
    match arp_table::read_arp_table().await {
        Ok(devices) if !devices.is_empty() => {
            // Emit log message
            emit_log(
                app,
                "info",
                &format!("Discovered {} devices from ARP table", devices.len()),
                None,
            ).await;

            // Emit devices found with ArpTable discovery method
            for device in &devices {
                let event = DeviceFoundEvent {
                    ip: device.ip.clone(),
                    mac: device.mac.clone(),
                    hostname: device.hostname.clone(),
                    vendor: device.vendor.clone(),
                    os: device.os.clone(),
                    timestamp: chrono::Utc::now().timestamp(),
                    ports: device.ports.clone(),
                    discovery_method: "ArpTable".to_string(),
                    banner_results: device.banner_results.clone(),
                };
                let _ = app.emit("device_found", event);
            }

            Ok(devices)
        }
        Ok(_) => {
            // ARP table is empty, fall back to TCP probing
            emit_log(
                app,
                "warn",
                "ARP table is empty, falling back to TCP probing",
                None,
            ).await;

            tcp_probe_fallback(app).await
        }
        Err(e) => {
            emit_log(
                app,
                "error",
                &format!("Failed to read ARP table: {}", e),
                None,
            ).await;

            tcp_probe_fallback(app).await
        }
    }
}

/// Fallback discovery using TCP port probing
async fn tcp_probe_fallback(app: &tauri::AppHandle) -> Result<Vec<Device>, ScanError> {
    emit_log(
        app,
        "info",
        "Starting TCP probing fallback discovery",
        None,
    ).await;

    // For TCP probing fallback, we need an IP range to scan
    // This would typically be passed in or detected from the local interface
    // For now, we return an empty list and let the caller decide what to do
    // In a full implementation, we'd get the local network interface and scan it

    emit_log(
        app,
        "warn",
        "TCP probing fallback requires a target network - use host_discovery module",
        None,
    ).await;

    Ok(Vec::new())
}

/// Emit a log event to the frontend
pub async fn emit_log(
    app: &tauri::AppHandle,
    level: &str,
    message: &str,
    target: Option<&str>,
) {
    let log_event = crate::types::ScanLogEvent {
        level: level.to_string(),
        message: message.to_string(),
        target: target.map(|s| s.to_string()),
        timestamp: chrono::Utc::now().timestamp(),
    };

    let _ = app.emit("scan_log", log_event);
}