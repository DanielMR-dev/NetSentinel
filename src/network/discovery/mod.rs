//! Network discovery module for finding devices on the local network.
//!
//! This module provides multiple discovery methods:
//! - `arp_table`: Read the system's ARP table for cached entries
//! - `tcp_probe`: TCP port probing as a fallback when ARP is unavailable

pub mod arp_sweep;
pub mod arp_table;
pub mod tcp_probe;

use tokio::sync::mpsc;

use crate::error::ScanError;
use crate::events::AppEvent;
use crate::types::Device;

/// Maximum concurrent TCP probes during discovery
#[allow(dead_code)]
const MAX_CONCURRENT_PROBES: usize = 50;

/// Discover devices using the system's ARP table (preferred method).
/// Falls back to TCP probing if ARP table is empty.
pub async fn discover_devices(
    event_tx: &mpsc::UnboundedSender<AppEvent>,
) -> Result<Vec<Device>, ScanError> {
    // First, try to read ARP table
    match arp_table::read_arp_table().await {
        Ok(devices) if !devices.is_empty() => {
            // Emit log message
            emit_log(
                event_tx,
                "info",
                &format!("Discovered {} devices from ARP table", devices.len()),
                None,
            );

            // Emit devices found via event channel
            for device in &devices {
                let _ = event_tx.send(AppEvent::DeviceFound(device.clone()));
            }

            Ok(devices)
        }
        Ok(_) => {
            // ARP table is empty, fall back to TCP probing
            emit_log(
                event_tx,
                "warn",
                "ARP table is empty, falling back to TCP probing",
                None,
            );

            tcp_probe_fallback(event_tx).await
        }
        Err(e) => {
            emit_log(
                event_tx,
                "error",
                &format!("Failed to read ARP table: {}", e),
                None,
            );

            tcp_probe_fallback(event_tx).await
        }
    }
}

/// Fallback discovery using TCP port probing
async fn tcp_probe_fallback(
    event_tx: &mpsc::UnboundedSender<AppEvent>,
) -> Result<Vec<Device>, ScanError> {
    emit_log(
        event_tx,
        "info",
        "Starting TCP probing fallback discovery",
        None,
    );

    // For TCP probing fallback, we need an IP range to scan
    // This would typically be passed in or detected from the local interface
    // For now, we return an empty list and let the caller decide what to do
    // In a full implementation, we'd get the local network interface and scan it

    emit_log(
        event_tx,
        "warn",
        "TCP probing fallback requires a target network - use host_discovery module",
        None,
    );

    Ok(Vec::new())
}

/// Emit a log event to the frontend via the event channel.
pub fn emit_log(
    event_tx: &mpsc::UnboundedSender<AppEvent>,
    level: &str,
    message: &str,
    target: Option<&str>,
) {
    let _ = event_tx.send(AppEvent::ScanLog {
        level: level.to_string(),
        message: message.to_string(),
        target: target.map(|s| s.to_string()),
        timestamp: chrono::Utc::now().timestamp(),
    });
}
