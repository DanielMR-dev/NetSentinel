//! Scan control commands.
//!
//! Provides `start_scan`, `stop_scan`, `pause_scan`, `resume_scan`, and
//! `get_scan_results` as plain async functions. The `start_scan` function
//! accepts an `UnboundedSender<AppEvent>` channel for streaming results
//! to the Iced UI, replacing Tauri's `app_handle.emit(...)` pattern.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use tokio::sync::{mpsc, oneshot};
use tracing::warn;

use crate::error::ScanError;
use crate::events::AppEvent;
use crate::network::{cidr, host_discovery, icmp, sanitize};
use crate::network::timing::TimingTemplate;
use crate::state::SharedScanState;
use crate::types::{Device, ScanResponse, ScanResultsResponse, ScanType};


/// Start a network scan.
///
/// Results are streamed to the UI via `event_tx`. The caller (Iced subscription)
/// receives `AppEvent` variants as the scan progresses.
pub async fn start_scan(
    state: Arc<SharedScanState>,
    event_tx: mpsc::UnboundedSender<AppEvent>,
    cidr: String,
    timeout_ms: u64,
    scan_ports: bool,
    ports: Vec<u16>,
    max_concurrent_hosts: Option<u32>,
    discovery_methods: Option<Vec<String>>,
    retry_count: Option<u8>,
    scan_type: Option<ScanType>,
    timing_template: Option<TimingTemplate>,
) -> Result<ScanResponse, ScanError> {
    // --- Input Validation ---
    let _validated_cidr = sanitize::validate_cidr(&cidr)?;
    let _validated_timeout = sanitize::validate_timeout_ms(timeout_ms)?;

    if scan_ports && !ports.is_empty() {
        sanitize::validate_ports(&ports)?;
    }

    let effective_scan_type = scan_type.unwrap_or_default();
    let effective_timing = timing_template.unwrap_or_default();

    // If SYN scan requested, verify privileges
    if effective_scan_type == ScanType::Syn {
        let priv_status = tokio::task::spawn_blocking(
            crate::network::privileges::check_system_privileges,
        )
        .await
        .map_err(|e| ScanError::NetworkError(format!("Privilege check failed: {}", e)))?;

        if !priv_status.syn_scan_available {
            return Err(ScanError::PermissionDenied(
                "SYN scanning requires raw socket privileges (root/CAP_NET_RAW/Administrator). \
                Please use TCP Connect scan or run with elevated privileges"
                .to_string(),
            ));
        }
    }

    // Helper closure to send log events
    let send_log = |level: &str, message: &str, target: Option<&str>| {
        let _ = event_tx.send(AppEvent::ScanLog {
            level: level.to_string(),
            message: message.to_string(),
            target: target.map(|s| s.to_string()),
            timestamp: chrono::Utc::now().timestamp(),
        });
    };

    send_log("info", &format!("Validating CIDR: {}", cidr), None);

    // Validate CIDR
    let network = cidr::validate_cidr(&cidr)?;
    let total_hosts = network.iter().count() as u32;

    send_log(
        "info",
        &format!("Scan target contains {} hosts", total_hosts),
        None,
    );

    // Check if already running
    if state.is_running() {
        send_log("error", "Scan already in progress", None);
        return Err(ScanError::NetworkError("Scan already in progress".to_string()));
    }

    // Resolve settings parameters
    let effective_max_concurrent = max_concurrent_hosts.unwrap_or(50) as usize;
    let methods = discovery_methods.unwrap_or_else(|| {
        vec!["arp".into(), "tcp_probe".into(), "icmp".into()]
    });
    let _use_arp = methods.iter().any(|m| m == "arp");
    let _use_tcp = methods.iter().any(|m| m == "tcp_probe");
    let _use_icmp = methods.iter().any(|m| m == "icmp");
    let effective_retry_count = retry_count.unwrap_or(0);

    // Reset state
    state.reset().await;
    state.set_total_hosts(total_hosts);
    state.set_running(true);

    // Create cancellation channel
    let (cancel_tx, cancel_rx) = oneshot::channel();
    state.set_cancel_tx(cancel_tx).await;

    let scan_id = uuid::Uuid::new_v4().to_string();

    send_log(
        "info",
        &format!(
            "Scan started (methods: {:?}, max_concurrent: {}, retries: {}, type: {:?}, timing: {:?})",
            methods, effective_max_concurrent, effective_retry_count, effective_scan_type, effective_timing
        ),
        None,
    );

    // Spawn the scanning task
    let state_clone = state.clone();
    let event_tx_clone = event_tx.clone();
    let scan_id_clone = scan_id.clone();
    let _cidr_clone = cidr.clone();

    tokio::spawn(async move {
        let start_time = Instant::now();

        // Parse IPs from CIDR
        let ips: Vec<IpAddr> = network.iter().map(|ip| IpAddr::from(ip)).collect();

        // Run host discovery
        let discovery_result = host_discovery::discover_hosts(
            ips,
            event_tx_clone.clone(),
            cancel_rx,
            effective_max_concurrent,
            effective_retry_count as u32,
        )
        .await;

        let duration_ms = start_time.elapsed().as_millis() as u64;

        match discovery_result {
            Ok(devices) => {
                let device_count = devices.len() as u32;

                // Store devices in shared state
                for device in &devices {
                    state_clone.add_device(device.clone()).await;
                }

                let _ = event_tx_clone.send(AppEvent::ScanComplete {
                    scan_id: scan_id_clone,
                    device_count,
                    duration_ms,
                    status: "completed".to_string(),
                });
            }
            Err(e) => {
                warn!("Scan failed: {}", e);
                let _ = event_tx_clone.send(AppEvent::ScanComplete {
                    scan_id: scan_id_clone,
                    device_count: 0,
                    duration_ms,
                    status: format!("error: {}", e),
                });
            }
        }

        state_clone.set_running(false);
    });

    Ok(ScanResponse {
        scan_id,
        status: "started".to_string(),
        scan_type: effective_scan_type,
    })
}

/// Stop an ongoing scan.
pub async fn stop_scan(
    state: Arc<SharedScanState>,
    event_tx: mpsc::UnboundedSender<AppEvent>,
) -> Result<(), ScanError> {
    let _ = event_tx.send(AppEvent::ScanLog {
        level: "info".to_string(),
        message: "Stop scan requested".to_string(),
        target: None,
        timestamp: chrono::Utc::now().timestamp(),
    });

    if !state.is_running() {
        let _ = event_tx.send(AppEvent::ScanLog {
            level: "warn".to_string(),
            message: "No scan running to stop".to_string(),
            target: None,
            timestamp: chrono::Utc::now().timestamp(),
        });
        return Err(ScanError::NotRunning);
    }

    state.set_cancelled().await;
    state.set_running(false);

    let _ = event_tx.send(AppEvent::ScanLog {
        level: "info".to_string(),
        message: "Scan stopped".to_string(),
        target: None,
        timestamp: chrono::Utc::now().timestamp(),
    });

    Ok(())
}

/// Pause an ongoing scan.
pub async fn pause_scan(
    state: Arc<SharedScanState>,
    event_tx: mpsc::UnboundedSender<AppEvent>,
) -> Result<(), ScanError> {
    let _ = event_tx.send(AppEvent::ScanLog {
        level: "info".to_string(),
        message: "Pause scan requested".to_string(),
        target: None,
        timestamp: chrono::Utc::now().timestamp(),
    });

    if !state.is_running() {
        let _ = event_tx.send(AppEvent::ScanLog {
            level: "warn".to_string(),
            message: "No scan running to pause".to_string(),
            target: None,
            timestamp: chrono::Utc::now().timestamp(),
        });
        return Err(ScanError::NotRunning);
    }

    state.set_paused(true);

    let _ = event_tx.send(AppEvent::ScanLog {
        level: "info".to_string(),
        message: "Scan paused".to_string(),
        target: None,
        timestamp: chrono::Utc::now().timestamp(),
    });

    Ok(())
}

/// Resume a paused scan.
pub async fn resume_scan(
    state: Arc<SharedScanState>,
    event_tx: mpsc::UnboundedSender<AppEvent>,
) -> Result<(), ScanError> {
    let _ = event_tx.send(AppEvent::ScanLog {
        level: "info".to_string(),
        message: "Resume scan requested".to_string(),
        target: None,
        timestamp: chrono::Utc::now().timestamp(),
    });

    if !state.is_running() {
        let _ = event_tx.send(AppEvent::ScanLog {
            level: "warn".to_string(),
            message: "No scan running to resume".to_string(),
            target: None,
            timestamp: chrono::Utc::now().timestamp(),
        });
        return Err(ScanError::NotRunning);
    }

    state.set_paused(false);

    let _ = event_tx.send(AppEvent::ScanLog {
        level: "info".to_string(),
        message: "Scan resumed".to_string(),
        target: None,
        timestamp: chrono::Utc::now().timestamp(),
    });

    Ok(())
}

/// Get current scan results.
pub async fn get_scan_results(
    state: Arc<SharedScanState>,
) -> Result<ScanResultsResponse, ScanError> {
    let devices = state.get_devices().await;
    let scanned = state.get_scanned_count();
    let total = state.get_total_hosts();

    Ok(ScanResultsResponse {
        devices,
        scanned_count: scanned,
        total_hosts: total,
    })
}

/// Attempt ICMP ping sweep discovery.
///
/// Checks privileges first, then runs an ICMP sweep. Returns the list of
/// devices that responded to ICMP Echo Requests.
///
/// # Errors
/// - `ScanError::PermissionDenied` if the process lacks raw socket privileges
/// - `ScanError::NetworkError` if the ICMP sweep encounters a fatal error
async fn try_icmp_discovery(
    ips: &[IpAddr],
    timeout_ms: u64,
    max_concurrent: usize,
    event_tx: mpsc::UnboundedSender<AppEvent>,
) -> Result<Vec<Device>, ScanError> {
    // Check privileges before attempting ICMP
    icmp::check_icmp_privileges()?;

    // Run ICMP ping sweep
    let devices = icmp::icmp_ping_sweep(
        ips.to_vec(),
        timeout_ms,
        max_concurrent,
        event_tx,
    )
    .await?;

    Ok(devices)
}
