use std::sync::Arc;
use std::time::Instant;

use tokio::sync::oneshot;
use tauri::{AppHandle, Emitter, State};

use crate::error::ScanError;
use crate::network::{cidr, discovery, host_discovery, icmp, oui};
use crate::state::SharedScanState;
use crate::types::{
    DeviceFoundEvent, ScanCompleteEvent, ScanLogEvent, ScanResponse,
    ScanResultsResponse, ScanStartedEvent,
};

/// Helper function to emit log events
async fn emit_log(
    app: &AppHandle,
    level: &str,
    message: &str,
    target: Option<&str>,
) {
    let log_event = ScanLogEvent {
        level: level.to_string(),
        message: message.to_string(),
        target: target.map(|s| s.to_string()),
        timestamp: chrono::Utc::now().timestamp(),
    };
    let _ = app.emit("scan_log", log_event);
}

/// Start a network scan
#[tauri::command]
pub async fn start_scan(
    app: AppHandle,
    state: State<'_, Arc<SharedScanState>>,
    cidr: String,
    timeout_ms: u64,
    scan_ports: bool,
    ports: Vec<u16>,
    max_concurrent_hosts: Option<u32>,
    discovery_methods: Option<Vec<String>>,
    retry_count: Option<u32>,
) -> Result<ScanResponse, ScanError> {
    emit_log(&app, "info", &format!("Validating CIDR: {}", cidr), None).await;

    // Validate CIDR
    let network = cidr::validate_cidr(&cidr)?;
    let total_hosts = network.iter().count() as u32;

    emit_log(&app, "info", &format!("Scan target contains {} hosts", total_hosts), None).await;

    // Check if already running
    if state.is_running() {
        emit_log(&app, "error", "Scan already in progress", None).await;
        return Err(ScanError::NetworkError("Scan already in progress".to_string()));
    }

    // Resolve settings parameters
    let effective_max_concurrent = max_concurrent_hosts.unwrap_or(50) as usize;
    let methods = discovery_methods.unwrap_or_else(|| {
        vec!["arp".into(), "tcp_probe".into(), "icmp".into()]
    });
    let use_arp = methods.iter().any(|m| m == "arp");
    let use_icmp = methods.iter().any(|m| m == "icmp");
    let use_tcp = methods.iter().any(|m| m == "tcp_probe");
    let effective_retry_count = retry_count.unwrap_or(0);

    // Reset state
    state.reset().await;
    state.set_total_hosts(total_hosts);
    state.set_running(true);

    // Create cancellation channel
    let (cancel_tx, cancel_rx) = oneshot::channel();
    state.set_cancel_tx(cancel_tx).await;

    let scan_id = uuid::Uuid::new_v4().to_string();

    // Emit scan started event
    let started_event = ScanStartedEvent {
        scan_id: scan_id.clone(),
        target_cidr: cidr.clone(),
        total_hosts,
        timestamp: chrono::Utc::now().timestamp(),
    };
    let _ = app.emit("scan_started", started_event);

    emit_log(
        &app,
        "info",
        &format!(
            "Scan started (methods: {:?}, max_concurrent: {}, retries: {})",
            methods, effective_max_concurrent, effective_retry_count
        ),
        None,
    )
    .await;

    // Spawn the scanning task
    let app_arc = Arc::new(app.clone());
    let state_clone = state.inner().clone();
    let scan_id_clone = scan_id.clone();
    let cidr_clone = cidr.clone();

    tokio::spawn(async move {
        let start_time = Instant::now();

        // Parse IPs
        let ips = match cidr::parse_cidr(&cidr_clone) {
            Ok(ips) => ips,
            Err(e) => {
                emit_log(&app_arc, "error", &format!("Failed to parse CIDR: {}", e), None).await;
                let complete_event = ScanCompleteEvent {
                    scan_id: scan_id_clone.clone(),
                    device_count: 0,
                    duration_ms: start_time.elapsed().as_millis() as u64,
                    status: "error".to_string(),
                };
                let _ = app_arc.emit("scan_complete", complete_event);
                state_clone.set_running(false);
                return;
            }
        };

        let total = ips.len() as u32;
        state_clone.set_total_hosts(total);

        emit_log(&app_arc, "info", &format!("Starting discovery on {} targets", total), None).await;

        // First try ARP table discovery (if enabled)
        if use_arp {
            emit_log(&app_arc, "info", "Attempting ARP table discovery first", None).await;

            match discovery::arp_table::read_arp_table().await {
                Ok(devices) if !devices.is_empty() => {
                    emit_log(
                        &app_arc,
                        "info",
                        &format!("Found {} devices in ARP table", devices.len()),
                        None,
                    ).await;

                    // Process ARP discovered devices with DNS/OUI enrichment
                    for device in &devices {
                        let mut enriched = device.clone();

                        // OUI vendor lookup
                        if !enriched.mac.is_empty() {
                            if let Some(vendor) = oui::lookup_vendor(&enriched.mac) {
                                enriched.vendor = Some(vendor);
                            }
                        }

                        // Reverse DNS lookup
                        if enriched.hostname.is_none() {
                            if let Some(hostname) = host_discovery::reverse_dns_lookup(&enriched.ip).await {
                                enriched.hostname = Some(hostname);
                            }
                        }

                        state_clone.add_device(enriched.clone()).await;

                        let event = DeviceFoundEvent {
                            ip: enriched.ip.clone(),
                            mac: enriched.mac.clone(),
                            hostname: enriched.hostname.clone(),
                            vendor: enriched.vendor.clone(),
                            timestamp: chrono::Utc::now().timestamp(),
                            ports: Vec::new(),
                            discovery_method: "ArpTable".to_string(),
                        };
                        let _ = app_arc.emit("device_found", event);
                    }

                    // Emit scan complete for ARP discovery
                    let duration = start_time.elapsed().as_millis() as u64;
                    let device_count = state_clone.get_devices().await.len() as u32;

                    let complete_event = ScanCompleteEvent {
                        scan_id: scan_id_clone.clone(),
                        device_count,
                        duration_ms: duration,
                        status: "completed".to_string(),
                    };
                    let _ = app_arc.emit("scan_complete", complete_event);
                    emit_log(&app_arc, "info", &format!("Scan completed in {}ms", duration), None).await;

                    state_clone.set_running(false);
                    return;
                }
                _ => {
                    emit_log(
                        &app_arc,
                        "warn",
                        "ARP table empty or unavailable, trying next discovery method",
                        None,
                    ).await;
                }
            }
        }

        // Try ICMP ping sweep (if enabled) before falling back to TCP probing
        if use_icmp {
            match try_icmp_discovery(&ips, timeout_ms, effective_max_concurrent, app_arc.clone()).await {
                Ok(devices) if !devices.is_empty() => {
                    emit_log(
                        &app_arc,
                        "info",
                        &format!("ICMP discovery found {} devices", devices.len()),
                        None,
                    ).await;

                    // Process ICMP discovered devices
                    for device in &devices {
                        state_clone.add_device(device.clone()).await;
                    }

                    // Scan ports on discovered devices if requested
                    let ports_to_scan = if scan_ports {
                        if ports.is_empty() {
                            host_discovery::DEFAULT_PORTS.to_vec()
                        } else {
                            ports.clone()
                        }
                    } else {
                        Vec::new()
                    };

                    if scan_ports && !ports_to_scan.is_empty() {
                        for device in &devices {
                            // Check for cancellation between devices
                            if !state_clone.is_running() {
                                emit_log(&app_arc, "warn", "Scan cancelled during port scanning", None).await;
                                break;
                            }

                            emit_log(
                                &app_arc,
                                "info",
                                &format!("Scanning ports on {}", device.ip),
                                Some(&device.ip),
                            ).await;

                            let ip_addr: std::net::IpAddr = match device.ip.parse() {
                                Ok(ip) => ip,
                                Err(e) => {
                                    emit_log(
                                        &app_arc,
                                        "error",
                                        &format!("Invalid IP: {} - {}", device.ip, e),
                                        None,
                                    ).await;
                                    continue;
                                }
                            };

                            let scanned_ports =
                                host_discovery::scan_ports(ip_addr, &ports_to_scan, timeout_ms).await;

                            let mut updated_device = device.clone();
                            updated_device.ports = scanned_ports;
                            state_clone.add_device(updated_device.clone()).await;

                            let event = DeviceFoundEvent {
                                ip: updated_device.ip.clone(),
                                mac: updated_device.mac.clone(),
                                hostname: updated_device.hostname.clone(),
                                vendor: updated_device.vendor.clone(),
                                timestamp: chrono::Utc::now().timestamp(),
                                ports: updated_device.ports.clone(),
                                discovery_method: "IcmpPing".to_string(),
                            };
                            let _ = app_arc.emit("device_found", event);
                        }
                    }

                    let duration = start_time.elapsed().as_millis() as u64;
                    let device_count = state_clone.get_devices().await.len() as u32;

                    let status = if state_clone.is_running() { "completed" } else { "cancelled" };

                    let complete_event = ScanCompleteEvent {
                        scan_id: scan_id_clone.clone(),
                        device_count,
                        duration_ms: duration,
                        status: status.to_string(),
                    };
                    let _ = app_arc.emit("scan_complete", complete_event);

                    emit_log(
                        &app_arc,
                        "info",
                        &format!("Scan {} in {}ms. Found {} devices", status, duration, device_count),
                        None,
                    ).await;

                    state_clone.set_running(false);
                    return;
                }
                Ok(_) => {
                    emit_log(
                        &app_arc,
                        "info",
                        "ICMP sweep found no hosts, falling back to TCP probing",
                        None,
                    ).await;
                }
                Err(ScanError::PermissionDenied(msg)) => {
                    emit_log(
                        &app_arc,
                        "warn",
                        &format!("ICMP unavailable (privileges): {}. Using TCP probing.", msg),
                        None,
                    ).await;
                }
                Err(e) => {
                    emit_log(
                        &app_arc,
                        "warn",
                        &format!("ICMP sweep failed: {}. Using TCP probing.", e),
                        None,
                    ).await;
                }
            }
        }

        // Fall back to TCP probing discovery (if enabled)
        if !use_tcp {
            // TCP probing disabled — complete scan with whatever we have
            let duration = start_time.elapsed().as_millis() as u64;
            let device_count = state_clone.get_devices().await.len() as u32;

            let complete_event = ScanCompleteEvent {
                scan_id: scan_id_clone.clone(),
                device_count,
                duration_ms: duration,
                status: "completed".to_string(),
            };
            let _ = app_arc.emit("scan_complete", complete_event);
            emit_log(
                &app_arc,
                "info",
                &format!("Scan completed in {}ms. Found {} devices", duration, device_count),
                None,
            ).await;
            state_clone.set_running(false);
            return;
        }

        let discovered = host_discovery::discover_hosts(
            ips,
            app_arc.clone(),
            cancel_rx,
            effective_max_concurrent,
            effective_retry_count,
        )
        .await;

        match discovered {
            Ok(devices) => {
                emit_log(
                    &app_arc,
                    "info",
                    &format!("Discovery found {} devices, processing ports", devices.len()),
                    None,
                ).await;

                // Add all discovered devices
                for device in &devices {
                    state_clone.add_device(device.clone()).await;
                }

                // Scan ports on discovered devices if requested
                let ports_to_scan = if scan_ports {
                    if ports.is_empty() {
                        host_discovery::DEFAULT_PORTS.to_vec()
                    } else {
                        ports.clone()
                    }
                } else {
                    Vec::new()
                };

                // Scan ports for each discovered device
                if scan_ports && !ports_to_scan.is_empty() {
                    for device in &devices {
                        // Check for cancellation between devices
                        if !state_clone.is_running() {
                            emit_log(&app_arc, "warn", "Scan cancelled during port scanning", None).await;
                            break;
                        }

                        emit_log(
                            &app_arc,
                            "info",
                            &format!("Scanning ports on {}", device.ip),
                            Some(&device.ip),
                        ).await;

                        let ip_addr: std::net::IpAddr = match device.ip.parse() {
                            Ok(ip) => ip,
                            Err(e) => {
                                emit_log(
                                    &app_arc,
                                    "error",
                                    &format!("Invalid IP: {} - {}", device.ip, e),
                                    None,
                                ).await;
                                continue;
                            }
                        };

                        let scanned_ports =
                            host_discovery::scan_ports(ip_addr, &ports_to_scan, timeout_ms).await;

                        // Update device with scanned ports
                        let mut updated_device = device.clone();
                        updated_device.ports = scanned_ports;

                        // Replace in state
                        state_clone.add_device(updated_device.clone()).await;

                        // Emit device found with ports
                        let event = DeviceFoundEvent {
                            ip: updated_device.ip.clone(),
                            mac: updated_device.mac.clone(),
                            hostname: updated_device.hostname.clone(),
                            vendor: updated_device.vendor.clone(),
                            timestamp: chrono::Utc::now().timestamp(),
                            ports: updated_device.ports.clone(),
                            discovery_method: "TcpProbe".to_string(),
                        };
                        let _ = app_arc.emit("device_found", event);
                    }
                }

                let duration = start_time.elapsed().as_millis() as u64;
                let device_count = state_clone.get_devices().await.len() as u32;

                let status = if state_clone.is_running() { "completed" } else { "cancelled" };

                // Emit scan complete
                let complete_event = ScanCompleteEvent {
                    scan_id: scan_id_clone.clone(),
                    device_count,
                    duration_ms: duration,
                    status: status.to_string(),
                };
                let _ = app_arc.emit("scan_complete", complete_event);

                emit_log(
                    &app_arc,
                    "info",
                    &format!("Scan {} in {}ms. Found {} devices", status, duration, device_count),
                    None,
                ).await;

                state_clone.set_running(false);
            }
            Err(e) => {
                emit_log(&app_arc, "error", &format!("Discovery failed: {}", e), None).await;

                let complete_event = ScanCompleteEvent {
                    scan_id: scan_id_clone,
                    device_count: state_clone.get_devices().await.len() as u32,
                    duration_ms: start_time.elapsed().as_millis() as u64,
                    status: "error".to_string(),
                };
                let _ = app_arc.emit("scan_complete", complete_event);
                state_clone.set_running(false);
            }
        }
    });

    Ok(ScanResponse {
        scan_id,
        status: "started".to_string(),
    })
}

/// Stop an ongoing scan
#[tauri::command]
pub async fn stop_scan(
    app: AppHandle,
    state: State<'_, Arc<SharedScanState>>,
) -> Result<(), ScanError> {
    emit_log(&app, "info", "Stop scan requested", None).await;

    if !state.is_running() {
        emit_log(&app, "warn", "No scan running to stop", None).await;
        return Err(ScanError::NotRunning);
    }

    state.set_cancelled().await;
    state.set_running(false);

    emit_log(&app, "info", "Scan stopped", None).await;
    Ok(())
}

/// Pause an ongoing scan
#[tauri::command]
pub async fn pause_scan(
    app: AppHandle,
    state: State<'_, Arc<SharedScanState>>,
) -> Result<(), ScanError> {
    emit_log(&app, "info", "Pause scan requested", None).await;

    if !state.is_running() {
        emit_log(&app, "warn", "No scan running to pause", None).await;
        return Err(ScanError::NotRunning);
    }

    state.set_paused(true);
    emit_log(&app, "info", "Scan paused", None).await;
    Ok(())
}

/// Resume a paused scan
#[tauri::command]
pub async fn resume_scan(
    app: AppHandle,
    state: State<'_, Arc<SharedScanState>>,
) -> Result<(), ScanError> {
    emit_log(&app, "info", "Resume scan requested", None).await;

    if !state.is_running() {
        emit_log(&app, "warn", "No scan running to resume", None).await;
        return Err(ScanError::NotRunning);
    }

    state.set_paused(false);
    emit_log(&app, "info", "Scan resumed", None).await;
    Ok(())
}

/// Get current scan results
#[tauri::command]
pub async fn get_scan_results(
    state: State<'_, Arc<SharedScanState>>,
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
    ips: &[std::net::IpAddr],
    timeout_ms: u64,
    max_concurrent: usize,
    app: Arc<tauri::AppHandle>,
) -> Result<Vec<crate::types::Device>, ScanError> {
    // Check privileges before attempting ICMP
    icmp::check_icmp_privileges()?;

    // Run ICMP ping sweep
    let devices = icmp::icmp_ping_sweep(
        ips.to_vec(),
        timeout_ms,
        max_concurrent,
        app,
    )
    .await?;

    Ok(devices)
}