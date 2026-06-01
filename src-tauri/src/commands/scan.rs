use std::sync::Arc;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Instant, Duration};

use tokio::sync::oneshot;
use tauri::{AppHandle, Emitter, State};
use tauri_plugin_notification::NotificationExt;
use tracing::warn;

use crate::error::ScanError;
use crate::network::{cidr, discovery, host_discovery, icmp, oui, sanitize};
use crate::network::timing::TimingTemplate;
use crate::state::SharedScanState;
use crate::types::{
    DeviceFoundEvent, ScanCompleteEvent, ScanLogEvent, ScanResponse,
    ScanResultsResponse, ScanStartedEvent, ScanType,
};

/// Send a system notification about scan status.
///
/// Failures are logged but never propagated — notifications are
/// best-effort and must not affect scan logic.
fn send_scan_notification(app: &AppHandle, title: &str, body: &str) {
    if let Err(e) = app
        .notification()
        .builder()
        .title(title)
        .body(body)
        .show()
    {
        warn!("Failed to send notification: {}", e);
    }
}

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
    scan_type: Option<ScanType>,
    timing_template: Option<TimingTemplate>,
) -> Result<ScanResponse, ScanError> {
    // ── Input Validation (IPC Hardening) ──────────────────────────────
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
                 Please use TCP Connect scan or run with elevated privileges.".to_string(),
            ));
        }
    }

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
            "Scan started (methods: {:?}, max_concurrent: {}, retries: {}, type: {:?}, timing: {:?})",
            methods, effective_max_concurrent, effective_retry_count, effective_scan_type, effective_timing
        ),
        None,
    )
    .await;

    // Spawn the scanning task
    let app_arc = Arc::new(app.clone());
    let state_clone = state.inner().clone();
    let scan_id_clone = scan_id.clone();
    let cidr_clone = cidr.clone();
    let timing_template_clone = effective_timing;
    let scan_type_clone = effective_scan_type.clone();

    tokio::spawn(async move {
        let start_time = Instant::now();

        // Parse IPs
        let ips = match cidr::parse_cidr(&cidr_clone) {
            Ok(ips) => ips,
            Err(e) => {
                emit_log(&app_arc, "error", &format!("Failed to parse CIDR: {}", e), None).await;
                let duration = start_time.elapsed().as_millis() as u64;
                let complete_event = ScanCompleteEvent {
                    scan_id: scan_id_clone.clone(),
                    device_count: 0,
                    duration_ms: duration,
                    status: "error".to_string(),
                };
                let _ = app_arc.emit("scan_complete", complete_event);
                send_scan_notification(
                    &app_arc,
                    "NetSentinel",
                    &format!("Scan failed: invalid CIDR ({})ms", duration),
                );
                state_clone.set_running(false);
                return;
            }
        };

        let total = ips.len() as u32;
        state_clone.set_total_hosts(total);

        emit_log(&app_arc, "info", &format!("Starting discovery on {} targets", total), None).await;

        let mut remaining_ips = ips.clone();

        // 1. ARP Discovery
        if use_arp {
            let priv_status = crate::network::privileges::check_system_privileges();
            let mut arp_devices = None;

            if priv_status.is_elevated {
                let ipv4_targets: Vec<Ipv4Addr> = ips.iter()
                    .filter_map(|ip| match ip {
                        IpAddr::V4(v4) => Some(*v4),
                        _ => None,
                    })
                    .collect();
                if let Some(target_ip) = ipv4_targets.first().copied() {
                    match crate::network::syn_scan::SynScanner::resolve_interface_and_ip(target_ip).await {
                        Some((interface, src_ip)) => {
                            emit_log(&app_arc, "info", &format!("Starting active ARP sweep on interface {}", interface.name), None).await;
                            let sweep_timeout = Duration::from_millis(timeout_ms);
                            match crate::network::discovery::arp_sweep::arp_sweep(
                                ipv4_targets,
                                interface,
                                src_ip,
                                sweep_timeout,
                                state_clone.clone(),
                            ).await {
                                Ok(devices) => {
                                    emit_log(&app_arc, "info", &format!("Active ARP sweep discovered {} devices", devices.len()), None).await;
                                    arp_devices = Some(devices);
                                }
                                Err(e) => {
                                    emit_log(&app_arc, "warn", &format!("Active ARP sweep failed: {}. Falling back to system ARP table.", e), None).await;
                                }
                            }
                        }
                        None => {
                            emit_log(&app_arc, "warn", "Could not resolve interface for active ARP sweep. Falling back to system ARP table.", None).await;
                        }
                    }
                }
            } else {
                emit_log(&app_arc, "info", "Active ARP sweep requires root privileges; falling back to system ARP table", None).await;
            }

            let is_active_sweep = arp_devices.is_some();
            // Fallback to system ARP table if active ARP sweep didn't run or returned empty/failed
            let devices = match arp_devices {
                Some(devs) => devs,
                None => {
                    emit_log(&app_arc, "info", "Attempting system ARP table discovery", None).await;
                    match discovery::arp_table::read_arp_table().await {
                        Ok(devs) => devs,
                        Err(e) => {
                            emit_log(&app_arc, "warn", &format!("Failed to read system ARP table: {}", e), None).await;
                            Vec::new()
                        }
                    }
                }
            };

            if !devices.is_empty() {
                let mut found_count = 0;
                let method_str = if is_active_sweep { "ArpSweep" } else { "ArpTable" };
                for device in &devices {
                    let device_ip = match device.ip.parse::<std::net::IpAddr>() {
                        Ok(ip) => ip,
                        Err(_) => continue,
                    };

                    if ips.contains(&device_ip) {
                        let mut enriched = device.clone();
                        if !enriched.mac.is_empty() {
                            if let Some(vendor) = oui::lookup_vendor(&enriched.mac) {
                                enriched.vendor = Some(vendor);
                            }
                        }
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
                            os: enriched.os.clone(),
                            timestamp: chrono::Utc::now().timestamp(),
                            ports: Vec::new(),
                            discovery_method: method_str.to_string(),
                            banner_results: enriched.banner_results.clone(),
                        };
                        let _ = app_arc.emit("device_found", event);
                        remaining_ips.retain(|&ip| ip != device_ip);
                        found_count += 1;
                    }
                }
                emit_log(
                    &app_arc,
                    "info",
                    &format!("Found {} devices via ARP matching CIDR target", found_count),
                    None,
                ).await;
            }
        }

        // 2. ICMP Discovery (on remaining target IPs)
        if use_icmp && !remaining_ips.is_empty() && state_clone.is_running() {
            emit_log(&app_arc, "info", &format!("Starting ICMP ping sweep on {} remaining targets", remaining_ips.len()), None).await;
            match try_icmp_discovery(&remaining_ips, timeout_ms, effective_max_concurrent, app_arc.clone()).await {
                Ok(devices) => {
                    emit_log(
                        &app_arc,
                        "info",
                        &format!("ICMP discovery found {} devices", devices.len()),
                        None,
                    ).await;

                    for device in &devices {
                        state_clone.add_device(device.clone()).await;
                        if let Ok(device_ip) = device.ip.parse::<std::net::IpAddr>() {
                            remaining_ips.retain(|&ip| ip != device_ip);
                        }
                    }
                }
                Err(e) => {
                    emit_log(
                        &app_arc,
                        "warn",
                        &format!("ICMP sweep failed or unavailable: {}", e),
                        None,
                    ).await;
                }
            }
        }

        // 3. TCP Probing (on remaining target IPs)
        if use_tcp && !remaining_ips.is_empty() && state_clone.is_running() {
            emit_log(&app_arc, "info", &format!("Starting TCP probing on {} remaining targets", remaining_ips.len()), None).await;
            let discovered = host_discovery::discover_hosts(
                remaining_ips.clone(),
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
                        &format!("TCP discovery found {} devices", devices.len()),
                        None,
                    ).await;

                    for device in &devices {
                        state_clone.add_device(device.clone()).await;
                    }
                }
                Err(e) => {
                    emit_log(&app_arc, "error", &format!("TCP discovery failed: {}", e), None).await;
                }
            }
        }

        // 4. Port Scanning Phase (on all discovered devices)
        let discovered_devices = state_clone.get_devices().await;
        let ports_to_scan = if scan_ports {
            if ports.is_empty() {
                host_discovery::DEFAULT_PORTS.to_vec()
            } else {
                ports.clone()
            }
        } else {
            Vec::new()
        };

        if scan_ports && !ports_to_scan.is_empty() && !discovered_devices.is_empty() && state_clone.is_running() {
            emit_log(
                &app_arc,
                "info",
                &format!("Starting port scan on {} discovered devices", discovered_devices.len()),
                None,
            ).await;

            for device in &discovered_devices {
                if !state_clone.is_running() {
                    emit_log(&app_arc, "warn", "Scan cancelled during port scanning", None).await;
                    break;
                }

                emit_log(
                    &app_arc,
                    "info",
                    &format!("Scanning ports on {} ({:?})", device.ip, scan_type_clone),
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

                let mut os_estimate = None;

                // Select the scanner based on scan_type_clone
                let scanned_ports = match scan_type_clone {
                    ScanType::Syn => {
                        if let IpAddr::V4(ipv4_addr) = ip_addr {
                            match crate::network::syn_scan::SynScanner::new_for_target(ipv4_addr).await {
                                Ok(scanner) => {
                                    let timing = crate::network::timing::TimingController::new(timing_template_clone);
                                    let (ports, ttl) = scanner.scan_ports(ipv4_addr, &ports_to_scan, &timing).await;
                                    if let Some(t) = ttl {
                                        os_estimate = crate::types::estimate_os_by_ttl(t);
                                    }
                                    ports
                                }
                                Err(e) => {
                                    emit_log(
                                        &app_arc,
                                        "warn",
                                        &format!("Failed to initialize SYN scanner for {}: {}. Falling back to TCP Connect scan.", device.ip, e),
                                        Some(&device.ip),
                                    ).await;
                                    host_discovery::scan_ports(ip_addr, &ports_to_scan, timeout_ms).await
                                }
                            }
                        } else {
                            emit_log(
                                &app_arc,
                                "warn",
                                &format!("SYN scan is not supported for IPv6 address {}. Falling back to TCP Connect scan.", device.ip),
                                Some(&device.ip),
                            ).await;
                            host_discovery::scan_ports(ip_addr, &ports_to_scan, timeout_ms).await
                        }
                    }
                    ScanType::Connect => {
                        host_discovery::scan_ports(ip_addr, &ports_to_scan, timeout_ms).await
                    }
                };

                let mut updated_device = device.clone();
                updated_device.ports = scanned_ports;
                if os_estimate.is_some() {
                    updated_device.os = os_estimate;
                }

                // Grab service banners for open ports
                let open_ports: Vec<u16> = updated_device.ports
                    .iter()
                    .filter(|p| p.state == crate::types::PortState::Open)
                    .map(|p| p.number)
                    .collect();

                if !open_ports.is_empty() && state_clone.is_running() {
                    emit_log(
                        &app_arc,
                        "info",
                        &format!("Grabbing service banners for {} open ports on {}", open_ports.len(), device.ip),
                        Some(&device.ip),
                    ).await;

                    let grabber = crate::network::banner::BannerGrabber::new(Duration::from_millis(timeout_ms));
                    let banner_results = grabber.grab_banners(&device.ip, &open_ports).await;
                    
                    // Match CVEs for grabbed banners
                    let mut matched_cves = Vec::new();
                    for banner in &banner_results {
                        let cves = crate::network::cve::lookup_cves(banner);
                        matched_cves.extend(cves);
                    }

                    updated_device.banner_results = banner_results;
                    
                    // Emit CVE alerts if found
                    if !matched_cves.is_empty() {
                        emit_log(
                            &app_arc,
                            "warn",
                            &format!("Found {} potential vulnerabilities (CVEs) on {}", matched_cves.len(), device.ip),
                            Some(&device.ip),
                        ).await;

                        for cve in matched_cves {
                            let _ = app_arc.emit("cve_alert", cve);
                        }
                    }
                }

                state_clone.add_device(updated_device.clone()).await;

                // Emit device found with updated ports and banners
                let event = DeviceFoundEvent {
                    ip: updated_device.ip.clone(),
                    mac: updated_device.mac.clone(),
                    hostname: updated_device.hostname.clone(),
                    vendor: updated_device.vendor.clone(),
                    os: updated_device.os.clone(),
                    timestamp: chrono::Utc::now().timestamp(),
                    ports: updated_device.ports.clone(),
                    discovery_method: if use_arp && ips.contains(&ip_addr) && !remaining_ips.contains(&ip_addr) {
                        let priv_status = crate::network::privileges::check_system_privileges();
                        if priv_status.is_elevated {
                            "ArpSweep".to_string()
                        } else {
                            "ArpTable".to_string()
                        }
                    } else if use_icmp {
                        "IcmpPing".to_string()
                    } else {
                        "TcpProbe".to_string()
                    },
                    banner_results: updated_device.banner_results.clone(),
                };
                let _ = app_arc.emit("device_found", event);
            }
        }

        // 5. Complete Scan and clean up
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
            &format!("Scan {} in {}ms. Found {} devices total", status, duration, device_count),
            None,
        ).await;

        if status == "cancelled" {
            send_scan_notification(&app_arc, "NetSentinel", "Scan cancelled");
        } else {
            send_scan_notification(
                &app_arc,
                "NetSentinel",
                &format!("Scan completed: {} devices found in {}ms", device_count, duration),
            );
        }

        state_clone.set_running(false);
    });

    Ok(ScanResponse {
        scan_id,
        status: "started".to_string(),
        scan_type: effective_scan_type,
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
    send_scan_notification(&app, "NetSentinel", "Scan cancelled");
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