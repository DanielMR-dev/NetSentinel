//! Scan control commands.
//!
//! Provides `start_scan`, `stop_scan`, `pause_scan`, `resume_scan`, and
//! `get_scan_results` as plain async functions. The `start_scan` function
//! accepts an `UnboundedSender<AppEvent>` channel for streaming results
//! to the Iced UI, replacing Tauri's `app_handle.emit(...)` pattern.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::stream::{self, StreamExt};
use tokio::sync::{mpsc, oneshot};
use tracing::warn;

use crate::error::ScanError;
use crate::events::AppEvent;
use crate::network::timing::TimingTemplate;
use crate::network::{cidr, host_discovery, icmp, sanitize};
use crate::scan_store::{NewScanSession, ScanSessionStatus, ScanStore, StoredScanConfig};
use crate::state::SharedScanState;
use crate::types::{Device, Finding, PortState, ScanResponse, ScanResultsResponse, ScanType};

const MAX_CONCURRENT_BANNER_GRABS: usize = 16;
const MAX_CONCURRENT_CVE_LOOKUPS: usize = 8;

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
    web_audit_profile: Option<crate::network::web_audit::WebAuditProfile>,
    run_active_checks: Option<bool>,
) -> Result<ScanResponse, ScanError> {
    // --- Input Validation ---
    let _validated_cidr = sanitize::validate_cidr(&cidr)?;
    let _validated_timeout = sanitize::validate_timeout_ms(timeout_ms)?;

    if scan_ports && !ports.is_empty() {
        sanitize::validate_ports(&ports)?;
    }

    let mut effective_scan_type = scan_type.unwrap_or_default();
    let effective_timing = timing_template.unwrap_or_default();

    // Helper closure to send log events
    let send_log = |level: &str, message: &str, target: Option<&str>| {
        let _ = event_tx.send(AppEvent::ScanLog {
            level: level.to_string(),
            message: message.to_string(),
            target: target.map(|s| s.to_string()),
            timestamp: chrono::Utc::now().timestamp(),
        });
    };

    // Verify privileges for raw scan types before starting.
    let requires_raw_socket = matches!(
        effective_scan_type,
        ScanType::Syn
            | ScanType::Fin
            | ScanType::Xmas
            | ScanType::Null
            | ScanType::Udp
            | ScanType::Sctp
    );

    // Cache the UDP scan mode once so we do not re-check privileges per host.
    let mut udp_uses_raw = true;

    if requires_raw_socket {
        let priv_status =
            tokio::task::spawn_blocking(crate::network::privileges::check_system_privileges)
                .await
                .map_err(|e| ScanError::Internal(format!("Privilege check task failed: {}", e)))?;

        match effective_scan_type {
            ScanType::Syn | ScanType::Fin | ScanType::Xmas | ScanType::Null => {
                if !priv_status.syn_scan_available && !priv_status.fin_xmas_null_available {
                    send_log(
                        "warn",
                        &format!(
                            "Insufficient privileges for {} scan (requires root/Administrator/CAP_NET_RAW). Downgrading to TCP Connect scan.",
                            effective_scan_type
                        ),
                        None,
                    );
                    effective_scan_type = ScanType::Connect;
                }
            }
            ScanType::Udp => {
                if !priv_status.udp_scan_available {
                    udp_uses_raw = false;
                    send_log(
                        "warn",
                        "Insufficient privileges for raw UDP scan (requires root/Administrator/CAP_NET_RAW). Falling back to UDP connect/basic scan for all hosts.",
                        None,
                    );
                }
            }
            ScanType::Sctp => {
                if !priv_status.sctp_scan_available {
                    send_log(
                        "error",
                        "SCTP INIT scan requires root/Administrator/CAP_NET_RAW privileges.",
                        None,
                    );
                    return Err(ScanError::ElevatedPrivilegesRequired(
                        "SCTP INIT scan requires elevated privileges".to_string(),
                    ));
                }
            }
            ScanType::Connect => {}
        }
    }

    send_log("info", &format!("Validating CIDR: {}", cidr), None);

    // Validate CIDR
    let network = cidr::validate_cidr(&cidr)?;
    let total_hosts = network.iter().count() as u32;

    send_log(
        "info",
        &format!("Scan target contains {} hosts", total_hosts),
        None,
    );

    // Reserve scan ownership before any await that could let another caller start.
    if !state.try_start_running() {
        send_log("error", "Scan already in progress", None);
        return Err(ScanError::AlreadyRunning);
    }
    state.reset_for_new_scan().await;
    state.set_total_hosts(total_hosts);

    // Resolve settings parameters
    let effective_max_concurrent = max_concurrent_hosts.unwrap_or(50) as usize;
    let methods =
        discovery_methods.unwrap_or_else(|| vec!["arp".into(), "tcp_probe".into(), "icmp".into()]);
    let _use_arp = methods.iter().any(|m| m == "arp");
    let _use_tcp = methods.iter().any(|m| m == "tcp_probe");
    let _use_icmp = methods.iter().any(|m| m == "icmp");
    let effective_retry_count = retry_count.unwrap_or(0);
    let scan_id = uuid::Uuid::new_v4().to_string();
    state.set_current_scan_id(Some(scan_id.clone())).await;

    // Install cancellation before scan-store setup so an early Stop is honored.
    let (cancel_tx, cancel_rx) = oneshot::channel();
    state.set_cancel_tx(cancel_tx).await;

    let config_dir = match crate::commands::settings::get_config_dir() {
        Ok(config_dir) => config_dir,
        Err(e) => {
            state.set_running(false);
            state.set_current_scan_id(None).await;
            return Err(e);
        }
    };
    let scan_store = ScanStore::new(config_dir);
    if let Err(e) = scan_store.initialize().await {
        state.set_running(false);
        state.set_current_scan_id(None).await;
        return Err(e);
    }
    if state.is_cancel_requested() || !state.is_running() {
        state.set_running(false);
        state.set_current_scan_id(None).await;
        return Err(ScanError::Cancelled);
    }
    if let Err(e) = scan_store
        .begin_session(NewScanSession {
            id: scan_id.clone(),
            cidr: cidr.clone(),
            total_hosts,
            started_at: chrono::Utc::now().timestamp(),
            config: StoredScanConfig {
                timeout_ms,
                scan_ports,
                ports: ports.clone(),
                max_concurrent_hosts,
                discovery_methods: Some(methods.clone()),
                retry_count,
                scan_type: scan_type_label(&effective_scan_type).to_string(),
                timing_template: Some(format!("{:?}", effective_timing)),
                web_audit_enabled: web_audit_profile.is_some(),
                active_checks_enabled: run_active_checks.unwrap_or(false),
            },
        })
        .await
    {
        state.set_running(false);
        state.set_current_scan_id(None).await;
        return Err(e);
    }
    if state.is_cancel_requested() || !state.is_running() {
        let _ = scan_store
            .complete_session(
                scan_id.clone(),
                ScanSessionStatus::Cancelled,
                Some(0),
                Some("Scan cancelled before execution".to_string()),
            )
            .await;
        state.set_running(false);
        state.set_current_scan_id(None).await;
        return Err(ScanError::Cancelled);
    }

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
    let scan_store_clone = scan_store.clone();
    let _cidr_clone = cidr.clone();
    let scan_type_for_thread = effective_scan_type.clone();

    tokio::spawn(async move {
        let start_time = Instant::now();

        // Parse IPs from CIDR
        let ips: Vec<IpAddr> = network.iter().map(|ip| IpAddr::from(ip)).collect();

        // Run IPv4 host discovery
        let mut discovery_result = host_discovery::discover_hosts(
            ips,
            event_tx_clone.clone(),
            cancel_rx,
            effective_max_concurrent,
            effective_retry_count as u32,
            Some(state_clone.scanned_count.clone()),
        )
        .await;

        // Extend with NetBIOS if requested (and if we have IPv4 targets)
        if _use_arp {
            let ipv4 = network.ip();
            let bcast =
                std::net::Ipv4Addr::new(ipv4.octets()[0], ipv4.octets()[1], ipv4.octets()[2], 255);
            if let Ok(nbns_devs) = crate::network::mdns_netbios::discover_netbios(bcast).await {
                if let Ok(ref mut devs) = discovery_result {
                    for d in nbns_devs {
                        if !devs.iter().any(|existing| existing.ip == d.ip) {
                            devs.push(d);
                        }
                    }
                }
            }

            // Extend with mDNS
            if let Ok(mdns_devs) = crate::network::mdns_netbios::discover_mdns().await {
                if let Ok(ref mut devs) = discovery_result {
                    for d in mdns_devs {
                        if !devs.iter().any(|existing| existing.ip == d.ip) {
                            devs.push(d);
                        }
                    }
                }
            }

            // Extend with IPv6
            if let Ok(ipv6_devs) =
                crate::network::ipv6_discovery::discover_ipv6_hosts(event_tx_clone.clone()).await
            {
                if let Ok(ref mut devs) = discovery_result {
                    for d in ipv6_devs {
                        if !devs.iter().any(|existing| existing.ip == d.ip) {
                            devs.push(d);
                        }
                    }
                }
            }
        }

        let duration_ms = start_time.elapsed().as_millis() as u64;

        match discovery_result {
            Ok(mut devices) => {
                for device in &devices {
                    if let Err(e) = scan_store_clone
                        .upsert_device(scan_id_clone.clone(), device.clone())
                        .await
                    {
                        send_persistence_warning(
                            &event_tx_clone,
                            &format!("Failed to persist discovered device {}: {}", device.ip, e),
                        );
                    }
                }

                if let Err(e) = scan_store_clone
                    .update_progress(scan_id_clone.clone(), devices.len() as u32, total_hosts)
                    .await
                {
                    send_persistence_warning(
                        &event_tx_clone,
                        &format!("Failed to persist scan progress: {}", e),
                    );
                }

                // Perform Port Scanning if requested
                if scan_ports && !ports.is_empty() && !devices.is_empty() {
                    let timing_controller =
                        crate::network::timing::TimingController::new(effective_timing.clone());

                    for device in devices.iter_mut() {
                        if !state_clone.is_running() {
                            break;
                        }

                        let ip_addr = match device.ip.parse::<std::net::Ipv4Addr>() {
                            Ok(ip) => ip,
                            Err(_) => continue, // Ignore IPv6 for raw scans currently
                        };

                        let (mut scanned_ports, detected_ttl) = match scan_type_for_thread {
                            ScanType::Syn | ScanType::Fin | ScanType::Xmas | ScanType::Null => {
                                if let Ok(scanner) =
                                    crate::network::tcp_raw_scan::RawTcpScanner::new_for_target(
                                        ip_addr,
                                        scan_type_for_thread.clone(),
                                    )
                                    .await
                                {
                                    scanner
                                        .scan_ports(ip_addr, &ports, &timing_controller)
                                        .await
                                } else {
                                    (vec![], None)
                                }
                            }
                            ScanType::Udp => {
                                if udp_uses_raw {
                                    if let Ok(scanner) =
                                        crate::network::udp_raw_scan::UdpRawScanner::new_for_target(
                                            ip_addr,
                                        )
                                        .await
                                    {
                                        scanner
                                            .scan_ports(ip_addr, &ports, &timing_controller)
                                            .await
                                    } else {
                                        let udp_ports = crate::network::udp_scan::scan_udp_ports(
                                            std::net::IpAddr::V4(ip_addr),
                                            &ports,
                                            timing_controller.connection_timeout().as_millis()
                                                as u64,
                                        )
                                        .await;
                                        (udp_ports, None)
                                    }
                                } else {
                                    let udp_ports = crate::network::udp_scan::scan_udp_ports(
                                        std::net::IpAddr::V4(ip_addr),
                                        &ports,
                                        timing_controller.connection_timeout().as_millis() as u64,
                                    )
                                    .await;
                                    (udp_ports, None)
                                }
                            }
                            ScanType::Sctp => {
                                if let Ok(scanner) =
                                    crate::network::sctp_scan::SctpScanner::new_for_target(ip_addr)
                                        .await
                                {
                                    scanner
                                        .scan_ports(ip_addr, &ports, &timing_controller)
                                        .await
                                } else {
                                    (vec![], None)
                                }
                            }
                            ScanType::Connect => {
                                let ip: std::net::IpAddr = ip_addr.into();
                                let timeout_ms =
                                    timing_controller.connection_timeout().as_millis() as u64;
                                let connect_ports = crate::network::host_discovery::scan_ports(
                                    ip, &ports, timeout_ms,
                                )
                                .await;
                                (connect_ports, None)
                            }
                        };

                        // Perform service detection on Open ports
                        let detector = crate::network::service_detection::ServiceDetector::new(
                            std::time::Duration::from_millis(
                                timing_controller.connection_timeout().as_millis() as u64 * 2,
                            ),
                        );

                        for port in scanned_ports.iter_mut() {
                            if port.state == crate::types::PortState::Open && port.protocol == "tcp"
                            {
                                if let Ok(info) = detector.detect_tcp(&device.ip, port.number).await
                                {
                                    if let Some(srv) = info.service {
                                        port.service = Some(srv);
                                    }
                                }
                            }
                        }

                        device.ports = scanned_ports.clone();
                        if let Some(ttl) = detected_ttl {
                            device.os = Some(format!("TTL: {}", ttl));
                        }

                        if !state_clone.is_running() {
                            break;
                        }

                        let open_banner_ports: Vec<u16> = scanned_ports
                            .iter()
                            .filter(|port| {
                                port.state == PortState::Open
                                    && port.protocol == "tcp"
                                    && crate::network::banner::BANNER_PORTS.contains(&port.number)
                            })
                            .map(|port| port.number)
                            .collect();

                        if !open_banner_ports.is_empty() {
                            let grabber = Arc::new(crate::network::banner::BannerGrabber::new(
                                Duration::from_millis(
                                    timing_controller.connection_timeout().as_millis() as u64,
                                ),
                            ));
                            let device_ip = device.ip.clone();
                            let banners: Vec<_> = stream::iter(open_banner_ports)
                                .map(|port| {
                                    let grabber = Arc::clone(&grabber);
                                    let ip = device_ip.clone();
                                    async move { grabber.grab_banner(&ip, port).await.ok() }
                                })
                                .buffer_unordered(MAX_CONCURRENT_BANNER_GRABS)
                                .filter_map(|result| async move { result })
                                .collect()
                                .await;

                            for banner in &banners {
                                let _ = event_tx_clone.send(AppEvent::BannerFound(banner.clone()));
                            }

                            device.banner_results = banners.clone();

                            if state_clone.is_running() {
                                let cve_results: Vec<Vec<_>> = stream::iter(banners)
                                    .map(|banner| async move {
                                        match crate::network::cve::lookup_cves_async(banner).await {
                                            Ok(matches) => matches,
                                            Err(e) => {
                                                tracing::warn!("CVE lookup failed: {}", e);
                                                Vec::new()
                                            }
                                        }
                                    })
                                    .buffer_unordered(MAX_CONCURRENT_CVE_LOOKUPS)
                                    .collect()
                                    .await;

                                for cve in cve_results.into_iter().flatten() {
                                    let finding = Finding::from_cve(&cve);
                                    let _ = event_tx_clone.send(AppEvent::CveAlert(cve));
                                    if push_unique_finding(&mut device.findings, finding.clone()) {
                                        let _ =
                                            event_tx_clone.send(AppEvent::FindingFound(finding));
                                    }
                                }
                            }
                        }

                        if !state_clone.is_running() {
                            break;
                        }

                        // Run Web Audits
                        if let Some(profile) = web_audit_profile {
                            let mut audits = Vec::new();
                            for port in &scanned_ports {
                                if !state_clone.is_running() {
                                    break;
                                }
                                if port.state == crate::types::PortState::Open
                                    && (port.number == 80
                                        || port.number == 443
                                        || port.number == 8080
                                        || port.number == 8443)
                                {
                                    let is_https = port.number == 443 || port.number == 8443;
                                    if let Ok(res) = crate::network::web_audit::audit_web_service(
                                        &device.ip,
                                        port.number,
                                        is_https,
                                        profile,
                                    )
                                    .await
                                    {
                                        audits.push(res);
                                    }
                                }
                            }
                            device.web_audits = audits;
                            let web_findings: Vec<Finding> = device
                                .web_audits
                                .iter()
                                .flat_map(Finding::from_web_audit)
                                .collect();
                            for finding in web_findings {
                                if push_unique_finding(&mut device.findings, finding.clone()) {
                                    let _ = event_tx_clone.send(AppEvent::FindingFound(finding));
                                }
                            }
                        }

                        // Run Active Checks
                        if run_active_checks.unwrap_or(false) {
                            if !state_clone.is_running() {
                                break;
                            }
                            let open_ports: Vec<u16> = scanned_ports
                                .iter()
                                .filter(|p| p.state == crate::types::PortState::Open)
                                .map(|p| p.number)
                                .collect();
                            device.active_checks =
                                crate::network::active_checks::run_active_checks(
                                    &device.ip,
                                    &open_ports,
                                )
                                .await;
                            let active_findings: Vec<Finding> = device
                                .active_checks
                                .iter()
                                .filter_map(|check| Finding::from_active_check(&device.ip, check))
                                .collect();
                            for finding in active_findings {
                                if push_unique_finding(&mut device.findings, finding.clone()) {
                                    let _ = event_tx_clone.send(AppEvent::FindingFound(finding));
                                }
                            }
                        }
                    }
                }

                let device_count = devices.len() as u32;

                // Store devices in shared state
                for device in &devices {
                    state_clone.add_device(device.clone()).await;
                    if let Err(e) = scan_store_clone
                        .upsert_device(scan_id_clone.clone(), device.clone())
                        .await
                    {
                        send_persistence_warning(
                            &event_tx_clone,
                            &format!("Failed to persist final device {}: {}", device.ip, e),
                        );
                    } else {
                        state_clone.set_persisted_device_count(device_count);
                    }
                }

                let final_scanned_count = if state_clone.is_cancel_requested() {
                    state_clone.get_scanned_count().min(total_hosts)
                } else {
                    total_hosts
                };
                if let Err(e) = scan_store_clone
                    .update_progress(scan_id_clone.clone(), final_scanned_count, total_hosts)
                    .await
                {
                    send_persistence_warning(
                        &event_tx_clone,
                        &format!("Failed to persist final scan progress: {}", e),
                    );
                }

                let final_status = if state_clone.is_cancel_requested() || !state_clone.is_running()
                {
                    ScanSessionStatus::Cancelled
                } else {
                    ScanSessionStatus::Completed
                };
                if let Err(e) = scan_store_clone
                    .complete_session(scan_id_clone.clone(), final_status, Some(duration_ms), None)
                    .await
                {
                    send_persistence_warning(
                        &event_tx_clone,
                        &format!("Failed to complete persisted scan session: {}", e),
                    );
                }

                let _ = event_tx_clone.send(AppEvent::ScanComplete {
                    scan_id: scan_id_clone,
                    device_count,
                    duration_ms,
                    status: final_status.as_str().to_string(),
                    devices,
                });
            }
            Err(e) => {
                warn!("Scan failed: {}", e);
                let persisted_status = if matches!(e, ScanError::Cancelled)
                    || state_clone.is_cancel_requested()
                    || !state_clone.is_running()
                {
                    ScanSessionStatus::Cancelled
                } else {
                    ScanSessionStatus::Error
                };
                if let Err(persist_error) = scan_store_clone
                    .complete_session(
                        scan_id_clone.clone(),
                        persisted_status,
                        Some(duration_ms),
                        Some(e.to_string()),
                    )
                    .await
                {
                    send_persistence_warning(
                        &event_tx_clone,
                        &format!(
                            "Failed to complete persisted scan session: {}",
                            persist_error
                        ),
                    );
                }
                let _ = event_tx_clone.send(AppEvent::ScanComplete {
                    scan_id: scan_id_clone,
                    device_count: 0,
                    duration_ms,
                    status: format!("error: {}", e),
                    devices: Vec::new(),
                });
            }
        }

        state_clone.set_running(false);
        state_clone.set_current_scan_id(None).await;
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

#[allow(dead_code)]
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
    let devices = icmp::icmp_ping_sweep(ips.to_vec(), timeout_ms, max_concurrent, event_tx).await?;

    Ok(devices)
}

fn push_unique_finding(findings: &mut Vec<Finding>, finding: Finding) -> bool {
    if findings.iter().any(|existing| existing.id == finding.id) {
        return false;
    }

    findings.push(finding);
    true
}

fn scan_type_label(scan_type: &ScanType) -> &'static str {
    match scan_type {
        ScanType::Connect => "connect",
        ScanType::Syn => "syn",
        ScanType::Fin => "fin",
        ScanType::Xmas => "xmas",
        ScanType::Null => "null",
        ScanType::Udp => "udp",
        ScanType::Sctp => "sctp",
    }
}

fn send_persistence_warning(event_tx: &mpsc::UnboundedSender<AppEvent>, message: &str) {
    let _ = event_tx.send(AppEvent::ScanLog {
        level: "warn".to_string(),
        message: message.to_string(),
        target: None,
        timestamp: chrono::Utc::now().timestamp(),
    });
}
