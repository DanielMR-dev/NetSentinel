use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use futures::stream::{self, StreamExt};
use tokio::net::TcpStream;
use std::time::Duration;

use crate::error::ScanError;
use crate::events::AppEvent;
use crate::types::{Device, Port, PortState, ScanType};
use crate::network::timing::{TimingTemplate, TimingController};
use super::context::{PipelineContext, wait_if_paused};

/// Stage 3: Port Scan
/// Scans designated ports of live hosts using the configured scan type and timing settings.
pub async fn stage_port_scan(
    ctx: Arc<PipelineContext>,
    ports: Vec<u16>,
    scan_type: ScanType,
    timing_template: TimingTemplate,
    mut in_rx: mpsc::Receiver<Device>,
    out_tx: mpsc::Sender<Device>,
) -> Result<(), ScanError> {
    let mut join_set = JoinSet::new();
    let mut pause_rx = ctx.pause_rx.clone();
    let mut cancel_rx = ctx.cancel_rx.clone();

    // If ports are empty (equivalent to scan_ports_enabled = false), bypass
    if ports.is_empty() {
        let _ = ctx.event_tx.send(AppEvent::ScanLog {
            level: "info".to_string(),
            message: "Port scanning skipped (no ports selected or disabled)".to_string(),
            target: None,
            timestamp: chrono::Utc::now().timestamp(),
        });
        while let Some(device) = in_rx.recv().await {
            wait_if_paused(&mut pause_rx).await;
            if *cancel_rx.borrow() {
                return Err(ScanError::Cancelled);
            }
            if out_tx.send(device).await.is_err() {
                break;
            }
        }
        return Ok(());
    }

    let _ = ctx.event_tx.send(AppEvent::ScanLog {
        level: "info".to_string(),
        message: format!(
            "Starting port scan stage (type: {:?}, ports: {} targets)",
            scan_type,
            ports.len()
        ),
        target: None,
        timestamp: chrono::Utc::now().timestamp(),
    });

    // Check privileges for UDP scan mode (same as original code)
    let mut udp_uses_raw = true;
    if scan_type == ScanType::Udp {
        if let Ok(priv_status) = tokio::task::spawn_blocking(crate::network::privileges::check_system_privileges).await {
            if !priv_status.udp_scan_available {
                udp_uses_raw = false;
            }
        }
    }

    loop {
        tokio::select! {
            // Immediate cancellation check
            _ = cancel_rx.changed() => {
                if *cancel_rx.borrow() {
                    join_set.abort_all();
                    return Err(ScanError::Cancelled);
                }
            }

            // Process finished sub-tasks
            Some(res) = join_set.join_next(), if !join_set.is_empty() => {
                if let Ok(Ok(device)) = res {
                    if out_tx.send(device).await.is_err() {
                        break;
                    }
                }
            }

            // Read next device from Host Discovery Stage
            Some(mut device) = in_rx.recv() => {
                wait_if_paused(&mut pause_rx).await;

                if *cancel_rx.borrow() {
                    join_set.abort_all();
                    return Err(ScanError::Cancelled);
                }

                let ctx_c = ctx.clone();
                let ports_c = ports.clone();
                let scan_type_c = scan_type.clone();
                let timing_c = timing_template.clone();

                // Acquire raw socket permit if it's a raw scan type
                let is_raw = matches!(
                    scan_type_c,
                    ScanType::Syn | ScanType::Fin | ScanType::Xmas | ScanType::Null | ScanType::Udp | ScanType::Sctp
                );
                let use_raw_permit = is_raw && (scan_type_c != ScanType::Udp || udp_uses_raw);

                join_set.spawn(async move {
                    let _raw_permit = if use_raw_permit {
                        Some(ctx_c.raw_socket_semaphore.clone().acquire_owned().await)
                    } else {
                        None
                    };

                    let ip_addr = match device.ip.parse::<std::net::Ipv4Addr>() {
                        Ok(ip) => ip,
                        Err(_) => {
                            // If IPv6 or invalid, return device as-is
                            return Ok::<Device, ScanError>(device);
                        }
                    };

                    let timing_controller = TimingController::new(timing_c);

                    let (scanned_ports, detected_ttl) = match scan_type_c {
                        ScanType::Syn | ScanType::Fin | ScanType::Xmas | ScanType::Null => {
                            if let Ok(scanner) = crate::network::tcp_raw_scan::RawTcpScanner::new_for_target(
                                ip_addr,
                                scan_type_c,
                            ).await {
                                scanner.scan_ports(ip_addr, &ports_c, &timing_controller).await
                            } else {
                                (vec![], None)
                            }
                        }
                        ScanType::Udp => {
                            if udp_uses_raw {
                                if let Ok(scanner) = crate::network::udp_raw_scan::UdpRawScanner::new_for_target(
                                    ip_addr,
                                ).await {
                                    scanner.scan_ports(ip_addr, &ports_c, &timing_controller).await
                                } else {
                                    let udp_ports = crate::network::udp_scan::scan_udp_ports(
                                        IpAddr::V4(ip_addr),
                                        &ports_c,
                                        timing_controller.connection_timeout().as_millis() as u64,
                                    ).await;
                                    (udp_ports, None)
                                }
                            } else {
                                let udp_ports = crate::network::udp_scan::scan_udp_ports(
                                    IpAddr::V4(ip_addr),
                                    &ports_c,
                                    timing_controller.connection_timeout().as_millis() as u64,
                                ).await;
                                (udp_ports, None)
                            }
                        }
                        ScanType::Sctp => {
                            if let Ok(scanner) = crate::network::sctp_scan::SctpScanner::new_for_target(
                                ip_addr,
                            ).await {
                                scanner.scan_ports(ip_addr, &ports_c, &timing_controller).await
                            } else {
                                (vec![], None)
                            }
                        }
                        ScanType::Connect => {
                            let ip = IpAddr::V4(ip_addr);
                            let timeout_ms = timing_controller.connection_timeout().as_millis() as u64;
                            let connect_ports = scan_ports_bounded(ctx_c.clone(), ip, &ports_c, timeout_ms).await;
                            (connect_ports, None)
                        }
                    };

                    device.ports = scanned_ports;
                    if let Some(ttl) = detected_ttl {
                        device.os = Some(format!("TTL: {}", ttl));
                    }

                    Ok::<Device, ScanError>(device)
                });
            }

            else => {
                if join_set.is_empty() {
                    break;
                }
            }
        }
    }

    Ok(())
}

/// Helper: scan_single_port
async fn scan_single_port_internal(ip: IpAddr, port: u16, timeout_ms: u64) -> PortState {
    let addr = std::net::SocketAddr::new(ip, port);
    let timeout_duration = Duration::from_millis(timeout_ms);

    match tokio::time::timeout(timeout_duration, TcpStream::connect(addr)).await {
        Ok(Ok(_stream)) => PortState::Open,
        Ok(Err(_)) => PortState::Closed,
        Err(_) => PortState::Filtered,
    }
}

/// Helper: scan_ports_bounded
async fn scan_ports_bounded(
    ctx: Arc<PipelineContext>,
    ip: IpAddr,
    ports: &[u16],
    timeout_ms: u64,
) -> Vec<Port> {
    stream::iter(ports.to_vec())
        .map(|port| {
            let sem = ctx.port_semaphore.clone();
            async move {
                let _permit = sem.acquire().await.ok();
                let state = scan_single_port_internal(ip, port, timeout_ms).await;
                let service = crate::types::get_service_name(port);
                Port {
                    number: port,
                    protocol: "tcp".to_string(),
                    service,
                    state,
                }
            }
        })
        .buffer_unordered(100)
        .collect()
        .await
}
