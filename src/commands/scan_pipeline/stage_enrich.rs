use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::task::JoinSet;

use super::context::{wait_if_paused, PipelineContext};
use crate::error::ScanError;
use crate::events::AppEvent;
use crate::network::active_checks::run_active_checks;
use crate::network::banner::{BannerGrabber, BANNER_PORTS};
use crate::network::service_detection::ServiceDetector;
use crate::network::tls::{analyze_tls, is_tls_port};
use crate::network::web_audit::{audit_web_service, WebAuditProfile};
use crate::types::{Device, PortState};

/// Stage 4: Enrichment
/// Runs service detection on open ports, grabs banners, performs TLS cert audits,
/// and executes Web Audits and Active Checks if configured. Governed by the enrichment semaphore.
pub async fn stage_enrichment(
    ctx: Arc<PipelineContext>,
    web_audit_profile: Option<WebAuditProfile>,
    enable_active_checks: bool,
    mut in_rx: mpsc::Receiver<Device>,
    out_tx: mpsc::Sender<Device>,
) -> Result<(), ScanError> {
    let mut join_set = JoinSet::new();
    let mut pause_rx = ctx.pause_rx.clone();
    let mut cancel_rx = ctx.cancel_rx.clone();

    let _ = ctx.event_tx.send(AppEvent::ScanLog {
        level: "info".to_string(),
        message: "Starting service enrichment stage".to_string(),
        target: None,
        timestamp: chrono::Utc::now().timestamp(),
    });

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

            // Read next device from Port Scan Stage
            Some(mut device) = in_rx.recv() => {
                wait_if_paused(&mut pause_rx).await;

                if *cancel_rx.borrow() {
                    join_set.abort_all();
                    return Err(ScanError::Cancelled);
                }

                let ctx_c = ctx.clone();
                let web_profile = web_audit_profile.clone();
                let run_active = enable_active_checks;

                join_set.spawn(async move {
                    let open_ports: Vec<u16> = device.ports
                        .iter()
                        .filter(|p| p.state == PortState::Open)
                        .map(|p| p.number)
                        .collect();

                    if open_ports.is_empty() {
                        return Ok::<Device, ScanError>(device);
                    }

                    // 1. Service Detection (Nmap Probe) on open ports
                    let timeout = Duration::from_millis(1000);
                    let detector = ServiceDetector::new(timeout * 2);

                    for port in device.ports.iter_mut() {
                        if port.state == PortState::Open && port.protocol == "tcp" {
                            if let Ok(info) = detector.detect_tcp(&device.ip, port.number).await {
                                if let Some(srv) = info.service {
                                    port.service = Some(srv);
                                }
                            }
                        }
                    }

                    // 2. Banner Grabbing & TLS Analysis
                    let open_banner_ports: Vec<u16> = device.ports
                        .iter()
                        .filter(|p| p.state == PortState::Open && p.protocol == "tcp" && BANNER_PORTS.contains(&p.number))
                        .map(|p| p.number)
                        .collect();

                    if !open_banner_ports.is_empty() {
                        let grabber = Arc::new(BannerGrabber::new(timeout));
                        let mut banners = Vec::new();

                        for port in open_banner_ports {
                            // Acquire enrichment semaphore permit
                            let permit = ctx_c.enrichment_semaphore.clone().acquire_owned().await;
                            let grabber_c = grabber.clone();
                            let ip = device.ip.clone();

                            // Run banner grab + optional TLS analysis in a blocking-safe manner
                            let banner_res = tokio::spawn(async move {
                                let _permit = permit; // hold permit during network I/O
                                let mut b_res = grabber_c.grab_banner(&ip, port).await.ok();
                                if let Some(ref mut b) = b_res {
                                    if is_tls_port(port) {
                                        if let Ok(tls) = analyze_tls(&ip, port, timeout).await {
                                            b.tls_info = Some(tls);
                                        }
                                    }
                                }
                                b_res
                            }).await.ok().flatten();

                            if let Some(b) = banner_res {
                                let _ = ctx_c.event_tx.send(AppEvent::BannerFound(b.clone()));
                                banners.push(b);
                            }
                        }
                        device.banner_results = banners;
                    }

                    // 3. Web Auditing
                    if let Some(profile) = web_profile {
                        let mut web_audits = Vec::new();
                        for port in &device.ports {
                            if port.state == PortState::Open && (port.number == 80 || port.number == 443 || port.number == 8080 || port.number == 8443) {
                                let is_https = port.number == 443 || port.number == 8443;
                                let permit = ctx_c.enrichment_semaphore.clone().acquire_owned().await;
                                let ip = device.ip.clone();
                                let port_num = port.number;

                                let audit_res = tokio::spawn(async move {
                                    let _permit = permit;
                                    audit_web_service(&ip, port_num, is_https, profile).await.ok()
                                }).await.ok().flatten();

                                if let Some(audit) = audit_res {
                                    web_audits.push(audit);
                                }
                            }
                        }
                        device.web_audits = web_audits;
                    }

                    // 4. Active Checks
                    if run_active {
                        let open_ports: Vec<u16> = device.ports
                            .iter()
                            .filter(|p| p.state == PortState::Open)
                            .map(|p| p.number)
                            .collect();
                        let active_res = run_active_checks(&device.ip, &open_ports).await;
                        device.active_checks = active_res;
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
