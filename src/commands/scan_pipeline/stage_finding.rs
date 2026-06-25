use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use futures::stream::{self, StreamExt};

use crate::error::ScanError;
use crate::events::AppEvent;
use crate::types::{Device, Finding};
use super::context::{PipelineContext, wait_if_paused};

const MAX_CONCURRENT_CVE_LOOKUPS: usize = 8;

/// Stage 5: Finding Generation
/// Correlates service banners, web audits, and active checks against vulnerability databases.
/// Generates CVE alerts and Finding structures, and updates the device.
pub async fn stage_finding_gen(
    ctx: Arc<PipelineContext>,
    mut in_rx: mpsc::Receiver<Device>,
    out_tx: mpsc::Sender<(Device, Vec<Finding>)>,
) -> Result<(), ScanError> {
    let mut join_set = JoinSet::new();
    let mut pause_rx = ctx.pause_rx.clone();
    let mut cancel_rx = ctx.cancel_rx.clone();

    let _ = ctx.event_tx.send(AppEvent::ScanLog {
        level: "info".to_string(),
        message: "Starting finding generation stage".to_string(),
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
                if let Ok(Ok((device, findings))) = res {
                    if out_tx.send((device, findings)).await.is_err() {
                        break;
                    }
                }
            }

            // Read next device from Enrichment Stage
            Some(mut device) = in_rx.recv() => {
                wait_if_paused(&mut pause_rx).await;

                if *cancel_rx.borrow() {
                    join_set.abort_all();
                    return Err(ScanError::Cancelled);
                }

                let ctx_c = ctx.clone();

                join_set.spawn(async move {
                    let mut new_findings = Vec::new();

                    // 1. CVE Lookup on grabbed banners
                    if !device.banner_results.is_empty() {
                        let cve_results: Vec<Vec<_>> = stream::iter(device.banner_results.clone())
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
                            let _ = ctx_c.event_tx.send(AppEvent::CveAlert(cve));
                            if push_unique_finding(&mut device.findings, finding.clone()) {
                                let _ = ctx_c.event_tx.send(AppEvent::FindingFound(finding.clone()));
                                new_findings.push(finding);
                            }
                        }
                    }

                    // 2. Web Audit Findings
                    let web_findings: Vec<Finding> = device.web_audits
                        .iter()
                        .flat_map(Finding::from_web_audit)
                        .collect();
                    for finding in web_findings {
                        if push_unique_finding(&mut device.findings, finding.clone()) {
                            let _ = ctx_c.event_tx.send(AppEvent::FindingFound(finding.clone()));
                            new_findings.push(finding);
                        }
                    }

                    // 3. Active Check Findings
                    let active_findings: Vec<Finding> = device.active_checks
                        .iter()
                        .filter_map(|check| Finding::from_active_check(&device.ip, check))
                        .collect();
                    for finding in active_findings {
                        if push_unique_finding(&mut device.findings, finding.clone()) {
                            let _ = ctx_c.event_tx.send(AppEvent::FindingFound(finding.clone()));
                            new_findings.push(finding);
                        }
                    }

                    Ok::<(Device, Vec<Finding>), ScanError>((device, new_findings))
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

fn push_unique_finding(findings: &mut Vec<Finding>, finding: Finding) -> bool {
    if findings.iter().any(|existing| existing.id == finding.id) {
        return false;
    }
    findings.push(finding);
    true
}
