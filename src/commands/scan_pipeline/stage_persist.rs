use std::sync::Arc;
use tokio::sync::mpsc;

use super::context::{emit_stage_lifecycle, wait_if_paused, PipelineContext};
use crate::error::ScanError;
use crate::events::AppEvent;
use crate::scan_store::ScanSessionStatus;
use crate::types::{Device, Finding};

/// Stage 6: Persistence & UI Events
/// Saves finalized device results and security findings to the database (ScanStore),
/// updates the shared in-memory scan state, and dispatches the final complete event to the UI.
pub async fn stage_persistence_ui(
    ctx: Arc<PipelineContext>,
    total_hosts: u32,
    mut in_rx: mpsc::Receiver<(Device, Vec<Finding>)>,
) -> Result<(), ScanError> {
    let mut pause_rx = ctx.pause_rx.clone();
    let mut cancel_rx = ctx.cancel_rx.clone();
    let start_time = std::time::Instant::now();

    let _ = ctx.event_tx.send(AppEvent::ScanLog {
        level: "info".to_string(),
        message: "Starting persistence and UI dispatch stage".to_string(),
        target: None,
        timestamp: chrono::Utc::now().timestamp(),
    });
    emit_stage_lifecycle(ctx.as_ref(), "persist", "started");

    loop {
        tokio::select! {
            // Immediate cancellation check
            _ = cancel_rx.changed() => {
                if *cancel_rx.borrow() {
                    break;
                }
            }

            // Receive processed device and findings
            item = in_rx.recv() => {
                match item {
                    Some((device, findings)) => {
                        wait_if_paused(&mut pause_rx).await;

                        if *cancel_rx.borrow() {
                            break;
                        }

                        // 1. Add/Update device in shared scan state
                        ctx.state.add_device(device.clone()).await;

                        // 2. Upsert device metadata in scan store
                        if let Err(e) = ctx.scan_store.upsert_device(ctx.scan_id.clone(), device.clone()).await {
                            send_persistence_warning(&ctx.event_tx, &format!("Failed to persist device {}: {}", device.ip, e));
                        }

                        // 3. Upsert each port through the standalone API
                        for port in &device.ports {
                            if let Err(e) = ctx.scan_store.upsert_port(ctx.scan_id.clone(), device.ip.clone(), port.clone()).await {
                                send_persistence_warning(&ctx.event_tx, &format!("Failed to persist port {}/{} for {}: {}", port.number, port.protocol, device.ip, e));
                            }
                        }

                        // 4. Insert each finding through the standalone API
                        for finding in findings {
                            if let Err(e) = ctx.scan_store.insert_finding(ctx.scan_id.clone(), finding.clone()).await {
                                send_persistence_warning(&ctx.event_tx, &format!("Failed to persist finding {}: {}", finding.id, e));
                            }
                        }

                        // 5. Update scan progress in SQLite
                        let current_scanned = ctx.state.get_scanned_count();
                        if let Err(e) = ctx.scan_store.update_progress(ctx.scan_id.clone(), current_scanned, total_hosts).await {
                            send_persistence_warning(&ctx.event_tx, &format!("Failed to persist scan progress: {}", e));
                        }

                        // 6. Emit DeviceFound event to update the UI with fully enriched details
                        let _ = ctx.event_tx.send(AppEvent::DeviceFound(device));
                    }
                    None => {
                        // Channel drained successfully
                        break;
                    }
                }
            }
        }
    }

    let duration_ms = start_time.elapsed().as_millis() as u64;

    // Finalize SQLite scan session
    let final_scanned = if ctx.state.is_cancel_requested() {
        ctx.state.get_scanned_count().min(total_hosts)
    } else {
        total_hosts
    };
    if let Err(e) = ctx
        .scan_store
        .update_progress(ctx.scan_id.clone(), final_scanned, total_hosts)
        .await
    {
        send_persistence_warning(
            &ctx.event_tx,
            &format!("Failed to persist final scan progress: {}", e),
        );
    }

    let final_status = if ctx.state.is_cancel_requested() || !ctx.state.is_running() {
        ScanSessionStatus::Cancelled
    } else {
        ScanSessionStatus::Completed
    };

    let devices = ctx.state.get_devices().await;
    let actual_device_count = devices.len() as u32;
    ctx.state.set_persisted_device_count(actual_device_count);

    if let Err(e) = ctx
        .scan_store
        .complete_scan_session(
            ctx.scan_id.clone(),
            final_status.clone(),
            Some(duration_ms),
            None,
        )
        .await
    {
        send_persistence_warning(
            &ctx.event_tx,
            &format!("Failed to complete scan session in store: {}", e),
        );
    }

    // Emit ScanComplete event
    let _ = ctx.event_tx.send(AppEvent::ScanComplete {
        scan_id: ctx.scan_id.clone(),
        device_count: actual_device_count,
        duration_ms,
        status: final_status.as_str().to_string(),
        devices,
    });

    let _ = ctx.event_tx.send(AppEvent::ScanLog {
        level: "info".to_string(),
        message: format!("Scan finished with status: {}", final_status.as_str()),
        target: None,
        timestamp: chrono::Utc::now().timestamp(),
    });
    emit_stage_lifecycle(ctx.as_ref(), "persist", final_status.as_str());

    // Reset scan state running flag
    ctx.state.set_running(false);
    ctx.state.set_current_scan_id(None).await;

    Ok(())
}

fn send_persistence_warning(event_tx: &mpsc::UnboundedSender<AppEvent>, message: &str) {
    let _ = event_tx.send(AppEvent::ScanLog {
        level: "warn".to_string(),
        message: message.to_string(),
        target: None,
        timestamp: chrono::Utc::now().timestamp(),
    });
}
