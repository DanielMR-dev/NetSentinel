//! Scan control commands.
//!
//! Provides `start_scan`, `stop_scan`, `pause_scan`, `resume_scan`, and
//! `get_scan_results` as plain async functions. The `start_scan` function
//! accepts an `UnboundedSender<AppEvent>` channel for streaming results
//! to the Iced UI, replacing Tauri's `app_handle.emit(...)` pattern.
//!
//! The scan engine is implemented as a bounded, multi-stage pipeline. All
//! spawned stage tasks are owned by a `JoinSet` supervisor stored in
//! `SharedScanState` so that `stop_scan` can abort and join them with a
//! timeout. Concurrency is governed by shared semaphores held in
//! `SharedScanState`, not by per-scan local semaphores.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;

use crate::commands::scan_pipeline::PipelineContext;
use crate::error::ScanError;
use crate::events::AppEvent;
use crate::network::timing::TimingTemplate;
use crate::network::{cidr, icmp, sanitize};
use crate::scan_plan::{
    safe_concurrency_defaults, ScanMode, DISCOVERY_CHANNEL_CAPACITY, ENRICH_CHANNEL_CAPACITY,
    FINDING_CHANNEL_CAPACITY, PORT_CHANNEL_CAPACITY, TARGET_CHANNEL_CAPACITY,
};
use crate::scan_store::{ScanSession, ScanSessionStatus, ScanStore, StoredScanConfig};
use crate::state::SharedScanState;
use crate::types::{Device, ScanResponse, ScanResultsResponse, ScanType};

/// Start a network scan.
///
/// Results are streamed to the UI via `event_tx`. The caller (Iced subscription)
/// receives `AppEvent` variants as the scan progresses.
#[allow(clippy::too_many_arguments)]
pub async fn start_scan(
    state: Arc<SharedScanState>,
    event_tx: mpsc::UnboundedSender<AppEvent>,
    cidr: String,
    timeout_ms: u64,
    scan_ports: bool,
    ports: Vec<u16>,
    max_concurrent_hosts: Option<u32>,
    max_concurrent_ports: Option<u32>,
    discovery_methods: Option<Vec<String>>,
    retry_count: Option<u8>,
    scan_type: Option<ScanType>,
    timing_template: Option<TimingTemplate>,
    web_audit_profile: Option<crate::network::web_audit::WebAuditProfile>,
    run_active_checks: Option<bool>,
    scan_mode: Option<ScanMode>,
) -> Result<ScanResponse, ScanError> {
    // --- Input Validation ---
    let _validated_cidr = sanitize::validate_cidr(&cidr)?;
    let _validated_timeout = sanitize::validate_timeout_ms(timeout_ms)?;

    if scan_ports && !ports.is_empty() {
        sanitize::validate_ports(&ports)?;
    }

    let mut effective_scan_type = scan_type.unwrap_or_default();
    let effective_timing = timing_template.unwrap_or_default();
    let effective_scan_mode = scan_mode.unwrap_or_default();
    if !effective_scan_mode.is_supported() {
        return Err(ScanError::InvalidInput(format!(
            "Unsupported scan mode: {}",
            effective_scan_mode
        )));
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
    let total_hosts = network.size() as u32;

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
    let (safe_hosts, safe_ports) = safe_concurrency_defaults(total_hosts as usize, ports.len());
    let effective_max_concurrent = max_concurrent_hosts
        .map(|value| value as usize)
        .unwrap_or(safe_hosts)
        .min(safe_hosts);
    let effective_max_concurrent_ports = max_concurrent_ports
        .map(|value| value as usize)
        .unwrap_or(safe_ports)
        .min(safe_ports);
    let methods =
        discovery_methods.unwrap_or_else(|| vec!["arp".into(), "tcp_probe".into(), "icmp".into()]);
    let effective_retry_count = retry_count.unwrap_or(0);
    let scan_id = uuid::Uuid::new_v4().to_string();
    state.set_current_scan_id(Some(scan_id.clone())).await;

    // Configure the shared semaphores from the active profile.
    state
        .configure_semaphores(effective_max_concurrent, effective_max_concurrent_ports)
        .await;

    // Setup Watch channels for lifecycle
    let (pause_tx, pause_rx) = tokio::sync::watch::channel(false);
    let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);

    // Register cancellation oneshot with state and bridge to watch channel
    let (cancel_state_tx, cancel_state_rx) = tokio::sync::oneshot::channel();
    state.set_cancel_tx(cancel_state_tx).await;

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
        .create_scan_session(ScanSession {
            id: scan_id.clone(),
            cidr: cidr.clone(),
            total_hosts,
            started_at: chrono::Utc::now().timestamp(),
            config: StoredScanConfig {
                timeout_ms,
                scan_ports,
                ports: ports.clone(),
                max_concurrent_hosts,
                max_concurrent_ports,
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
            .complete_scan_session(
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
            "Scan started (mode: {}, methods: {:?}, max_hosts: {}, max_ports: {}, retries: {}, type: {:?}, timing: {:?})",
            effective_scan_mode, methods, effective_max_concurrent, effective_max_concurrent_ports, effective_retry_count, effective_scan_type, effective_timing
        ),
        None,
    );

    // Create the pipeline supervisor. All spawned stage tasks are owned by this
    // `JoinSet` so `stop_scan` can abort and join them.
    let mut pipeline = tokio::task::JoinSet::new();

    // Bridge state pause status to watch channel
    let state_pause = state.clone();
    pipeline.spawn(async move {
        let mut last_paused = false;
        while state_pause.is_running() {
            let current_paused = state_pause.is_paused();
            if current_paused != last_paused {
                let _ = pause_tx.send(current_paused);
                last_paused = current_paused;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    });

    // Bridge state cancellation oneshot to watch channel
    let cancel_tx_clone = cancel_tx.clone();
    pipeline.spawn(async move {
        let _ = cancel_state_rx.await;
        let _ = cancel_tx_clone.send(true);
    });

    // Clone the shared semaphores into the pipeline context.
    let (host_sem, port_sem, raw_sem, enrich_sem) = {
        let semaphores = state.semaphores.lock().await;
        (
            semaphores.host_semaphore.clone(),
            semaphores.port_semaphore.clone(),
            semaphores.raw_socket_semaphore.clone(),
            semaphores.enrichment_semaphore.clone(),
        )
    };

    // Create PipelineContext
    let ctx = Arc::new(PipelineContext {
        state: state.clone(),
        scan_store: scan_store.clone(),
        scan_id: scan_id.clone(),
        event_tx: event_tx.clone(),
        timeout_ms,
        host_semaphore: host_sem,
        port_semaphore: port_sem,
        raw_socket_semaphore: raw_sem,
        enrichment_semaphore: enrich_sem,
        pause_rx,
        cancel_rx,
    });

    // Connect stages via bounded channels
    let (target_tx, target_rx) = mpsc::channel(TARGET_CHANNEL_CAPACITY);
    let (discovery_tx, discovery_rx) = mpsc::channel(DISCOVERY_CHANNEL_CAPACITY);
    let (port_tx, port_rx) = mpsc::channel(PORT_CHANNEL_CAPACITY);
    let (enrich_tx, enrich_rx) = mpsc::channel(ENRICH_CHANNEL_CAPACITY);
    let (finding_tx, finding_rx) = mpsc::channel(FINDING_CHANNEL_CAPACITY);

    // Spawn Stage 1: Target Stream
    let ctx_c1 = ctx.clone();
    let cidr_c = cidr.clone();
    pipeline.spawn(async move {
        if let Err(e) =
            crate::commands::scan_pipeline::stage_target_stream(ctx_c1, cidr_c, target_tx).await
        {
            if !matches!(e, ScanError::Cancelled) {
                tracing::error!("Stage 1 (Target Stream) failed: {}", e);
            }
        }
    });

    // Spawn Stage 2: Host Discovery
    let ctx_c2 = ctx.clone();
    let cidr_c2 = cidr.clone();
    let methods_c = methods.clone();
    let retry_count_c = effective_retry_count;
    pipeline.spawn(async move {
        if let Err(e) = crate::commands::scan_pipeline::stage_host_discovery(
            ctx_c2,
            cidr_c2,
            methods_c,
            retry_count_c,
            target_rx,
            discovery_tx,
        )
        .await
        {
            if !matches!(e, ScanError::Cancelled) {
                tracing::error!("Stage 2 (Host Discovery) failed: {}", e);
            }
        }
    });

    // Spawn Stage 3: Port Scan
    let ctx_c3 = ctx.clone();
    let ports_c = if scan_ports && !matches!(effective_scan_mode, ScanMode::DiscoveryOnly) {
        ports.clone()
    } else {
        Vec::new()
    };
    let scan_type_c = effective_scan_type.clone();
    let timing_template_c = effective_timing;
    pipeline.spawn(async move {
        if let Err(e) = crate::commands::scan_pipeline::stage_port_scan(
            ctx_c3,
            ports_c,
            scan_type_c,
            timing_template_c,
            discovery_rx,
            port_tx,
        )
        .await
        {
            if !matches!(e, ScanError::Cancelled) {
                tracing::error!("Stage 3 (Port Scan) failed: {}", e);
            }
        }
    });

    // Spawn Stage 4: Enrichment
    let ctx_c4 = ctx.clone();
    let web_profile_c = if matches!(effective_scan_mode, ScanMode::FullAudit) {
        web_audit_profile.clone()
    } else {
        None
    };
    let run_active_c =
        run_active_checks.unwrap_or(false) && matches!(effective_scan_mode, ScanMode::FullAudit);
    pipeline.spawn(async move {
        if let Err(e) = crate::commands::scan_pipeline::stage_enrichment(
            ctx_c4,
            web_profile_c,
            run_active_c,
            port_rx,
            enrich_tx,
        )
        .await
        {
            if !matches!(e, ScanError::Cancelled) {
                tracing::error!("Stage 4 (Enrichment) failed: {}", e);
            }
        }
    });

    // Spawn Stage 5: Finding Generation
    let ctx_c5 = ctx.clone();
    pipeline.spawn(async move {
        if let Err(e) =
            crate::commands::scan_pipeline::stage_finding_gen(ctx_c5, enrich_rx, finding_tx).await
        {
            if !matches!(e, ScanError::Cancelled) {
                tracing::error!("Stage 5 (Finding Gen) failed: {}", e);
            }
        }
    });

    // Spawn Stage 6: Persistence & UI Events
    let ctx_c6 = ctx.clone();
    pipeline.spawn(async move {
        if let Err(e) =
            crate::commands::scan_pipeline::stage_persistence_ui(ctx_c6, total_hosts, finding_rx)
                .await
        {
            if !matches!(e, ScanError::Cancelled) {
                tracing::error!("Stage 6 (Persistence & UI) failed: {}", e);
            }
        }
    });

    // Register the supervisor with shared state so `stop_scan` can take ownership.
    state.set_pipeline(pipeline).await;

    Ok(ScanResponse {
        scan_id,
        status: "started".to_string(),
        scan_type: effective_scan_type,
    })
}

/// Stop an ongoing scan.
///
/// Signals cancellation, then takes ownership of the pipeline supervisor and
/// aborts all spawned stage tasks. Waits up to 5 seconds for tasks to finish;
/// any remaining tasks are aborted when the supervisor is dropped.
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

    // Take ownership of the pipeline supervisor and shut it down.
    if let Some(mut pipeline) = state.take_pipeline().await {
        pipeline.abort_all();
        let _ = tokio::time::timeout(Duration::from_secs(5), async {
            while let Some(_) = pipeline.join_next().await {}
        })
        .await;
        // Dropping `pipeline` aborts any stragglers.
    }

    let scan_id = state.current_scan_id().await.unwrap_or_default();
    if !scan_id.is_empty() {
        let config_dir = crate::commands::settings::get_config_dir()?;
        let scan_store = ScanStore::new(config_dir);
        let _ = scan_store
            .complete_scan_session(
                scan_id,
                ScanSessionStatus::Cancelled,
                None,
                Some("Scan stopped by user".to_string()),
            )
            .await;
    }

    state.set_running(false);
    state.set_current_scan_id(None).await;

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
