use crate::events::AppEvent;
use crate::scan_store::ScanStore;
use crate::state::SharedScanState;
use std::sync::Arc;
use tokio::sync::{mpsc, watch, Semaphore};

/// Shared environment and controls for all pipeline stages.
#[derive(Clone)]
pub struct PipelineContext {
    pub state: Arc<SharedScanState>,
    pub scan_store: ScanStore,
    pub scan_id: String,
    pub event_tx: mpsc::UnboundedSender<AppEvent>,

    /// Timeout per host/port check, in milliseconds.
    pub timeout_ms: u64,

    // Concurrency Semaphores (cloned from the global shared semaphore state).
    pub host_semaphore: Arc<Semaphore>,
    pub port_semaphore: Arc<Semaphore>,
    pub raw_socket_semaphore: Arc<Semaphore>,
    pub enrichment_semaphore: Arc<Semaphore>,

    // Lifecycle Watch Channels
    pub pause_rx: watch::Receiver<bool>,
    pub cancel_rx: watch::Receiver<bool>,
}

/// Blocks if the scan is paused, resuming when the pause status is false.
pub async fn wait_if_paused(pause_rx: &mut watch::Receiver<bool>) {
    while *pause_rx.borrow() {
        if pause_rx.changed().await.is_err() {
            // Watch channel was closed, treat as unpaused or cancel
            break;
        }
    }
}
