use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::state::ScanSemaphores;
use crate::types::Device;

/// Shared scan state that can be accessed from multiple commands.
///
/// Boolean flags (`is_paused`, `is_running`) use `AtomicBool` for lock-free,
/// non-blocking reads. Complex state (`devices`, `cancel_tx`, `current_target`)
/// uses `tokio::sync::Mutex` to avoid holding guards across `.await` points.
pub struct SharedScanState {
    pub devices: Arc<Mutex<HashMap<String, Device>>>,
    pub scanned_count: Arc<AtomicU32>,
    pub total_hosts: Arc<AtomicU32>,
    pub persisted_device_count: Arc<AtomicU32>,
    pub is_paused: AtomicBool,
    pub is_running: AtomicBool,
    pub cancel_requested: AtomicBool,
    pub cancel_tx: Arc<Mutex<Option<tokio::sync::oneshot::Sender<()>>>>,
    pub current_target: Arc<Mutex<Option<String>>>,
    pub current_scan_id: Arc<Mutex<Option<String>>>,
    /// Global/shared semaphores used by all scan pipeline stages.
    pub semaphores: Arc<Mutex<ScanSemaphores>>,
    /// Active pipeline task supervisor. Holds the `JoinSet` for all spawned
    /// stage tasks so `stop_scan` can abort and join them with a timeout.
    pipeline: Arc<Mutex<Option<tokio::task::JoinSet<()>>>>,
}

impl Default for SharedScanState {
    fn default() -> Self {
        Self::new()
    }
}

impl SharedScanState {
    pub fn new() -> Self {
        Self {
            devices: Arc::new(Mutex::new(HashMap::new())),
            scanned_count: Arc::new(AtomicU32::new(0)),
            total_hosts: Arc::new(AtomicU32::new(0)),
            persisted_device_count: Arc::new(AtomicU32::new(0)),
            is_paused: AtomicBool::new(false),
            is_running: AtomicBool::new(false),
            cancel_requested: AtomicBool::new(false),
            cancel_tx: Arc::new(Mutex::new(None)),
            current_target: Arc::new(Mutex::new(None)),
            current_scan_id: Arc::new(Mutex::new(None)),
            semaphores: Arc::new(Mutex::new(ScanSemaphores::new(50, 100, 50, 16))),
            pipeline: Arc::new(Mutex::new(None)),
        }
    }

    pub async fn reset(&self) {
        self.devices.lock().await.clear();
        self.scanned_count.store(0, Ordering::SeqCst);
        self.total_hosts.store(0, Ordering::SeqCst);
        self.persisted_device_count.store(0, Ordering::SeqCst);
        self.is_paused.store(false, Ordering::SeqCst);
        self.is_running.store(false, Ordering::SeqCst);
        self.cancel_requested.store(false, Ordering::SeqCst);
        *self.cancel_tx.lock().await = None;
        *self.current_target.lock().await = None;
        *self.current_scan_id.lock().await = None;
    }

    pub async fn reset_for_new_scan(&self) {
        self.devices.lock().await.clear();
        self.scanned_count.store(0, Ordering::SeqCst);
        self.total_hosts.store(0, Ordering::SeqCst);
        self.persisted_device_count.store(0, Ordering::SeqCst);
        self.is_paused.store(false, Ordering::SeqCst);
        self.cancel_requested.store(false, Ordering::SeqCst);
        *self.cancel_tx.lock().await = None;
        *self.current_target.lock().await = None;
        *self.current_scan_id.lock().await = None;
    }

    pub async fn set_cancelled(&self) {
        self.cancel_requested.store(true, Ordering::SeqCst);
        let maybe_tx = self.cancel_tx.lock().await.take();
        if let Some(tx) = maybe_tx {
            let _ = tx.send(());
        }
    }

    pub async fn get_devices(&self) -> Vec<Device> {
        self.devices.lock().await.values().cloned().collect()
    }

    pub async fn add_device(&self, device: Device) {
        self.devices.lock().await.insert(device.ip.clone(), device);
    }

    pub fn get_scanned_count(&self) -> u32 {
        self.scanned_count.load(Ordering::SeqCst)
    }

    pub fn get_total_hosts(&self) -> u32 {
        self.total_hosts.load(Ordering::SeqCst)
    }

    pub fn increment_scanned(&self) {
        self.scanned_count.fetch_add(1, Ordering::SeqCst);
    }

    pub fn set_total_hosts(&self, total: u32) {
        self.total_hosts.store(total, Ordering::SeqCst);
    }

    pub fn get_persisted_device_count(&self) -> u32 {
        self.persisted_device_count.load(Ordering::SeqCst)
    }

    pub fn set_persisted_device_count(&self, total: u32) {
        self.persisted_device_count.store(total, Ordering::SeqCst);
    }

    pub async fn set_current_target(&self, target: Option<String>) {
        *self.current_target.lock().await = target;
    }

    pub async fn set_current_scan_id(&self, scan_id: Option<String>) {
        *self.current_scan_id.lock().await = scan_id;
    }

    pub async fn current_scan_id(&self) -> Option<String> {
        self.current_scan_id.lock().await.clone()
    }

    pub fn set_paused(&self, paused: bool) {
        self.is_paused.store(paused, Ordering::SeqCst);
    }

    pub fn is_paused(&self) -> bool {
        self.is_paused.load(Ordering::SeqCst)
    }

    pub fn is_running(&self) -> bool {
        self.is_running.load(Ordering::SeqCst)
    }

    pub fn set_running(&self, running: bool) {
        self.is_running.store(running, Ordering::SeqCst);
    }

    pub fn try_start_running(&self) -> bool {
        self.is_running
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    }

    pub fn is_cancel_requested(&self) -> bool {
        self.cancel_requested.load(Ordering::SeqCst)
    }

    pub async fn set_cancel_tx(&self, tx: tokio::sync::oneshot::Sender<()>) {
        *self.cancel_tx.lock().await = Some(tx);
    }

    /// Reconfigure shared semaphores from the active scan settings.
    pub async fn configure_semaphores(&self, hosts: usize, ports: usize) {
        self.semaphores.lock().await.configure(hosts, ports);
    }

    /// Store the active pipeline supervisor.
    pub async fn set_pipeline(&self, join_set: tokio::task::JoinSet<()>) {
        *self.pipeline.lock().await = Some(join_set);
    }

    /// Take ownership of the active pipeline supervisor.
    pub async fn take_pipeline(&self) -> Option<tokio::task::JoinSet<()>> {
        self.pipeline.lock().await.take()
    }
}
