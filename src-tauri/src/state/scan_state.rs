use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use tokio::sync::Mutex;

use crate::types::Device;

/// Shared scan state that can be accessed from multiple commands
pub struct SharedScanState {
    pub devices: Arc<Mutex<HashMap<String, Device>>>,
    pub scanned_count: Arc<AtomicU32>,
    pub total_hosts: Arc<AtomicU32>,
    pub is_paused: Arc<Mutex<bool>>,
    pub is_running: Arc<Mutex<bool>>,
    pub cancel_tx: Arc<Mutex<Option<tokio::sync::oneshot::Sender<()>>>>,
    pub current_target: Arc<Mutex<Option<String>>>,
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
            is_paused: Arc::new(Mutex::new(false)),
            is_running: Arc::new(Mutex::new(false)),
            cancel_tx: Arc::new(Mutex::new(None)),
            current_target: Arc::new(Mutex::new(None)),
        }
    }

    pub async fn reset(&self) {
        self.devices.lock().await.clear();
        self.scanned_count.store(0, Ordering::SeqCst);
        self.total_hosts.store(0, Ordering::SeqCst);
        *self.is_paused.lock().await = false;
        *self.is_running.lock().await = false;
        *self.cancel_tx.lock().await = None;
        *self.current_target.lock().await = None;
    }

    pub async fn set_cancelled(&self) {
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

    pub async fn set_current_target(&self, target: Option<String>) {
        *self.current_target.lock().await = target;
    }

    pub async fn set_paused(&self, paused: bool) {
        *self.is_paused.lock().await = paused;
    }

    pub async fn is_paused(&self) -> bool {
        *self.is_paused.lock().await
    }

    pub async fn is_running(&self) -> bool {
        *self.is_running.lock().await
    }

    pub async fn set_running(&self, running: bool) {
        *self.is_running.lock().await = running;
    }

    pub async fn set_cancel_tx(&self, tx: tokio::sync::oneshot::Sender<()>) {
        *self.cancel_tx.lock().await = Some(tx);
    }
}