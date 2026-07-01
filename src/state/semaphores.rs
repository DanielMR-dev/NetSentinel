//! Global/shared semaphore state for the scan pipeline.
//!
//! These semaphores live inside [`SharedScanState`](crate::state::SharedScanState)
//! and are reused across scans. They are reconfigured from the active settings
//! profile at the start of each scan, so concurrency limits are respected without
//! creating per-scan local semaphores.

use std::sync::Arc;

use tokio::sync::Semaphore;

/// Shared semaphores that enforce global concurrency limits across all scan
/// pipeline stages.
#[derive(Debug, Clone)]
pub struct ScanSemaphores {
    /// Maximum concurrent host-level discovery tasks.
    pub host_semaphore: Arc<Semaphore>,
    /// Maximum concurrent port checks (per scan, but shared across hosts).
    pub port_semaphore: Arc<Semaphore>,
    /// Maximum concurrent raw socket users (ICMP/ARP/raw TCP).
    pub raw_socket_semaphore: Arc<Semaphore>,
    /// Maximum concurrent HTTP/TLS/active-check enrichment tasks.
    pub enrichment_semaphore: Arc<Semaphore>,
}

impl ScanSemaphores {
    /// Create semaphores with sensible defaults.
    pub fn new(hosts: usize, ports: usize, raw: usize, enrichment: usize) -> Self {
        Self {
            host_semaphore: Arc::new(Semaphore::new(hosts.max(1))),
            port_semaphore: Arc::new(Semaphore::new(ports.max(1))),
            raw_socket_semaphore: Arc::new(Semaphore::new(raw.max(1))),
            enrichment_semaphore: Arc::new(Semaphore::new(enrichment.max(1))),
        }
    }

    /// Reconfigure host and port semaphore sizes from the active profile.
    ///
    /// This replaces the inner `Arc<Semaphore>` so any in-flight permits from a
    /// previous scan are not affected. It is called while no scan is running.
    pub fn configure(&mut self, hosts: usize, ports: usize) {
        let hosts = hosts.clamp(1, 1000);
        let ports = ports.clamp(1, 1000);
        self.host_semaphore = Arc::new(Semaphore::new(hosts));
        self.port_semaphore = Arc::new(Semaphore::new(ports));
    }
}
