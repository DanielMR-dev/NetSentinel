---
name: Backend Standards
description: Comprehensive coding standards, patterns, and best practices for the NetSentinel backend. This skill defines the non-negotiable rules for Rust safety, Tokio async execution, Tauri IPC, network scanning, and concurrency.
version: 1.0.0
project: NetSentinel
context: Rust + Tauri + Tokio + pnet
---

# NetSentinel Backend Standards

This skill defines the authoritative rules and patterns that every backend developer, planner, and reviewer must follow when working on the NetSentinel project.

---

## 1. Rust Safety Principles

### 1.1 Forbidden Patterns

| Pattern | Rule | Reason |
|---------|------|--------|
| `.unwrap()` | **NEVER use in production** | Can panic and crash the application. |
| `.expect()` | **NEVER use in production** | Can panic and crash the application. |
| `panic!()` | **NEVER use** | Unacceptable in library code or Tauri commands. |
| `unsafe {}` | **Avoid unless necessary** | Only use for low-level operations with documented justification. |
| `Vec::get_unchecked()` | **NEVER use** | Bounds checking is mandatory. |

### 1.2 Error Propagation

Always use the `?` operator and return `Result<T, CustomError>`:

```rust
// BAD — can panic
fn parse_ip(input: &str) -> Ipv4Addr {
    input.parse().unwrap()
}

// GOOD — proper error propagation
fn parse_ip(input: &str) -> Result<Ipv4Addr, ScanError> {
    input
        .parse()
        .map_err(|e| ScanError::InvalidInput(format!("Invalid IP address: {}", e)))
}
```

### 1.3 Custom Error Type

Define a project-wide error enum that implements `Serialize`:

```rust
use serde::Serialize;
use thiserror::Error;

#[derive(Error, Debug, Serialize)]
pub enum ScanError {
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Scan cancelled")]
    Cancelled,

    #[error("Timeout")]
    Timeout,
}

impl From<std::io::Error> for ScanError {
    fn from(err: std::io::Error) -> Self {
        ScanError::NetworkError(err.to_string())
    }
}
```

---

## 2. Tauri Commands

### 2.1 Command Structure

All Tauri commands must follow this pattern:

```rust
#[tauri::command]
pub async fn start_scan(
    app: AppHandle,
    cidr: String,
    timeout_ms: u64,
) -> Result<ScanResponse, ScanError> {
    // Validate input first
    let cidr = validate_cidr(&cidr)?;

    // Create cancellable scan task
    let (tx, rx) = tokio::sync::oneshot::channel();

    // Store cancellation handle if needed
    app.state::<ScanState>().set_running(tx);

    // Spawn async task and emit progress
    tokio::spawn(async move {
        scan_network(app, cidr, timeout_ms, rx).await;
    });

    Ok(ScanResponse {
        scan_id: Uuid::new_v4().to_string(),
        status: "started".to_string(),
    })
}
```

### 2.2 Command Rules

- **All commands are async** — never block the main thread
- **Return `Result<T, CustomError>`** — never panic or return raw errors
- **Emit events for long-running operations** — use `AppHandle::emit` for progress updates
- **Validate input at command boundary** — reject invalid data before processing

### 2.3 Cancellable Commands

For long-running scans, provide cancellation:

```rust
#[tauri::command]
pub async fn stop_scan(state: State<'_, ScanState>) -> Result<(), ScanError> {
    state
        .cancel()
        .ok_or(ScanError::Cancelled)?;
    Ok(())
}
```

---

## 3. Async Concurrency with Tokio

### 3.1 Non-Blocking I/O

All network operations must be async:

```rust
// BAD — blocks the Tauri thread
fn sync_scan(cidr: &str) -> Vec<Device> {
    let socket = std::net::TcpStream::connect_timeout(/* ... */);
    // blocking I/O
}

// GOOD — async with tokio
async fn async_scan(cidr: &str) -> Result<Vec<Device>, ScanError> {
    let socket = tokio::net::TcpStream::connect(/* ... */).await?;
    // non-blocking I/O
}
```

### 3.2 Spawning Tasks

Use `tokio::spawn` for concurrent operations:

```rust
use futures::stream::{self, StreamExt};
use tokio::sync::Semaphore;

// Limit concurrent connections to avoid file descriptor exhaustion
let sem = Arc::new(Semaphore::new(MAX_CONCURRENT_SCANS));

let results: Vec<Device> = stream::iter(ips)
    .map(|ip| {
        let permit = sem.clone().acquire_owned();
        async move {
            let _permit = permit.await?;
            scan_host(ip, timeout).await
        }
    })
    .buffer_unordered(MAX_CONCURRENT_SCANS)
    .filter_map(|r| async move { r.ok() })
    .collect()
    .await;
```

### 3.3 Task Cancellation

Support cancellation via `tokio::sync::oneshot`:

```rust
async fn scan_network(
    app: AppHandle,
    cidr: String,
    timeout_ms: u64,
    mut cancel: oneshot::Receiver<()>,
) {
    loop {
        tokio::select! {
            _ = &mut cancel => {
                let _ = app.emit("scan_cancelled", ());
                return;
            }
            result = scan_batch() => {
                if let Some(devices) = result {
                    let _ = app.emit("devices_found", &devices);
                }
            }
        }
    }
}
```

---

## 4. Tauri Events

### 4.1 Event Emission Pattern

Emit events for real-time updates during long operations:

```rust
use tauri::{AppHandle, Emitter};

fn emit_device_found(app: &AppHandle, device: Device) -> Result<(), ScanError> {
    app.emit("device_found", DeviceFoundEvent {
        ip: device.ip.to_string(),
        mac: device.mac.to_string(),
        hostname: device.hostname.clone(),
        timestamp: Utc::now().timestamp(),
    }).map_err(|e| ScanError::EventError(e.to_string()))?;
    Ok(())
}

#[derive(Serialize, Clone)]
struct DeviceFoundEvent {
    ip: String,
    mac: String,
    hostname: Option<String>,
    timestamp: i64,
}
```

### 4.2 Progress Events

For operations with measurable progress:

```rust
#[derive(Serialize)]
struct ScanProgressEvent {
    scanned: u32,
    total: u32,
    current_target: String,
    devices_found: u32,
}

app.emit("scan_progress", ScanProgressEvent {
    scanned: i,
    total: total,
    current_target: target_ip.to_string(),
    devices_found: devices.len() as u32,
}).ok(); // Use ok() when non-critical
```

---

## 5. Data Structures & Serialization

### 5.1 IPC-Capable Structs

All types crossing the IPC boundary must derive `Serialize` and `Deserialize`:

```rust
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Device {
    pub ip: String,
    pub mac: String,
    pub hostname: Option<String>,
    pub status: DeviceStatus,
    pub ports: Vec<Port>,
    pub last_seen: i64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum DeviceStatus {
    Online,
    Offline,
    Unknown,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Port {
    pub number: u16,
    pub protocol: String,
    pub service: Option<String>,
    pub state: PortState,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum PortState {
    Open,
    Closed,
    Filtered,
}
```

### 5.2 Request/Response Types

Define explicit command request/response types:

```rust
#[derive(Serialize, Deserialize)]
pub struct ScanRequest {
    pub cidr: String,
    pub timeout_ms: u64,
    pub scan_ports: bool,
}

#[derive(Serialize, Deserialize)]
pub struct ScanResponse {
    pub scan_id: String,
    pub status: String,
    pub devices: Vec<Device>,
    pub duration_ms: u64,
}
```

### 5.3 Collections

Use `Vec<T>` for sequential data and `HashMap<K, V>` for lookups:

```rust
// Device list by IP for fast lookup
pub type DeviceMap = HashMap<String, Device>;

// Scan results accumulated in a thread-safe structure
pub type SharedDeviceMap = Arc<tokio::sync::Mutex<DeviceMap>>;
```

---

## 6. Concurrency & Thread Safety

### 6.1 Shared State

Use `Arc<Mutex<T>>` or `Arc<RwLock<T>>` for shared mutable state:

```rust
use std::sync::{Arc, Mutex};
use tokio::sync::Mutex as AsyncMutex;

// For async contexts — prefer AsyncMutex
pub type AsyncDeviceMap = Arc<AsyncMutex<HashMap<String, Device>>>;

// Initialize shared state
let devices: AsyncDeviceMap = Arc::new(AsyncMutex::new(HashMap::new()));

// Use in async command
async fn add_device(state: State<'_, AsyncDeviceMap>, device: Device) -> Result<(), ScanError> {
    let mut devices = state.lock().await;
    devices.insert(device.ip.clone(), device);
    Ok(())
}
```

### 6.2 Deadlock Prevention

Never hold a `MutexGuard` across an `.await` point:

```rust
// BAD — deadlock risk
async fn bad_example(state: AsyncDeviceMap) {
    let mut devices = state.lock().await;
    some_async_operation().await; // DANGEROUS — holds lock during await
    devices.insert(key, value);
}

// GOOD — no lock held during await
async fn good_example(state: AsyncDeviceMap) {
    let value = some_async_operation().await;
    let mut devices = state.lock().await;
    devices.insert(key, value);
}
```

### 6.3 Concurrency Limits

Protect system resources with semaphores:

```rust
use tokio::sync::Semaphore;

const MAX_CONCURRENT_TCP_CONNECTIONS: usize = 1000;
const MAX_CONCURRENT_ARP_REQUESTS: usize = 50;

lazy_static::lazy_static! {
    static ref TCP_SEMAPHORE: Semaphore = Semaphore::new(MAX_CONCURRENT_TCP_CONNECTIONS);
    static ref ARP_SEMAPHORE: Semaphore = Semaphore::new(MAX_CONCURRENT_ARP_REQUESTS);
}
```

---

## 7. Network Scanning Patterns

### 7.1 Host Discovery

#### ARP Scanning (requires elevated privileges)

```rust
use pnet::datalink::{self, NetworkInterface};

fn arp_scan(interface: &NetworkInterface) -> Result<Vec<Device>, ScanError> {
    // Use pnet for ARP packet construction and reception
    // Emit devices as they are discovered via events
}
```

#### ICMP Ping Scanning

```rust
async fn ping_host(ip: Ipv4Addr, timeout: Duration) -> Result<bool, ScanError> {
    // ICMP echo request with tokio-based timeout
    // Return true if host responds within timeout
}
```

### 7.2 Port Scanning

#### TCP Connect Scan

```rust
async fn tcp_connect_scan(
    ip: Ipv4Addr,
    port: u16,
    timeout: Duration,
) -> Result<PortState, ScanError> {
    let addr = SocketAddr::new(ip.into(), port);

    match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr)).await {
        Ok(Ok(_)) => Ok(PortState::Open),
        Ok(Err(_)) => Ok(PortState::Closed),
        Err(_) => Ok(PortState::Filtered),
    }
}
```

### 7.3 Scan Batching

Process targets in batches to manage memory and rate limits:

```rust
const BATCH_SIZE: usize = 254; // /24 subnet

fn chunk_iter<T: Iterator<Item = IpAddr>>(iter: T, size: usize) -> Vec<Vec<IpAddr>> {
    iter.collect::<Vec<_>>()
        .chunks(size)
        .map(|c| c.to_vec())
        .collect()
}
```

---

## 8. Logging

### 8.1 Structured Logging

Use `tracing` for structured logging:

```rust
use tracing::{info, warn, error, instrument};

#[instrument(skip(state), fields(scan_id = %scan_id))]
pub async fn start_scan(
    state: State<'_, ScanState>,
    scan_id: String,
    cidr: String,
) -> Result<ScanResponse, ScanError> {
    info!("Starting network scan");

    // ... implementation

    info!(device_count = devices.len(), "Scan completed");
    Ok(response)
}
```

### 8.2 Log Levels

| Level | Usage |
|-------|-------|
| `error!` | Failures that prevent operation completion |
| `warn!` | Recoverable issues (e.g., permission denied for ARP) |
| `info!` | Major operation milestones |
| `debug!` | Detailed troubleshooting information |
| `trace!` | Very verbose, for development only |

---

## 9. Permissions & Privilege Handling

### 9.1 Privilege Detection

Check for required capabilities at startup:

```rust
fn check_arp_capability() -> bool {
    #[cfg(target_os = "linux")]
    {
        // Check if running as root or has CAP_NET_RAW
        std::fs::read_to_string("/proc/self/status")
            .map(|s| s.contains("CapNetRaw: 1"))
            .unwrap_or(false)
    }
    #[cfg(target_os = "windows")]
    {
        // Check for Administrator privileges
        is_elevated()
    }
}
```

### 9.2 Graceful Degradation

Handle permission errors gracefully:

```rust
if !check_arp_capability() {
    warn!("ARP scanning requires elevated privileges; falling back to ICMP");
    // Return error that frontend can display with user-friendly message
    return Err(ScanError::PermissionDenied(
        "ARP scanning requires administrator/root privileges".to_string(),
    ));
}
```

---

## 10. Performance Considerations

### 10.1 Resource Limits

| Resource | Limit | Reason |
|----------|-------|--------|
| TCP connections | 1000 | Prevent file descriptor exhaustion |
| ARP requests | 50/s | Avoid network flooding |
| Memory per scan | 100MB | Prevent OOM in large subnets |
| Scan timeout | 5 minutes | Prevent stuck scans |

### 10.2 Memory Efficiency

```rust
// Use Vec with capacity pre-allocation when size is known
let mut devices = Vec::with_capacity(254);

// Process in streaming fashion rather than collecting all at once
stream::iter(ips)
    .map(|ip| async move { process_ip(ip).await })
    .buffered(100)
    .for_each(|result| async move {
        if let Ok(device) = result {
            emit_device_found(&app, device).await;
        }
    })
    .await;
```

---

## 11. Testing Patterns

### 11.1 Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cidr_validation() {
        assert!(validate_cidr("192.168.1.0/24").is_ok());
        assert!(validate_cidr("invalid").is_err());
        assert!(validate_cidr("256.1.1.1/24").is_err());
    }

    #[test]
    fn test_port_state_serialization() {
        let state = PortState::Open;
        let json = serde_json::to_string(&state).unwrap();
        assert_eq!(json, "\"Open\"");
    }
}
```

### 11.2 Async Tests

```rust
#[cfg(test)]
mod tests {
    use tokio::test;

    #[tokio::test]
    async fn test_tcp_scan_timeout() {
        let result = tcp_connect_scan(
            "192.168.1.1".parse().unwrap(),
            9999, // unlikely open port
            Duration::from_millis(100),
        )
        .await;

        assert!(matches!(result, Ok(PortState::Closed | PortState::Filtered)));
    }
}
```

---

## 12. File Structure

```
src/
  lib.rs              # Module declarations
  main.rs             # Tauri app entry
  commands/
    mod.rs
    scan.rs           # Scan-related commands
    device.rs         # Device queries
  network/
    mod.rs
    arp.rs            # ARP scanning
    icmp.rs           # ICMP ping
    tcp.rs            # TCP connect scan
  state/
    mod.rs
    scan_state.rs     # Scan runtime state
  error.rs            # Custom error types
  types.rs            # Shared data structures
```

---

## 13. Code Review Checklist

Before submitting any Rust code, verify:

- [ ] No `.unwrap()`, `.expect()`, or `panic!()` in production code
- [ ] All `tokio::spawn` tasks have proper error handling
- [ ] All Tauri commands return `Result<T, Error>` and emit appropriate events
- [ ] No synchronous network I/O (`std::net`) in async contexts
- [ ] Shared state uses proper synchronization (`Arc<Mutex>` or `Arc<RwLock>`)
- [ ] No `MutexGuard` held across `.await` points
- [ ] Semaphore limits protect against resource exhaustion
- [ ] All IPC types derive `Serialize` and `Deserialize`
- [ ] Permission errors have graceful fallbacks
- [ ] Logging uses `tracing` with appropriate levels

---

*This skill document is aligned with the NetSentinel project architecture (Rust + Tauri + Tokio + pnet) and is mandatory for all backend development tasks.*