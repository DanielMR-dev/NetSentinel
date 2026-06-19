---
name: Backend Standards
description: Comprehensive coding standards, patterns, and best practices for the NetSentinel backend. This skill defines the non-negotiable rules for Rust safety, Tokio async execution, concurrency, SQLite database storage, and integration with Iced.
version: 1.0.0
project: NetSentinel
context: Rust + Tokio + pnet + Iced Integration
---

# NetSentinel Backend Standards

This skill defines the authoritative rules and patterns that every backend developer, planner, and reviewer must follow when working on the NetSentinel project backend core.

---

## 1. Rust Safety Principles

### 1.1 Forbidden Patterns

| Pattern | Rule | Reason |
|---------|------|--------|
| `.unwrap()` | **NEVER use in production** | Can panic and crash the application. |
| `.expect()` | **NEVER use in production** | Can panic and crash the application. |
| `panic!()` | **NEVER use** | Unacceptable in library code or scanning engines. |
| `unsafe {}` | **Avoid unless necessary** | Only use for low-level operations (e.g. raw socket creation) with documented justification. |
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

Define a project-wide error enum:

```rust
use serde::Serialize;
use thiserror::Error;

#[derive(Error, Debug, Serialize, Clone, PartialEq)]
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

## 2. API & Service Interfaces

In the absence of a Webview IPC layer, the backend core integrates directly with the Iced UI using standard Rust messaging primitives.

### 2.1 Async Scan Engine Task

All heavy-lifting tasks must run asynchronously using Tokio. Instead of returning full lists at the end, stream results as they are found.

```rust
pub async fn run_scan_task(
    cidr: String,
    progress_sender: tokio::sync::mpsc::UnboundedSender<ScanEvent>,
    mut cancel_receiver: tokio::sync::oneshot::Receiver<()>,
) -> Result<(), ScanError> {
    let targets = parse_cidr(&cidr)?;
    let total = targets.len() as f32;

    for (i, target) in targets.into_iter().enumerate() {
        // Check for cancellation
        if cancel_receiver.try_recv().is_ok() {
            let _ = progress_sender.send(ScanEvent::Finished(Err("Cancelled".to_string())));
            return Err(ScanError::Cancelled);
        }

        // Scan host
        if let Ok(Some(device)) = scan_host(target).await {
            let _ = progress_sender.send(ScanEvent::DeviceFound(device));
        }

        // Report progress percentage
        let progress = (i as f32 + 1.0) / total;
        let _ = progress_sender.send(ScanEvent::Progress(progress));
    }

    let _ = progress_sender.send(ScanEvent::Finished(Ok(())));
    Ok(())
}
```

---

## 3. Async Concurrency with Tokio

### 3.1 Non-Blocking I/O

All network operations must be async:

```rust
// BAD — blocks the OS thread
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

### 3.2 Spawning Tasks and Concurrency Control

Use `tokio::spawn` combined with semaphores to avoid exhausting file descriptors:

```rust
use futures::stream::{self, StreamExt};
use tokio::sync::Semaphore;
use std::sync::Arc;

let sem = Arc::new(Semaphore::new(MAX_CONCURRENT_SCANS));
let mut tasks = stream::iter(ips)
    .map(|ip| {
        let permit = sem.clone().acquire_owned();
        async move {
            let _permit = permit.await?;
            scan_host(ip).await
        }
    })
    .buffer_unordered(MAX_CONCURRENT_SCANS);
```

---

## 4. Async Event Streaming

### 4.1 Scan Events definition

The core defines structured events to let the UI react dynamically:

```rust
#[derive(Debug, Clone)]
pub enum ScanEvent {
    DeviceFound(Device),
    Progress(f32),
    Finished(Result<(), String>),
}
```

---

## 5. Data Structures

All data structures should be simple, cloneable, and serialize/deserialize enabled if needed for storage (e.g. SQLite database or files).

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
```

---

## 6. Concurrency & Thread Safety

### 6.1 Shared State

Use thread-safe synchronization wrapper `Arc<tokio::sync::Mutex<T>>` or `Arc<tokio::sync::RwLock<T>>` for long-term shared state.

```rust
pub type SharedState = Arc<tokio::sync::RwLock<Settings>>;
```

### 6.2 Deadlock Prevention

Never hold a `MutexGuard` (especially std::sync::MutexGuard or Tokio's lock) across an `.await` point.

---

## 7. Network Scanning Patterns

### 7.1 Host Discovery (ARP/ICMP)

* **ARP scans:** Directly constructs and writes raw packets using the `pnet` library. Requires root or `CAP_NET_RAW` privileges on Linux.
* **ICMP scans:** Uses ICMP Echo requests. Requires elevated raw sockets or privileges.

### 7.2 Port Scanning

* **TCP Connect scans:** Uses standard `tokio::net::TcpStream::connect` with a timeout mechanism.

---

## 8. Structured Logging

Use the `tracing` library to record warnings, errors, and key operational details.

---

## 9. Permissions & Privilege Handling

### 9.1 Privilege Detection

Provide helper checks for capabilities before starting privilege-dependent scans:

```rust
pub fn has_net_raw_capability() -> bool {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/proc/self/status")
            .map(|s| s.contains("CapNetRaw: 1") || s.contains("CapNetRaw:\t0000000000002000"))
            .unwrap_or(false)
    }
    #[cfg(target_os = "windows")]
    {
        // Admin privilege check
        is_elevated()
    }
}
```

---

## 10. Performance Considerations

* **TCP Concurrency Limit:** Max 1000 connections.
* **ARP rate limit:** Max 50 packets per second to avoid flooding switches.
* **Memory Management:** Pre-allocate vectors with capacities where appropriate (`Vec::with_capacity`).

---

## 11. File Structure

```
src/
  main.rs             # Application runner & GUI entry
  lib.rs              # Library exports (modular entry)
  error.rs            # Core error types
  types.rs            # Shared structs
  settings.rs         # Configuration logic
  history.rs          # Scanning database/persistence
  network/
    mod.rs              # Network operations module
    banner.rs           # Port service banner grabbing
    cidr.rs             # CIDR parsing
    cve.rs              # Vulnerability mapping logic
    host_discovery.rs   # ARP/ICMP sweeps
    icmp.rs             # ICMP implementations
    oui.rs              # MAC OUI vendor resolution
    privileges.rs       # Cap checks & elevation helpers
    sanitize.rs         # String sanitizations
    syn_scan.rs         # SYN scan implementation
    timing.rs           # Port scanning timers/delay strategies
    tls.rs              # SSL/TLS cert queries
    udp_scan.rs         # UDP scan implementation
```

---

## 12. Code Review Checklist

* [ ] No `.unwrap()`, `.expect()`, or `panic!()` in production scanning logic.
* [ ] Async tasks have correct timeout mechanisms.
* [ ] No blocking I/O inside async code contexts.
* [ ] Shared mutable states have correct lock scoping to prevent deadlocks.
* [ ] Semaphore rules correctly restrict active TCP/ARP sockets.
* [ ] Privilege checks fail gracefully with custom `ScanError` returns.

---

*This skill document is aligned with the NetSentinel project architecture (Rust + Iced + Tokio) and is mandatory for all backend development tasks.*