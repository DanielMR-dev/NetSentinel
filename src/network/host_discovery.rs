use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures::stream::{self, StreamExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Semaphore};

use crate::error::ScanError;
use crate::events::AppEvent;
use crate::network::oui;
use crate::types::{Device, DeviceStatus, Port, PortState};

/// Default maximum concurrent host checks
const DEFAULT_MAX_CONCURRENT_HOSTS: usize = 50;

/// Maximum concurrent port checks per host
const MAX_CONCURRENT_PORTS: usize = 100;

/// Progress update interval (every N hosts)
const PROGRESS_INTERVAL: u32 = 10;

/// Common ports to scan if none specified
pub const DEFAULT_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 5900, 6379, 8080, 8443,
];

/// Emit a scan_log event to the frontend via the event channel.
fn emit_log(
    event_tx: &mpsc::UnboundedSender<AppEvent>,
    level: &str,
    message: &str,
    target: Option<&str>,
) {
    let _ = event_tx.send(AppEvent::ScanLog {
        level: level.to_string(),
        message: message.to_string(),
        target: target.map(|s| s.to_string()),
        timestamp: chrono::Utc::now().timestamp(),
    });
}

/// Discover live hosts by TCP probing common ports.
///
/// Supports cancellation via the `cancel_rx` oneshot receiver. When cancelled,
/// the entire stream is dropped (cancelling all in-flight TCP probes) and
/// partial results collected so far are returned.
///
/// # Arguments
/// * `ips` - List of IP addresses to probe
/// * `event_tx` - Channel sender for emitting events to the Iced UI
/// * `cancel_rx` - Cancellation receiver
/// * `max_concurrent` - Maximum concurrent host probes (0 = use default of 50)
/// * `retry_count` - Number of retries for failed host probes
pub async fn discover_hosts(
    ips: Vec<IpAddr>,
    event_tx: mpsc::UnboundedSender<AppEvent>,
    cancel_rx: tokio::sync::oneshot::Receiver<()>,
    max_concurrent: usize,
    retry_count: u32,
    shared_scanned: Option<Arc<AtomicU32>>,
) -> Result<Vec<Device>, ScanError> {
    let mut cancel_rx = cancel_rx;
    let effective_concurrency = if max_concurrent == 0 {
        DEFAULT_MAX_CONCURRENT_HOSTS
    } else {
        max_concurrent
    };
    let semaphore = Arc::new(Semaphore::new(effective_concurrency));
    let found_devices = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let total = ips.len() as u32;
    let scanned = Arc::new(std::sync::atomic::AtomicU32::new(0));

    emit_log(
        &event_tx,
        "info",
        &format!(
            "Starting host discovery for {} targets (max {} concurrent, {} retries)",
            total, effective_concurrency, retry_count
        ),
        None,
    );

    // Wrap the entire stream collection in tokio::select! so that cancellation
    // drops the stream and all in-flight tasks immediately.
    let result = tokio::select! {
        _ = &mut cancel_rx => {
            emit_log(&event_tx, "warn", "Scan cancelled by user", None);
            let partial = found_devices.lock().await.clone();
            emit_log(
                &event_tx,
                "info",
                &format!(
                    "Scan cancelled. {} devices found before cancellation",
                    partial.len()
                ),
                None,
            );
            return Ok(partial);
        }
        _results = stream::iter(ips)
            .map(|ip| {
                let sem = semaphore.clone();
                let event_tx = event_tx.clone();
                let found = found_devices.clone();
                let scanned = scanned.clone();
                let shared_scanned = shared_scanned.clone();

                async move {
                    let _permit = sem.acquire().await.ok();

                    let current = scanned.fetch_add(1, Ordering::SeqCst) + 1;
                    if let Some(shared_scanned) = shared_scanned {
                        shared_scanned.store(current, Ordering::SeqCst);
                    }

                    // Update current target
                    let target_str = ip.to_string();

                    // Emit log for debug purposes every N hosts
                    if current % PROGRESS_INTERVAL == 0 || current == 1 {
                        emit_log(
                            &event_tx,
                            "debug",
                            &format!("Scanning {} ({}/{})", target_str, current, total),
                            Some(&target_str),
                        );
                    }

                    // TCP probe to check if host is alive (with retry)
                    let is_alive = check_host_alive_with_retry(ip, retry_count).await;

                    if is_alive {
                        emit_log(
                            &event_tx,
                            "info",
                            &format!("Host found: {}", target_str),
                            Some(&target_str),
                        );

                        let mut device = Device::new(ip.to_string());
                        device.status = DeviceStatus::Online;

                        // Try to get MAC address from ARP cache
                        if let Some(mac) = get_mac_from_arp(&target_str).await {
                            // Look up OUI vendor
                            let vendor = oui::lookup_vendor(&mac);
                            device = device.with_mac(mac).with_vendor(vendor);
                        }
                        // If ARP lookup fails, leave mac as empty/unknown - do not fabricate

                        // Attempt reverse DNS lookup
                        if let Some(hostname) = reverse_dns_lookup(&target_str).await {
                            device = device.with_hostname(Some(hostname));
                        }

                        found.lock().await.push(device.clone());

                        // Emit device found event
                        let _ = event_tx.send(AppEvent::DeviceFound(device));
                    }

                    // Emit progress every N hosts
                    if current % PROGRESS_INTERVAL == 0 {
                        let _ = event_tx.send(AppEvent::ScanProgress {
                            scanned: current,
                            total,
                            current_target: target_str,
                        });
                    }

                    Some(is_alive)
                }
            })
            .buffer_unordered(effective_concurrency)
            .filter_map(|r| async move { r })
            .collect::<Vec<bool>>() => {
            let result = found_devices.lock().await.clone();
            emit_log(
                &event_tx,
                "info",
                &format!("Host discovery complete. Found {} devices", result.len()),
                None,
            );
            Ok(result)
        }
    };

    result
}

/// Get MAC address from the system ARP cache for a given IP.
///
/// Delegates to the platform-specific `ArpProvider` implementation:
/// - **Linux**: Reads `/proc/net/arp`
/// - **Windows**: Executes `arp -a` and searches output
/// - **macOS**: Executes `arp -a` and searches output
async fn get_mac_from_arp(ip: &str) -> Option<String> {
    let provider = crate::network::platform::create_arp_provider();
    provider.get_mac_for_ip(ip).await
}

/// Attempt reverse DNS lookup for an IP address with a timeout.
/// Returns `None` if lookup fails or times out.
///
/// Uses `libc::getnameinfo` via `spawn_blocking` since reverse DNS
/// is a blocking operation with no pure-async alternative in tokio.
pub async fn reverse_dns_lookup(ip: &str) -> Option<String> {
    let ip_owned = ip.to_string();
    let timeout = std::time::Duration::from_secs(2);

    let lookup = tokio::task::spawn_blocking(move || reverse_dns_lookup_blocking(&ip_owned));

    match tokio::time::timeout(timeout, lookup).await {
        Ok(Ok(result)) => result,
        _ => None,
    }
}

/// Blocking reverse DNS lookup using `libc::getnameinfo`.
///
/// Returns `Some(hostname)` if a PTR record is found and it differs from the IP.
fn reverse_dns_lookup_blocking(ip: &str) -> Option<String> {
    use std::ffi::CStr;
    use std::mem;
    use std::net::IpAddr;
    use std::os::raw::c_char;

    let ip_addr: IpAddr = ip.parse().ok()?;

    // Prepare sockaddr storage
    // SAFETY: `sockaddr_storage` is a plain-old-data struct; zeroing it is safe
    // because all fields are integers/byte arrays and zero is a valid bit pattern.
    let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
    let sockaddr_len: libc::socklen_t;

    match ip_addr {
        IpAddr::V4(v4) => {
            // SAFETY: `sockaddr_storage` is guaranteed to be at least as large as
            // `sockaddr_in`, and both share the same initial layout (sa_family).
            let addr = unsafe { &mut *(&mut storage as *mut _ as *mut libc::sockaddr_in) };
            addr.sin_family = libc::AF_INET as libc::sa_family_t;
            addr.sin_port = 0;
            addr.sin_addr = libc::in_addr {
                s_addr: u32::from_ne_bytes(v4.octets()),
            };
            sockaddr_len = mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        }
        IpAddr::V6(v6) => {
            // SAFETY: `sockaddr_storage` is guaranteed to be at least as large as
            // `sockaddr_in6`, and both share the same initial layout (sa_family).
            let addr = unsafe { &mut *(&mut storage as *mut _ as *mut libc::sockaddr_in6) };
            addr.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            addr.sin6_port = 0;
            addr.sin6_addr = libc::in6_addr {
                s6_addr: v6.octets(),
            };
            sockaddr_len = mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
        }
    }

    let mut host_buf = [0u8; 1025]; // NI_MAXHOST is 1025

    // SAFETY: We've properly initialized `storage` with the correct sockaddr
    // structure for the IP version. `host_buf` is a valid writable buffer.
    // `getnameinfo` will write at most `host_buf.len()` bytes.
    let result = unsafe {
        libc::getnameinfo(
            &storage as *const _ as *const libc::sockaddr,
            sockaddr_len,
            host_buf.as_mut_ptr() as *mut c_char,
            host_buf.len() as libc::socklen_t,
            std::ptr::null_mut(),
            0,
            libc::NI_NAMEREQD, // Require a hostname, fail if only IP is available
        )
    };

    if result != 0 {
        return None;
    }

    // SAFETY: `getnameinfo` returned 0, so `host_buf` contains a valid
    // null-terminated C string.
    let hostname = unsafe { CStr::from_ptr(host_buf.as_ptr() as *const c_char) }
        .to_str()
        .ok()?
        .to_string();

    // Only return if we got an actual hostname (not just the IP back)
    if hostname != ip {
        Some(hostname)
    } else {
        None
    }
}

/// Check if a host is alive by probing common ports, with retry support.
///
/// Retries the probe up to `retry_count` times if the initial attempt fails.
pub async fn check_host_alive_with_retry(ip: IpAddr, retry_count: u32) -> bool {
    for attempt in 0..=retry_count {
        if check_host_alive(ip).await {
            return true;
        }
        if attempt < retry_count {
            tracing::debug!("Retry {}/{} for host {}", attempt + 1, retry_count, ip);
        }
    }
    false
}

/// Check if a host is alive by probing common ports
async fn check_host_alive(ip: IpAddr) -> bool {
    for port in [22, 80, 443, 445, 3389, 8080, 139] {
        if probe_port(ip, port, 200).await {
            return true;
        }
    }
    false
}

/// Probe a specific port on an IP address
async fn probe_port(ip: IpAddr, port: u16, timeout_ms: u64) -> bool {
    let addr = std::net::SocketAddr::new(ip, port);
    let timeout_duration = Duration::from_millis(timeout_ms);

    match tokio::time::timeout(timeout_duration, TcpStream::connect(addr)).await {
        Ok(Ok(_stream)) => true,
        _ => false,
    }
}

/// Scan ports on a discovered host
pub async fn scan_ports(ip: IpAddr, ports: &[u16], timeout_ms: u64) -> Vec<Port> {
    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_PORTS));

    stream::iter(ports.to_vec())
        .map(|port| {
            let sem = semaphore.clone();
            let ip = ip;

            async move {
                let _permit = sem.acquire().await.ok();
                let state = scan_single_port(ip, port, timeout_ms).await;
                Some((port, state))
            }
        })
        .buffer_unordered(MAX_CONCURRENT_PORTS)
        .filter_map(|r| async { r })
        .collect::<Vec<(u16, PortState)>>()
        .await
        .into_iter()
        .map(|(port, state)| {
            let service = crate::types::get_service_name(port);
            Port {
                number: port,
                protocol: "tcp".to_string(),
                service,
                state,
            }
        })
        .collect()
}

/// Scan a single port with timeout
async fn scan_single_port(ip: IpAddr, port: u16, timeout_ms: u64) -> PortState {
    let addr = std::net::SocketAddr::new(ip, port);
    let timeout_duration = Duration::from_millis(timeout_ms);

    match tokio::time::timeout(timeout_duration, TcpStream::connect(addr)).await {
        Ok(Ok(_stream)) => PortState::Open,
        Ok(Err(_)) => PortState::Closed,
        Err(_) => PortState::Filtered,
    }
}
