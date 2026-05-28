use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use futures::stream::{self, StreamExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tauri::Emitter;

use crate::error::ScanError;
use crate::types::{Device, DeviceFoundEvent, DeviceStatus, Port, PortState, ScanProgressEvent, ScanStartedEvent};

/// Maximum concurrent host checks
const MAX_CONCURRENT_HOSTS: usize = 50;

/// Maximum concurrent port checks per host
const MAX_CONCURRENT_PORTS: usize = 100;

/// Progress update interval (every N hosts)
const PROGRESS_INTERVAL: u32 = 10;

/// Common ports to scan if none specified
pub const DEFAULT_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995,
    3306, 3389, 5432, 5900, 6379, 8080, 8443,
];

/// Emit a scan_log event to the frontend
async fn emit_log(
    app: &tauri::AppHandle,
    level: &str,
    message: &str,
    target: Option<&str>,
) {
    let log_event = crate::types::ScanLogEvent {
        level: level.to_string(),
        message: message.to_string(),
        target: target.map(|s| s.to_string()),
        timestamp: chrono::Utc::now().timestamp(),
    };
    let _ = app.emit("scan_log", log_event);
}

/// Discover live hosts by TCP probing common ports
pub async fn discover_hosts(
    ips: Vec<IpAddr>,
    app: Arc<tauri::AppHandle>,
    _cancel_rx: tokio::sync::oneshot::Receiver<()>,
) -> Result<Vec<Device>, ScanError> {
    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_HOSTS));
    let found_devices = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let total = ips.len() as u32;
    let scanned = Arc::new(std::sync::atomic::AtomicU32::new(0));

    // Emit scan started event
    let started_event = ScanStartedEvent {
        scan_id: uuid::Uuid::new_v4().to_string(),
        target_cidr: "unknown".to_string(), // Caller should set this properly
        total_hosts: total,
        timestamp: chrono::Utc::now().timestamp(),
    };
    let _ = app.emit("scan_started", started_event);

    emit_log(&app, "info", &format!("Starting host discovery for {} targets", total), None).await;

    stream::iter(ips)
        .map(|ip| {
            let sem = semaphore.clone();
            let app = app.clone();
            let found = found_devices.clone();
            let scanned = scanned.clone();

            async move {
                let _permit = sem.acquire().await.ok();

                let current = scanned.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;

                // Update current target
                let target_str = ip.to_string();

                // Emit log for debug purposes every N hosts
                if current % PROGRESS_INTERVAL == 0 || current == 1 {
                    emit_log(
                        &app,
                        "debug",
                        &format!("Scanning {} ({}/{})", target_str, current, total),
                        Some(&target_str),
                    ).await;
                }

                // TCP probe to check if host is alive
                let is_alive = check_host_alive(ip).await;

                if is_alive {
                    emit_log(
                        &app,
                        "info",
                        &format!("Host found: {}", target_str),
                        Some(&target_str),
                    ).await;

                    let mut device = Device::new(ip.to_string());
                    device.status = DeviceStatus::Online;

                    // Try to get MAC address from /proc/net/arp
                    if let Some(mac) = get_mac_from_arp(&target_str).await {
                        device.mac = mac;
                    }
                    // If ARP lookup fails, leave mac as empty/unknown - do not fabricate

                    found.lock().await.push(device.clone());

                    // Emit device found event with discovery method
                    let event = DeviceFoundEvent {
                        ip: device.ip.clone(),
                        mac: device.mac.clone(),
                        hostname: device.hostname.clone(),
                        timestamp: chrono::Utc::now().timestamp(),
                        ports: Vec::new(),
                        discovery_method: "TcpProbe".to_string(),
                    };
                    let _ = app.emit("device_found", event);
                }

                // Emit progress every N hosts
                if current % PROGRESS_INTERVAL == 0 {
                    let progress = ScanProgressEvent {
                        scanned: current,
                        total,
                        current_target: target_str,
                        devices_found: found.lock().await.len() as u32,
                    };
                    let _ = app.emit("scan_progress", progress);
                }

                Some(is_alive)
            }
        })
        .buffer_unordered(MAX_CONCURRENT_HOSTS)
        .filter_map(|r| async move { r })
        .collect::<Vec<bool>>()
        .await;

    let result = found_devices.lock().await.clone();
    emit_log(
        &app,
        "info",
        &format!("Host discovery complete. Found {} devices", result.len()),
        None,
    ).await;

    Ok(result)
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
pub async fn scan_ports(
    ip: IpAddr,
    ports: &[u16],
    timeout_ms: u64,
) -> Vec<Port> {
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

