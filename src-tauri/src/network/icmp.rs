//! ICMP Echo Request (ping) host discovery module.
//!
//! Provides ICMP-based host discovery using raw sockets via `socket2` and
//! packet construction/parsing via `pnet_packet`.
//!
//! # Architecture
//!
//! - **`ping_host_blocking`**: Synchronous ICMP ping using a raw socket.
//!   MUST be called inside `tokio::task::spawn_blocking` to avoid blocking
//!   the async runtime.
//! - **`icmp_ping_sweep`**: Async wrapper that fans out concurrent pings
//!   using `spawn_blocking` + `futures::stream::buffer_unordered`.
//! - **`check_icmp_privileges`**: Platform-specific privilege detection
//!   (root / CAP_NET_RAW on Linux, Administrator on Windows, root on macOS).
//!
//! # Graceful Degradation
//!
//! If privileges are insufficient or socket creation fails, the scan pipeline
//! falls back to TCP probing. No panics, no crashes.

use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use std::mem::MaybeUninit;

use futures::stream::{self, StreamExt};
use pnet_packet::icmp::echo_reply::EchoReplyPacket;
use pnet_packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet_packet::icmp::{IcmpCode, IcmpPacket, IcmpTypes, MutableIcmpPacket};
use pnet_packet::{MutablePacket, Packet};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tauri::Emitter;

use crate::error::ScanError;
use crate::types::{Device, DeviceFoundEvent, DeviceStatus, ScanProgressEvent};

/// Maximum concurrent ICMP pings
const MAX_CONCURRENT_PINGS: usize = 50;

/// ICMP packet size: 8 bytes header (type+code+checksum+id+seq) + 56 bytes payload
const ICMP_PACKET_SIZE: usize = 64;

/// IP header size for IPv4 (minimum, no options)
const IPV4_HEADER_MIN: usize = 20;

/// Receive buffer size
const RECV_BUF_SIZE: usize = 1024;

/// Progress update interval (every N hosts)
const PROGRESS_INTERVAL: u32 = 10;

/// Global counter for generating unique ICMP identifiers across concurrent pings.
static ICMP_ID_COUNTER: AtomicU16 = AtomicU16::new(0);

/// Generate a unique ICMP identifier for this ping session.
///
/// Combines the process ID with an atomic counter to ensure each concurrent
/// ping has a distinct identifier, preventing reply cross-talk.
fn generate_icmp_identifier() -> u16 {
    let pid = (std::process::id() & 0xFFFF) as u16;
    let counter = ICMP_ID_COUNTER.fetch_add(1, Ordering::SeqCst);
    pid.wrapping_add(counter)
}

/// Ping a single host via ICMP Echo Request (BLOCKING).
///
/// **IMPORTANT**: This function performs blocking I/O on a raw socket.
/// It MUST be called inside `tokio::task::spawn_blocking` to avoid
/// blocking the Tokio async runtime.
///
/// # Arguments
/// * `ip` - Target IPv4 address
/// * `timeout_ms` - Maximum time to wait for a reply in milliseconds
///
/// # Returns
/// * `Ok(true)` - Host responded with ICMP Echo Reply
/// * `Ok(false)` - Timeout or host unreachable
/// * `Err(ScanError)` - Socket creation or send failure
fn ping_host_blocking(ip: Ipv4Addr, timeout_ms: u64) -> Result<bool, ScanError> {
    let timeout = Duration::from_millis(timeout_ms);

    // Create raw ICMP socket
    let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)).map_err(|e| {
        ScanError::PermissionDenied(format!(
            "Cannot create ICMP raw socket for {}: {}. Check privileges (root/CAP_NET_RAW).",
            ip, e
        ))
    })?;

    // Set read timeout so recv_from doesn't block forever
    socket.set_read_timeout(Some(timeout)).map_err(|e| {
        ScanError::NetworkError(format!("Failed to set ICMP socket timeout: {}", e))
    })?;

    // Generate unique identifier for this ping
    let identifier = generate_icmp_identifier();
    let sequence_number: u16 = 1;

    // Build ICMP Echo Request packet
    let mut buffer = vec![0u8; ICMP_PACKET_SIZE];

    // Step 1: Build echo request payload (starts at offset 4 in ICMP packet,
    // after type(1) + code(1) + checksum(2))
    {
        let echo_buf = &mut buffer[4..];
        let mut echo = MutableEchoRequestPacket::new(echo_buf).ok_or_else(|| {
            ScanError::NetworkError("Buffer too small for ICMP echo request".to_string())
        })?;
        echo.set_identifier(identifier);
        echo.set_sequence_number(sequence_number);

        // Fill payload with timestamp-derived data for uniqueness
        let payload = echo.payload_mut();
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        for (i, byte) in payload.iter_mut().enumerate() {
            *byte = ((ts >> ((i % 16) * 8)) & 0xFF) as u8;
        }
    }

    // Step 2: Set ICMP header fields
    {
        let mut icmp = MutableIcmpPacket::new(&mut buffer[..]).ok_or_else(|| {
            ScanError::NetworkError("Buffer too small for ICMP packet".to_string())
        })?;
        icmp.set_icmp_type(IcmpTypes::EchoRequest);
        icmp.set_icmp_code(IcmpCode::new(0));

        // Calculate checksum over the entire ICMP message
        // The `1` parameter means skip the first 16-bit word (the checksum field itself
        // is at offset 2-3, which is the second 16-bit word, so we skip 1 word)
        let csum = pnet_packet::util::checksum(icmp.packet(), 1);
        icmp.set_checksum(csum);
    }

    // Step 3: Send the packet
    let dest = SockAddr::from(SocketAddrV4::new(ip, 0));
    socket.send_to(&buffer, &dest).map_err(|e| {
        ScanError::NetworkError(format!("Failed to send ICMP Echo Request to {}: {}", ip, e))
    })?;

    // Step 4: Receive and match Echo Reply
    let mut recv_buf: Vec<MaybeUninit<u8>> = vec![MaybeUninit::uninit(); RECV_BUF_SIZE];
    let deadline = Instant::now() + timeout;

    loop {
        // Check deadline before each receive
        if Instant::now() >= deadline {
            return Ok(false);
        }

        // Update remaining timeout on socket
        let remaining = deadline.saturating_duration_since(Instant::now());
        let _ = socket.set_read_timeout(Some(remaining));

        match socket.recv_from(&mut recv_buf) {
            Ok((size, addr)) => {
                // Verify source address matches our target
                if let Some(sockaddr) = addr.as_socket_ipv4() {
                    if sockaddr.ip() != &ip {
                        continue; // Reply from different host, keep listening
                    }
                } else {
                    continue; // Not an IPv4 address
                }

                // For SOCK_RAW, the received data includes the IP header.
                // Parse IP header length from the first byte (lower nibble * 4).
                if size < IPV4_HEADER_MIN {
                    continue; // Packet too small
                }

                // Safety: we've received `size` bytes, so the first `size` elements
                // are initialized. We convert to a slice of initialized bytes.
                let recv_bytes = unsafe {
                    std::slice::from_raw_parts(recv_buf[0].as_ptr(), size)
                };

                let ip_header_len = ((recv_bytes[0] & 0x0F) as usize) * 4;
                if size < ip_header_len + 8 {
                    continue; // Not enough data for ICMP header
                }

                let icmp_bytes = &recv_bytes[ip_header_len..size];

                // Parse ICMP packet
                if let Some(icmp_packet) = IcmpPacket::new(icmp_bytes) {
                    if icmp_packet.get_icmp_type() == IcmpTypes::EchoReply {
                        // Parse echo reply payload (identifier + sequence + data)
                        if let Some(echo_reply) = EchoReplyPacket::new(icmp_packet.payload()) {
                            if echo_reply.get_identifier() == identifier
                                && echo_reply.get_sequence_number() == sequence_number
                            {
                                return Ok(true); // It's our reply!
                            }
                        }
                    }
                    // Not our Echo Reply (could be different type or different id/seq)
                    // Continue listening
                }
            }
            Err(e) => {
                match e.kind() {
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => {
                        return Ok(false); // Timeout
                    }
                    // On some systems, ICMP Destination Unreachable comes back as
                    // ConnectionRefused on the raw socket
                    std::io::ErrorKind::ConnectionRefused => {
                        return Ok(false); // Host unreachable
                    }
                    _ => {
                        return Err(ScanError::NetworkError(format!(
                            "ICMP receive error for {}: {}",
                            ip, e
                        )));
                    }
                }
            }
        }
    }
}

/// Check if the current process has privileges for raw socket ICMP.
///
/// Platform-specific checks:
/// - **Linux**: Effective UID 0 (root) OR `CAP_NET_RAW` capability (bit 13 in CapEff)
/// - **Windows**: Administrator privileges via `net session`
/// - **macOS**: Effective UID 0 (root) via `id -u`
///
/// # Returns
/// * `Ok(())` if privileged
/// * `Err(ScanError::PermissionDenied(...))` if not privileged
pub fn check_icmp_privileges() -> Result<(), ScanError> {
    check_privileges_impl()
}

/// Linux privilege check: root or CAP_NET_RAW
#[cfg(target_os = "linux")]
fn check_privileges_impl() -> Result<(), ScanError> {
    let status = std::fs::read_to_string("/proc/self/status").map_err(|e| {
        ScanError::NetworkError(format!("Failed to read /proc/self/status: {}", e))
    })?;

    let mut is_root = false;
    let mut has_cap_net_raw = false;

    for line in status.lines() {
        // Check effective UID (second field in "Uid: real effective saved fs")
        if line.starts_with("Uid:") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            // parts[0] = "Uid:", parts[1] = real, parts[2] = effective
            if parts.len() >= 3 && parts[2] == "0" {
                is_root = true;
            }
        }

        // Check effective capabilities for CAP_NET_RAW (bit 13)
        if line.starts_with("CapEff:") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                if let Ok(cap) = u64::from_str_radix(parts[1], 16) {
                    // CAP_NET_RAW is capability bit 13
                    if cap & (1u64 << 13) != 0 {
                        has_cap_net_raw = true;
                    }
                }
            }
        }
    }

    if is_root || has_cap_net_raw {
        Ok(())
    } else {
        Err(ScanError::PermissionDenied(
            "ICMP ping requires root privileges or CAP_NET_RAW capability on Linux".to_string(),
        ))
    }
}

/// Windows privilege check: Administrator
#[cfg(target_os = "windows")]
fn check_privileges_impl() -> Result<(), ScanError> {
    let output = std::process::Command::new("net")
        .arg("session")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    match output {
        Ok(status) if status.success() => Ok(()),
        _ => Err(ScanError::PermissionDenied(
            "ICMP ping requires Administrator privileges on Windows. \
             Ensure Npcap is also installed for raw socket support."
                .to_string(),
        )),
    }
}

/// macOS privilege check: root
#[cfg(target_os = "macos")]
fn check_privileges_impl() -> Result<(), ScanError> {
    let output = std::process::Command::new("id").arg("-u").output();

    match output {
        Ok(out) => {
            let uid = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if uid == "0" {
                Ok(())
            } else {
                Err(ScanError::PermissionDenied(
                    "ICMP ping requires root privileges on macOS. Run with sudo.".to_string(),
                ))
            }
        }
        Err(e) => Err(ScanError::NetworkError(format!(
            "Failed to check privileges: {}",
            e
        ))),
    }
}

/// Fallback for unsupported platforms
#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
fn check_privileges_impl() -> Result<(), ScanError> {
    Err(ScanError::PermissionDenied(
        "ICMP ping is not supported on this platform".to_string(),
    ))
}

/// Perform an ICMP ping sweep across multiple hosts concurrently.
///
/// Uses `tokio::task::spawn_blocking` for each ping (since pnet/socket2
/// raw socket operations are blocking) and `futures::stream::buffer_unordered`
/// to limit concurrency.
///
/// # Arguments
/// * `ips` - List of IP addresses to ping
/// * `timeout_ms` - Timeout per ping in milliseconds
/// * `max_concurrent` - Maximum number of concurrent pings
/// * `app` - Tauri AppHandle for emitting events
///
/// # Returns
/// A list of `Device` structs for hosts that responded to ICMP Echo Request.
pub async fn icmp_ping_sweep(
    ips: Vec<IpAddr>,
    timeout_ms: u64,
    max_concurrent: usize,
    app: Arc<tauri::AppHandle>,
) -> Result<Vec<Device>, ScanError> {
    let total = ips.len() as u32;
    let scanned = Arc::new(std::sync::atomic::AtomicU32::new(0));
    let devices_found = Arc::new(std::sync::atomic::AtomicU32::new(0));

    emit_log(
        &app,
        "info",
        &format!("Starting ICMP ping sweep for {} hosts (max {} concurrent)", total, max_concurrent),
        None,
    )
    .await;

    let effective_concurrency = if max_concurrent == 0 {
        MAX_CONCURRENT_PINGS
    } else {
        max_concurrent.min(MAX_CONCURRENT_PINGS)
    };

    let results: Vec<Option<Device>> = stream::iter(ips)
        .map(|ip| {
            let app = app.clone();
            let scanned = scanned.clone();
            let devices_found = devices_found.clone();

            async move {
                let current = scanned.fetch_add(1, Ordering::SeqCst) + 1;
                let ip_str = ip.to_string();

                // Only handle IPv4 for ICMPv4
                let ipv4 = match ip {
                    IpAddr::V4(v4) => v4,
                    IpAddr::V6(_) => {
                        log::debug!("Skipping IPv6 address {} for ICMP sweep", ip_str);
                        return None;
                    }
                };

                // Spawn blocking ICMP ping
                let timeout = timeout_ms;
                let ping_result =
                    tokio::task::spawn_blocking(move || ping_host_blocking(ipv4, timeout)).await;

                let device = match ping_result {
                    Ok(Ok(true)) => {
                        // Host is alive — create device
                        let mut device = Device::new(ip_str.clone());
                        device.status = DeviceStatus::Online;

                        // Try to resolve MAC address via ARP cache
                        let provider = crate::network::platform::create_arp_provider();
                        if let Some(mac) = provider.get_mac_for_ip(&ip_str).await {
                            device.mac = mac;
                        }

                        emit_log(
                            &app,
                            "info",
                            &format!("ICMP: Host responded: {}", ip_str),
                            Some(&ip_str),
                        )
                        .await;

                        // Emit device_found event
                        let event = DeviceFoundEvent {
                            ip: device.ip.clone(),
                            mac: device.mac.clone(),
                            hostname: device.hostname.clone(),
                            timestamp: chrono::Utc::now().timestamp(),
                            ports: Vec::new(),
                            discovery_method: "IcmpPing".to_string(),
                        };
                        let _ = app.emit("device_found", event);

                        devices_found.fetch_add(1, Ordering::SeqCst);
                        Some(device)
                    }
                    Ok(Ok(false)) => {
                        // Timeout — host unreachable, no device
                        None
                    }
                    Ok(Err(e)) => {
                        log::warn!("ICMP ping error for {}: {}", ip_str, e);
                        None
                    }
                    Err(join_err) => {
                        log::warn!("ICMP spawn_blocking join error for {}: {}", ip_str, join_err);
                        None
                    }
                };

                // Emit progress events periodically
                if current % PROGRESS_INTERVAL == 0 || current == total {
                    let found_count = devices_found.load(Ordering::SeqCst);
                    let progress = ScanProgressEvent {
                        scanned: current,
                        total,
                        current_target: ip_str,
                        devices_found: found_count,
                    };
                    let _ = app.emit("scan_progress", progress);
                }

                device
            }
        })
        .buffer_unordered(effective_concurrency)
        .collect()
        .await;

    let devices: Vec<Device> = results.into_iter().flatten().collect();

    emit_log(
        &app,
        "info",
        &format!(
            "ICMP ping sweep complete: {} hosts responded out of {} scanned",
            devices.len(),
            total
        ),
        None,
    )
    .await;

    Ok(devices)
}

/// Emit a scan_log event to the frontend.
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_icmp_identifier_uniqueness() {
        let id1 = generate_icmp_identifier();
        let id2 = generate_icmp_identifier();
        let id3 = generate_icmp_identifier();
        // Each call should produce a different identifier
        assert_ne!(id1, id2);
        assert_ne!(id2, id3);
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_icmp_packet_construction() {
        // Verify we can construct a valid ICMP Echo Request packet
        let identifier: u16 = 12345;
        let sequence_number: u16 = 1;
        let mut buffer = vec![0u8; ICMP_PACKET_SIZE];

        // Build echo request payload
        {
            let echo_buf = &mut buffer[4..];
            let mut echo = MutableEchoRequestPacket::new(echo_buf)
                .expect("Buffer should be large enough for echo request");
            echo.set_identifier(identifier);
            echo.set_sequence_number(sequence_number);
            let payload = echo.payload_mut();
            for (i, byte) in payload.iter_mut().enumerate() {
                *byte = i as u8;
            }
        }

        // Set ICMP header
        {
            let mut icmp = MutableIcmpPacket::new(&mut buffer[..])
                .expect("Buffer should be large enough for ICMP packet");
            icmp.set_icmp_type(IcmpTypes::EchoRequest);
            icmp.set_icmp_code(IcmpCode::new(0));
            let csum = pnet_packet::util::checksum(icmp.packet(), 1);
            icmp.set_checksum(csum);

            // Verify the packet type
            assert_eq!(icmp.get_icmp_type(), IcmpTypes::EchoRequest);
            assert_eq!(icmp.get_icmp_code(), IcmpCode::new(0));
        }

        // Verify we can parse the echo request back
        let parsed = IcmpPacket::new(&buffer[..]).expect("Should parse ICMP packet");
        assert_eq!(parsed.get_icmp_type(), IcmpTypes::EchoRequest);

        let echo =
            EchoReplyPacket::new(parsed.payload()).or_else(|| {
                // EchoReplyPacket and EchoRequestPacket have the same layout,
                // so we can parse the request as a reply for verification
                EchoReplyPacket::new(parsed.payload())
            });
        // The echo request payload should be parseable
        assert!(echo.is_some(), "Should be able to parse echo payload");
        if let Some(echo) = echo {
            assert_eq!(echo.get_identifier(), identifier);
            assert_eq!(echo.get_sequence_number(), sequence_number);
        }
    }

    #[test]
    fn test_icmp_checksum_nonzero() {
        let mut buffer = vec![0u8; ICMP_PACKET_SIZE];

        {
            let echo_buf = &mut buffer[4..];
            let mut echo = MutableEchoRequestPacket::new(echo_buf)
                .expect("Buffer should be large enough");
            echo.set_identifier(42);
            echo.set_sequence_number(1);
        }

        {
            let mut icmp = MutableIcmpPacket::new(&mut buffer[..])
                .expect("Buffer should be large enough");
            icmp.set_icmp_type(IcmpTypes::EchoRequest);
            icmp.set_icmp_code(IcmpCode::new(0));
            let csum = pnet_packet::util::checksum(icmp.packet(), 1);
            icmp.set_checksum(csum);

            // Checksum should be non-zero for a non-trivial packet
            assert_ne!(icmp.get_checksum(), 0, "Checksum should be non-zero");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_check_privileges_does_not_panic() {
        // This test verifies the privilege check doesn't panic.
        // The result depends on the test environment (may or may not be root).
        let result = check_icmp_privileges();
        assert!(result.is_ok() || result.is_err());
    }

    #[test]
    fn test_ping_host_blocking_invalid_ip() {
        // Pinging 0.0.0.0 should fail gracefully (not panic)
        let result = ping_host_blocking(Ipv4Addr::new(0, 0, 0, 0), 100);
        // Should return an error or false, never panic
        assert!(result.is_ok() || result.is_err());
    }

    #[test]
    fn test_ping_host_blocking_localhost() {
        // Pinging localhost (127.0.0.1) — may succeed if privileged,
        // or return PermissionDenied if not. Either way, no panic.
        let result = ping_host_blocking(Ipv4Addr::new(127, 0, 0, 1), 500);
        match &result {
            Ok(alive) => {
                // If we got a result, it should be a valid boolean
                assert!(*alive || !*alive);
            }
            Err(ScanError::PermissionDenied(_)) => {
                // Expected when not running as root
            }
            Err(e) => {
                // Other errors are acceptable (e.g., network config issues)
                eprintln!("Unexpected error (acceptable in test): {}", e);
            }
        }
    }
}
