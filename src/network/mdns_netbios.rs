//! NetBIOS and mDNS Enumeration
//!
//! Native implementations of NBNS (UDP 137) and mDNS (UDP 5353) parsers
//! using tokio `UdpSocket` directly.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;
use tracing::warn;

use crate::error::ScanError;
use crate::types::{Device, DeviceStatus};

/// Perform mDNS discovery on the local network (224.0.0.251:5353).
pub async fn discover_mdns() -> Result<Vec<Device>, ScanError> {
    let mut discovered = Vec::new();
    let mdns_addr: SocketAddr = "224.0.0.251:5353"
        .parse()
        .map_err(|e| ScanError::NetworkError(format!("Invalid mDNS address: {}", e)))?;
    let bind_addr: SocketAddr = "0.0.0.0:0"
        .parse()
        .map_err(|e| ScanError::NetworkError(format!("Invalid bind address: {}", e)))?;

    let socket = UdpSocket::bind(&bind_addr)
        .await
        .map_err(|e| ScanError::NetworkError(format!("Failed to bind mDNS socket: {}", e)))?;

    socket.set_multicast_loop_v4(true).ok();

    // Standard mDNS PTR query for _services._dns-sd._udp.local.
    let query = build_mdns_service_discovery_query();

    if let Err(e) = socket.send_to(&query, &mdns_addr).await {
        warn!("Failed to send mDNS query: {}", e);
        return Err(ScanError::NetworkError(format!(
            "Failed to send mDNS query: {}",
            e
        )));
    }

    let mut buf = [0u8; 1024];
    let timeout = Duration::from_secs(3);
    let deadline = tokio::time::Instant::now() + timeout;

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }

        match tokio::time::timeout(remaining, socket.recv_from(&mut buf)).await {
            Ok(Ok((_len, src_addr))) => {
                // We got a response
                let ip_str = src_addr.ip().to_string();
                if !discovered.iter().any(|d: &Device| d.ip == ip_str) {
                    discovered.push(Device {
                        ip: ip_str,
                        mac: "".to_string(), // We can't get MAC easily from UdpSocket
                        hostname: None, // We would need full DNS parsing here to get the actual name from the answers
                        status: DeviceStatus::Online,
                        ports: vec![],
                        last_seen: chrono::Utc::now().timestamp(),
                        os: None,
                        vendor: None,
                        banner_results: vec![],
                        active_checks: vec![],
                        web_audits: vec![],
                        findings: vec![],
                    });
                }
            }
            Ok(Err(_)) | Err(_) => {
                // Timeout or receive error
                break;
            }
        }
    }

    Ok(discovered)
}

/// Perform NetBIOS Name Service (NBNS) discovery (137/UDP broadcast).
pub async fn discover_netbios(broadcast_ip: Ipv4Addr) -> Result<Vec<Device>, ScanError> {
    let mut discovered = Vec::new();
    let nbns_addr = SocketAddr::new(std::net::IpAddr::V4(broadcast_ip), 137);
    let bind_addr: SocketAddr = "0.0.0.0:0"
        .parse()
        .map_err(|e| ScanError::NetworkError(format!("Invalid bind address: {}", e)))?;

    let socket = UdpSocket::bind(&bind_addr)
        .await
        .map_err(|e| ScanError::NetworkError(format!("Failed to bind NBNS socket: {}", e)))?;

    socket.set_broadcast(true).ok();

    // NetBIOS Node Status Request (Query: `*`)
    let query = build_nbns_status_request();

    if let Err(e) = socket.send_to(&query, &nbns_addr).await {
        warn!("Failed to send NBNS query: {}", e);
        return Err(ScanError::NetworkError(format!(
            "Failed to send NBNS query: {}",
            e
        )));
    }

    let mut buf = [0u8; 1024];
    let timeout = Duration::from_secs(3);
    let deadline = tokio::time::Instant::now() + timeout;

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }

        match tokio::time::timeout(remaining, socket.recv_from(&mut buf)).await {
            Ok(Ok((len, src_addr))) => {
                let ip_str = src_addr.ip().to_string();

                // Parse NetBIOS response to get hostname and MAC if possible
                let (hostname, mac) = parse_nbns_response(&buf[..len]);

                if !discovered.iter().any(|d: &Device| d.ip == ip_str) {
                    discovered.push(Device {
                        ip: ip_str,
                        mac: mac.unwrap_or_default(),
                        hostname,
                        status: DeviceStatus::Online,
                        ports: vec![],
                        last_seen: chrono::Utc::now().timestamp(),
                        os: None,
                        vendor: None,
                        banner_results: vec![],
                        active_checks: Vec::new(),
                        web_audits: Vec::new(),
                        findings: Vec::new(),
                    });
                }
            }
            Ok(Err(_)) | Err(_) => {
                break;
            }
        }
    }

    Ok(discovered)
}

fn build_mdns_service_discovery_query() -> Vec<u8> {
    // Transaction ID: 0x0000, Flags: 0x0000, Q: 1, A: 0, Auth: 0, Add: 0
    // Query: _services._dns-sd._udp.local. (PTR, IN)
    vec![
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, b'_', b's',
        b'e', b'r', b'v', b'i', b'c', b'e', b's', 0x07, b'_', b'd', b'n', b's', b'-', b's', b'd',
        0x04, b'_', b'u', b'd', b'p', 0x05, b'l', b'o', b'c', b'a', b'l', 0x00, 0x00,
        0x0c, // Type: PTR
        0x00, 0x01, // Class: IN
    ]
}

fn build_nbns_status_request() -> Vec<u8> {
    // Transaction ID: 0x8228, Flags: 0x0000
    // Questions: 1
    // Query Name: `*`
    // Type: NBSTAT (0x0021), Class: IN (0x0001)
    vec![
        0x82, 0x28, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x43, 0x4b,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x00, 0x00, 0x21, 0x00, 0x01,
    ]
}

fn parse_nbns_response(buf: &[u8]) -> (Option<String>, Option<String>) {
    if buf.len() < 56 {
        return (None, None);
    }

    // Very simplified parser.
    // The number of names is usually at offset 56.
    let num_names = buf[56] as usize;

    let mut hostname = None;
    let mut offset = 57;

    for _ in 0..num_names {
        if offset + 18 > buf.len() {
            break;
        }

        let flags = u16::from_be_bytes([buf[offset + 16], buf[offset + 17]]);
        let is_group = (flags & 0x8000) != 0;
        let record_type = buf[offset + 15];

        // 0x00 is usually the unique hostname
        if record_type == 0x00 && !is_group && hostname.is_none() {
            let name_bytes = &buf[offset..offset + 15];
            let name_end = name_bytes
                .iter()
                .position(|&b| b == 0x20 || b == 0x00)
                .unwrap_or(15);
            hostname = String::from_utf8(name_bytes[..name_end].to_vec()).ok();
        }

        offset += 18;
    }

    let mut mac = None;
    if offset + 6 <= buf.len() {
        let m = &buf[offset..offset + 6];
        mac = Some(format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            m[0], m[1], m[2], m[3], m[4], m[5]
        ));
    }

    (hostname, mac)
}
