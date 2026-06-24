//! UDP port scanning module.
//!
//! Sends empty UDP datagrams (or protocol-specific probes) to target ports
//! and analyzes responses:
//!
//! - **ICMP Port Unreachable** → port is `Closed`
//! - **UDP response received** → port is `Open`
//! - **No response (timeout)** → port is `Filtered` (open|filtered, ambiguous)
//!
//! # Concurrency
//!
//! Uses `tokio::sync::Semaphore` with a maximum of 50 concurrent UDP probes.
//! UDP is connectionless, so we can be more aggressive than TCP connect scans
//! without risking file descriptor exhaustion.
//!
//! # Protocol-Specific Probes
//!
//! For well-known UDP services, we send minimal valid protocol packets to
//! increase the likelihood of receiving a response from open ports:
//!
//! - **DNS (53)**: Minimal DNS query for `.` (root)
//! - **NTP (123)**: Minimal NTP client request (version 4, client mode)
//! - **SNMP (161)**: Minimal SNMPv2c GetRequest
//! - **All others**: Empty datagram

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use futures::stream::{self, StreamExt};
use tokio::net::UdpSocket;
use tokio::sync::Semaphore;
use tracing::{debug, warn};

use crate::types::{get_service_name, Port, PortState};

/// Maximum concurrent UDP probes to avoid socket exhaustion.
const MAX_CONCURRENT_UDP_PROBES: usize = 50;

/// Default UDP ports to scan when no explicit port list is provided.
pub const DEFAULT_UDP_PORTS: &[u16] = &[
    53,   // DNS
    67,   // DHCP Server
    68,   // DHCP Client
    69,   // TFTP
    123,  // NTP
    161,  // SNMP
    162,  // SNMP Trap
    500,  // IKE (IPsec)
    514,  // Syslog
    1900, // SSDP/UPnP
    5353, // mDNS (Bonjour)
    5355, // LLMNR
    4789, // VXLAN
];

/// Scan a list of UDP ports on a target IP address.
///
/// For each port, sends a UDP datagram (protocol-specific probe for known
/// services, empty datagram otherwise) and waits for a response within the
/// specified timeout.
///
/// # Arguments
/// * `ip` - Target IP address (IPv4 or IPv6)
/// * `ports` - List of port numbers to scan
/// * `timeout_ms` - Per-port timeout in milliseconds
///
/// # Returns
/// A `Vec<Port>` with one entry per scanned port, each with its determined
/// state (`Open`, `Closed`, or `Filtered`).
pub async fn scan_udp_ports(ip: IpAddr, ports: &[u16], timeout_ms: u64) -> Vec<Port> {
    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_UDP_PROBES));
    let timeout = Duration::from_millis(timeout_ms);

    debug!(
        target_ip = %ip,
        port_count = ports.len(),
        timeout_ms = timeout_ms,
        "Starting UDP port scan"
    );

    let results: Vec<(u16, PortState)> = stream::iter(ports.to_vec())
        .map(|port| {
            let sem = semaphore.clone();
            let ip = ip;

            async move {
                let _permit = sem.acquire().await.ok();
                let state = scan_single_udp_port(ip, port, timeout).await;
                (port, state)
            }
        })
        .buffer_unordered(MAX_CONCURRENT_UDP_PROBES)
        .collect()
        .await;

    let scanned_ports: Vec<Port> = results
        .into_iter()
        .map(|(port, state)| {
            let service = get_service_name(port);
            Port {
                number: port,
                protocol: "udp".to_string(),
                service,
                state,
            }
        })
        .collect();

    debug!(
        target_ip = %ip,
        open = scanned_ports.iter().filter(|p| p.state == PortState::Open).count(),
        closed = scanned_ports.iter().filter(|p| p.state == PortState::Closed).count(),
        filtered = scanned_ports.iter().filter(|p| p.state == PortState::Filtered).count(),
        "UDP port scan complete"
    );

    scanned_ports
}

/// Scan a single UDP port on a target IP.
///
/// Creates an ephemeral UDP socket, sends a probe datagram, and waits for
/// a response within the timeout period.
///
/// # State determination
/// - `Open`: A UDP response was received from the target port
/// - `Closed`: The OS reported `ConnectionRefused` (ICMP Port Unreachable)
/// - `Filtered`: No response within the timeout (port may be open or firewalled)
async fn scan_single_udp_port(ip: IpAddr, port: u16, timeout: Duration) -> PortState {
    // Bind to an ephemeral port on the appropriate address family
    let bind_addr = match ip {
        IpAddr::V4(_) => "0.0.0.0:0",
        IpAddr::V6(_) => "[::]:0",
    };

    let socket = match UdpSocket::bind(bind_addr).await {
        Ok(s) => s,
        Err(e) => {
            warn!(
                target_ip = %ip,
                port = port,
                error = %e,
                "Failed to bind UDP socket for probe"
            );
            return PortState::Filtered;
        }
    };

    // Connect the socket to the target (sets the default destination)
    let target_addr = std::net::SocketAddr::new(ip, port);
    if let Err(e) = socket.connect(target_addr).await {
        warn!(
            target_ip = %ip,
            port = port,
            error = %e,
            "Failed to connect UDP socket to target"
        );
        return PortState::Filtered;
    }

    // Build the probe payload
    let probe = build_udp_probe(port);

    // Send the probe datagram
    if let Err(e) = socket.send(&probe).await {
        warn!(
            target_ip = %ip,
            port = port,
            error = %e,
            "Failed to send UDP probe"
        );
        return PortState::Filtered;
    }

    // Wait for a response with timeout
    let mut recv_buf = [0u8; 4096];

    match tokio::time::timeout(timeout, socket.recv(&mut recv_buf)).await {
        Ok(Ok(bytes_received)) => {
            if bytes_received > 0 {
                debug!(
                    target_ip = %ip,
                    port = port,
                    bytes = bytes_received,
                    "UDP response received — port is open"
                );
                PortState::Open
            } else {
                // Zero-byte response is unusual but treat as open
                PortState::Open
            }
        }
        Ok(Err(e)) => {
            // On Linux, ICMP Port Unreachable manifests as ConnectionRefused
            // on the connected UDP socket's recv() call.
            match e.kind() {
                std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::ConnectionReset => {
                    debug!(
                        target_ip = %ip,
                        port = port,
                        "ICMP Port Unreachable received — port is closed"
                    );
                    PortState::Closed
                }
                _ => {
                    debug!(
                        target_ip = %ip,
                        port = port,
                        error = %e,
                        "UDP recv error — treating as filtered"
                    );
                    PortState::Filtered
                }
            }
        }
        Err(_) => {
            // Timeout — no response received
            debug!(
                target_ip = %ip,
                port = port,
                "UDP probe timed out — port is open|filtered"
            );
            PortState::Filtered
        }
    }
}

/// Build a protocol-specific UDP probe payload for the given port.
///
/// For well-known UDP services, returns a minimal valid protocol packet
/// to increase the chance of eliciting a response from an open port.
/// For all other ports, returns an empty datagram.
fn build_udp_probe(port: u16) -> Vec<u8> {
    match port {
        53 => build_dns_probe(),
        123 => build_ntp_probe(),
        161 => build_snmp_probe(),
        _ => Vec::new(), // Empty datagram for all other ports
    }
}

/// Build a minimal DNS query probe.
///
/// Constructs a standard DNS query for the root domain (`.`) with type A
/// and class IN. This is the smallest valid DNS query that most DNS
/// servers will respond to.
///
/// Packet layout:
/// - Transaction ID: 2 bytes (0x1234)
/// - Flags: 2 bytes (standard query, recursion desired)
/// - Questions: 1
/// - Answer/Authority/Additional RRs: 0
/// - Query: root label (0x00), type A (0x0001), class IN (0x0001)
fn build_dns_probe() -> Vec<u8> {
    vec![
        0x12, 0x34, // Transaction ID
        0x01, 0x00, // Flags: standard query, recursion desired (RD=1)
        0x00, 0x01, // Questions: 1
        0x00, 0x00, // Answer RRs: 0
        0x00, 0x00, // Authority RRs: 0
        0x00, 0x00, // Additional RRs: 0
        0x00, // Root domain label (empty = ".")
        0x00, 0x01, // Type: A
        0x00, 0x01, // Class: IN
    ]
}

/// Build a minimal NTP client request probe.
///
/// Constructs a 48-byte NTP packet with:
/// - LI (Leap Indicator): 0 (no warning)
/// - Version: 4
/// - Mode: 3 (client)
/// - All other fields zeroed
///
/// The first byte encodes LI (2 bits) + Version (3 bits) + Mode (3 bits):
/// `00_100_011` = 0x23
fn build_ntp_probe() -> Vec<u8> {
    let mut packet = vec![0u8; 48];
    // LI=0 (00), Version=4 (100), Mode=3 client (011) → 0b00100011 = 0x23
    packet[0] = 0x23;
    packet
}

/// Build a minimal SNMPv2c GetRequest probe.
///
/// Constructs a valid SNMPv2c GetRequest for the `sysDescr` OID
/// (1.3.6.1.2.1.1.1.0) with community string "public".
///
/// This is the most basic SNMP request that any SNMP agent should respond to.
fn build_snmp_probe() -> Vec<u8> {
    // Pre-built SNMPv2c GetRequest for sysDescr.0 with community "public"
    // This is a hand-crafted BER-encoded SNMP PDU:
    //
    // SEQUENCE {
    //   INTEGER version (1 = SNMPv2c)
    //   OCTET STRING community ("public")
    //   GetRequest-PDU {
    //     INTEGER request-id (1)
    //     INTEGER error-status (0)
    //     INTEGER error-index (0)
    //     SEQUENCE OF {
    //       SEQUENCE {
    //         OID 1.3.6.1.2.1.1.1.0 (sysDescr.0)
    //         NULL
    //       }
    //     }
    //   }
    // }
    vec![
        0x30, 0x29, // SEQUENCE, length 41
        0x02, 0x01, 0x01, // INTEGER: version = 1 (SNMPv2c)
        0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, // OCTET STRING: "public"
        0xa0, 0x1c, // GetRequest-PDU, length 28
        0x02, 0x04, 0x00, 0x00, 0x00, 0x01, // INTEGER: request-id = 1
        0x02, 0x01, 0x00, // INTEGER: error-status = 0
        0x02, 0x01, 0x00, // INTEGER: error-index = 0
        0x30, 0x0e, // SEQUENCE OF, length 14
        0x30, 0x0c, // SEQUENCE, length 12
        0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01,
        0x00, // OID: 1.3.6.1.2.1.1.1.0 (sysDescr.0)
        0x05, 0x00, // NULL
    ]
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_udp_ports_not_empty() {
        assert!(!DEFAULT_UDP_PORTS.is_empty());
        assert!(DEFAULT_UDP_PORTS.contains(&53));
        assert!(DEFAULT_UDP_PORTS.contains(&123));
        assert!(DEFAULT_UDP_PORTS.contains(&161));
        assert!(DEFAULT_UDP_PORTS.contains(&5353));
    }

    #[test]
    fn test_build_dns_probe_structure() {
        let probe = build_dns_probe();
        // DNS header is 12 bytes + query section
        assert!(probe.len() >= 12);
        // Transaction ID should be 0x1234
        assert_eq!(probe[0], 0x12);
        assert_eq!(probe[1], 0x34);
        // Flags: standard query with RD=1 → 0x0100
        assert_eq!(probe[2], 0x01);
        assert_eq!(probe[3], 0x00);
        // Questions count = 1
        assert_eq!(probe[4], 0x00);
        assert_eq!(probe[5], 0x01);
    }

    #[test]
    fn test_build_ntp_probe_structure() {
        let probe = build_ntp_probe();
        // NTP packets are exactly 48 bytes
        assert_eq!(probe.len(), 48);
        // First byte: LI=0, Version=4, Mode=3 → 0x23
        assert_eq!(probe[0], 0x23);
        // Rest should be zeros
        assert!(probe[1..].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_build_snmp_probe_structure() {
        let probe = build_snmp_probe();
        // SNMP probe should be a valid BER-encoded SEQUENCE
        assert!(probe.len() > 10);
        // First byte should be SEQUENCE tag (0x30)
        assert_eq!(probe[0], 0x30);
        // Should contain "public" community string
        let public = b"public";
        assert!(
            probe.windows(public.len()).any(|w| w == public),
            "SNMP probe should contain 'public' community string"
        );
    }

    #[test]
    fn test_build_udp_probe_empty_for_unknown_ports() {
        // Ports without specific probes should return empty datagrams
        assert!(build_udp_probe(69).is_empty()); // TFTP
        assert!(build_udp_probe(500).is_empty()); // IKE
        assert!(build_udp_probe(514).is_empty()); // Syslog
        assert!(build_udp_probe(1900).is_empty()); // SSDP
        assert!(build_udp_probe(9999).is_empty()); // Unknown
    }

    #[test]
    fn test_build_udp_probe_known_ports() {
        // Known ports should return non-empty probes
        assert!(!build_udp_probe(53).is_empty()); // DNS
        assert!(!build_udp_probe(123).is_empty()); // NTP
        assert!(!build_udp_probe(161).is_empty()); // SNMP
    }

    #[tokio::test]
    async fn test_scan_udp_ports_returns_correct_count() {
        // Scan a small set of ports on localhost.
        // We don't assert specific states (depends on system config),
        // but we verify the function returns one result per port.
        let ports = vec![53, 123, 9999];
        let results = scan_udp_ports(
            "127.0.0.1".parse().unwrap(),
            &ports,
            500, // Short timeout for test speed
        )
        .await;

        assert_eq!(
            results.len(),
            ports.len(),
            "Should return one Port result per scanned port"
        );

        // All results should have protocol "udp"
        for port_result in &results {
            assert_eq!(port_result.protocol, "udp");
        }
    }

    #[tokio::test]
    async fn test_scan_udp_ports_empty_list() {
        let results = scan_udp_ports("127.0.0.1".parse().unwrap(), &[], 500).await;

        assert!(
            results.is_empty(),
            "Empty port list should return empty results"
        );
    }

    #[tokio::test]
    async fn test_scan_udp_localhost_closed_port() {
        // Port 1 is almost certainly not running a UDP service on localhost.
        // We expect either Closed (ICMP unreachable) or Filtered (timeout).
        let results = scan_udp_ports("127.0.0.1".parse().unwrap(), &[1], 500).await;

        assert_eq!(results.len(), 1);
        assert!(
            results[0].state == PortState::Closed || results[0].state == PortState::Filtered,
            "Port 1 on localhost should be Closed or Filtered, got {:?}",
            results[0].state
        );
    }

    #[tokio::test]
    async fn test_scan_udp_port_service_names() {
        let ports = vec![53, 123, 161];
        let results = scan_udp_ports("127.0.0.1".parse().unwrap(), &ports, 500).await;

        // Verify service names are populated for known ports
        let dns_port = results.iter().find(|p| p.number == 53).unwrap();
        assert_eq!(dns_port.service, Some("DNS".to_string()));

        let ntp_port = results.iter().find(|p| p.number == 123).unwrap();
        assert_eq!(ntp_port.service, Some("NTP".to_string()));

        let snmp_port = results.iter().find(|p| p.number == 161).unwrap();
        assert_eq!(snmp_port.service, Some("SNMP".to_string()));
    }
}
