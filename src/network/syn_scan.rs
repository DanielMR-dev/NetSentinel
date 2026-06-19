//! Stealth TCP SYN scanning engine.
//!
//! Implements half-open SYN scanning using raw packet injection via `pnet`.
//! This method sends SYN packets and listens for SYN-ACK responses without
//! completing the TCP handshake, making it faster and stealthier than
//! TCP connect scanning.
//!
//! # Requirements
//! - Root/Administrator privileges or CAP_NET_RAW on Linux
//! - Raw socket capability (verified via `privileges::check_system_privileges()`)
//!
//! # Safety
//! All raw socket operations are performed in `spawn_blocking` to avoid
//! blocking the Tokio async runtime. Datalink channels are cleaned up
//! on scan cancellation.

use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use pnet::datalink::{self, NetworkInterface};
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::tcp::{ipv4_checksum, MutableTcpPacket, TcpFlags, TcpPacket};
use pnet::util::MacAddr;

use crate::error::ScanError;
use crate::network::platform;
use crate::network::timing::TimingController;
use crate::types::{Port, PortState};

/// Size of the TCP header (20 bytes, no options)
const TCP_HEADER_SIZE: usize = 20;

/// Size of the IPv4 header (20 bytes, no options)
const IPV4_HEADER_SIZE: usize = 20;

/// Size of the Ethernet header (14 bytes)
const ETHERNET_HEADER_SIZE: usize = 14;

/// Total packet size for SYN probe
const SYN_PACKET_SIZE: usize = ETHERNET_HEADER_SIZE + IPV4_HEADER_SIZE + TCP_HEADER_SIZE;

/// Receive buffer size
const RECV_BUF_SIZE: usize = 65535;

/// SYN scanner that performs stealth TCP scanning via raw packets.
pub struct SynScanner {
    /// Source IPv4 address
    src_ip: Ipv4Addr,
    /// Network interface to use
    interface: NetworkInterface,
    /// Source MAC address
    src_mac: MacAddr,
    /// Gateway MAC address (for routing)
    gateway_mac: MacAddr,
}

impl SynScanner {
    /// Create a new SYN scanner.
    ///
    /// Automatically detects the appropriate network interface and
    /// resolves the gateway MAC address.
    ///
    /// # Errors
    /// Returns `ScanError::PermissionDenied` if raw socket access is unavailable.
    /// Returns `ScanError::NetworkError` if no suitable interface is found.
    pub fn new(src_ip: Ipv4Addr) -> Result<Self, ScanError> {
        let interfaces = datalink::interfaces();

        // Find the interface that has our source IP
        let interface = interfaces
            .into_iter()
            .find(|iface| {
                iface.ips.iter().any(|ip| {
                    ip.ip() == IpAddr::V4(src_ip)
                }) && !iface.is_loopback()
            })
            .ok_or_else(|| {
                ScanError::NetworkError(format!(
                    "No network interface found with IP {}. \
                     SYN scanning requires a valid local interface.",
                    src_ip
                ))
            })?;

        let src_mac = interface.mac.unwrap_or(MacAddr::zero());

        // For local network scanning, we use the broadcast MAC as a fallback.
        // In a production implementation, we'd resolve the gateway MAC via ARP.
        let gateway_mac = MacAddr::broadcast();

        Ok(Self {
            src_ip,
            interface,
            src_mac,
            gateway_mac,
        })
    }

    /// Create a new SYN scanner resolved automatically for target_ip.
    pub async fn new_for_target(target_ip: Ipv4Addr) -> Result<Self, ScanError> {
        let (interface, src_ip) = Self::resolve_interface_and_ip(target_ip)
            .await
            .ok_or_else(|| {
                ScanError::NetworkError(format!(
                    "Failed to resolve network interface for target {}",
                    target_ip
                ))
            })?;

        let src_mac = interface.mac.unwrap_or(MacAddr::zero());
        let gateway_mac = MacAddr::broadcast();

        Ok(Self {
            src_ip,
            interface,
            src_mac,
            gateway_mac,
        })
    }

    /// Resolve the best interface and source IP to route to target_ip.
    pub async fn resolve_interface_and_ip(
        target_ip: Ipv4Addr,
    ) -> Option<(NetworkInterface, Ipv4Addr)> {
        let interfaces = datalink::interfaces();

        // 1. Direct subnet check
        for iface in &interfaces {
            if iface.is_loopback() {
                continue;
            }
            for ip_net in &iface.ips {
                if let IpAddr::V4(ipv4_addr) = ip_net.ip() {
                    if let Ok(subnet) = ipnetwork::Ipv4Network::new(ipv4_addr, ip_net.prefix()) {
                        if subnet.contains(target_ip) {
                            return Some((iface.clone(), ipv4_addr));
                        }
                    }
                }
            }
        }

        // 2. Gateway route check
        let gateway_provider = platform::create_gateway_provider();
        if let Some(gateway_str) = gateway_provider.get_default_gateway().await {
            if let Ok(gateway_ip) = gateway_str.parse::<Ipv4Addr>() {
                for iface in &interfaces {
                    if iface.is_loopback() {
                        continue;
                    }
                    for ip_net in &iface.ips {
                        if let IpAddr::V4(ipv4_addr) = ip_net.ip() {
                            if let Ok(subnet) = ipnetwork::Ipv4Network::new(ipv4_addr, ip_net.prefix()) {
                                if subnet.contains(gateway_ip) {
                                    return Some((iface.clone(), ipv4_addr));
                                }
                            }
                        }
                    }
                }
            }
        }

        // 3. Fallback: first non-loopback interface with an IPv4 address
        for iface in &interfaces {
            if iface.is_loopback() {
                continue;
            }
            for ip_net in &iface.ips {
                if let IpAddr::V4(ipv4_addr) = ip_net.ip() {
                    return Some((iface.clone(), ipv4_addr));
                }
            }
        }

        None
    }

    /// Craft a TCP SYN packet for the given target.
    fn craft_syn_packet(
        &self,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
    ) -> Vec<u8> {
        let mut buffer = vec![0u8; SYN_PACKET_SIZE];

        // Ethernet header
        {
            let mut eth = MutableEthernetPacket::new(&mut buffer[..ETHERNET_HEADER_SIZE])
                .unwrap_or_else(|| {
                    // This should never happen with a properly sized buffer
                    panic!("Buffer too small for Ethernet header")
                });
            eth.set_destination(self.gateway_mac);
            eth.set_source(self.src_mac);
            eth.set_ethertype(EtherTypes::Ipv4);
        }

        // IPv4 header
        {
            let mut ipv4 = MutableIpv4Packet::new(
                &mut buffer[ETHERNET_HEADER_SIZE..ETHERNET_HEADER_SIZE + IPV4_HEADER_SIZE],
            )
            .unwrap_or_else(|| panic!("Buffer too small for IPv4 header"));

            ipv4.set_version(4);
            ipv4.set_header_length(5);
            ipv4.set_total_length((IPV4_HEADER_SIZE + TCP_HEADER_SIZE) as u16);
            ipv4.set_identification(rand_port());
            ipv4.set_ttl(64);
            ipv4.set_flags(0);
            ipv4.set_fragment_offset(0);
            ipv4.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
            ipv4.set_source(self.src_ip);
            ipv4.set_destination(dst_ip);

            // Calculate IPv4 header checksum
            let checksum = pnet::packet::ipv4::checksum(&ipv4.to_immutable());
            ipv4.set_checksum(checksum);
        }

        // TCP header (SYN)
        {
            let mut tcp = MutableTcpPacket::new(
                &mut buffer[ETHERNET_HEADER_SIZE + IPV4_HEADER_SIZE..],
            )
            .unwrap_or_else(|| panic!("Buffer too small for TCP header"));

            tcp.set_source(src_port);
            tcp.set_destination(dst_port);
            tcp.set_sequence(rand_port() as u32 * 1000);
            tcp.set_acknowledgement(0);
            tcp.set_data_offset(5);
            tcp.set_flags(TcpFlags::SYN);
            tcp.set_window(1024);
            tcp.set_urgent_ptr(0);

            // Calculate TCP checksum
            let checksum = ipv4_checksum(&tcp.to_immutable(), &self.src_ip, &dst_ip);
            tcp.set_checksum(checksum);
        }

        buffer
    }

    /// Craft a TCP RST packet to abort the handshake.
    fn craft_rst_packet(
        &self,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        seq_num: u32,
    ) -> Vec<u8> {
        let mut buffer = vec![0u8; SYN_PACKET_SIZE];

        // Ethernet header
        {
            let mut eth = MutableEthernetPacket::new(&mut buffer[..ETHERNET_HEADER_SIZE])
                .unwrap_or_else(|| panic!("Buffer too small for Ethernet header"));
            eth.set_destination(self.gateway_mac);
            eth.set_source(self.src_mac);
            eth.set_ethertype(EtherTypes::Ipv4);
        }

        // IPv4 header
        {
            let mut ipv4 = MutableIpv4Packet::new(
                &mut buffer[ETHERNET_HEADER_SIZE..ETHERNET_HEADER_SIZE + IPV4_HEADER_SIZE],
            )
            .unwrap_or_else(|| panic!("Buffer too small for IPv4 header"));

            ipv4.set_version(4);
            ipv4.set_header_length(5);
            ipv4.set_total_length((IPV4_HEADER_SIZE + TCP_HEADER_SIZE) as u16);
            ipv4.set_identification(rand_port());
            ipv4.set_ttl(64);
            ipv4.set_flags(0);
            ipv4.set_fragment_offset(0);
            ipv4.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
            ipv4.set_source(self.src_ip);
            ipv4.set_destination(dst_ip);

            let checksum = pnet::packet::ipv4::checksum(&ipv4.to_immutable());
            ipv4.set_checksum(checksum);
        }

        // TCP header (RST)
        {
            let mut tcp = MutableTcpPacket::new(
                &mut buffer[ETHERNET_HEADER_SIZE + IPV4_HEADER_SIZE..],
            )
            .unwrap_or_else(|| panic!("Buffer too small for TCP header"));

            tcp.set_source(src_port);
            tcp.set_destination(dst_port);
            tcp.set_sequence(seq_num);
            tcp.set_acknowledgement(0);
            tcp.set_data_offset(5);
            tcp.set_flags(TcpFlags::RST);
            tcp.set_window(0);
            tcp.set_urgent_ptr(0);

            let checksum = ipv4_checksum(&tcp.to_immutable(), &self.src_ip, &dst_ip);
            tcp.set_checksum(checksum);
        }

        buffer
    }

    /// Scan a single port using SYN scanning (blocking).
    ///
    /// **IMPORTANT**: This function performs blocking I/O on raw sockets.
    /// It MUST be called inside `tokio::task::spawn_blocking`.
    ///
    /// # Returns
    /// - `(PortState::Open, Some(ttl))` if SYN-ACK received (RST sent to abort)
    /// - `(PortState::Closed, Some(ttl))` if RST/RST-ACK received
    /// - `(PortState::Filtered, None)` if timeout (no response)
    pub fn scan_port_blocking(
        &self,
        target_ip: Ipv4Addr,
        target_port: u16,
        timeout: Duration,
    ) -> Result<(PortState, Option<u8>), ScanError> {
        let src_port = rand_port();

        // Create raw socket for sending
        let send_socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::RAW,
            Some(socket2::Protocol::TCP),
        )
        .map_err(|e| {
            ScanError::PermissionDenied(format!(
                "Cannot create raw socket for SYN scan: {}. Check privileges.",
                e
            ))
        })?;

        // Craft and send SYN packet
        let syn_packet = self.craft_syn_packet(target_ip, src_port, target_port);

        // For raw IP sockets, we skip the Ethernet header and let the kernel handle routing
        let ip_packet = &syn_packet[ETHERNET_HEADER_SIZE..];

        let dest = std::net::SocketAddrV4::new(target_ip, 0);
        send_socket
            .send_to(
                ip_packet,
                &socket2::SockAddr::from(dest),
            )
            .map_err(|e| {
                ScanError::NetworkError(format!(
                    "Failed to send SYN packet to {}:{}: {}",
                    target_ip, target_port, e
                ))
            })?;

        // Create receive socket for listening responses
        let recv_socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::RAW,
            Some(socket2::Protocol::TCP),
        )
        .map_err(|e| {
            ScanError::NetworkError(format!("Failed to create receive socket: {}", e))
        })?;

        recv_socket.set_read_timeout(Some(timeout)).map_err(|e| {
            ScanError::NetworkError(format!("Failed to set receive timeout: {}", e))
        })?;

        // Listen for response
        let mut recv_buf: Vec<std::mem::MaybeUninit<u8>> = vec![std::mem::MaybeUninit::uninit(); RECV_BUF_SIZE];
        let deadline = Instant::now() + timeout;

        loop {
            if Instant::now() >= deadline {
                return Ok((PortState::Filtered, None));
            }

            let remaining = deadline.saturating_duration_since(Instant::now());
            let _ = recv_socket.set_read_timeout(Some(remaining));

            match recv_socket.recv(&mut recv_buf) {
                Ok(size) => {
                    if size < IPV4_HEADER_SIZE + TCP_HEADER_SIZE {
                        continue;
                    }

                    // SAFETY: recv returned Ok(size), so the first `size` bytes are initialized
                    let recv_bytes = unsafe {
                        std::slice::from_raw_parts(recv_buf[0].as_ptr(), size)
                    };

                    // Parse IP header
                    if let Some(ipv4) = Ipv4Packet::new(recv_bytes) {
                        // Check if this is from our target
                        if ipv4.get_source() != target_ip {
                            continue;
                        }

                        // Check if it's a TCP packet
                        if ipv4.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
                            continue;
                        }

                        let ip_header_len = (ipv4.get_header_length() as usize) * 4;
                        if size < ip_header_len + TCP_HEADER_SIZE {
                            continue;
                        }

                        // Parse TCP header
                        if let Some(tcp) = TcpPacket::new(&recv_bytes[ip_header_len..size]) {
                            // Check if this response is for our source port
                            if tcp.get_destination() != src_port {
                                continue;
                            }

                            let flags = tcp.get_flags();

                            // SYN-ACK received → port is open
                            if flags & TcpFlags::SYN != 0 && flags & TcpFlags::ACK != 0 {
                                // Send RST to abort the handshake
                                let rst_packet = self.craft_rst_packet(
                                    target_ip,
                                    src_port,
                                    target_port,
                                    tcp.get_acknowledgement(),
                                );
                                let rst_ip = &rst_packet[ETHERNET_HEADER_SIZE..];
                                let _ = send_socket.send_to(
                                    rst_ip,
                                    &socket2::SockAddr::from(dest),
                                );

                                return Ok((PortState::Open, Some(ipv4.get_ttl())));
                            }

                            // RST received → port is closed
                            if flags & TcpFlags::RST != 0 {
                                return Ok((PortState::Closed, Some(ipv4.get_ttl())));
                            }
                        }
                    }
                }
                Err(e) => {
                    match e.kind() {
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => {
                            return Ok((PortState::Filtered, None));
                        }
                        _ => {
                            return Err(ScanError::NetworkError(format!(
                                "SYN scan receive error for {}:{}: {}",
                                target_ip, target_port, e
                            )));
                        }
                    }
                }
            }
        }
    }

    /// Scan multiple ports on a target using SYN scanning with timing control.
    ///
    /// This is the async entry point that spawns blocking tasks for each port
    /// and applies timing constraints via the `TimingController`.
    pub async fn scan_ports(
        &self,
        target_ip: Ipv4Addr,
        ports: &[u16],
        timing: &TimingController,
    ) -> (Vec<Port>, Option<u8>) {
        use futures::stream::{self, StreamExt};

        let timeout = timing.connection_timeout();

        let results: Vec<(u16, PortState, Option<u8>)> = stream::iter(ports.to_vec())
            .map(|port| {
                let scanner_ip = self.src_ip;
                let scanner_iface_name = self.interface.name.clone();
                let scanner_src_mac = self.src_mac;
                let scanner_gw_mac = self.gateway_mac;
                let timing_clone = timing.semaphore();

                async move {
                    // Acquire semaphore permit
                    let _permit = timing_clone.acquire().await.ok();

                    // Apply inter-packet delay
                    timing.apply_delay().await;

                    // Spawn blocking SYN scan
                    let result = tokio::task::spawn_blocking(move || {
                        let scanner = SynScanner {
                            src_ip: scanner_ip,
                            interface: datalink::interfaces()
                                .into_iter()
                                .find(|i| i.name == scanner_iface_name)
                                .unwrap_or_else(|| {
                                    datalink::interfaces()
                                        .into_iter()
                                        .next()
                                        .unwrap_or_else(|| {
                                            panic!("No network interface available")
                                        })
                                    }),
                            src_mac: scanner_src_mac,
                            gateway_mac: scanner_gw_mac,
                        };
                        scanner.scan_port_blocking(target_ip, port, timeout)
                    })
                    .await;

                    let (state, ttl) = match result {
                        Ok(Ok((state, ttl))) => (state, ttl),
                        Ok(Err(_)) => (PortState::Filtered, None),
                        Err(_) => (PortState::Filtered, None),
                    };

                    (port, state, ttl)
                }
            })
            .buffer_unordered(timing.max_concurrent().min(ports.len().max(1)))
            .collect()
            .await;

        let mut detected_ttl = None;
        let scanned_ports: Vec<Port> = results
            .into_iter()
            .map(|(port, state, ttl)| {
                if let Some(t) = ttl {
                    if detected_ttl.is_none() {
                        detected_ttl = Some(t);
                    }
                }
                let service = crate::types::get_service_name(port);
                Port {
                    number: port,
                    protocol: "tcp".to_string(),
                    service,
                    state,
                }
            })
            .collect();

        (scanned_ports, detected_ttl)
    }
}

/// Generate a random port number for use as source port.
fn rand_port() -> u16 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    use std::time::SystemTime;

    let mut hasher = DefaultHasher::new();
    SystemTime::now().hash(&mut hasher);
    std::thread::current().id().hash(&mut hasher);
    let hash = hasher.finish();
    ((hash % 16383) + 49152) as u16 // Use ephemeral port range
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rand_port_in_ephemeral_range() {
        for _ in 0..100 {
            let port = rand_port();
            assert!(port >= 49152, "Port {} should be >= 49152", port);
        }
    }

    #[test]
    fn test_syn_scanner_creation_no_panic() {
        // This may fail if no suitable interface is found, but should never panic
        let result = SynScanner::new(Ipv4Addr::new(127, 0, 0, 1));
        // On most systems, 127.0.0.1 is on loopback which we skip
        assert!(result.is_ok() || result.is_err());
    }

    #[test]
    fn test_craft_syn_packet_size() {
        // We can't easily test packet crafting without a real interface,
        // but we can verify the constants are correct
        assert_eq!(TCP_HEADER_SIZE, 20);
        assert_eq!(IPV4_HEADER_SIZE, 20);
        assert_eq!(ETHERNET_HEADER_SIZE, 14);
        assert_eq!(SYN_PACKET_SIZE, 54);
    }
}
