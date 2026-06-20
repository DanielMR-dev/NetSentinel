//! Raw UDP scanning engine.
//!
//! Implements stealth UDP scanning using raw packet injection.

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use pnet::datalink::{self, NetworkInterface};
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::udp::{ipv4_checksum, MutableUdpPacket, UdpPacket};
use pnet::packet::icmp::{IcmpPacket, IcmpTypes, IcmpCode};
use pnet::util::MacAddr;

use crate::error::ScanError;
use crate::network::timing::TimingController;
use crate::types::{Port, PortState};

const IPV4_HEADER_SIZE: usize = 20;
const ETHERNET_HEADER_SIZE: usize = 14;
const UDP_HEADER_SIZE: usize = 8;
const UDP_PACKET_SIZE: usize = ETHERNET_HEADER_SIZE + IPV4_HEADER_SIZE + UDP_HEADER_SIZE;
const RECV_BUF_SIZE: usize = 65535;

pub struct UdpRawScanner {
    src_ip: Ipv4Addr,
    interface: NetworkInterface,
    src_mac: MacAddr,
    gateway_mac: MacAddr,
}

impl UdpRawScanner {
    pub async fn new_for_target(target_ip: Ipv4Addr) -> Result<Self, ScanError> {
        let (interface, src_ip) = crate::network::tcp_raw_scan::RawTcpScanner::resolve_interface_and_ip(target_ip)
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

    /// Craft a raw UDP packet.
    fn craft_udp_packet(
        &self,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
    ) -> Vec<u8> {
        // Some UDP services respond better to specific payloads. For basic UDP scan, we send empty payload.
        let payload: &[u8] = match dst_port {
            53 => b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03", // DNS Version.bind request
            161 => b"\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04\x00\x00\x00\x00\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00", // SNMP sysDescr request
            _ => b"", // Empty payload
        };

        let total_size = UDP_PACKET_SIZE + payload.len();
        let mut buffer = vec![0u8; total_size];

        // Ethernet header
        {
            let mut eth = MutableEthernetPacket::new(&mut buffer[..ETHERNET_HEADER_SIZE]).unwrap();
            eth.set_destination(self.gateway_mac);
            eth.set_source(self.src_mac);
            eth.set_ethertype(EtherTypes::Ipv4);
        }

        // IPv4 header
        {
            let mut ipv4 = MutableIpv4Packet::new(
                &mut buffer[ETHERNET_HEADER_SIZE..ETHERNET_HEADER_SIZE + IPV4_HEADER_SIZE],
            ).unwrap();
            ipv4.set_version(4);
            ipv4.set_header_length(5);
            ipv4.set_total_length((IPV4_HEADER_SIZE + UDP_HEADER_SIZE + payload.len()) as u16);
            ipv4.set_identification(crate::network::tcp_raw_scan::rand_port());
            ipv4.set_ttl(64);
            ipv4.set_flags(0);
            ipv4.set_fragment_offset(0);
            ipv4.set_next_level_protocol(IpNextHeaderProtocols::Udp);
            ipv4.set_source(self.src_ip);
            ipv4.set_destination(dst_ip);
            
            let checksum = pnet::packet::ipv4::checksum(&ipv4.to_immutable());
            ipv4.set_checksum(checksum);
        }

        // UDP header
        {
            let mut udp = MutableUdpPacket::new(
                &mut buffer[ETHERNET_HEADER_SIZE + IPV4_HEADER_SIZE..],
            ).unwrap();
            udp.set_source(src_port);
            udp.set_destination(dst_port);
            udp.set_length((UDP_HEADER_SIZE + payload.len()) as u16);
            udp.set_payload(payload);
            
            let checksum = ipv4_checksum(&udp.to_immutable(), &self.src_ip, &dst_ip);
            udp.set_checksum(checksum);
        }

        buffer
    }

    pub fn scan_port_blocking(
        &self,
        target_ip: Ipv4Addr,
        target_port: u16,
        timeout: Duration,
    ) -> Result<(PortState, Option<u8>), ScanError> {
        let src_port = crate::network::tcp_raw_scan::rand_port();

        // Send Socket
        let send_socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::RAW,
            Some(socket2::Protocol::UDP),
        ).map_err(|e| {
            ScanError::PermissionDenied(format!("Cannot create raw socket for UDP scan: {}", e))
        })?;

        let packet = self.craft_udp_packet(target_ip, src_port, target_port);
        let ip_packet = &packet[ETHERNET_HEADER_SIZE..];

        let dest = std::net::SocketAddrV4::new(target_ip, 0);
        send_socket.send_to(ip_packet, &socket2::SockAddr::from(dest)).map_err(|e| {
            ScanError::NetworkError(format!("Failed to send UDP packet: {}", e))
        })?;

        // We need to listen to both ICMP (for Port Unreachable) and UDP (for application response)
        // Wait, socket2 RAW IPPROTO_ICMP will receive ICMP packets.
        // And RAW IPPROTO_UDP will receive UDP packets.
        // It's tricky to poll two raw sockets in a blocking loop simultaneously.
        // We can create an ICMP raw socket, but receiving UDP on a raw socket might only get packets meant for us.
        // Actually, UDP ports can be polled using standard UdpSocket or RAW UDP socket with a small timeout in a loop.
        
        let icmp_socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::RAW,
            Some(socket2::Protocol::ICMPV4),
        ).map_err(|e| ScanError::NetworkError(format!("Failed to create ICMP receive socket: {}", e)))?;
        icmp_socket.set_read_timeout(Some(Duration::from_millis(50))).unwrap();

        let udp_socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::RAW,
            Some(socket2::Protocol::UDP),
        ).map_err(|e| ScanError::NetworkError(format!("Failed to create UDP receive socket: {}", e)))?;
        udp_socket.set_read_timeout(Some(Duration::from_millis(50))).unwrap();

        let mut recv_buf: Vec<std::mem::MaybeUninit<u8>> = vec![std::mem::MaybeUninit::uninit(); RECV_BUF_SIZE];
        let deadline = Instant::now() + timeout;

        loop {
            if Instant::now() >= deadline {
                // If no response is received, port is Open|Filtered. We map to Open.
                return Ok((PortState::Open, None));
            }

            // Check ICMP
            if let Ok(size) = icmp_socket.recv(&mut recv_buf) {
                let recv_bytes = unsafe { std::slice::from_raw_parts(recv_buf[0].as_ptr(), size) };
                if let Some(ipv4) = Ipv4Packet::new(recv_bytes) {
                    if ipv4.get_source() == target_ip {
                        let ip_header_len = (ipv4.get_header_length() as usize) * 4;
                        if size >= ip_header_len + 8 {
                            if let Some(icmp) = IcmpPacket::new(&recv_bytes[ip_header_len..size]) {
                                // Destination Unreachable (Type 3)
                                if icmp.get_icmp_type() == IcmpTypes::DestinationUnreachable {
                                    let code = icmp.get_icmp_code();
                                    if code == IcmpCode::new(3) { // Port Unreachable
                                        // Technically we should check the embedded IP header inside the ICMP payload
                                        // to make sure it matches our sent packet, but matching the target_ip and Type 3 Code 3
                                        // is usually sufficient for a simple scan.
                                        return Ok((PortState::Closed, Some(ipv4.get_ttl())));
                                    } else {
                                        // Other unreachables mean Filtered
                                        return Ok((PortState::Filtered, Some(ipv4.get_ttl())));
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Check UDP
            if let Ok(size) = udp_socket.recv(&mut recv_buf) {
                let recv_bytes = unsafe { std::slice::from_raw_parts(recv_buf[0].as_ptr(), size) };
                if let Some(ipv4) = Ipv4Packet::new(recv_bytes) {
                    if ipv4.get_source() == target_ip && ipv4.get_next_level_protocol() == IpNextHeaderProtocols::Udp {
                        let ip_header_len = (ipv4.get_header_length() as usize) * 4;
                        if size >= ip_header_len + 8 {
                            if let Some(udp) = UdpPacket::new(&recv_bytes[ip_header_len..size]) {
                                if udp.get_source() == target_port && udp.get_destination() == src_port {
                                    // Received a UDP response!
                                    return Ok((PortState::Open, Some(ipv4.get_ttl())));
                                }
                            }
                        }
                    }
                }
            }
        }
    }

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
                    let _permit = timing_clone.acquire().await.ok();
                    timing.apply_delay().await;

                    let result = tokio::task::spawn_blocking(move || {
                        let scanner = UdpRawScanner {
                            src_ip: scanner_ip,
                            interface: datalink::interfaces().into_iter().find(|i| i.name == scanner_iface_name).unwrap(),
                            src_mac: scanner_src_mac,
                            gateway_mac: scanner_gw_mac,
                        };
                        scanner.scan_port_blocking(target_ip, port, timeout)
                    }).await;

                    let (state, ttl) = match result {
                        Ok(Ok((state, ttl))) => (state, ttl),
                        _ => (PortState::Filtered, None),
                    };

                    (port, state, ttl)
                }
            })
            .buffer_unordered(timing.max_concurrent().min(ports.len().max(1)))
            .collect().await;

        let mut detected_ttl = None;
        let scanned_ports: Vec<Port> = results
            .into_iter()
            .map(|(port, state, ttl)| {
                if let Some(t) = ttl {
                    if detected_ttl.is_none() { detected_ttl = Some(t); }
                }
                Port {
                    number: port,
                    protocol: "udp".to_string(),
                    service: crate::types::get_service_name(port),
                    state,
                }
            })
            .collect();

        (scanned_ports, detected_ttl)
    }
}
