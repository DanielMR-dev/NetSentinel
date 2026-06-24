//! SCTP INIT scanning engine.
//!
//! Implements stealth SCTP INIT scanning using raw packet injection.

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use pnet::datalink::{self, NetworkInterface};
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::util::MacAddr;

use crate::error::ScanError;
use crate::network::timing::TimingController;
use crate::types::{Port, PortState};

const IPV4_HEADER_SIZE: usize = 20;
const ETHERNET_HEADER_SIZE: usize = 14;
const SCTP_HEADER_SIZE: usize = 12;
const SCTP_INIT_CHUNK_SIZE: usize = 20;
const SCTP_PACKET_SIZE: usize =
    ETHERNET_HEADER_SIZE + IPV4_HEADER_SIZE + SCTP_HEADER_SIZE + SCTP_INIT_CHUNK_SIZE;
const RECV_BUF_SIZE: usize = 65535;

pub struct SctpScanner {
    src_ip: Ipv4Addr,
    interface: NetworkInterface,
    src_mac: MacAddr,
    gateway_mac: MacAddr,
}

impl SctpScanner {
    pub async fn new_for_target(target_ip: Ipv4Addr) -> Result<Self, ScanError> {
        let (interface, src_ip) =
            crate::network::tcp_raw_scan::RawTcpScanner::resolve_interface_and_ip(target_ip)
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

    /// Craft a raw SCTP INIT packet.
    fn craft_sctp_packet(
        &self,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
    ) -> Result<Vec<u8>, ScanError> {
        if SCTP_PACKET_SIZE
            < ETHERNET_HEADER_SIZE + IPV4_HEADER_SIZE + SCTP_HEADER_SIZE + SCTP_INIT_CHUNK_SIZE
        {
            return Err(ScanError::PacketError(
                "SCTP packet buffer size mismatch".to_string(),
            ));
        }

        let mut buffer = vec![0u8; SCTP_PACKET_SIZE];

        // Ethernet header
        {
            let mut eth = MutableEthernetPacket::new(&mut buffer[..ETHERNET_HEADER_SIZE])
                .ok_or_else(|| {
                    ScanError::PacketError("Buffer too small for Ethernet header".to_string())
                })?;
            eth.set_destination(self.gateway_mac);
            eth.set_source(self.src_mac);
            eth.set_ethertype(EtherTypes::Ipv4);
        }

        // IPv4 header
        {
            let mut ipv4 = MutableIpv4Packet::new(
                &mut buffer[ETHERNET_HEADER_SIZE..ETHERNET_HEADER_SIZE + IPV4_HEADER_SIZE],
            )
            .ok_or_else(|| {
                ScanError::PacketError("Buffer too small for IPv4 header".to_string())
            })?;
            ipv4.set_version(4);
            ipv4.set_header_length(5);
            ipv4.set_total_length(
                (IPV4_HEADER_SIZE + SCTP_HEADER_SIZE + SCTP_INIT_CHUNK_SIZE) as u16,
            );
            ipv4.set_identification(rand_port());
            ipv4.set_ttl(64);
            ipv4.set_flags(0);
            ipv4.set_fragment_offset(0);
            // IP Protocol 132 for SCTP
            ipv4.set_next_level_protocol(pnet::packet::ip::IpNextHeaderProtocol(132));
            ipv4.set_source(self.src_ip);
            ipv4.set_destination(dst_ip);

            let checksum = pnet::packet::ipv4::checksum(&ipv4.to_immutable());
            ipv4.set_checksum(checksum);
        }

        // SCTP Payload
        let sctp_offset = ETHERNET_HEADER_SIZE + IPV4_HEADER_SIZE;

        // SCTP Common Header (12 bytes)
        // Source Port (2)
        buffer[sctp_offset..sctp_offset + 2].copy_from_slice(&src_port.to_be_bytes());
        // Dest Port (2)
        buffer[sctp_offset + 2..sctp_offset + 4].copy_from_slice(&dst_port.to_be_bytes());
        // Verification Tag (4) - 0 for INIT
        buffer[sctp_offset + 4..sctp_offset + 8].copy_from_slice(&[0, 0, 0, 0]);
        // Checksum (4) - calculated later

        // SCTP INIT Chunk (20 bytes)
        let chunk_offset = sctp_offset + 12;
        // Type = 1 (INIT)
        buffer[chunk_offset] = 1;
        // Flags = 0
        buffer[chunk_offset + 1] = 0;
        // Length = 20
        buffer[chunk_offset + 2..chunk_offset + 4].copy_from_slice(&20u16.to_be_bytes());
        // Initiate Tag (4)
        buffer[chunk_offset + 4..chunk_offset + 8].copy_from_slice(&12345678u32.to_be_bytes());
        // a_rwnd (4)
        buffer[chunk_offset + 8..chunk_offset + 12].copy_from_slice(&106496u32.to_be_bytes());
        // Number of Outbound Streams (2)
        buffer[chunk_offset + 12..chunk_offset + 14].copy_from_slice(&10u16.to_be_bytes());
        // Number of Inbound Streams (2)
        buffer[chunk_offset + 14..chunk_offset + 16].copy_from_slice(&10u16.to_be_bytes());
        // Initial TSN (4)
        buffer[chunk_offset + 16..chunk_offset + 20].copy_from_slice(&0u32.to_be_bytes());

        // Calculate CRC32c Checksum over SCTP header + chunks
        let sctp_bytes =
            &mut buffer[sctp_offset..sctp_offset + SCTP_HEADER_SIZE + SCTP_INIT_CHUNK_SIZE];
        let checksum = crc32fast::hash(sctp_bytes);
        // SCTP uses little-endian for checksum!
        sctp_bytes[8..12].copy_from_slice(&checksum.to_le_bytes());

        Ok(buffer)
    }

    pub fn scan_port_blocking(
        &self,
        target_ip: Ipv4Addr,
        target_port: u16,
        timeout: Duration,
    ) -> Result<(PortState, Option<u8>), ScanError> {
        let src_port = rand_port();

        // 255 = IPPROTO_RAW
        let send_socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::RAW,
            Some(socket2::Protocol::from(255)),
        )
        .map_err(|e| {
            ScanError::PermissionDenied(format!("Cannot create raw socket for SCTP scan: {}", e))
        })?;

        let packet = self.craft_sctp_packet(target_ip, src_port, target_port)?;
        let ip_packet = &packet[ETHERNET_HEADER_SIZE..];

        let dest = std::net::SocketAddrV4::new(target_ip, 0);
        send_socket
            .send_to(ip_packet, &socket2::SockAddr::from(dest))
            .map_err(|e| ScanError::NetworkError(format!("Failed to send SCTP packet: {}", e)))?;

        // 132 = IPPROTO_SCTP
        let recv_socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::RAW,
            Some(socket2::Protocol::from(132)),
        )
        .map_err(|e| ScanError::NetworkError(format!("Failed to create receive socket: {}", e)))?;

        recv_socket.set_read_timeout(Some(timeout)).map_err(|e| {
            ScanError::NetworkError(format!("Failed to set receive timeout: {}", e))
        })?;

        let mut recv_buf: Vec<std::mem::MaybeUninit<u8>> =
            vec![std::mem::MaybeUninit::uninit(); RECV_BUF_SIZE];
        let deadline = Instant::now() + timeout;

        loop {
            if Instant::now() >= deadline {
                return Ok((PortState::Filtered, None));
            }

            let remaining = deadline.saturating_duration_since(Instant::now());
            let _ = recv_socket.set_read_timeout(Some(remaining));

            match recv_socket.recv(&mut recv_buf) {
                Ok(size) => {
                    // Defensive validation before the unsafe slice construction.
                    if size > recv_buf.len() {
                        continue;
                    }

                    // SAFETY: `recv` returned `Ok(size)`, so the first `size` bytes of
                    // `recv_buf` have been initialized by the kernel. We verified that
                    // `size <= recv_buf.len()`, so the slice is in bounds.
                    let recv_bytes =
                        unsafe { std::slice::from_raw_parts(recv_buf[0].as_ptr(), size) };

                    if let Some(ipv4) = Ipv4Packet::new(recv_bytes) {
                        if ipv4.get_source() != target_ip || ipv4.get_next_level_protocol().0 != 132
                        {
                            continue;
                        }

                        let ip_header_len = (ipv4.get_header_length() as usize) * 4;
                        if size < ip_header_len + 12 {
                            continue;
                        }

                        let sctp_bytes = &recv_bytes[ip_header_len..size];

                        // Check dest port matches our src port
                        let resp_dst_port = u16::from_be_bytes([sctp_bytes[2], sctp_bytes[3]]);
                        if resp_dst_port != src_port {
                            continue;
                        }

                        // Check chunks
                        if sctp_bytes.len() < 16 {
                            continue;
                        }
                        let chunk_type = sctp_bytes[12];

                        // Chunk Type 2 is INIT-ACK (Open)
                        if chunk_type == 2 {
                            return Ok((PortState::Open, Some(ipv4.get_ttl())));
                        }

                        // Chunk Type 6 is ABORT (Closed)
                        if chunk_type == 6 {
                            return Ok((PortState::Closed, Some(ipv4.get_ttl())));
                        }
                    }
                }
                Err(e) => match e.kind() {
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => {
                        return Ok((PortState::Filtered, None));
                    }
                    _ => {
                        return Err(ScanError::NetworkError(format!(
                            "SCTP scan receive error: {}",
                            e
                        )));
                    }
                },
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
                        let interface = datalink::interfaces()
                            .into_iter()
                            .find(|i| i.name == scanner_iface_name)
                            .ok_or_else(|| {
                                ScanError::NoInterfaceForIp(scanner_iface_name.clone())
                            })?;

                        let scanner = SctpScanner {
                            src_ip: scanner_ip,
                            interface,
                            src_mac: scanner_src_mac,
                            gateway_mac: scanner_gw_mac,
                        };
                        scanner.scan_port_blocking(target_ip, port, timeout)
                    })
                    .await;

                    let (state, ttl) = match result {
                        Ok(Ok((state, ttl))) => (state, ttl),
                        Ok(Err(e)) => {
                            tracing::warn!("SCTP scan failed for {}:{}: {}", target_ip, port, e);
                            (PortState::Filtered, None)
                        }
                        Err(e) => {
                            tracing::warn!(
                                "SCTP scan task panicked for {}:{}: {}",
                                target_ip,
                                port,
                                e
                            );
                            (PortState::Filtered, None)
                        }
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
                Port {
                    number: port,
                    protocol: "sctp".to_string(),
                    service: crate::types::get_service_name(port),
                    state,
                }
            })
            .collect();

        (scanned_ports, detected_ttl)
    }
}

fn rand_port() -> u16 {
    crate::network::tcp_raw_scan::rand_port()
}
