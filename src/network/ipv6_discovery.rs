//! Advanced IPv6 Network Discovery
//!
//! Uses active Multicast ICMPv6 Ping to `ff02::1` (all-nodes) and passive 
//! listening for ICMPv6 NDP (Neighbor Discovery Protocol) Router/Neighbor Advertisements.

use std::net::{IpAddr, Ipv6Addr};
use std::time::Duration;
use pnet::datalink;
use pnet::packet::icmpv6::{Icmpv6Types, MutableIcmpv6Packet, Icmpv6Packet, ndp::NeighborAdvertPacket, ndp::RouterAdvertPacket};
use pnet::packet::ipv6::{Ipv6Packet, MutableIpv6Packet};
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::{Packet, MutablePacket};
use pnet::util::MacAddr;
use tokio::sync::mpsc;

use crate::error::ScanError;
use crate::events::AppEvent;
use crate::types::{Device, DeviceStatus};

/// All-nodes IPv6 Multicast Address
pub const FF02_1_ALL_NODES: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);

/// Maximum time to wait for multicast responses
const MULTICAST_TIMEOUT_MS: u64 = 3000;

/// Perform IPv6 discovery on the local network.
///
/// Combines Active (ff02::1 ping) and Passive (NDP snooping).
pub async fn discover_ipv6_hosts(
    event_tx: mpsc::UnboundedSender<AppEvent>,
) -> Result<Vec<Device>, ScanError> {
    let mut discovered = Vec::new();
    
    // Find suitable interface for IPv6
    let interfaces = datalink::interfaces();
    let iface = interfaces.into_iter()
        .find(|iface| iface.is_up() && !iface.is_loopback() && iface.ips.iter().any(|ip| ip.is_ipv6()))
        .ok_or_else(|| ScanError::NetworkError("No suitable IPv6 interface found".to_string()))?;
        
    let src_ipv6 = iface.ips.iter()
        .find_map(|ip| if let IpAddr::V6(ipv6) = ip.ip() { Some(ipv6) } else { None })
        .unwrap();

    let _ = event_tx.send(AppEvent::ScanLog {
        level: "info".to_string(),
        message: format!("Starting IPv6 Multicast discovery on {} ({})", iface.name, src_ipv6),
        target: None,
        timestamp: chrono::Utc::now().timestamp(),
    });

    // We will do this using raw sockets in a spawn_blocking block due to pnet sync restrictions
    let iface_clone = iface.clone();
    
    let devices = tokio::task::spawn_blocking(move || -> Result<Vec<Device>, ScanError> {
        let mut local_discovered = Vec::new();
        
        let (mut sender, mut receiver) = match datalink::channel(&iface_clone, Default::default()) {
            Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => return Err(ScanError::NetworkError("Unhandled channel type".to_string())),
            Err(e) => return Err(ScanError::PermissionDenied(format!("Failed to create datalink channel: {}", e))),
        };

        // Craft ICMPv6 Echo Request
        let mut ethernet_buffer = [0u8; 62];
        let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
        
        // IPv6 Multicast MAC: 33:33:xx:xx:xx:xx
        let dst_mac = MacAddr::new(0x33, 0x33, 0x00, 0x00, 0x00, 0x01);
        ethernet_packet.set_destination(dst_mac);
        ethernet_packet.set_source(iface_clone.mac.unwrap_or(MacAddr::zero()));
        ethernet_packet.set_ethertype(EtherTypes::Ipv6);

        let mut ipv6_packet = MutableIpv6Packet::new(ethernet_packet.payload_mut()).unwrap();
        ipv6_packet.set_version(6);
        ipv6_packet.set_payload_length(8); // ICMPv6 header
        ipv6_packet.set_next_header(IpNextHeaderProtocols::Icmpv6);
        ipv6_packet.set_hop_limit(255);
        ipv6_packet.set_source(src_ipv6);
        ipv6_packet.set_destination(FF02_1_ALL_NODES);

        let mut icmp_packet = MutableIcmpv6Packet::new(ipv6_packet.payload_mut()).unwrap();
        icmp_packet.set_icmpv6_type(Icmpv6Types::EchoRequest);
        
        // Checksum
        let checksum = pnet::packet::icmpv6::checksum(&icmp_packet.to_immutable(), &src_ipv6, &FF02_1_ALL_NODES);
        icmp_packet.set_checksum(checksum);

        // Send multicast ping
        sender.send_to(ethernet_packet.packet(), None);

        // Listen for responses (Echo Replies and NDP Advertisements)
        let deadline = std::time::Instant::now() + Duration::from_millis(MULTICAST_TIMEOUT_MS);
        
        while std::time::Instant::now() < deadline {
            if let Ok(packet) = receiver.next() {
                if let Some(ethernet) = pnet::packet::ethernet::EthernetPacket::new(packet) {
                    if ethernet.get_ethertype() == EtherTypes::Ipv6 {
                        if let Some(ipv6) = Ipv6Packet::new(ethernet.payload()) {
                            // Only care about packets NOT from us
                            if ipv6.get_source() == src_ipv6 {
                                continue;
                            }
                            
                            let mut is_new_device = false;
                            
                            if ipv6.get_next_header() == IpNextHeaderProtocols::Icmpv6 {
                                if let Some(icmpv6) = Icmpv6Packet::new(ipv6.payload()) {
                                    match icmpv6.get_icmpv6_type() {
                                        Icmpv6Types::EchoReply => {
                                            is_new_device = true;
                                        },
                                        Icmpv6Types::NeighborAdvert => {
                                            if let Some(_) = NeighborAdvertPacket::new(icmpv6.packet()) {
                                                is_new_device = true;
                                            }
                                        },
                                        Icmpv6Types::RouterAdvert => {
                                            if let Some(_) = RouterAdvertPacket::new(icmpv6.packet()) {
                                                is_new_device = true;
                                            }
                                        },
                                        _ => {}
                                    }
                                }
                            }
                            
                            if is_new_device {
                                let ip_str = ipv6.get_source().to_string();
                                if !local_discovered.iter().any(|d: &Device| d.ip == ip_str) {
                                    local_discovered.push(Device {
                                        ip: ip_str,
                                        mac: ethernet.get_source().to_string(),
                                        hostname: None,
                                        status: DeviceStatus::Online,
                                        ports: vec![],
                                        last_seen: chrono::Utc::now().timestamp(),
                                        os: None,
                                        vendor: None,
                                        banner_results: vec![],
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
        
        Ok(local_discovered)
    }).await.map_err(|e| ScanError::NetworkError(format!("Thread crashed: {}", e)))??;

    for device in devices {
        discovered.push(device);
    }
    
    Ok(discovered)
}
