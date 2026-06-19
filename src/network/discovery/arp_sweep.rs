use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use pnet::datalink::{self, NetworkInterface};
use pnet::packet::Packet;
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::util::MacAddr;

use crate::error::ScanError;
use crate::state::SharedScanState;
use crate::types::{Device, DeviceStatus};

/// Craft an ARP request packet.
fn craft_arp_request(
    src_mac: MacAddr,
    src_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
) -> [u8; 42] {
    let mut buf = [0u8; 42];

    // Ethernet header (14 bytes)
    {
        let mut eth = MutableEthernetPacket::new(&mut buf[..14])
            .unwrap_or_else(|| panic!("Buffer too small for Ethernet header"));
        eth.set_destination(MacAddr::broadcast());
        eth.set_source(src_mac);
        eth.set_ethertype(EtherTypes::Arp);
    }

    // ARP header (28 bytes)
    {
        let mut arp = MutableArpPacket::new(&mut buf[14..])
            .unwrap_or_else(|| panic!("Buffer too small for ARP header"));
        arp.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp.set_protocol_type(EtherTypes::Ipv4);
        arp.set_hw_addr_len(6);
        arp.set_proto_addr_len(4);
        arp.set_operation(ArpOperations::Request);
        arp.set_sender_hw_addr(src_mac);
        arp.set_sender_proto_addr(src_ip);
        arp.set_target_hw_addr(MacAddr::zero());
        arp.set_target_proto_addr(target_ip);
    }

    buf
}

/// Perform an active ARP sweep on the local network interface.
pub async fn arp_sweep(
    ips: Vec<Ipv4Addr>,
    interface: NetworkInterface,
    src_ip: Ipv4Addr,
    timeout: Duration,
    state: Arc<SharedScanState>,
) -> Result<Vec<Device>, ScanError> {
    let src_mac = interface.mac.unwrap_or(MacAddr::zero());
    let discovered = Arc::new(Mutex::new(HashMap::new()));
    let running = Arc::new(AtomicBool::new(true));

    let config = datalink::Config {
        read_timeout: Some(Duration::from_millis(50)),
        ..Default::default()
    };

    // Open datalink channel
    let (mut tx, mut rx) = match datalink::channel(&interface, config) {
        Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => return Err(ScanError::NetworkError("Unsupported channel type".to_string())),
        Err(e) => return Err(ScanError::NetworkError(format!("Failed to open datalink channel: {}", e))),
    };

    let running_clone = running.clone();
    let discovered_clone = discovered.clone();

    // Spawn a background receiver thread to capture replies
    let rx_thread = std::thread::spawn(move || {
        while running_clone.load(Ordering::Relaxed) {
            match rx.next() {
                Ok(packet_bytes) => {
                    if packet_bytes.len() < 42 {
                        continue;
                    }
                    if let Some(eth) = EthernetPacket::new(packet_bytes) {
                        if eth.get_ethertype() == EtherTypes::Arp {
                            if let Some(arp) = ArpPacket::new(eth.payload()) {
                                if arp.get_operation() == ArpOperations::Reply {
                                    let ip = arp.get_sender_proto_addr();
                                    let mac = arp.get_sender_hw_addr();
                                    let mut map = discovered_clone.lock().unwrap();
                                    map.insert(ip, mac);
                                }
                            }
                        }
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                    // Loop again
                }
                Err(_) => {
                    break;
                }
            }
        }
    });

    // Send ARP requests
    for target_ip in ips.iter() {
        if !state.is_running() {
            break;
        }

        let packet = craft_arp_request(src_mac, src_ip, *target_ip);
        if let Some(send_res) = tx.send_to(&packet, None) {
            if let Err(e) = send_res {
                tracing::warn!("Failed to send ARP request for {}: {}", target_ip, e);
            }
        }

        // Small inter-packet delay to prevent flooding (e.g. 1ms)
        std::thread::sleep(Duration::from_millis(1));
    }

    // Wait for final replies to arrive
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline && state.is_running() {
        std::thread::sleep(Duration::from_millis(50));
    }

    // Stop receiver thread
    running.store(false, Ordering::Relaxed);
    let _ = rx_thread.join();

    // Collect discovered devices
    let mut map = discovered.lock().unwrap();
    
    // Add local host if it is in the target IP list and not already found
    if ips.contains(&src_ip) && !map.contains_key(&src_ip) {
        map.insert(src_ip, src_mac);
    }

    let mut devices = Vec::new();
    for (ip, mac) in map.iter() {
        let mut dev = Device::new(ip.to_string());
        dev.mac = mac.to_string();
        dev.status = DeviceStatus::Online;
        devices.push(dev);
    }

    Ok(devices)
}
