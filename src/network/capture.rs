//! Background Packet Capture & NetFlow Summarization
//!
//! Spawns a background thread listening in promiscuous mode on the default interface.
//! Summarizes traffic into SQLite and runs ARP spoofing detection.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use pnet::datalink;
use pnet::packet::arp::ArpPacket;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use rusqlite::{params, Connection};
use tracing::{error, info, warn};

use crate::network::threats::{ArpMonitor, ThreatAlert};

/// Represents a summarized network flow
#[derive(Debug, Clone)]
pub struct NetFlow {
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: String,
    pub bytes: u64,
    pub packets: u64,
    pub first_seen: u64,
    pub last_seen: u64,
}

/// A key for unique flows (ignoring directionality for simplicity, or keeping it unidirectional.
/// We'll use unidirectional here for simplicity: A->B is a different flow than B->A).
#[derive(Debug, Hash, Eq, PartialEq, Clone)]
struct FlowKey {
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
    protocol: u8,
}

/// Helper to get the app's local data directory.
fn get_app_local_data_dir() -> Option<std::path::PathBuf> {
    dirs::data_local_dir().map(|p| p.join("com.netsentinel.app"))
}

/// Initializes the SQLite database for traffic flows
fn init_traffic_db() -> rusqlite::Result<Connection> {
    let mut path = get_app_local_data_dir().unwrap_or_else(|| std::path::PathBuf::from("."));
    if !path.exists() {
        let _ = std::fs::create_dir_all(&path);
    }
    path.push("netsentinel-traffic.db");

    let conn = Connection::open(&path)?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS flows (
            id INTEGER PRIMARY KEY,
            src_ip TEXT NOT NULL,
            dst_ip TEXT NOT NULL,
            src_port INTEGER NOT NULL,
            dst_port INTEGER NOT NULL,
            protocol TEXT NOT NULL,
            bytes INTEGER NOT NULL,
            packets INTEGER NOT NULL,
            first_seen INTEGER NOT NULL,
            last_seen INTEGER NOT NULL
        )",
        (),
    )?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY,
            threat_type TEXT NOT NULL,
            description TEXT NOT NULL,
            severity TEXT NOT NULL,
            timestamp INTEGER NOT NULL
        )",
        (),
    )?;

    Ok(conn)
}

/// Flushes active flows and alerts to SQLite.
fn flush_to_sqlite(
    conn: &mut Connection,
    flows: &mut HashMap<FlowKey, NetFlow>,
    alerts: &mut Vec<ThreatAlert>,
    flush_all: bool,
) {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let mut to_remove = Vec::new();

    let tx = match conn.transaction() {
        Ok(tx) => tx,
        Err(e) => {
            error!("Capture Thread: Failed to begin SQLite transaction: {}", e);
            return;
        }
    };

    for (key, flow) in flows.iter() {
        // Flush if forced (app closing), or if flow hasn't been seen in 60 seconds
        if flush_all || (now.saturating_sub(flow.last_seen) > 60) {
            if let Err(e) = tx.execute(
                "INSERT INTO flows (src_ip, dst_ip, src_port, dst_port, protocol, bytes, packets, first_seen, last_seen)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    flow.src_ip, flow.dst_ip, flow.src_port, flow.dst_port, flow.protocol,
                    flow.bytes, flow.packets, flow.first_seen, flow.last_seen
                ]
            ) {
                warn!("Capture Thread: Failed to insert flow: {}", e);
            }
            to_remove.push(key.clone());
        }
    }

    // Write alerts
    for alert in alerts.drain(..) {
        if let Err(e) = tx.execute(
            "INSERT INTO alerts (threat_type, description, severity, timestamp) VALUES (?1, ?2, ?3, ?4)",
            params![alert.threat_type, alert.description, alert.severity, alert.timestamp]
        ) {
            warn!("Capture Thread: Failed to insert alert: {}", e);
        }
    }

    if let Err(e) = tx.commit() {
        error!("Capture Thread: Failed to commit SQLite transaction: {}", e);
        return;
    }

    for key in to_remove {
        flows.remove(&key);
    }
}

/// Spawns the background capture thread.
pub fn spawn_capture_thread(
    running_flag: Arc<AtomicBool>,
    default_gateway: Option<std::net::Ipv4Addr>,
) {
    std::thread::spawn(move || {
        let interfaces = datalink::interfaces();
        // Automatically pick a non-loopback interface that is UP.
        // In a real scenario we'd use routing tables to find the default route,
        // but checking `is_up` and `!is_loopback` works for 90% of cases.
        let iface = match interfaces
            .into_iter()
            .find(|i| i.is_up() && !i.is_loopback() && !i.ips.is_empty())
        {
            Some(i) => i,
            None => {
                error!("Capture Thread: No suitable network interface found.");
                return;
            }
        };

        info!(
            "Starting background packet capture on interface: {}",
            iface.name
        );

        let mut rx = match datalink::channel(&iface, Default::default()) {
            Ok(datalink::Channel::Ethernet(_, rx)) => rx,
            Ok(_) => {
                error!("Capture Thread: Unhandled channel type");
                return;
            }
            Err(e) => {
                error!("Capture Thread: Failed to create datalink channel: {}", e);
                return;
            }
        };

        let mut db_conn = match init_traffic_db() {
            Ok(conn) => conn,
            Err(e) => {
                error!("Capture Thread: Failed to init traffic DB: {}", e);
                return;
            }
        };

        let mut active_flows: HashMap<FlowKey, NetFlow> = HashMap::new();
        let mut arp_monitor = ArpMonitor::new(default_gateway);
        let mut pending_alerts = Vec::new();
        let mut last_flush = Instant::now();

        while running_flag.load(Ordering::Relaxed) {
            match rx.next() {
                Ok(packet) => {
                    let now_secs = SystemTime::now()
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();

                    if let Some(ethernet) = EthernetPacket::new(packet) {
                        match ethernet.get_ethertype() {
                            EtherTypes::Ipv4 => {
                                if let Some(ipv4) = Ipv4Packet::new(ethernet.payload()) {
                                    let mut src_port = 0;
                                    let mut dst_port = 0;
                                    let protocol_num = ipv4.get_next_level_protocol().0;
                                    let protocol_str = match ipv4.get_next_level_protocol() {
                                        IpNextHeaderProtocols::Tcp => {
                                            if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                                                src_port = tcp.get_source();
                                                dst_port = tcp.get_destination();
                                            }
                                            "TCP"
                                        }
                                        IpNextHeaderProtocols::Udp => {
                                            if let Some(udp) = UdpPacket::new(ipv4.payload()) {
                                                src_port = udp.get_source();
                                                dst_port = udp.get_destination();
                                            }
                                            "UDP"
                                        }
                                        IpNextHeaderProtocols::Icmp => "ICMP",
                                        _ => "OTHER",
                                    };

                                    let key = FlowKey {
                                        src_ip: IpAddr::V4(ipv4.get_source()),
                                        dst_ip: IpAddr::V4(ipv4.get_destination()),
                                        src_port,
                                        dst_port,
                                        protocol: protocol_num,
                                    };

                                    let bytes = packet.len() as u64;

                                    let flow = active_flows.entry(key).or_insert(NetFlow {
                                        src_ip: ipv4.get_source().to_string(),
                                        dst_ip: ipv4.get_destination().to_string(),
                                        src_port,
                                        dst_port,
                                        protocol: protocol_str.to_string(),
                                        bytes: 0,
                                        packets: 0,
                                        first_seen: now_secs,
                                        last_seen: now_secs,
                                    });

                                    flow.packets += 1;
                                    flow.bytes += bytes;
                                    flow.last_seen = now_secs;
                                }
                            }
                            EtherTypes::Arp => {
                                if let Some(arp) = ArpPacket::new(ethernet.payload()) {
                                    if let Some(alert) = arp_monitor.observe_arp(
                                        arp.get_sender_proto_addr(),
                                        arp.get_sender_hw_addr(),
                                    ) {
                                        pending_alerts.push(alert);
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
                Err(e) => {
                    warn!("Capture Thread: Error reading packet: {}", e);
                }
            }

            // Periodically flush flows (every 10 seconds)
            if last_flush.elapsed() > Duration::from_secs(10) {
                flush_to_sqlite(&mut db_conn, &mut active_flows, &mut pending_alerts, false);
                last_flush = Instant::now();
            }
        }

        // Final flush on exit
        info!("Capture Thread: Stopping, flushing final flows to DB...");
        flush_to_sqlite(&mut db_conn, &mut active_flows, &mut pending_alerts, true);
    });
}
