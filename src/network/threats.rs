//! ARP Spoofing & Threat Detection
//!
//! Analyzes incoming ARP traffic to detect multiple MAC addresses claiming
//! the same IP, and specifically monitors the default gateway.

use pnet::util::MacAddr;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::SystemTime;
use tracing::{info, warn};

/// Represents a detected threat
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatAlert {
    pub threat_type: String,
    pub description: String,
    pub severity: String,
    pub timestamp: u64,
}

/// Tracks MAC to IP mappings for ARP spoofing detection.
pub struct ArpMonitor {
    /// Maps IP Address -> (MAC Address, Last Seen Timestamp)
    ip_to_mac: HashMap<Ipv4Addr, (MacAddr, u64)>,
    /// The default gateway IP, if known, for special tracking
    gateway_ip: Option<Ipv4Addr>,
}

impl ArpMonitor {
    pub fn new(gateway_ip: Option<Ipv4Addr>) -> Self {
        Self {
            ip_to_mac: HashMap::new(),
            gateway_ip,
        }
    }

    /// Process an observed ARP packet (Reply or Request).
    /// Returns a `ThreatAlert` if spoofing is detected.
    pub fn observe_arp(&mut self, sender_ip: Ipv4Addr, sender_mac: MacAddr) -> Option<ThreatAlert> {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Avoid tracking all-zero or broadcast MACs/IPs as typical senders
        if sender_mac == MacAddr::zero()
            || sender_mac == MacAddr::broadcast()
            || sender_ip.is_unspecified()
            || sender_ip.is_broadcast()
        {
            return None;
        }

        if let Some((existing_mac, _last_seen)) = self.ip_to_mac.get(&sender_ip) {
            if *existing_mac != sender_mac {
                // MAC address changed for this IP!
                let is_gateway = self.gateway_ip == Some(sender_ip);

                let alert = ThreatAlert {
                    threat_type: if is_gateway {
                        "GATEWAY_ARP_SPOOFING".to_string()
                    } else {
                        "ARP_SPOOFING".to_string()
                    },
                    description: format!(
                        "IP {} was previously seen with MAC {}, but is now claimed by MAC {}.",
                        sender_ip, existing_mac, sender_mac
                    ),
                    severity: if is_gateway {
                        "CRITICAL".to_string()
                    } else {
                        "HIGH".to_string()
                    },
                    timestamp: now,
                };

                warn!(
                    "Threat Detected: {} - {}",
                    alert.threat_type, alert.description
                );

                // Update the mapping to the new MAC so we don't alert continuously on the exact same spoofing state
                self.ip_to_mac.insert(sender_ip, (sender_mac, now));

                return Some(alert);
            } else {
                // Update timestamp
                self.ip_to_mac.insert(sender_ip, (*existing_mac, now));
            }
        } else {
            // First time seeing this IP
            self.ip_to_mac.insert(sender_ip, (sender_mac, now));

            if self.gateway_ip == Some(sender_ip) {
                info!("Gateway MAC locked in: {} -> {}", sender_ip, sender_mac);
            }
        }

        None
    }
}
