//! Linux-specific ARP and gateway implementations.
//!
//! - ARP: Reads `/proc/net/arp` (kernel ARP cache via procfs)
//! - Gateway: Parses `/proc/net/route` (kernel routing table via procfs)

use std::collections::HashMap;
use std::net::Ipv4Addr;

use async_trait::async_trait;
use tokio::fs;

use crate::error::ScanError;
use crate::types::{Device, DeviceStatus};

use super::{ArpProvider, GatewayProvider};

// ---------------------------------------------------------------------------
// ARP Provider
// ---------------------------------------------------------------------------

/// Linux ARP provider that reads `/proc/net/arp`.
pub struct LinuxArpProvider;

#[async_trait]
impl ArpProvider for LinuxArpProvider {
    async fn read_arp_table(&self) -> Result<Vec<Device>, ScanError> {
        let content = fs::read_to_string("/proc/net/arp")
            .await
            .map_err(|e| ScanError::NetworkError(format!("Failed to read /proc/net/arp: {}", e)))?;

        let mut devices = Vec::new();
        for line in content.lines().skip(1) {
            if let Some(device) = parse_arp_line(line) {
                devices.push(device);
            }
        }
        Ok(devices)
    }

    async fn get_mac_for_ip(&self, ip: &str) -> Option<String> {
        let content = fs::read_to_string("/proc/net/arp").await.ok()?;

        for line in content.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 && parts[0] == ip {
                let mac = parts[3];
                if mac != "00:00:00:00:00:00" {
                    return Some(mac.to_string());
                }
            }
        }
        None
    }

    async fn get_arp_cache(&self) -> Result<HashMap<String, String>, ScanError> {
        let content = fs::read_to_string("/proc/net/arp")
            .await
            .map_err(|e| ScanError::NetworkError(format!("Failed to read /proc/net/arp: {}", e)))?;

        let mut cache = HashMap::new();
        for line in content.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                let ip = parts[0];
                let mac = parts[3];
                if mac != "00:00:00:00:00:00" && parts[2] != "0x0" {
                    cache.insert(ip.to_string(), mac.to_string());
                }
            }
        }
        Ok(cache)
    }
}

// ---------------------------------------------------------------------------
// Gateway Provider
// ---------------------------------------------------------------------------

/// Linux gateway provider that parses `/proc/net/route`.
pub struct LinuxGatewayProvider;

#[async_trait]
impl GatewayProvider for LinuxGatewayProvider {
    async fn get_default_gateway(&self) -> Option<String> {
        let content = fs::read_to_string("/proc/net/route").await.ok()?;

        for line in content.lines().skip(1) {
            let fields: Vec<&str> = line.split('\t').collect();
            if fields.len() >= 3 {
                let destination = fields[1];
                let gateway = fields[2];

                // Default route has destination 00000000 and a non-zero gateway
                if destination == "00000000" && gateway != "00000000" {
                    return hex_to_ip(gateway);
                }
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Parse a single line from `/proc/net/arp`.
///
/// Format: `IP_address  HW_type  Flags  HW_address  Mask  Device`
///
/// Example:
/// ```text
/// 192.168.1.1          0x1         0x2         00:11:22:33:44:55     *        eth0
/// ```
fn parse_arp_line(line: &str) -> Option<Device> {
    let parts: Vec<&str> = line.split_whitespace().collect();

    // Need at least 4 parts: IP, HW type, Flags, HW address
    if parts.len() < 4 {
        return None;
    }

    let ip = parts[0];

    // Skip incomplete entries (flags == 0x0)
    let flags = parts[2];
    if flags == "0x0" {
        return None;
    }

    let mac = parts[3];

    // Skip empty/zero MAC addresses
    if mac == "00:00:00:00:00:00" {
        return None;
    }

    // Validate IP address format
    let _ip_addr: Ipv4Addr = ip.parse().ok()?;

    let mut device = Device::new(ip.to_string());
    device.mac = mac.to_string();
    device.status = DeviceStatus::Online;

    Some(device)
}

/// Convert a little-endian hex string (e.g., `"01A8C0"`) to a dotted-decimal IP.
///
/// `/proc/net/route` stores IPs as 8-character hex strings in **little-endian**
/// byte order: `0101A8C0` → `192.168.1.1`.
fn hex_to_ip(hex: &str) -> Option<String> {
    if hex.len() != 8 {
        return None;
    }
    let b0 = u8::from_str_radix(&hex[6..8], 16).ok()?;
    let b1 = u8::from_str_radix(&hex[4..6], 16).ok()?;
    let b2 = u8::from_str_radix(&hex[2..4], 16).ok()?;
    let b3 = u8::from_str_radix(&hex[0..2], 16).ok()?;
    Some(format!("{}.{}.{}.{}", b0, b1, b2, b3))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    // -- parse_arp_line tests --

    #[test]
    fn test_parse_arp_line_valid() {
        let line =
            "192.168.1.1          0x1         0x2         00:11:22:33:44:55     *        eth0";
        let device = parse_arp_line(line);
        assert!(device.is_some());
        let device = device.unwrap();
        assert_eq!(device.ip, "192.168.1.1");
        assert_eq!(device.mac, "00:11:22:33:44:55");
        assert_eq!(device.status, DeviceStatus::Online);
    }

    #[test]
    fn test_parse_arp_line_incomplete_flags() {
        let line =
            "192.168.1.1          0x1         0x0         00:00:00:00:00:00     *        eth0";
        assert!(parse_arp_line(line).is_none());
    }

    #[test]
    fn test_parse_arp_line_zero_mac() {
        let line =
            "192.168.1.1          0x1         0x2         00:00:00:00:00:00     *        eth0";
        assert!(parse_arp_line(line).is_none());
    }

    #[test]
    fn test_parse_arp_line_insufficient_parts() {
        let line = "192.168.1.1 0x1 0x2";
        assert!(parse_arp_line(line).is_none());
    }

    #[test]
    fn test_parse_arp_line_invalid_ip() {
        let line = "not_an_ip          0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0";
        assert!(parse_arp_line(line).is_none());
    }

    #[test]
    fn test_parse_arp_line_multiple_devices() {
        let lines = vec![
            "192.168.1.1          0x1         0x2         aa:bb:cc:dd:ee:01     *        eth0",
            "192.168.1.2          0x1         0x2         aa:bb:cc:dd:ee:02     *        eth0",
            "192.168.1.3          0x1         0x0         00:00:00:00:00:00     *        eth0",
        ];
        let devices: Vec<Device> = lines.iter().filter_map(|l| parse_arp_line(l)).collect();
        assert_eq!(devices.len(), 2);
        assert_eq!(devices[0].mac, "aa:bb:cc:dd:ee:01");
        assert_eq!(devices[1].mac, "aa:bb:cc:dd:ee:02");
    }

    // -- hex_to_ip tests --

    #[test]
    fn test_hex_to_ip_default_gateway() {
        // 0101A8C0 in little-endian = 192.168.1.1
        assert_eq!(hex_to_ip("0101A8C0"), Some("192.168.1.1".to_string()));
    }

    #[test]
    fn test_hex_to_ip_zero() {
        assert_eq!(hex_to_ip("00000000"), Some("0.0.0.0".to_string()));
    }

    #[test]
    fn test_hex_to_ip_invalid_length() {
        assert_eq!(hex_to_ip("0101A8"), None);
        assert_eq!(hex_to_ip("0101A8C0FF"), None);
    }

    #[test]
    fn test_hex_to_ip_invalid_hex() {
        assert_eq!(hex_to_ip("GGGGGGGG"), None);
    }

    #[test]
    fn test_hex_to_ip_typical_gateway() {
        // FE01A8C0 = 192.168.1.254
        assert_eq!(hex_to_ip("FE01A8C0"), Some("192.168.1.254".to_string()));
    }
}
