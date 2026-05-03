use std::collections::HashMap;
use std::net::Ipv4Addr;

use tokio::fs;
use crate::error::ScanError;
use crate::types::Device;

/// Read the system's ARP table to discover devices on the local network.
/// This is the most reliable method on mobile/laptop devices as it uses
/// the kernel's ARP cache populated by any network activity.
pub async fn read_arp_table() -> Result<Vec<Device>, ScanError> {
    let mut devices = Vec::new();

    // Read /proc/net/arp which contains the kernel's ARP table
    let content = fs::read_to_string("/proc/net/arp")
        .await
        .map_err(|e| ScanError::NetworkError(format!("Failed to read ARP table: {}", e)))?;

    // Parse each line (skip header)
    for line in content.lines().skip(1) {
        if let Some(device) = parse_arp_line(line) {
            devices.push(device);
        }
    }

    Ok(devices)
}

/// Parse a single line from /proc/net/arp
/// Format: IP address  HW type  Flags  HW address        Mask  Device
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

    // Skip empty MAC addresses
    if mac == "00:00:00:00:00:00" {
        return None;
    }

    // Parse IP address
    let _ip_addr: Ipv4Addr = ip.parse().ok()?;

    // Determine hostname (optional, can be None)
    let hostname = None;

    let mut device = Device::new(ip.to_string());
    device.mac = mac.to_string();
    device.hostname = hostname;
    device.status = crate::types::DeviceStatus::Online;

    Some(device)
}

/// Get a mapping of IP addresses to MAC addresses from the ARP table
pub async fn get_arp_cache() -> Result<HashMap<String, String>, ScanError> {
    let content = fs::read_to_string("/proc/net/arp")
        .await
        .map_err(|e| ScanError::NetworkError(format!("Failed to read ARP table: {}", e)))?;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_arp_line_valid() {
        let line = "192.168.1.1          0x1         0x2         00:11:22:33:44:55     *        eth0";
        let device = parse_arp_line(line);
        assert!(device.is_some());
        let device = device.unwrap();
        assert_eq!(device.ip, "192.168.1.1");
        assert_eq!(device.mac, "00:11:22:33:44:55");
    }

    #[test]
    fn test_parse_arp_line_incomplete() {
        let line = "192.168.1.1          0x1         0x0         00:00:00:00:00:00     *        eth0";
        let device = parse_arp_line(line);
        assert!(device.is_none());
    }

    #[test]
    fn test_parse_arp_line_insufficient_parts() {
        let line = "192.168.1.1 0x1 0x2";
        let device = parse_arp_line(line);
        assert!(device.is_none());
    }
}