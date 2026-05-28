//! Windows-specific ARP and gateway implementations.
//!
//! - ARP: Executes `arp -a` via `tokio::process::Command` and parses the output.
//! - Gateway: Executes `route print 0.0.0.0` via `tokio::process::Command` and
//!   parses the active routes for the default gateway.

use async_trait::async_trait;
use tokio::process::Command;

use crate::error::ScanError;
use crate::types::{Device, DeviceStatus};

use super::{ArpProvider, GatewayProvider};

// ---------------------------------------------------------------------------
// ARP Provider
// ---------------------------------------------------------------------------

/// Windows ARP provider that executes `arp -a` and parses the output.
pub struct WindowsArpProvider;

#[async_trait]
impl ArpProvider for WindowsArpProvider {
    async fn read_arp_table(&self) -> Result<Vec<Device>, ScanError> {
        let output = run_arp_command().await?;
        let mut devices = Vec::new();

        for line in output.lines() {
            if let Some(device) = parse_windows_arp_line(line) {
                devices.push(device);
            }
        }

        Ok(devices)
    }

    async fn get_mac_for_ip(&self, ip: &str) -> Option<String> {
        let output = run_arp_command().await.ok()?;

        for line in output.lines() {
            if let Some((entry_ip, mac)) = parse_windows_arp_entry(line) {
                if entry_ip == ip {
                    return Some(mac);
                }
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// Gateway Provider
// ---------------------------------------------------------------------------

/// Windows gateway provider that executes `route print 0.0.0.0` and parses
/// the active routes.
pub struct WindowsGatewayProvider;

#[async_trait]
impl GatewayProvider for WindowsGatewayProvider {
    async fn get_default_gateway(&self) -> Option<String> {
        let output = Command::new("route")
            .args(["print", "0.0.0.0"])
            .output()
            .await
            .ok()?;

        if !output.status.success() {
            return None;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        parse_windows_route_output(&stdout)
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Execute `arp -a` and return its stdout as a `String`.
async fn run_arp_command() -> Result<String, ScanError> {
    let output = Command::new("arp")
        .arg("-a")
        .output()
        .await
        .map_err(|e| ScanError::NetworkError(format!("Failed to execute 'arp -a': {}", e)))?;

    if !output.status.success() {
        return Err(ScanError::NetworkError(format!(
            "'arp -a' exited with status {}",
            output.status
        )));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Parse a single line from Windows `arp -a` output.
///
/// Windows `arp -a` format:
/// ```text
///   192.168.1.1           aa-bb-cc-dd-ee-ff     dynamic
///   192.168.1.255         ff-ff-ff-ff-ff-ff     static
/// ```
///
/// Returns `None` for header lines, interface lines, empty lines,
/// static/broadcast entries, and entries with zero MACs.
fn parse_windows_arp_line(line: &str) -> Option<Device> {
    let (ip, mac) = parse_windows_arp_entry(line)?;

    // Skip broadcast/static entries with all-ff MAC
    if mac == "ff:ff:ff:ff:ff:ff" {
        return None;
    }

    // Skip zero MAC
    if mac == "00:00:00:00:00:00" {
        return None;
    }

    let mut device = Device::new(ip);
    device.mac = mac;
    device.status = DeviceStatus::Online;

    Some(device)
}

/// Extract (IP, normalized-MAC) from a Windows ARP line.
///
/// Returns `None` if the line is not a valid ARP entry.
fn parse_windows_arp_entry(line: &str) -> Option<(String, String)> {
    let trimmed = line.trim();
    let parts: Vec<&str> = trimmed.split_whitespace().collect();

    // Need at least 3 parts: IP, MAC, type
    if parts.len() < 3 {
        return None;
    }

    let ip = parts[0];

    // Validate that the first part looks like an IPv4 address
    if ip.parse::<std::net::Ipv4Addr>().is_err() {
        return None;
    }

    let raw_mac = parts[1];

    // Windows uses dashes: aa-bb-cc-dd-ee-ff → normalize to colons
    let mac = normalize_windows_mac(raw_mac)?;

    Some((ip.to_string(), mac))
}

/// Normalize a Windows MAC address from dash format to colon format.
///
/// `aa-bb-cc-dd-ee-ff` → `aa:bb:cc:dd:ee:ff`
///
/// Returns `None` if the format is invalid.
fn normalize_windows_mac(mac: &str) -> Option<String> {
    let parts: Vec<&str> = mac.split('-').collect();
    if parts.len() != 6 {
        return None;
    }

    // Validate each octet is a 2-character hex string
    for part in &parts {
        if part.len() != 2 {
            return None;
        }
        if u8::from_str_radix(part, 16).is_err() {
            return None;
        }
    }

    Some(parts.join(":"))
}

/// Parse the output of `route print 0.0.0.0` to find the default gateway.
///
/// Expected format (within Active Routes section):
/// ```text
/// Network Destination        Netmask          Gateway       Interface  Metric
///           0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.100     25
/// ```
fn parse_windows_route_output(output: &str) -> Option<String> {
    for line in output.lines() {
        let trimmed = line.trim();
        let parts: Vec<&str> = trimmed.split_whitespace().collect();

        // Look for a route line with at least 4 columns:
        // destination, netmask, gateway, interface
        if parts.len() >= 4 {
            let destination = parts[0];
            let netmask = parts[1];
            let gateway = parts[2];

            // Default route: destination 0.0.0.0 with netmask 0.0.0.0
            if destination == "0.0.0.0" && netmask == "0.0.0.0" {
                // Validate gateway is a valid IP and not 0.0.0.0
                if gateway != "0.0.0.0" && gateway.parse::<std::net::Ipv4Addr>().is_ok() {
                    return Some(gateway.to_string());
                }
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    // -- parse_windows_arp_line tests --

    #[test]
    fn test_parse_windows_arp_line_valid_dynamic() {
        let line = "  192.168.1.1           aa-bb-cc-dd-ee-ff     dynamic";
        let device = parse_windows_arp_line(line);
        assert!(device.is_some());
        let device = device.unwrap();
        assert_eq!(device.ip, "192.168.1.1");
        assert_eq!(device.mac, "aa:bb:cc:dd:ee:ff");
        assert_eq!(device.status, DeviceStatus::Online);
    }

    #[test]
    fn test_parse_windows_arp_line_static_broadcast() {
        let line = "  192.168.1.255         ff-ff-ff-ff-ff-ff     static";
        assert!(parse_windows_arp_line(line).is_none());
    }

    #[test]
    fn test_parse_windows_arp_line_header() {
        let line = "  Internet Address      Physical Address      Type";
        assert!(parse_windows_arp_line(line).is_none());
    }

    #[test]
    fn test_parse_windows_arp_line_interface_header() {
        let line = "Interface: 192.168.1.100 --- 0x3";
        assert!(parse_windows_arp_line(line).is_none());
    }

    #[test]
    fn test_parse_windows_arp_line_empty() {
        assert!(parse_windows_arp_line("").is_none());
        assert!(parse_windows_arp_line("   ").is_none());
    }

    #[test]
    fn test_parse_windows_arp_line_multiple_entries() {
        let lines = vec![
            "  192.168.1.1           aa-bb-cc-dd-ee-01     dynamic",
            "  192.168.1.2           aa-bb-cc-dd-ee-02     dynamic",
            "  192.168.1.255         ff-ff-ff-ff-ff-ff     static",
        ];
        let devices: Vec<Device> = lines.iter().filter_map(|l| parse_windows_arp_line(l)).collect();
        assert_eq!(devices.len(), 2);
        assert_eq!(devices[0].mac, "aa:bb:cc:dd:ee:01");
        assert_eq!(devices[1].mac, "aa:bb:cc:dd:ee:02");
    }

    // -- normalize_windows_mac tests --

    #[test]
    fn test_normalize_windows_mac_valid() {
        assert_eq!(
            normalize_windows_mac("aa-bb-cc-dd-ee-ff"),
            Some("aa:bb:cc:dd:ee:ff".to_string())
        );
    }

    #[test]
    fn test_normalize_windows_mac_uppercase() {
        assert_eq!(
            normalize_windows_mac("AA-BB-CC-DD-EE-FF"),
            Some("AA:BB:CC:DD:EE:FF".to_string())
        );
    }

    #[test]
    fn test_normalize_windows_mac_invalid_length() {
        assert_eq!(normalize_windows_mac("aa-bb-cc"), None);
        assert_eq!(normalize_windows_mac("aa-bb-cc-dd-ee-ff-00"), None);
    }

    #[test]
    fn test_normalize_windows_mac_invalid_hex() {
        assert_eq!(normalize_windows_mac("gg-bb-cc-dd-ee-ff"), None);
    }

    #[test]
    fn test_normalize_windows_mac_colon_format() {
        // Already in colon format — should fail (not Windows format)
        assert_eq!(normalize_windows_mac("aa:bb:cc:dd:ee:ff"), None);
    }

    // -- parse_windows_route_output tests --

    #[test]
    fn test_parse_windows_route_output_valid() {
        let output = r#"
===========================================================================
Interface List
 12 ...00 50 56 c0 00 08 ...... VMware Network Adapter VMnet8
===========================================================================

IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.100     25
        127.0.0.0        255.0.0.0        127.0.0.1      127.0.0.1    331
===========================================================================
"#;
        assert_eq!(
            parse_windows_route_output(output),
            Some("192.168.1.1".to_string())
        );
    }

    #[test]
    fn test_parse_windows_route_output_no_default() {
        let output = r#"
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
        127.0.0.0        255.0.0.0        127.0.0.1      127.0.0.1    331
"#;
        assert_eq!(parse_windows_route_output(output), None);
    }

    #[test]
    fn test_parse_windows_route_output_empty() {
        assert_eq!(parse_windows_route_output(""), None);
    }

    #[test]
    fn test_parse_windows_route_output_multiple_routes() {
        let output = r#"
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0     10.0.0.1       10.0.0.50       10
          0.0.0.0          0.0.0.0     192.168.1.1    192.168.1.100   25
"#;
        // Should return the first default route found
        assert_eq!(
            parse_windows_route_output(output),
            Some("10.0.0.1".to_string())
        );
    }
}
