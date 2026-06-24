//! macOS-specific ARP and gateway implementations.
//!
//! - ARP: Executes `arp -a` via `tokio::process::Command` and parses the output.
//! - Gateway: Executes `route -n get default` via `tokio::process::Command` and
//!   parses the `gateway:` line. Falls back to `netstat -rn` if `route` fails.

use async_trait::async_trait;
use tokio::process::Command;

use crate::error::ScanError;
use crate::types::{Device, DeviceStatus};

use super::{ArpProvider, GatewayProvider};

// ---------------------------------------------------------------------------
// ARP Provider
// ---------------------------------------------------------------------------

/// macOS ARP provider that executes `arp -a` and parses the output.
pub struct MacOsArpProvider;

#[async_trait]
impl ArpProvider for MacOsArpProvider {
    async fn read_arp_table(&self) -> Result<Vec<Device>, ScanError> {
        let output = run_arp_command().await?;
        let mut devices = Vec::new();

        for line in output.lines() {
            if let Some(device) = parse_macos_arp_line(line) {
                devices.push(device);
            }
        }

        Ok(devices)
    }

    async fn get_mac_for_ip(&self, ip: &str) -> Option<String> {
        let output = run_arp_command().await.ok()?;

        for line in output.lines() {
            if let Some((entry_ip, mac)) = parse_macos_arp_entry(line) {
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

/// macOS gateway provider that executes `route -n get default` and parses
/// the gateway line. Falls back to `netstat -rn` if `route` fails.
pub struct MacOsGatewayProvider;

#[async_trait]
impl GatewayProvider for MacOsGatewayProvider {
    async fn get_default_gateway(&self) -> Option<String> {
        // Primary method: route -n get default
        if let Some(gateway) = get_gateway_via_route_command().await {
            return Some(gateway);
        }

        // Fallback: netstat -rn
        get_gateway_via_netstat().await
    }
}

// ---------------------------------------------------------------------------
// Internal helpers — ARP
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

/// Parse a single line from macOS `arp -a` output.
///
/// macOS `arp -a` format:
/// ```text
/// ? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]
/// ? (192.168.1.2) at (incomplete) on en0 ifscope [ethernet]
/// gateway.domain (192.168.1.254) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]
/// ```
///
/// Returns `None` for incomplete entries or lines that don't match the format.
fn parse_macos_arp_line(line: &str) -> Option<Device> {
    let (ip, mac) = parse_macos_arp_entry(line)?;

    // Skip zero MAC
    if mac == "00:00:00:00:00:00" {
        return None;
    }

    let mut device = Device::new(ip);
    device.mac = mac;
    device.status = DeviceStatus::Online;

    Some(device)
}

/// Extract (IP, MAC) from a macOS ARP line.
///
/// Returns `None` if the line is incomplete or doesn't match the expected format.
fn parse_macos_arp_entry(line: &str) -> Option<(String, String)> {
    // Find IP between parentheses: "? (192.168.1.1) at ..."
    let open_paren = line.find('(')?;
    let close_paren = line.find(')')?;
    if close_paren <= open_paren {
        return None;
    }
    let ip = &line[open_paren + 1..close_paren];

    // Validate IP
    if ip.parse::<std::net::Ipv4Addr>().is_err() {
        return None;
    }

    // Find MAC after "at "
    let after_paren = &line[close_paren..];
    let at_pos = after_paren.find(" at ")?;
    let after_at = &after_paren[at_pos + 4..]; // skip " at "

    // MAC is the next whitespace-delimited token
    let mac = after_at.split_whitespace().next()?;

    // Skip incomplete entries: "(incomplete)"
    if mac == "(incomplete)" {
        return None;
    }

    // Validate MAC format (should be colon-separated hex)
    if !is_valid_colon_mac(mac) {
        return None;
    }

    Some((ip.to_string(), mac.to_string()))
}

/// Check if a string is a valid colon-separated MAC address.
///
/// Accepts formats like `aa:bb:cc:dd:ee:ff` (6 groups of 1-2 hex digits).
fn is_valid_colon_mac(mac: &str) -> bool {
    let parts: Vec<&str> = mac.split(':').collect();
    if parts.len() != 6 {
        return false;
    }
    parts.iter().all(|part| {
        !part.is_empty() && part.len() <= 2 && part.chars().all(|c| c.is_ascii_hexdigit())
    })
}

// ---------------------------------------------------------------------------
// Internal helpers — Gateway
// ---------------------------------------------------------------------------

/// Try to get the default gateway using `route -n get default`.
///
/// Output format:
/// ```text
///    route to: default
/// destination: default
///        mask: default
///     gateway: 192.168.1.1
///   interface: en0
/// ```
async fn get_gateway_via_route_command() -> Option<String> {
    let output = Command::new("route")
        .args(["-n", "get", "default"])
        .output()
        .await
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_route_get_output(&stdout)
}

/// Parse the output of `route -n get default` to extract the gateway.
fn parse_route_get_output(output: &str) -> Option<String> {
    for line in output.lines() {
        let trimmed = line.trim();
        if let Some(value) = trimmed.strip_prefix("gateway:") {
            let gateway = value.trim();
            if !gateway.is_empty() && gateway != "default" {
                return Some(gateway.to_string());
            }
        }
    }
    None
}

/// Fallback: get the default gateway using `netstat -rn`.
///
/// Output format:
/// ```text
/// Routing tables
///
/// Internet:
/// Destination        Gateway            Flags        Netif Expire
/// default            192.168.1.1        UGSc           en0
/// ```
async fn get_gateway_via_netstat() -> Option<String> {
    let output = Command::new("netstat").args(["-rn"]).output().await.ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_netstat_output(&stdout)
}

/// Parse the output of `netstat -rn` to find the default gateway.
fn parse_netstat_output(output: &str) -> Option<String> {
    for line in output.lines() {
        let trimmed = line.trim();
        let parts: Vec<&str> = trimmed.split_whitespace().collect();

        // Look for "default" as the destination
        if parts.len() >= 2 && parts[0] == "default" {
            let gateway = parts[1];
            // Validate it looks like an IP address
            if gateway.parse::<std::net::Ipv4Addr>().is_ok() {
                return Some(gateway.to_string());
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

    // -- parse_macos_arp_line tests --

    #[test]
    fn test_parse_macos_arp_line_valid() {
        let line = "? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]";
        let device = parse_macos_arp_line(line);
        assert!(device.is_some());
        let device = device.unwrap();
        assert_eq!(device.ip, "192.168.1.1");
        assert_eq!(device.mac, "aa:bb:cc:dd:ee:ff");
        assert_eq!(device.status, DeviceStatus::Online);
    }

    #[test]
    fn test_parse_macos_arp_line_with_hostname() {
        let line = "gateway.local (192.168.1.254) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]";
        let device = parse_macos_arp_line(line);
        assert!(device.is_some());
        let device = device.unwrap();
        assert_eq!(device.ip, "192.168.1.254");
        assert_eq!(device.mac, "aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn test_parse_macos_arp_line_incomplete() {
        let line = "? (192.168.1.2) at (incomplete) on en0 ifscope [ethernet]";
        assert!(parse_macos_arp_line(line).is_none());
    }

    #[test]
    fn test_parse_macos_arp_line_empty() {
        assert!(parse_macos_arp_line("").is_none());
    }

    #[test]
    fn test_parse_macos_arp_line_no_parens() {
        let line = "some random text without parens";
        assert!(parse_macos_arp_line(line).is_none());
    }

    #[test]
    fn test_parse_macos_arp_line_multiple_entries() {
        let lines = vec![
            "? (192.168.1.1) at aa:bb:cc:dd:ee:01 on en0 ifscope [ethernet]",
            "? (192.168.1.2) at aa:bb:cc:dd:ee:02 on en0 ifscope [ethernet]",
            "? (192.168.1.3) at (incomplete) on en0 ifscope [ethernet]",
        ];
        let devices: Vec<Device> = lines
            .iter()
            .filter_map(|l| parse_macos_arp_line(l))
            .collect();
        assert_eq!(devices.len(), 2);
        assert_eq!(devices[0].mac, "aa:bb:cc:dd:ee:01");
        assert_eq!(devices[1].mac, "aa:bb:cc:dd:ee:02");
    }

    // -- is_valid_colon_mac tests --

    #[test]
    fn test_is_valid_colon_mac_valid() {
        assert!(is_valid_colon_mac("aa:bb:cc:dd:ee:ff"));
        assert!(is_valid_colon_mac("AA:BB:CC:DD:EE:FF"));
        assert!(is_valid_colon_mac("0:1:2:3:4:5")); // single-digit octets (macOS can do this)
    }

    #[test]
    fn test_is_valid_colon_mac_invalid() {
        assert!(!is_valid_colon_mac("aa-bb-cc-dd-ee-ff"));
        assert!(!is_valid_colon_mac("aa:bb:cc"));
        assert!(!is_valid_colon_mac("gg:bb:cc:dd:ee:ff"));
        assert!(!is_valid_colon_mac(""));
    }

    // -- parse_route_get_output tests --

    #[test]
    fn test_parse_route_get_output_valid() {
        let output = r#"   route to: default
destination: default
       mask: default
    gateway: 192.168.1.1
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING>
 sockbuf size: send 131072 recv 131072
"#;
        assert_eq!(
            parse_route_get_output(output),
            Some("192.168.1.1".to_string())
        );
    }

    #[test]
    fn test_parse_route_get_output_no_gateway() {
        let output = "   route to: default\ndestination: default\n";
        assert_eq!(parse_route_get_output(output), None);
    }

    #[test]
    fn test_parse_route_get_output_empty() {
        assert_eq!(parse_route_get_output(""), None);
    }

    // -- parse_netstat_output tests --

    #[test]
    fn test_parse_netstat_output_valid() {
        let output = r#"Routing tables

Internet:
Destination        Gateway            Flags        Netif Expire
default            192.168.1.1        UGSc           en0
127.0.0.1          127.0.0.1          UH             lo0
192.168.1.0/24     link#4             UCS            en0
"#;
        assert_eq!(
            parse_netstat_output(output),
            Some("192.168.1.1".to_string())
        );
    }

    #[test]
    fn test_parse_netstat_output_no_default() {
        let output = r#"Routing tables

Internet:
Destination        Gateway            Flags        Netif Expire
127.0.0.1          127.0.0.1          UH             lo0
"#;
        assert_eq!(parse_netstat_output(output), None);
    }

    #[test]
    fn test_parse_netstat_output_empty() {
        assert_eq!(parse_netstat_output(""), None);
    }
}
