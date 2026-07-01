//! Input sanitization and validation module for IPC hardening.
//!
//! All string inputs from the frontend MUST be validated through these
//! functions before any processing occurs. This prevents injection attacks,
//! invalid data propagation, and ensures type safety at the IPC boundary.

use std::net::IpAddr;
use std::str::FromStr;

use crate::error::ScanError;

/// Maximum length for validated names and identifiers.
const MAX_NAME_LEN: usize = 100;

/// Validate and parse a CIDR notation string.
///
/// Accepts standard CIDR notation (e.g., "192.168.1.0/24").
/// Returns the parsed `IpNetwork` on success, or `ScanError::InvalidCidr` on failure.
///
/// # Examples
/// ```ignore
/// let net = validate_cidr("192.168.1.0/24")?;
/// assert_eq!(net.prefix(), 24);
/// ```
pub fn validate_cidr(input: &str) -> Result<ipnetwork::IpNetwork, ScanError> {
    let trimmed = input.trim();

    if trimmed.is_empty() {
        return Err(ScanError::InvalidCidr(
            "CIDR string cannot be empty".to_string(),
        ));
    }

    // Reject strings that are excessively long (prevent DoS via huge allocations)
    if trimmed.len() > 50 {
        return Err(ScanError::InvalidCidr(format!(
            "CIDR string too long ({} chars, max 50)",
            trimmed.len()
        )));
    }

    ipnetwork::IpNetwork::from_str(trimmed)
        .map_err(|e| ScanError::InvalidCidr(format!("'{}': {}", trimmed, e)))
}

/// Validate and parse an IP address string.
///
/// Accepts both IPv4 and IPv6 addresses.
/// Returns the parsed `IpAddr` on success, or `ScanError::InvalidInput` on failure.
pub fn validate_ip(input: &str) -> Result<IpAddr, ScanError> {
    let trimmed = input.trim();

    if trimmed.is_empty() {
        return Err(ScanError::InvalidInput(
            "IP address string cannot be empty".to_string(),
        ));
    }

    IpAddr::from_str(trimmed)
        .map_err(|e| ScanError::InvalidInput(format!("Invalid IP address '{}': {}", trimmed, e)))
}

/// Validate a single port number.
///
/// Ports must be in the range 1-65535 (port 0 is reserved).
pub fn validate_port(port: u16) -> Result<(), ScanError> {
    if port == 0 {
        return Err(ScanError::InvalidPort(
            "Port 0 is reserved and cannot be scanned".to_string(),
        ));
    }
    Ok(())
}

/// Validate a list of port numbers.
///
/// All ports must be in the range 1-65535. The list must not be empty
/// and must not exceed 65535 entries.
pub fn validate_ports(ports: &[u16]) -> Result<(), ScanError> {
    if ports.is_empty() {
        return Err(ScanError::InvalidPort(
            "Port list cannot be empty when ports are explicitly specified".to_string(),
        ));
    }

    if ports.len() > 65535 {
        return Err(ScanError::InvalidPort(format!(
            "Too many ports specified ({} max 65535)",
            ports.len()
        )));
    }

    for &port in ports {
        validate_port(port)?;
    }

    // Check for duplicates
    let mut sorted = ports.to_vec();
    sorted.sort();
    sorted.dedup();
    if sorted.len() != ports.len() {
        return Err(ScanError::InvalidPort(
            "Duplicate port numbers detected".to_string(),
        ));
    }

    Ok(())
}

/// Validate a name string (profile name, baseline name, etc.).
///
/// Names must be 1-100 characters and contain only alphanumeric characters,
/// underscores, hyphens, and spaces.
/// Returns the trimmed name on success.
pub fn validate_name(input: &str) -> Result<String, ScanError> {
    let trimmed = input.trim();

    if trimmed.is_empty() {
        return Err(ScanError::InvalidInput("Name cannot be empty".to_string()));
    }

    if trimmed.len() > MAX_NAME_LEN {
        return Err(ScanError::InvalidInput(format!(
            "Name '{}' exceeds maximum length of {} characters",
            trimmed, MAX_NAME_LEN
        )));
    }

    if !trimmed
        .chars()
        .all(|c| c.is_alphanumeric() || c == '_' || c == '-' || c.is_whitespace())
    {
        return Err(ScanError::InvalidInput(format!(
            "Name '{}' contains invalid characters. Only alphanumeric, underscore, hyphen, and space are allowed (max {} chars)",
            trimmed, MAX_NAME_LEN
        )));
    }

    Ok(trimmed.to_string())
}

/// Validate a UUID-format identifier string.
///
/// Accepts standard UUID format: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`
/// Also accepts the special "default" identifier.
/// Returns the validated ID on success.
pub fn validate_id(input: &str) -> Result<String, ScanError> {
    let trimmed = input.trim();

    if trimmed.is_empty() {
        return Err(ScanError::InvalidInput("ID cannot be empty".to_string()));
    }

    // Allow the special "default" identifier
    if trimmed == "default" {
        return Ok(trimmed.to_string());
    }

    if !is_valid_uuid(trimmed) {
        return Err(ScanError::InvalidInput(format!(
            "ID '{}' is not a valid UUID format",
            trimmed
        )));
    }

    Ok(trimmed.to_string())
}

/// Manual UUID format check without regex to avoid production panics.
///
/// Accepts `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` where `x` is a hex digit.
fn is_valid_uuid(input: &str) -> bool {
    let bytes = input.as_bytes();
    if bytes.len() != 36 {
        return false;
    }

    let expected_dashes: [usize; 4] = [8, 13, 18, 23];
    for &pos in &expected_dashes {
        if bytes[pos] != b'-' {
            return false;
        }
    }

    for (i, &b) in bytes.iter().enumerate() {
        if expected_dashes.contains(&i) {
            continue;
        }
        if !b.is_ascii_hexdigit() {
            return false;
        }
    }

    true
}

/// Validate a timeout value in milliseconds.
///
/// Timeout must be between 100ms and 300000ms (5 minutes).
pub fn validate_timeout_ms(timeout_ms: u64) -> Result<u64, ScanError> {
    if timeout_ms < 100 {
        return Err(ScanError::InvalidInput(
            "Timeout must be at least 100ms".to_string(),
        ));
    }
    if timeout_ms > 300_000 {
        return Err(ScanError::InvalidInput(
            "Timeout cannot exceed 300000ms (5 minutes)".to_string(),
        ));
    }
    Ok(timeout_ms)
}

/// Validate a concurrency limit.
///
/// Must be between 1 and 10000.
pub fn validate_concurrency(value: usize) -> Result<usize, ScanError> {
    if value == 0 {
        return Err(ScanError::InvalidInput(
            "Concurrency limit cannot be 0".to_string(),
        ));
    }
    if value > 10_000 {
        return Err(ScanError::InvalidInput(
            "Concurrency limit cannot exceed 10000".to_string(),
        ));
    }
    Ok(value)
}

/// Parse a port expression into a sorted, deduplicated list of ports.
///
/// Supported syntax:
/// - Comma-separated ports: `22,80,443`
/// - Ranges: `22-100`, `1000-2000`
/// - Presets (case-insensitive): `top-100`, `top100`, `top-1000`, `top1000`,
///   `top-10000`, `top10000`
/// - Mixed: `22,80,443,1000-2000,top-100`
///
/// Duplicate ports are removed and reported via the returned `Option<String>`
/// warning. Port 0 is rejected.
pub fn parse_port_expression(input: &str) -> Result<(Vec<u16>, Option<String>), ScanError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Ok((Vec::new(), None));
    }

    let mut ports = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut duplicates = Vec::new();

    for token in trimmed.split(',') {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }

        let lower = token.to_lowercase();
        let preset_ports = match lower.as_str() {
            "top-100" | "top100" => Some(top_100_ports()),
            "top-1000" | "top1000" => Some(top_1000_ports()),
            "top-10000" | "top10000" => Some(top_10000_ports()),
            _ => None,
        };

        if let Some(preset_ports) = preset_ports {
            for port in preset_ports {
                if !seen.insert(port) {
                    duplicates.push(port);
                } else {
                    ports.push(port);
                }
            }
        } else if let Some((start, end)) = token.split_once('-') {
            let start = start.trim().parse::<u16>().map_err(|_| {
                ScanError::InvalidPort(format!("Invalid port range start in '{}'", token))
            })?;
            let end = end.trim().parse::<u16>().map_err(|_| {
                ScanError::InvalidPort(format!("Invalid port range end in '{}'", token))
            })?;

            if start == 0 || end == 0 {
                return Err(ScanError::InvalidPort(
                    "Port 0 is not allowed in port ranges".to_string(),
                ));
            }
            if start > end {
                return Err(ScanError::InvalidPort(format!(
                    "Invalid port range '{}': start is greater than end",
                    token
                )));
            }

            for port in start..=end {
                if !seen.insert(port) {
                    duplicates.push(port);
                } else {
                    ports.push(port);
                }
            }
        } else {
            let port = token
                .parse::<u16>()
                .map_err(|_| ScanError::InvalidPort(format!("Invalid port number '{}'", token)))?;
            if port == 0 {
                return Err(ScanError::InvalidPort("Port 0 is not allowed".to_string()));
            }
            if !seen.insert(port) {
                duplicates.push(port);
            } else {
                ports.push(port);
            }
        }
    }

    let warning = if duplicates.is_empty() {
        None
    } else {
        duplicates.sort_unstable();
        duplicates.dedup();
        Some(format!(
            "Duplicate ports removed: {}",
            duplicates
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ))
    };

    ports.sort_unstable();
    Ok((ports, warning))
}

fn top_100_ports() -> Vec<u16> {
    (1..=100).collect()
}

fn top_1000_ports() -> Vec<u16> {
    (1..=1000).collect()
}

fn top_10000_ports() -> Vec<u16> {
    (1..=10000).collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    // -- CIDR validation tests --

    #[test]
    fn test_validate_cidr_valid() {
        assert!(validate_cidr("192.168.1.0/24").is_ok());
        assert!(validate_cidr("10.0.0.0/8").is_ok());
        assert!(validate_cidr("172.16.0.0/12").is_ok());
        assert!(validate_cidr("192.168.1.0/30").is_ok());
    }

    #[test]
    fn test_validate_cidr_invalid() {
        assert!(validate_cidr("").is_err());
        assert!(validate_cidr("invalid").is_err());
        assert!(validate_cidr("256.1.1.1/24").is_err());
        assert!(validate_cidr("192.168.1.0/33").is_err());
        assert!(validate_cidr("   ").is_err());
    }

    #[test]
    fn test_validate_cidr_trimming() {
        assert!(validate_cidr("  192.168.1.0/24  ").is_ok());
    }

    #[test]
    fn test_validate_cidr_too_long() {
        let long = "a".repeat(51);
        assert!(validate_cidr(&long).is_err());
    }

    // -- IP validation tests --

    #[test]
    fn test_validate_ip_valid() {
        assert!(validate_ip("192.168.1.1").is_ok());
        assert!(validate_ip("10.0.0.1").is_ok());
        assert!(validate_ip("::1").is_ok());
        assert!(validate_ip("fe80::1").is_ok());
    }

    #[test]
    fn test_validate_ip_invalid() {
        assert!(validate_ip("").is_err());
        assert!(validate_ip("not_an_ip").is_err());
        assert!(validate_ip("256.1.1.1").is_err());
    }

    // -- Port validation tests --

    #[test]
    fn test_validate_port_valid() {
        assert!(validate_port(1).is_ok());
        assert!(validate_port(80).is_ok());
        assert!(validate_port(443).is_ok());
        assert!(validate_port(65535).is_ok());
    }

    #[test]
    fn test_validate_port_zero() {
        assert!(validate_port(0).is_err());
    }

    #[test]
    fn test_validate_ports_valid() {
        assert!(validate_ports(&[80, 443, 8080]).is_ok());
    }

    #[test]
    fn test_validate_ports_empty() {
        assert!(validate_ports(&[]).is_err());
    }

    #[test]
    fn test_validate_ports_duplicates() {
        assert!(validate_ports(&[80, 80, 443]).is_err());
    }

    #[test]
    fn test_validate_ports_with_zero() {
        assert!(validate_ports(&[80, 0, 443]).is_err());
    }

    // -- Name validation tests --

    #[test]
    fn test_validate_name_valid() {
        assert!(validate_name("My Profile").is_ok());
        assert!(validate_name("test-profile_1").is_ok());
        assert!(validate_name("Default").is_ok());
    }

    #[test]
    fn test_validate_name_invalid() {
        assert!(validate_name("").is_err());
        assert!(validate_name("   ").is_err());
        assert!(validate_name("name<script>").is_err());
        assert!(validate_name("name;DROP TABLE").is_err());
    }

    #[test]
    fn test_validate_name_too_long() {
        let long_name = "a".repeat(101);
        assert!(validate_name(&long_name).is_err());
    }

    // -- ID validation tests --

    #[test]
    fn test_validate_id_valid_uuid() {
        assert!(validate_id("550e8400-e29b-41d4-a716-446655440000").is_ok());
    }

    #[test]
    fn test_validate_id_default() {
        assert!(validate_id("default").is_ok());
    }

    #[test]
    fn test_validate_id_invalid() {
        assert!(validate_id("").is_err());
        assert!(validate_id("not-a-uuid").is_err());
        assert!(validate_id("../../../etc/passwd").is_err());
    }

    // -- Timeout validation tests --

    #[test]
    fn test_validate_timeout_valid() {
        assert!(validate_timeout_ms(100).is_ok());
        assert!(validate_timeout_ms(3000).is_ok());
        assert!(validate_timeout_ms(300_000).is_ok());
    }

    #[test]
    fn test_validate_timeout_too_small() {
        assert!(validate_timeout_ms(0).is_err());
        assert!(validate_timeout_ms(50).is_err());
    }

    #[test]
    fn test_validate_timeout_too_large() {
        assert!(validate_timeout_ms(300_001).is_err());
    }

    // -- Concurrency validation tests --

    #[test]
    fn test_validate_concurrency_valid() {
        assert!(validate_concurrency(1).is_ok());
        assert!(validate_concurrency(100).is_ok());
        assert!(validate_concurrency(10_000).is_ok());
    }

    #[test]
    fn test_validate_concurrency_zero() {
        assert!(validate_concurrency(0).is_err());
    }

    #[test]
    fn test_validate_concurrency_too_large() {
        assert!(validate_concurrency(10_001).is_err());
    }

    // -- Port expression parser tests --

    #[test]
    fn test_parse_port_expression_comma_list() {
        let (ports, warning) = parse_port_expression("22,80,443").unwrap();
        assert_eq!(ports, vec![22, 80, 443]);
        assert!(warning.is_none());
    }

    #[test]
    fn test_parse_port_expression_range() {
        let (ports, warning) = parse_port_expression("22-25").unwrap();
        assert_eq!(ports, vec![22, 23, 24, 25]);
        assert!(warning.is_none());
    }

    #[test]
    fn test_parse_port_expression_presets() {
        let (ports, warning) = parse_port_expression("top100").unwrap();
        assert_eq!(ports.len(), 100);
        assert_eq!(ports[0], 1);
        assert_eq!(ports[99], 100);
        assert!(warning.is_none());

        let (ports, warning) = parse_port_expression("top-1000").unwrap();
        assert_eq!(ports.len(), 1000);
        assert!(warning.is_none());

        let (ports, warning) = parse_port_expression("TOP10000").unwrap();
        assert_eq!(ports.len(), 10000);
        assert!(warning.is_none());
    }

    #[test]
    fn test_parse_port_expression_mixed() {
        let (ports, warning) = parse_port_expression("5000,6000,7000-7002,top-100").unwrap();
        let mut expected: Vec<u16> = (1..=100).collect();
        expected.extend_from_slice(&[5000, 6000, 7000, 7001, 7002]);
        assert_eq!(ports, expected);
        assert!(warning.is_none());
    }

    #[test]
    fn test_parse_port_expression_duplicates_warn() {
        let (ports, warning) = parse_port_expression("80,80,443,443").unwrap();
        assert_eq!(ports, vec![80, 443]);
        assert!(warning.is_some());
        assert!(warning.unwrap().contains("Duplicate ports removed"));
    }

    #[test]
    fn test_parse_port_expression_invalid_port() {
        assert!(parse_port_expression("abc").is_err());
        assert!(parse_port_expression("70000").is_err());
    }

    #[test]
    fn test_parse_port_expression_zero_rejected() {
        assert!(parse_port_expression("0").is_err());
        assert!(parse_port_expression("0-10").is_err());
        assert!(parse_port_expression("10-0").is_err());
    }

    #[test]
    fn test_parse_port_expression_invalid_range() {
        assert!(parse_port_expression("10-5").is_err());
        assert!(parse_port_expression("abc-def").is_err());
    }

    #[test]
    fn test_parse_port_expression_empty() {
        let (ports, warning) = parse_port_expression("").unwrap();
        assert!(ports.is_empty());
        assert!(warning.is_none());
    }
}
