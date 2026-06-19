//! Input sanitization and validation module for IPC hardening.
//!
//! All string inputs from the frontend MUST be validated through these
//! functions before any processing occurs. This prevents injection attacks,
//! invalid data propagation, and ensures type safety at the IPC boundary.

use std::net::IpAddr;
use std::str::FromStr;

use once_cell::sync::Lazy;
use regex::Regex;

use crate::error::ScanError;

/// Regex for validating profile/baseline names and IDs.
/// Allows alphanumeric characters, underscores, hyphens, and spaces.
/// Length: 1-100 characters.
static NAME_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[a-zA-Z0-9_\-\s]{1,100}$").unwrap_or_else(|_| Regex::new(r"^.{1,100}$").unwrap())
});

/// Regex for validating UUID format strings.
static UUID_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
        .unwrap_or_else(|_| Regex::new(r"^.{1,100}$").unwrap())
});

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
/// Names must match the regex `^[a-zA-Z0-9_\-\s]{1,100}$`.
/// Returns the trimmed name on success.
pub fn validate_name(input: &str) -> Result<String, ScanError> {
    let trimmed = input.trim();

    if trimmed.is_empty() {
        return Err(ScanError::InvalidInput("Name cannot be empty".to_string()));
    }

    if !NAME_REGEX.is_match(trimmed) {
        return Err(ScanError::InvalidInput(format!(
            "Name '{}' contains invalid characters. Only alphanumeric, underscore, hyphen, and space are allowed (max 100 chars)",
            trimmed
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

    if !UUID_REGEX.is_match(trimmed) {
        return Err(ScanError::InvalidInput(format!(
            "ID '{}' is not a valid UUID format",
            trimmed
        )));
    }

    Ok(trimmed.to_string())
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
}
