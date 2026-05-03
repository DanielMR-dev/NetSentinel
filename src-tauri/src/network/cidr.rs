use std::net::IpAddr;
use ipnetwork::Ipv4Network;
use crate::error::ScanError;

/// Validate and parse a CIDR notation string
pub fn parse_cidr(cidr: &str) -> Result<Vec<IpAddr>, ScanError> {
    let trimmed = cidr.trim();
    
    // Parse the network
    let network: Ipv4Network = trimmed.parse()
        .map_err(|e| ScanError::InvalidCidr(format!("'{}': {}", trimmed, e)))?;
    
    // Generate all IP addresses in the range
    let mut ips = Vec::new();
    for ip in network.iter() {
        ips.push(IpAddr::V4(ip));
    }
    
    Ok(ips)
}

/// Validate a CIDR string without generating all IPs
pub fn validate_cidr(cidr: &str) -> Result<Ipv4Network, ScanError> {
    let trimmed = cidr.trim();
    trimmed.parse()
        .map_err(|e| ScanError::InvalidCidr(format!("'{}': {}", trimmed, e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_cidr_valid() {
        assert!(validate_cidr("192.168.1.0/24").is_ok());
        assert!(validate_cidr("10.0.0.0/16").is_ok());
        assert!(validate_cidr("192.168.1.0/30").is_ok());
    }

    #[test]
    fn test_validate_cidr_invalid() {
        assert!(validate_cidr("invalid").is_err());
        assert!(validate_cidr("256.1.1.1/24").is_err());
        assert!(validate_cidr("192.168.1.0/33").is_err());
    }
}