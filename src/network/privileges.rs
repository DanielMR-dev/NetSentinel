//! Comprehensive system privilege detection module.
//!
//! Provides a unified `check_system_privileges()` function that returns
//! a `PrivilegeStatus` struct detailing all available capabilities.
//! This is used at startup and on-demand to determine which scanning
//! methods are available.

use serde::{Deserialize, Serialize};

/// Comprehensive privilege status report for the current process.
///
/// Sent to the frontend at startup and on-demand so the UI can
/// show/hide features and display appropriate warnings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrivilegeStatus {
    /// Whether the process is running as root/administrator.
    pub is_elevated: bool,

    /// Whether raw socket creation is possible.
    pub has_raw_socket: bool,

    /// Whether CAP_NET_RAW is available (Linux only).
    pub has_cap_net_raw: bool,

    /// Whether SYN scanning is available (requires raw sockets).
    pub syn_scan_available: bool,

    /// Whether ICMP ping is available (requires raw sockets or elevated).
    pub icmp_available: bool,

    /// Whether ARP sweep (active raw Ethernet) is available.
    pub arp_available: bool,

    /// Whether UDP raw scanning is available.
    pub udp_scan_available: bool,

    /// Whether SCTP INIT scanning is available.
    pub sctp_scan_available: bool,

    /// Whether IPv6 multicast discovery is available.
    pub ipv6_discovery_available: bool,

    /// Whether FIN/XMAS/NULL raw TCP scans are available.
    pub fin_xmas_null_available: bool,

    /// Human-readable warnings about missing capabilities.
    pub warnings: Vec<String>,

    /// Current platform identifier.
    pub platform: String,
}

/// Perform a comprehensive privilege check for the current process.
///
/// This function never panics or returns an error. All failures are
/// captured as data in the `PrivilegeStatus` struct.
pub fn check_system_privileges() -> PrivilegeStatus {
    let platform = std::env::consts::OS.to_string();
    let mut warnings = Vec::new();

    let (is_elevated, has_cap_net_raw, has_raw_socket) = check_platform_privileges(&platform);

    // All raw-packet features depend on raw socket capability
    let syn_scan_available = has_raw_socket;
    let icmp_available = has_raw_socket;
    let arp_available = has_raw_socket;
    let udp_scan_available = has_raw_socket;
    let sctp_scan_available = has_raw_socket;
    let ipv6_discovery_available = has_raw_socket;
    let fin_xmas_null_available = has_raw_socket;

    // Generate warnings for missing capabilities
    if !is_elevated {
        match platform.as_str() {
            "linux" => {
                if !has_cap_net_raw {
                    warnings.push(
                        "Not running as root and CAP_NET_RAW is not set. \
                         SYN/FIN/XMAS/NULL, ICMP ping, ARP sweep, UDP raw, SCTP and IPv6 raw \
                         discovery will be unavailable. \
                         Run with sudo or set capabilities: sudo setcap cap_net_raw+ep <binary>"
                            .to_string(),
                    );
                }
            }
            "windows" => {
                warnings.push(
                    "Not running as Administrator. SYN/FIN/XMAS/NULL, ICMP ping, \
                     ARP sweep, UDP raw, SCTP and IPv6 raw discovery will be \
                     unavailable. Run as Administrator for full functionality."
                        .to_string(),
                );
            }
            "macos" => {
                warnings.push(
                    "Not running as root. SYN/FIN/XMAS/NULL, ICMP ping, ARP sweep, \
                     UDP raw, SCTP and IPv6 raw discovery will be unavailable. \
                     Run with sudo for full functionality."
                        .to_string(),
                );
            }
            _ => {
                warnings.push(format!(
                    "Unsupported platform '{}'. Advanced scanning features may be unavailable.",
                    platform
                ));
            }
        }
    }

    if !has_raw_socket && is_elevated {
        // Elevated but still no raw socket — likely a platform limitation
        warnings.push(
            "Raw socket creation failed despite elevated privileges. \
             Raw-packet scanning features may not be supported on this platform."
                .to_string(),
        );
    }

    tracing::info!(
        "Privilege check: elevated={}, cap_net_raw={}, raw_socket={}, syn={}, icmp={}, arp={}, udp={}, sctp={}, ipv6={}, fin/xmas/null={}",
        is_elevated,
        has_cap_net_raw,
        has_raw_socket,
        syn_scan_available,
        icmp_available,
        arp_available,
        udp_scan_available,
        sctp_scan_available,
        ipv6_discovery_available,
        fin_xmas_null_available
    );

    PrivilegeStatus {
        is_elevated,
        has_raw_socket,
        has_cap_net_raw,
        syn_scan_available,
        icmp_available,
        arp_available,
        udp_scan_available,
        sctp_scan_available,
        ipv6_discovery_available,
        fin_xmas_null_available,
        warnings,
        platform,
    }
}

/// Platform-specific privilege checks.
///
/// Returns (is_elevated, has_cap_net_raw, has_raw_socket).
fn check_platform_privileges(platform: &str) -> (bool, bool, bool) {
    match platform {
        "linux" => check_linux_privileges(),
        "windows" => check_windows_privileges(),
        "macos" => check_macos_privileges(),
        _ => (false, false, false),
    }
}

/// Linux privilege check: root and/or CAP_NET_RAW.
#[cfg(target_os = "linux")]
fn check_linux_privileges() -> (bool, bool, bool) {
    let status = match std::fs::read_to_string("/proc/self/status") {
        Ok(s) => s,
        Err(_) => return (false, false, false),
    };

    let mut is_root = false;
    let mut has_cap_net_raw = false;

    for line in status.lines() {
        if line.starts_with("Uid:") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 && parts[2] == "0" {
                is_root = true;
            }
        }

        if line.starts_with("CapEff:") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                if let Ok(cap) = u64::from_str_radix(parts[1], 16) {
                    // CAP_NET_RAW is capability bit 13
                    if cap & (1u64 << 13) != 0 {
                        has_cap_net_raw = true;
                    }
                }
            }
        }
    }

    // Test raw socket creation
    let has_raw_socket = is_root || has_cap_net_raw || test_raw_socket_creation();

    (is_root, has_cap_net_raw, has_raw_socket)
}

#[cfg(not(target_os = "linux"))]
fn check_linux_privileges() -> (bool, bool, bool) {
    (false, false, false)
}

/// Windows privilege check: Administrator.
#[cfg(target_os = "windows")]
fn check_windows_privileges() -> (bool, bool, bool) {
    let output = std::process::Command::new("net")
        .arg("session")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    let is_elevated = match output {
        Ok(status) => status.success(),
        Err(_) => false,
    };

    let has_raw_socket = is_elevated || test_raw_socket_creation();

    (is_elevated, false, has_raw_socket)
}

#[cfg(not(target_os = "windows"))]
fn check_windows_privileges() -> (bool, bool, bool) {
    (false, false, false)
}

/// macOS privilege check: root.
#[cfg(target_os = "macos")]
fn check_macos_privileges() -> (bool, bool, bool) {
    let output = std::process::Command::new("id").arg("-u").output();

    let is_root = match output {
        Ok(out) => {
            let uid = String::from_utf8_lossy(&out.stdout).trim().to_string();
            uid == "0"
        }
        Err(_) => false,
    };

    let has_raw_socket = is_root || test_raw_socket_creation();

    (is_root, false, has_raw_socket)
}

#[cfg(not(target_os = "macos"))]
fn check_macos_privileges() -> (bool, bool, bool) {
    (false, false, false)
}

/// Test whether we can actually create a raw socket.
///
/// This is the definitive test — privilege checks are hints, but
/// actually creating the socket is the proof.
fn test_raw_socket_creation() -> bool {
    use socket2::{Domain, Protocol, Socket, Type};

    match Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::TCP)) {
        Ok(_socket) => true,
        Err(_) => {
            // Try ICMP as fallback
            match Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)) {
                Ok(_socket) => true,
                Err(_) => false,
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_system_privileges_no_panic() {
        let status = check_system_privileges();
        // Should always return a valid status, never panic
        assert!(!status.platform.is_empty());
    }

    #[test]
    fn test_privilege_status_serialization() {
        let status = PrivilegeStatus {
            is_elevated: false,
            has_raw_socket: false,
            has_cap_net_raw: false,
            syn_scan_available: false,
            icmp_available: false,
            arp_available: false,
            udp_scan_available: false,
            sctp_scan_available: false,
            ipv6_discovery_available: false,
            fin_xmas_null_available: false,
            warnings: vec!["test warning".to_string()],
            platform: "linux".to_string(),
        };

        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("\"isElevated\""));
        assert!(json.contains("\"hasRawSocket\""));
        assert!(json.contains("\"hasCapNetRaw\""));
        assert!(json.contains("\"synScanAvailable\""));
        assert!(json.contains("\"icmpAvailable\""));
        assert!(json.contains("\"arpAvailable\""));
        assert!(json.contains("\"udpScanAvailable\""));
        assert!(json.contains("\"sctpScanAvailable\""));
        assert!(json.contains("\"ipv6DiscoveryAvailable\""));
        assert!(json.contains("\"finXmasNullAvailable\""));
    }

    #[test]
    fn test_privilege_status_roundtrip() {
        let status = check_system_privileges();
        let json = serde_json::to_string(&status).unwrap();
        let deserialized: PrivilegeStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(status.platform, deserialized.platform);
        assert_eq!(status.is_elevated, deserialized.is_elevated);
    }

    #[test]
    fn test_test_raw_socket_creation_no_panic() {
        // Should never panic, just return true/false
        let _result = test_raw_socket_creation();
    }
}
