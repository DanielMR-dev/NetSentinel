//! Platform capabilities detection command.
//!
//! Provides `get_platform_capabilities`, which detects the current operating
//! system, privilege level, and available network discovery capabilities.
//! Called once at frontend startup so the UI can show/hide discovery methods
//! and display privilege warnings.
//!
//! # Design
//!
//! This function **never fails**. Privilege or I/O errors are captured as data
//! (missing capabilities + human-readable warnings) rather than propagated.

use serde::{Deserialize, Serialize};

use crate::network::privileges;

/// Platform capabilities response sent to the frontend.
///
/// Field names serialize as `camelCase` to match the TypeScript interface:
/// ```typescript
/// interface PlatformCapabilities {
///   platform: 'linux' | 'windows' | 'macos';
///   isElevated: boolean;
///   capabilities: string[];
///   warnings: string[];
/// }
/// ```
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct PlatformCapabilities {
    /// Current operating system: `"linux"`, `"windows"`, or `"macos"`.
    pub platform: String,

    /// Whether the process is running with elevated privileges (root/admin).
    pub is_elevated: bool,

    /// List of available discovery capabilities.
    ///
    /// Possible values:
    /// - `"tcp_probe"` — **always** available (no privileges needed)
    /// - `"arp_scan"` — available if the ARP table can be read
    /// - `"icmp_ping"` — available only with root / CAP_NET_RAW / Administrator
    /// - `"syn_scan"` — available only with raw socket privileges
    pub capabilities: Vec<String>,

    /// Human-readable warnings about missing capabilities.
    ///
    /// Empty when all capabilities are available.
    pub warnings: Vec<String>,
}

/// Detect the current platform's network scanning capabilities.
///
/// This function is called once at application startup by the frontend to
/// determine which discovery methods should be enabled and whether any
/// privilege warnings need to be displayed.
///
/// # Returns
///
/// Always returns `PlatformCapabilities`. Capability detection failures
/// are encoded in the `warnings` field rather than as errors.
pub fn get_platform_capabilities() -> PlatformCapabilities {
    let platform = std::env::consts::OS.to_string();

    // Use the comprehensive privilege check
    let priv_status = privileges::check_system_privileges();

    let mut capabilities = Vec::with_capacity(4);
    let mut warnings = Vec::new();

    // ── TCP probe: always available ─────────────────────────────────────
    capabilities.push("tcp_probe".to_string());

    // ── ARP scan: always advertised (read-only operation) ────────────────
    // The actual ARP table read is async; capability is always available.
    capabilities.push("arp_scan".to_string());

    // ── ICMP ping: requires elevated privileges ─────────────────────────
    let is_elevated = priv_status.is_elevated;

    if priv_status.icmp_available {
        tracing::info!("ICMP privileges confirmed — icmp_ping available");
        capabilities.push("icmp_ping".to_string());
    } else {
        tracing::info!("ICMP privileges unavailable");

        let warning = match platform.as_str() {
            "linux" => concat!(
                "ICMP ping requires root privileges or CAP_NET_RAW capability. ",
                "Run with sudo or set capabilities."
            )
            .to_string(),
            "windows" => concat!(
                "ICMP ping requires Administrator privileges. ",
                "Run as Administrator and ensure Npcap is installed."
            )
            .to_string(),
            "macos" => {
                "ICMP ping requires root privileges. Run with sudo.".to_string()
            }
            other => {
                format!("ICMP ping is not supported on platform '{}'.", other)
            }
        };

        warnings.push(warning);
    }

    // ── SYN scan: requires raw socket privileges ────────────────────────
    if priv_status.syn_scan_available {
        tracing::info!("SYN scan available");
        capabilities.push("syn_scan".to_string());
    } else {
        let warning = match platform.as_str() {
            "linux" => concat!(
                "SYN scanning requires root privileges or CAP_NET_RAW capability. ",
                "Run with sudo or set capabilities for stealth scanning."
            )
            .to_string(),
            "windows" => concat!(
                "SYN scanning requires Administrator privileges and Npcap. ",
                "Run as Administrator for stealth scanning."
            )
            .to_string(),
            "macos" => {
                "SYN scanning requires root privileges. Run with sudo for stealth scanning."
                    .to_string()
            }
            _ => "SYN scanning is not available on this platform.".to_string(),
        };
        warnings.push(warning);
    }

    // Add any warnings from the privilege check
    warnings.extend(priv_status.warnings);

    tracing::info!(
        "Platform capabilities detected: platform={}, elevated={}, capabilities={:?}, warnings={:?}",
        platform,
        is_elevated,
        capabilities,
        warnings
    );

    PlatformCapabilities {
        platform,
        is_elevated,
        capabilities,
        warnings,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_platform_is_valid_os() {
        let caps = get_platform_capabilities();
        let valid_platforms = ["linux", "windows", "macos"];
        assert!(
            valid_platforms.contains(&caps.platform.as_str()),
            "Platform '{}' is not a recognized OS string",
            caps.platform
        );
    }

    #[test]
    fn test_tcp_probe_always_present() {
        let caps = get_platform_capabilities();
        assert!(
            caps.capabilities.contains(&"tcp_probe".to_string()),
            "tcp_probe must always be in capabilities"
        );
    }

    #[test]
    fn test_arp_scan_always_present() {
        let caps = get_platform_capabilities();
        assert!(
            caps.capabilities.contains(&"arp_scan".to_string()),
            "arp_scan should always be advertised (read-only operation)"
        );
    }

    #[test]
    fn test_icmp_ping_conditional() {
        let caps = get_platform_capabilities();

        if caps.is_elevated {
            assert!(
                caps.capabilities.contains(&"icmp_ping".to_string()),
                "icmp_ping must be present when is_elevated is true"
            );
            assert!(
                caps.warnings.is_empty(),
                "No warnings expected when all capabilities are available"
            );
        } else {
            assert!(
                !caps.capabilities.contains(&"icmp_ping".to_string()),
                "icmp_ping must NOT be present when is_elevated is false"
            );
            assert!(
                !caps.warnings.is_empty(),
                "Warnings must be present when ICMP is unavailable"
            );
        }
    }

    #[test]
    fn test_serde_camel_case_serialization() {
        let caps = PlatformCapabilities {
            platform: "linux".to_string(),
            is_elevated: true,
            capabilities: vec!["tcp_probe".to_string()],
            warnings: vec![],
        };

        let json = serde_json::to_string(&caps).expect("serialization should not fail");

        // Verify camelCase field names
        assert!(
            json.contains("\"isElevated\""),
            "Field 'is_elevated' must serialize as 'isElevated'. Got: {}",
            json
        );
        assert!(
            !json.contains("\"is_elevated\""),
            "Field 'is_elevated' must NOT appear in snake_case. Got: {}",
            json
        );

        // Verify all expected fields are present
        assert!(json.contains("\"platform\""));
        assert!(json.contains("\"capabilities\""));
        assert!(json.contains("\"warnings\""));
    }

    #[test]
    fn test_serde_roundtrip() {
        let original = PlatformCapabilities {
            platform: "linux".to_string(),
            is_elevated: false,
            capabilities: vec![
                "tcp_probe".to_string(),
                "arp_scan".to_string(),
            ],
            warnings: vec![
                "ICMP ping requires root privileges.".to_string(),
            ],
        };

        let json = serde_json::to_string(&original).expect("serialization should not fail");
        let deserialized: PlatformCapabilities =
            serde_json::from_str(&json).expect("deserialization should not fail");

        assert_eq!(original.platform, deserialized.platform);
        assert_eq!(original.is_elevated, deserialized.is_elevated);
        assert_eq!(original.capabilities, deserialized.capabilities);
        assert_eq!(original.warnings, deserialized.warnings);
    }

    #[test]
    fn test_capabilities_vec_has_no_duplicates() {
        let caps = get_platform_capabilities();
        let mut seen = std::collections::HashSet::new();
        for cap in &caps.capabilities {
            assert!(
                seen.insert(cap.clone()),
                "Duplicate capability found: {}",
                cap
            );
        }
    }

    #[test]
    fn test_platform_matches_env_consts() {
        let caps = get_platform_capabilities();
        assert_eq!(caps.platform, std::env::consts::OS);
    }
}
