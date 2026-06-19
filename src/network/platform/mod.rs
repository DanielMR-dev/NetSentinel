//! Cross-platform abstraction layer for ARP table reading and gateway detection.
//!
//! This module provides trait-based interfaces (`ArpProvider` and `GatewayProvider`)
//! with platform-specific implementations selected at compile time via `#[cfg]`.
//!
//! # Supported Platforms
//! - **Linux**: Reads `/proc/net/arp` and `/proc/net/route`
//! - **Windows**: Executes `arp -a` and `route print` via `tokio::process::Command`
//! - **macOS**: Executes `arp -a` and `route -n get default` via `tokio::process::Command`

use std::collections::HashMap;

use async_trait::async_trait;

use crate::error::ScanError;
use crate::types::Device;

// ---------------------------------------------------------------------------
// Conditional compilation: pull in the correct platform module
// ---------------------------------------------------------------------------
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
pub use windows::*;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::*;

// ---------------------------------------------------------------------------
// Traits
// ---------------------------------------------------------------------------

/// Provides ARP table reading capabilities per platform.
///
/// All methods are async because they may involve file I/O (Linux) or
/// subprocess execution (Windows, macOS).
#[async_trait]
pub trait ArpProvider: Send + Sync {
    /// Read all valid entries from the system ARP table.
    async fn read_arp_table(&self) -> Result<Vec<Device>, ScanError>;

    /// Look up the MAC address for a specific IP in the ARP cache.
    ///
    /// Returns `None` if the IP is not present or the entry is incomplete.
    async fn get_mac_for_ip(&self, ip: &str) -> Option<String>;

    /// Build a full IP-to-MAC mapping from the ARP cache.
    ///
    /// Default implementation derives the map from `read_arp_table()`.
    async fn get_arp_cache(&self) -> Result<HashMap<String, String>, ScanError> {
        let devices = self.read_arp_table().await?;
        let mut cache = HashMap::with_capacity(devices.len());
        for device in devices {
            if !device.mac.is_empty() {
                cache.insert(device.ip, device.mac);
            }
        }
        Ok(cache)
    }
}

/// Provides default gateway detection per platform.
///
/// The trait method is async because:
/// - **Linux**: Reads `/proc/net/route` via `tokio::fs`
/// - **Windows**: Executes `route print 0.0.0.0` via `tokio::process::Command`
/// - **macOS**: Executes `route -n get default` via `tokio::process::Command`
#[async_trait]
pub trait GatewayProvider: Send + Sync {
    /// Get the default gateway IP address.
    ///
    /// Returns `None` if no default route is found.
    async fn get_default_gateway(&self) -> Option<String>;
}

// ---------------------------------------------------------------------------
// Factory functions
// ---------------------------------------------------------------------------

/// Create the platform-appropriate ARP provider.
pub fn create_arp_provider() -> Box<dyn ArpProvider> {
    #[cfg(target_os = "linux")]
    {
        Box::new(LinuxArpProvider)
    }
    #[cfg(target_os = "windows")]
    {
        Box::new(WindowsArpProvider)
    }
    #[cfg(target_os = "macos")]
    {
        Box::new(MacOsArpProvider)
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    {
        compile_error!("NetSentinel: unsupported target OS for ARP provider");
    }
}

/// Create the platform-appropriate gateway provider.
pub fn create_gateway_provider() -> Box<dyn GatewayProvider> {
    #[cfg(target_os = "linux")]
    {
        Box::new(LinuxGatewayProvider)
    }
    #[cfg(target_os = "windows")]
    {
        Box::new(WindowsGatewayProvider)
    }
    #[cfg(target_os = "macos")]
    {
        Box::new(MacOsGatewayProvider)
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    {
        compile_error!("NetSentinel: unsupported target OS for gateway provider");
    }
}

// ---------------------------------------------------------------------------
// Utility: cross-platform loopback interface detection
// ---------------------------------------------------------------------------

/// Check whether a network interface name corresponds to a loopback interface.
///
/// | Platform | Loopback names                        |
/// |----------|---------------------------------------|
/// | Linux    | `lo`                                  |
/// | macOS    | `lo0`                                 |
/// | Windows  | Names containing `loopback` (case-insensitive) |
pub fn is_loopback_interface(name: &str) -> bool {
    let lower = name.to_lowercase();
    lower == "lo" || lower == "lo0" || lower.contains("loopback")
}

// ---------------------------------------------------------------------------
// Tests for the loopback utility (platform-independent)
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_loopback_linux() {
        assert!(is_loopback_interface("lo"));
        assert!(!is_loopback_interface("eth0"));
    }

    #[test]
    fn test_is_loopback_macos() {
        assert!(is_loopback_interface("lo0"));
        assert!(!is_loopback_interface("en0"));
    }

    #[test]
    fn test_is_loopback_windows() {
        assert!(is_loopback_interface("Loopback Pseudo-Interface 1"));
        assert!(is_loopback_interface("loopback"));
        assert!(!is_loopback_interface("Ethernet"));
    }

    #[test]
    fn test_is_loopback_case_insensitive() {
        assert!(is_loopback_interface("LO"));
        assert!(is_loopback_interface("LO0"));
        assert!(is_loopback_interface("LOOPBACK"));
    }
}
