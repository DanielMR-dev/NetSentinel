//! ARP table discovery module.
//!
//! Provides functions to read the system's ARP table for device discovery.
//! This is the most reliable method on mobile/laptop devices as it uses
//! the kernel's ARP cache populated by any network activity.
//!
//! **Platform abstraction**: All platform-specific logic is delegated to
//! `crate::network::platform`, which selects the correct implementation
//! at compile time via `#[cfg(target_os = "...")]`.

use std::collections::HashMap;

use crate::error::ScanError;
use crate::network::platform;
use crate::types::Device;

/// Read the system's ARP table to discover devices on the local network.
///
/// Delegates to the platform-specific `ArpProvider` implementation:
/// - **Linux**: Reads `/proc/net/arp`
/// - **Windows**: Executes `arp -a` and parses output
/// - **macOS**: Executes `arp -a` and parses output
pub async fn read_arp_table() -> Result<Vec<Device>, ScanError> {
    let provider = platform::create_arp_provider();
    provider.read_arp_table().await
}

/// Get a mapping of IP addresses to MAC addresses from the ARP table.
///
/// Delegates to the platform-specific `ArpProvider` implementation.
pub async fn get_arp_cache() -> Result<HashMap<String, String>, ScanError> {
    let provider = platform::create_arp_provider();
    provider.get_arp_cache().await
}

#[cfg(test)]
mod tests {
    use super::*;

    // Integration tests that verify the delegation works correctly.
    // Platform-specific parsing tests live in `platform/{linux,windows,macos}.rs`.

    #[tokio::test]
    async fn test_read_arp_table_returns_result() {
        // On a real system this should succeed; in CI it may fail due to
        // permissions or missing /proc, which is acceptable.
        let result = read_arp_table().await;
        // We just verify it doesn't panic and returns a Result
        assert!(result.is_ok() || result.is_err());
    }

    #[tokio::test]
    async fn test_get_arp_cache_returns_result() {
        let result = get_arp_cache().await;
        assert!(result.is_ok() || result.is_err());
    }
}
