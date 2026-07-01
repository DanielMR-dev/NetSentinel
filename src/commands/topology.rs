//! Topology command.
//!
//! Builds a `TopologyGraph` from the current shared scan state, network
//! information, and the system ARP cache. All I/O is performed asynchronously
//! so the GUI never blocks.

use std::collections::HashMap;
use std::sync::Arc;

use crate::error::ScanError;
use crate::network::discovery::arp_table;
use crate::network::topology::{build_topology_graph, FlowObserved, TopologyInput};
use crate::state::SharedScanState;
use crate::types::TopologyGraph;

/// Build a topology graph from the current shared scan state.
///
/// This command gathers discovered devices, the local network configuration,
/// and the ARP cache, then delegates to the pure `build_topology_graph`
/// builder. Flow observation is reserved as a future hook and is not used to
/// synthesize edges.
pub async fn build_current_topology(
    state: Arc<SharedScanState>,
) -> Result<TopologyGraph, ScanError> {
    let devices = state.get_devices().await;

    let network_info = crate::commands::get_network_info()
        .await
        .map_err(|e| ScanError::NetworkError(e.to_string()))?;

    let gateway_ip = clean_ip(&network_info.gateway);
    let localhost_ip = clean_ip(&network_info.ip_address);

    let arp_cache = match arp_table::get_arp_cache().await {
        Ok(cache) => cache,
        Err(e) => {
            tracing::warn!("Failed to read ARP cache for topology: {}", e);
            HashMap::new()
        }
    };

    let input = TopologyInput {
        devices,
        gateway_ip,
        localhost_ip,
        arp_cache,
        flows: Vec::<FlowObserved>::new(),
    };

    Ok(build_topology_graph(input))
}

/// Normalize a raw IP string into a usable value, filtering placeholders.
fn clean_ip(ip: &str) -> Option<String> {
    let trimmed = ip.trim();
    let lower = trimmed.to_lowercase();

    if trimmed.is_empty()
        || lower == "unknown"
        || lower == "0.0.0.0"
        || lower == "::"
        || lower.starts_with("127.")
    {
        None
    } else {
        Some(trimmed.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_ip_filters_placeholders() {
        assert_eq!(clean_ip(""), None);
        assert_eq!(clean_ip("unknown"), None);
        assert_eq!(clean_ip("0.0.0.0"), None);
        assert_eq!(clean_ip("127.0.0.1"), None);
        assert_eq!(clean_ip("192.168.1.1"), Some("192.168.1.1".to_string()));
    }
}
