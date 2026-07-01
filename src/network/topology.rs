//! Network topology graph builder.
//!
//! Provides a pure, synchronous builder that constructs a `TopologyGraph` from
//! discovered devices, gateway/network information, the ARP cache, and optional
//! flow observations. The builder performs no I/O and never panics.

use std::collections::HashMap;

use crate::types::{
    Device, EdgeKind, NodeKind, TopologyEdge, TopologyGraph, TopologyNode, TopologySource,
};

/// Observed flow record. Currently treated as a future hook; no edges are
/// synthesized from flows until reliable flow data is available.
#[derive(Debug, Clone)]
pub struct FlowObserved {
    pub source_ip: String,
    pub target_ip: String,
    pub protocol: String,
}

/// Input bundle for building a topology graph.
#[derive(Debug, Clone)]
pub struct TopologyInput {
    /// Devices discovered by active scans.
    pub devices: Vec<Device>,
    /// Default gateway IP, if known.
    pub gateway_ip: Option<String>,
    /// Local host IP, if known.
    pub localhost_ip: Option<String>,
    /// IP-to-MAC mapping from the ARP cache.
    pub arp_cache: HashMap<String, String>,
    /// Observed flows (future hook; not used for edges yet).
    pub flows: Vec<FlowObserved>,
}

impl Default for TopologyInput {
    fn default() -> Self {
        Self {
            devices: Vec::new(),
            gateway_ip: None,
            localhost_ip: None,
            arp_cache: HashMap::new(),
            flows: Vec::new(),
        }
    }
}

/// Build a topology graph from the provided input sources.
///
/// The builder deduplicates nodes by stable id, adds gateway and localhost
/// nodes when available, includes discovered devices, adds ARP-only nodes, and
/// links non-gateway/non-local nodes to the gateway.
pub fn build_topology_graph(input: TopologyInput) -> TopologyGraph {
    let mut graph = TopologyGraph::new();

    let gateway_ip = input.gateway_ip.filter(|ip| is_valid_ip(ip));
    let localhost_ip = input.localhost_ip.filter(|ip| is_valid_ip(ip));

    // Gateway node
    if let Some(ref ip) = gateway_ip {
        graph.add_node(TopologyNode {
            id: ip.clone(),
            label: format!("Gateway ({})", ip),
            kind: NodeKind::Gateway,
            source: TopologySource::NetworkInfo,
            device: None,
            group: None,
        });
    }

    // Localhost node
    if let Some(ref ip) = localhost_ip {
        graph.add_node(TopologyNode {
            id: ip.clone(),
            label: format!("Localhost ({})", ip),
            kind: NodeKind::LocalHost,
            source: TopologySource::NetworkInfo,
            device: None,
            group: None,
        });

        // Link localhost to gateway when both are known.
        if let Some(ref gw) = gateway_ip {
            graph.add_edge(TopologyEdge {
                source: ip.clone(),
                target: gw.clone(),
                kind: EdgeKind::GatewayLink,
            });
        }
    }

    // Discovered devices
    for device in input.devices {
        if device.ip.is_empty() {
            continue;
        }

        let kind = infer_node_kind(&device);
        let label = device
            .hostname
            .clone()
            .filter(|h| !h.is_empty())
            .unwrap_or_else(|| device.ip.clone());

        graph.add_node(TopologyNode {
            id: device.ip.clone(),
            label,
            kind,
            source: TopologySource::Discovery,
            device: Some(device),
            group: None,
        });
    }

    // ARP-only nodes (entries not already represented by a discovered device)
    for (ip, mac) in input.arp_cache {
        if ip.is_empty() || mac.is_empty() {
            continue;
        }

        if graph.nodes.iter().any(|n| n.id == ip) {
            continue;
        }

        graph.add_node(TopologyNode {
            id: ip.clone(),
            label: format!("{} ({})", ip, mac),
            kind: NodeKind::Unknown,
            source: TopologySource::ArpTable,
            device: None,
            group: None,
        });
    }

    // Link non-gateway, non-local nodes to the gateway.
    if let Some(ref gw) = gateway_ip {
        let gw_id = gw.clone();
        let local_id = localhost_ip.clone();

        let node_ids: Vec<String> = graph
            .nodes
            .iter()
            .filter(|n| n.id != gw_id && local_id.as_ref().map_or(true, |l| n.id != *l))
            .map(|n| n.id.clone())
            .collect();

        for node_id in node_ids {
            graph.add_edge(TopologyEdge {
                source: gw_id.clone(),
                target: node_id,
                kind: EdgeKind::GatewayLink,
            });
        }
    }

    // `flows` is intentionally not used to create edges. It is exposed as a
    // future hook so the topology engine can synthesize flow-based edges once
    // reliable flow telemetry is integrated.
    let _ = input.flows;

    graph
}

/// Validate that an IP string is non-empty and not a placeholder.
fn is_valid_ip(ip: &str) -> bool {
    let lower = ip.to_lowercase();
    !ip.is_empty()
        && lower != "unknown"
        && lower != "0.0.0.0"
        && lower != "::"
        && !lower.starts_with("127.")
}

/// Infer a node kind from device characteristics.
fn infer_node_kind(device: &Device) -> NodeKind {
    if device
        .os
        .as_deref()
        .unwrap_or("")
        .to_lowercase()
        .contains("router")
    {
        return NodeKind::Router;
    }

    let has_open_services = device.ports.iter().any(|p| {
        matches!(p.state, crate::types::PortState::Open)
            || matches!(
                p.number,
                21 | 22
                    | 25
                    | 53
                    | 80
                    | 110
                    | 143
                    | 443
                    | 445
                    | 3306
                    | 3389
                    | 5432
                    | 5900
                    | 6379
                    | 8080
                    | 8443
            )
    });

    if has_open_services {
        NodeKind::Server
    } else {
        NodeKind::Endpoint
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_device(ip: &str) -> Device {
        Device::new(ip.to_string())
    }

    #[test]
    fn empty_input_produces_empty_graph() {
        let input = TopologyInput::default();
        let graph = build_topology_graph(input);
        assert!(graph.nodes.is_empty());
        assert!(graph.edges.is_empty());
    }

    #[test]
    fn gateway_creates_gateway_node_and_edges() {
        let mut input = TopologyInput::default();
        input.gateway_ip = Some("192.168.1.1".to_string());
        input.devices = vec![make_device("192.168.1.10"), make_device("192.168.1.11")];

        let graph = build_topology_graph(input);

        assert!(graph
            .nodes
            .iter()
            .any(|n| n.id == "192.168.1.1" && n.kind == NodeKind::Gateway));
        assert_eq!(graph.edges.len(), 2);
        assert!(graph.edges.iter().all(|e| e.source == "192.168.1.1"));
        assert!(graph
            .edges
            .iter()
            .any(|e| e.target == "192.168.1.10" && e.kind == EdgeKind::GatewayLink));
        assert!(graph
            .edges
            .iter()
            .any(|e| e.target == "192.168.1.11" && e.kind == EdgeKind::GatewayLink));
    }

    #[test]
    fn nodes_are_deduplicated_by_id() {
        let mut input = TopologyInput::default();
        input.gateway_ip = Some("192.168.1.1".to_string());
        input.devices = vec![make_device("192.168.1.2")];
        let mut arp = HashMap::new();
        arp.insert("192.168.1.2".to_string(), "aa:bb:cc:dd:ee:ff".to_string());
        arp.insert("192.168.1.3".to_string(), "11:22:33:44:55:66".to_string());
        input.arp_cache = arp;

        let graph = build_topology_graph(input);

        let node_ids: Vec<&str> = graph.nodes.iter().map(|n| n.id.as_str()).collect();
        assert_eq!(node_ids.len(), 3);
        assert!(node_ids.contains(&"192.168.1.1"));
        assert!(node_ids.contains(&"192.168.1.2"));
        assert!(node_ids.contains(&"192.168.1.3"));
        assert_eq!(graph.edges.len(), 2);
    }

    #[test]
    fn arp_only_nodes_are_included() {
        let mut input = TopologyInput::default();
        input.gateway_ip = Some("10.0.0.1".to_string());
        let mut arp = HashMap::new();
        arp.insert("10.0.0.5".to_string(), "00:11:22:33:44:55".to_string());
        input.arp_cache = arp;

        let graph = build_topology_graph(input);

        assert!(graph
            .nodes
            .iter()
            .any(|n| n.id == "10.0.0.5" && n.source == TopologySource::ArpTable));
        assert!(graph
            .edges
            .iter()
            .any(|e| e.source == "10.0.0.1" && e.target == "10.0.0.5"));
    }

    #[test]
    fn localhost_is_linked_to_gateway_but_not_to_itself() {
        let mut input = TopologyInput::default();
        input.gateway_ip = Some("192.168.1.1".to_string());
        input.localhost_ip = Some("192.168.1.42".to_string());
        input.devices = vec![make_device("192.168.1.10")];

        let graph = build_topology_graph(input);

        assert!(graph
            .nodes
            .iter()
            .any(|n| n.id == "192.168.1.42" && n.kind == NodeKind::LocalHost));
        assert!(graph
            .edges
            .iter()
            .any(|e| e.source == "192.168.1.42" && e.target == "192.168.1.1"));
        assert!(!graph
            .edges
            .iter()
            .any(|e| e.source == "192.168.1.1" && e.target == "192.168.1.42"));
    }

    #[test]
    fn placeholder_gateway_is_ignored() {
        let mut input = TopologyInput::default();
        input.gateway_ip = Some("0.0.0.0".to_string());
        input.devices = vec![make_device("192.168.1.10")];

        let graph = build_topology_graph(input);

        assert!(!graph.nodes.iter().any(|n| n.id == "0.0.0.0"));
        assert!(graph.edges.is_empty());
    }
}
