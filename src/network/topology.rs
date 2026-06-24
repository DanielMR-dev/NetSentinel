//! Network topology graph scaffolding.
//!
//! Provides the foundational data structures for representing a discovered
//! network as a graph of nodes (devices) and edges (observed links). This is
//! intentionally a placeholder implementation that compiles and is ready for
//! future visualization and analysis features.

use serde::{Deserialize, Serialize};

use crate::types::Device;

/// Classification of a topology node for rendering and analysis.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "camelCase")]
pub enum TopologyDeviceType {
    /// Default/unknown device type.
    Unknown,
    /// Workstation, laptop, or mobile endpoint.
    Endpoint,
    /// Router, switch, or access point.
    Router,
    /// Server providing network services.
    Server,
    /// Printer, camera, IoT gadget, etc.
    Peripheral,
    /// Multi-homed or dedicated gateway.
    Gateway,
    /// Container, VM, or other virtualized host.
    Virtual,
}

impl Default for TopologyDeviceType {
    fn default() -> Self {
        TopologyDeviceType::Unknown
    }
}

/// A single node in the topology graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TopologyNode {
    /// Stable node identifier (typically the device IP).
    pub id: String,
    /// Human-readable label.
    pub label: String,
    /// Classified device type.
    pub device_type: TopologyDeviceType,
    /// Underlying device data, if available.
    pub device: Option<Device>,
    /// Optional grouping/hierarchy identifier.
    pub group: Option<String>,
}

/// Type of observed link between two topology nodes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "camelCase")]
pub enum LinkType {
    /// Link type is unknown.
    Unknown,
    /// Direct Ethernet/L2 adjacency.
    Ethernet,
    /// Wireless association.
    Wireless,
    /// Observed layer-3 flow.
    Routed,
    /// Inferred parent/child relationship (e.g., gateway -> host).
    ParentChild,
}

impl Default for LinkType {
    fn default() -> Self {
        LinkType::Unknown
    }
}

/// A single edge in the topology graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TopologyEdge {
    /// Source node identifier.
    pub source: String,
    /// Target node identifier.
    pub target: String,
    /// Observed link type.
    pub link_type: LinkType,
    /// Optional edge weight or confidence score (0.0 - 1.0).
    pub weight: Option<f32>,
}

/// A graph representation of the discovered network topology.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TopologyGraph {
    /// Nodes in the topology.
    pub nodes: Vec<TopologyNode>,
    /// Edges connecting nodes.
    pub edges: Vec<TopologyEdge>,
    /// Timestamp when the graph was generated.
    pub generated_at: i64,
}

impl TopologyGraph {
    /// Create an empty topology graph.
    pub fn new() -> Self {
        Self {
            nodes: Vec::new(),
            edges: Vec::new(),
            generated_at: chrono::Utc::now().timestamp(),
        }
    }

    /// Build a very basic topology graph from a list of discovered devices.
    ///
    /// This placeholder creates one node per device and no edges. Future
    /// iterations will infer edges from ARP tables, routing data, and flow
    /// records.
    pub fn from_devices(devices: &[Device]) -> Self {
        let nodes = devices
            .iter()
            .map(|d| TopologyNode {
                id: d.ip.clone(),
                label: d.hostname.clone().unwrap_or_else(|| d.ip.clone()),
                device_type: TopologyDeviceType::Unknown,
                device: Some(d.clone()),
                group: None,
            })
            .collect();

        Self {
            nodes,
            edges: Vec::new(),
            generated_at: chrono::Utc::now().timestamp(),
        }
    }

    /// Add a node to the graph if it does not already exist.
    pub fn add_node(&mut self, node: TopologyNode) {
        if !self.nodes.iter().any(|n| n.id == node.id) {
            self.nodes.push(node);
        }
    }

    /// Add an edge to the graph if it does not already exist.
    pub fn add_edge(&mut self, edge: TopologyEdge) {
        if !self.edges.iter().any(|e| {
            e.source == edge.source && e.target == edge.target && e.link_type == edge.link_type
        }) {
            self.edges.push(edge);
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    fn make_device(ip: &str) -> Device {
        Device::new(ip.to_string())
    }

    #[test]
    fn test_topology_graph_from_devices() {
        let devices = vec![make_device("192.168.1.1"), make_device("192.168.1.2")];
        let graph = TopologyGraph::from_devices(&devices);
        assert_eq!(graph.nodes.len(), 2);
        assert!(graph.edges.is_empty());
    }

    #[test]
    fn test_topology_graph_add_node_deduplicates() {
        let mut graph = TopologyGraph::new();
        let node = TopologyNode {
            id: "1.2.3.4".to_string(),
            label: "test".to_string(),
            device_type: TopologyDeviceType::Server,
            device: None,
            group: None,
        };
        graph.add_node(node.clone());
        graph.add_node(node);
        assert_eq!(graph.nodes.len(), 1);
    }

    #[test]
    fn test_topology_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<TopologyGraph>();
        assert_send_sync::<TopologyNode>();
        assert_send_sync::<TopologyEdge>();
    }
}
