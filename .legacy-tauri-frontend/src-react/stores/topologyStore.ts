import { create } from 'zustand';
import type { Node, Edge } from '@xyflow/react';
import type { Device } from '../types/device';
import {
  clusterDevicesBySubnet,
  clusterDevicesByVendor,
  generateClusterLayout,
  generateFlatLayout,
  expandCluster,
  collapseCluster,
  type ClusterGroup,
} from '../utils/clustering';

export type ViewMode = 'flat' | 'clustered';
export type ClusterBy = 'subnet' | 'vendor';

interface TopologyState {
  nodes: Node[];
  edges: Edge[];
  clusters: Map<string, ClusterGroup>;
  expandedClusters: Set<string>;
  viewMode: ViewMode;
  clusterBy: ClusterBy;
}

interface TopologyActions {
  updateNodesFromDevices: (devices: Device[]) => void;
  toggleCluster: (clusterId: string) => void;
  setViewMode: (mode: ViewMode) => void;
  setClusterBy: (clusterBy: ClusterBy) => void;
  expandAll: () => void;
  collapseAll: () => void;
}

type TopologyStore = TopologyState & TopologyActions;

export const useTopologyStore = create<TopologyStore>((set, get) => ({
  nodes: [],
  edges: [],
  clusters: new Map(),
  expandedClusters: new Set(),
  viewMode: 'flat',
  clusterBy: 'subnet',

  updateNodesFromDevices: (devices: Device[]) => {
    const { viewMode, clusterBy, expandedClusters } = get();

    if (viewMode === 'flat') {
      const { nodes, edges } = generateFlatLayout(devices);
      set({ nodes, edges, clusters: new Map(), expandedClusters: new Set() });
      return;
    }

    // Clustered mode
    const clusterGroups = clusterBy === 'subnet'
      ? clusterDevicesBySubnet(devices)
      : clusterDevicesByVendor(devices);

    const clusterMap = new Map<string, ClusterGroup>();
    for (const group of clusterGroups) {
      clusterMap.set(group.id, group);
    }

    const { nodes, edges } = generateClusterLayout(clusterGroups);

    // Re-expand any previously expanded clusters
    let finalNodes = nodes;
    let finalEdges = edges;
    for (const clusterId of expandedClusters) {
      const group = clusterMap.get(clusterId);
      if (group) {
        const result = expandCluster(clusterId, group, finalNodes);
        finalNodes = result.nodes;
        finalEdges = [...finalEdges, ...result.edges];
      }
    }

    set({ nodes: finalNodes, edges: finalEdges, clusters: clusterMap });
  },

  toggleCluster: (clusterId: string) => {
    const { nodes, edges, clusters, expandedClusters } = get();
    const clusterGroup = clusters.get(clusterId);
    if (!clusterGroup) return;

    const isExpanded = expandedClusters.has(clusterId);
    const newExpanded = new Set(expandedClusters);

    if (isExpanded) {
      newExpanded.delete(clusterId);
      const result = collapseCluster(clusterId, clusterGroup, nodes, edges);
      set({ nodes: result.nodes, edges: result.edges, expandedClusters: newExpanded });
    } else {
      newExpanded.add(clusterId);
      const result = expandCluster(clusterId, clusterGroup, nodes);
      set({
        nodes: result.nodes,
        edges: [...edges, ...result.edges],
        expandedClusters: newExpanded,
      });
    }
  },

  setViewMode: (mode: ViewMode) => {
    set({ viewMode: mode });
  },

  setClusterBy: (clusterBy: ClusterBy) => {
    set({ clusterBy, expandedClusters: new Set() });
  },

  expandAll: () => {
    const { nodes, edges, clusters } = get();
    let finalNodes = nodes;
    let finalEdges = edges;
    const newExpanded = new Set<string>();

    for (const [clusterId, group] of clusters) {
      newExpanded.add(clusterId);
      const result = expandCluster(clusterId, group, finalNodes);
      finalNodes = result.nodes;
      finalEdges = [...finalEdges, ...result.edges];
    }

    set({ nodes: finalNodes, edges: finalEdges, expandedClusters: newExpanded });
  },

  collapseAll: () => {
    const { nodes, edges, clusters, expandedClusters } = get();
    let finalNodes = nodes;
    let finalEdges = edges;

    for (const clusterId of expandedClusters) {
      const group = clusters.get(clusterId);
      if (group) {
        const result = collapseCluster(clusterId, group, finalNodes, finalEdges);
        finalNodes = result.nodes;
        finalEdges = result.edges;
      }
    }

    set({ nodes: finalNodes, edges: finalEdges, expandedClusters: new Set() });
  },
}));

// Selector hooks
export const useTopologyNodes = () => useTopologyStore((s) => s.nodes);
export const useTopologyEdges = () => useTopologyStore((s) => s.edges);
export const useTopologyViewMode = () => useTopologyStore((s) => s.viewMode);
export const useTopologyClusterBy = () => useTopologyStore((s) => s.clusterBy);
