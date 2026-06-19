import type { Device } from '../types/device';
import type { Node, Edge } from '@xyflow/react';

export interface ClusterGroup {
  id: string;
  label: string;
  devices: Device[];
  onlineCount: number;
  offlineCount: number;
  unknownCount: number;
}

export interface ClusterNodeData {
  label: string;
  deviceCount: number;
  onlineCount: number;
  offlineCount: number;
  unknownCount: number;
  isExpanded: boolean;
  [key: string]: unknown;
}

export interface HostNodeData {
  ip: string;
  hostname: string | null;
  vendor: string | null;
  status: string;
  openPortCount: number;
  hasCveAlerts: boolean;
  hasChanges: boolean;
  [key: string]: unknown;
}

/** Extract /24 subnet from an IPv4 address */
function getSubnet24(ip: string): string {
  const parts = ip.split('.');
  if (parts.length !== 4) return ip;
  return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
}

/** Group devices by /24 subnet */
export function clusterDevicesBySubnet(devices: Device[]): ClusterGroup[] {
  const groups = new Map<string, Device[]>();

  for (const device of devices) {
    const subnet = getSubnet24(device.ip);
    const existing = groups.get(subnet);
    if (existing) {
      existing.push(device);
    } else {
      groups.set(subnet, [device]);
    }
  }

  return Array.from(groups.entries()).map(([subnet, devs]) => ({
    id: `subnet-${subnet}`,
    label: subnet,
    devices: devs,
    onlineCount: devs.filter((d) => d.status === 'online').length,
    offlineCount: devs.filter((d) => d.status === 'offline').length,
    unknownCount: devs.filter((d) => d.status === 'unknown').length,
  }));
}

/** Group devices by vendor */
export function clusterDevicesByVendor(devices: Device[]): ClusterGroup[] {
  const groups = new Map<string, Device[]>();

  for (const device of devices) {
    const vendor = device.vendor ?? 'Unknown';
    const existing = groups.get(vendor);
    if (existing) {
      existing.push(device);
    } else {
      groups.set(vendor, [device]);
    }
  }

  return Array.from(groups.entries()).map(([vendor, devs]) => ({
    id: `vendor-${vendor}`,
    label: vendor,
    devices: devs,
    onlineCount: devs.filter((d) => d.status === 'online').length,
    offlineCount: devs.filter((d) => d.status === 'offline').length,
    unknownCount: devs.filter((d) => d.status === 'unknown').length,
  }));
}

/** Generate a clustered layout with cluster nodes */
export function generateClusterLayout(clusters: ClusterGroup[]): { nodes: Node[]; edges: Edge[] } {
  const nodes: Node[] = [];
  const edges: Edge[] = [];
  const cols = Math.ceil(Math.sqrt(clusters.length));
  const spacingX = 350;
  const spacingY = 250;

  clusters.forEach((cluster, i) => {
    const col = i % cols;
    const row = Math.floor(i / cols);

    nodes.push({
      id: cluster.id,
      type: 'clusterNode',
      position: { x: col * spacingX + 50, y: row * spacingY + 50 },
      data: {
        label: cluster.label,
        deviceCount: cluster.devices.length,
        onlineCount: cluster.onlineCount,
        offlineCount: cluster.offlineCount,
        unknownCount: cluster.unknownCount,
        isExpanded: false,
      } satisfies ClusterNodeData,
    });
  });

  return { nodes, edges };
}

/** Generate flat layout with individual host nodes */
export function generateFlatLayout(devices: Device[]): { nodes: Node[]; edges: Edge[] } {
  const nodes: Node[] = [];
  const edges: Edge[] = [];
  const cols = Math.ceil(Math.sqrt(devices.length));
  const spacingX = 250;
  const spacingY = 150;

  devices.forEach((device, i) => {
    const col = i % cols;
    const row = Math.floor(i / cols);

    nodes.push({
      id: `host-${device.ip}`,
      type: 'hostNode',
      position: { x: col * spacingX + 50, y: row * spacingY + 50 },
      data: {
        ip: device.ip,
        hostname: device.hostname ?? null,
        vendor: device.vendor ?? null,
        status: device.status,
        openPortCount: device.ports.filter((p) => p.state === 'open').length,
        hasCveAlerts: false,
        hasChanges: false,
      } satisfies HostNodeData,
    });
  });

  return { nodes, edges };
}

/** Expand a cluster to show individual hosts within it */
export function expandCluster(
  clusterId: string,
  clusterGroup: ClusterGroup,
  existingNodes: Node[]
): { nodes: Node[]; edges: Edge[] } {
  const clusterNode = existingNodes.find((n) => n.id === clusterId);
  if (!clusterNode) return { nodes: existingNodes, edges: [] };

  const baseX = clusterNode.position.x;
  const baseY = clusterNode.position.y;
  const cols = Math.ceil(Math.sqrt(clusterGroup.devices.length));
  const spacingX = 250;
  const spacingY = 150;

  const newNodes: Node[] = clusterGroup.devices.map((device, i) => {
    const col = i % cols;
    const row = Math.floor(i / cols);

    return {
      id: `host-${device.ip}`,
      type: 'hostNode',
      position: { x: baseX + col * spacingX + 50, y: baseY + (row + 1) * spacingY + 50 },
      data: {
        ip: device.ip,
        hostname: device.hostname ?? null,
        vendor: device.vendor ?? null,
        status: device.status,
        openPortCount: device.ports.filter((p) => p.state === 'open').length,
        hasCveAlerts: false,
        hasChanges: false,
      } satisfies HostNodeData,
    };
  });

  const newEdges: Edge[] = clusterGroup.devices.map((device) => ({
    id: `edge-${clusterId}-${device.ip}`,
    source: clusterId,
    target: `host-${device.ip}`,
    type: 'smoothstep',
    animated: false,
    style: { stroke: '#6b7280', strokeWidth: 1 },
  }));

  // Update cluster node to show as expanded
  const updatedNodes = existingNodes.map((n) =>
    n.id === clusterId
      ? { ...n, data: { ...n.data, isExpanded: true } }
      : n
  );

  return {
    nodes: [...updatedNodes, ...newNodes],
    edges: newEdges,
  };
}

/** Remove expanded host nodes for a cluster */
export function collapseCluster(
  clusterId: string,
  clusterGroup: ClusterGroup,
  existingNodes: Node[],
  existingEdges: Edge[]
): { nodes: Node[]; edges: Edge[] } {
  const hostIds = new Set(clusterGroup.devices.map((d) => `host-${d.ip}`));

  const filteredNodes = existingNodes
    .filter((n) => !hostIds.has(n.id))
    .map((n) =>
      n.id === clusterId
        ? { ...n, data: { ...n.data, isExpanded: false } }
        : n
    );

  const filteredEdges = existingEdges.filter(
    (e) => !hostIds.has(e.source) && !hostIds.has(e.target)
  );

  return { nodes: filteredNodes, edges: filteredEdges };
}
