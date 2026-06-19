import { describe, it, expect } from 'vitest';
import {
  clusterDevicesBySubnet,
  clusterDevicesByVendor,
  generateClusterLayout,
  generateFlatLayout,
  expandCluster,
  collapseCluster,
} from '../clustering';
import type { Device } from '../../types/device';

function createMockDevice(overrides: Partial<Device> = {}): Device {
  return {
    ip: '192.168.1.1',
    mac: 'AA:BB:CC:DD:EE:FF',
    hostname: 'test-host',
    vendor: 'TestVendor',
    status: 'online',
    ports: [],
    lastSeen: 1700000000,
    banner_results: [],
    ...overrides,
  };
}

describe('clustering utilities', () => {
  describe('clusterDevicesBySubnet', () => {
    it('groups devices by /24 subnet', () => {
      const devices: Device[] = [
        createMockDevice({ ip: '192.168.1.1' }),
        createMockDevice({ ip: '192.168.1.2' }),
        createMockDevice({ ip: '192.168.2.1' }),
        createMockDevice({ ip: '10.0.0.1' }),
      ];

      const clusters = clusterDevicesBySubnet(devices);

      expect(clusters).toHaveLength(3);

      const subnet1 = clusters.find((c) => c.label === '192.168.1.0/24');
      expect(subnet1?.devices).toHaveLength(2);

      const subnet2 = clusters.find((c) => c.label === '192.168.2.0/24');
      expect(subnet2?.devices).toHaveLength(1);

      const subnet3 = clusters.find((c) => c.label === '10.0.0.0/24');
      expect(subnet3?.devices).toHaveLength(1);
    });

    it('counts online, offline, and unknown devices correctly', () => {
      const devices: Device[] = [
        createMockDevice({ ip: '192.168.1.1', status: 'online' }),
        createMockDevice({ ip: '192.168.1.2', status: 'offline' }),
        createMockDevice({ ip: '192.168.1.3', status: 'unknown' }),
        createMockDevice({ ip: '192.168.1.4', status: 'online' }),
      ];

      const clusters = clusterDevicesBySubnet(devices);
      expect(clusters).toHaveLength(1);

      const cluster = clusters[0];
      expect(cluster.onlineCount).toBe(2);
      expect(cluster.offlineCount).toBe(1);
      expect(cluster.unknownCount).toBe(1);
    });

    it('handles empty device list', () => {
      const clusters = clusterDevicesBySubnet([]);
      expect(clusters).toEqual([]);
    });

    it('generates correct cluster IDs', () => {
      const devices = [createMockDevice({ ip: '10.0.5.100' })];
      const clusters = clusterDevicesBySubnet(devices);

      expect(clusters[0].id).toBe('subnet-10.0.5.0/24');
    });
  });

  describe('clusterDevicesByVendor', () => {
    it('groups devices by vendor', () => {
      const devices: Device[] = [
        createMockDevice({ ip: '192.168.1.1', vendor: 'Cisco' }),
        createMockDevice({ ip: '192.168.1.2', vendor: 'Cisco' }),
        createMockDevice({ ip: '192.168.1.3', vendor: 'Netgear' }),
        createMockDevice({ ip: '192.168.1.4', vendor: undefined }),
      ];

      const clusters = clusterDevicesByVendor(devices);

      expect(clusters).toHaveLength(3);

      const cisco = clusters.find((c) => c.label === 'Cisco');
      expect(cisco?.devices).toHaveLength(2);

      const netgear = clusters.find((c) => c.label === 'Netgear');
      expect(netgear?.devices).toHaveLength(1);

      const unknown = clusters.find((c) => c.label === 'Unknown');
      expect(unknown?.devices).toHaveLength(1);
    });

    it('handles empty device list', () => {
      const clusters = clusterDevicesByVendor([]);
      expect(clusters).toEqual([]);
    });
  });

  describe('generateClusterLayout', () => {
    it('creates nodes for each cluster', () => {
      const clusters = clusterDevicesBySubnet([
        createMockDevice({ ip: '192.168.1.1' }),
        createMockDevice({ ip: '10.0.0.1' }),
      ]);

      const { nodes, edges } = generateClusterLayout(clusters);

      expect(nodes).toHaveLength(2);
      expect(edges).toHaveLength(0); // No edges in cluster view
      expect(nodes[0].type).toBe('clusterNode');
    });

    it('includes correct data in cluster nodes', () => {
      const clusters = clusterDevicesBySubnet([
        createMockDevice({ ip: '192.168.1.1', status: 'online' }),
        createMockDevice({ ip: '192.168.1.2', status: 'offline' }),
      ]);

      const { nodes } = generateClusterLayout(clusters);
      const nodeData = nodes[0].data as Record<string, unknown>;

      expect(nodeData.label).toBe('192.168.1.0/24');
      expect(nodeData.deviceCount).toBe(2);
      expect(nodeData.onlineCount).toBe(1);
      expect(nodeData.offlineCount).toBe(1);
      expect(nodeData.isExpanded).toBe(false);
    });

    it('handles empty cluster list', () => {
      const { nodes, edges } = generateClusterLayout([]);
      expect(nodes).toEqual([]);
      expect(edges).toEqual([]);
    });
  });

  describe('generateFlatLayout', () => {
    it('creates a host node for each device', () => {
      const devices = [
        createMockDevice({ ip: '192.168.1.1' }),
        createMockDevice({ ip: '192.168.1.2' }),
        createMockDevice({ ip: '192.168.1.3' }),
      ];

      const { nodes } = generateFlatLayout(devices);

      expect(nodes).toHaveLength(3);
      expect(nodes[0].type).toBe('hostNode');
      expect(nodes[0].id).toBe('host-192.168.1.1');
    });

    it('includes correct data in host nodes', () => {
      const devices = [
        createMockDevice({
          ip: '192.168.1.1',
          hostname: 'router',
          vendor: 'Cisco',
          status: 'online',
          ports: [
            { number: 80, protocol: 'tcp', state: 'open' },
            { number: 22, protocol: 'tcp', state: 'closed' },
          ],
        }),
      ];

      const { nodes } = generateFlatLayout(devices);
      const nodeData = nodes[0].data as Record<string, unknown>;

      expect(nodeData.ip).toBe('192.168.1.1');
      expect(nodeData.hostname).toBe('router');
      expect(nodeData.vendor).toBe('Cisco');
      expect(nodeData.status).toBe('online');
      expect(nodeData.openPortCount).toBe(1); // only port 80 is open
    });

    it('handles empty device list', () => {
      const { nodes, edges } = generateFlatLayout([]);
      expect(nodes).toEqual([]);
      expect(edges).toEqual([]);
    });
  });

  describe('expandCluster', () => {
    it('adds host nodes for devices in the cluster', () => {
      const devices = [
        createMockDevice({ ip: '192.168.1.1' }),
        createMockDevice({ ip: '192.168.1.2' }),
      ];
      const clusters = clusterDevicesBySubnet(devices);
      const { nodes: clusterNodes } = generateClusterLayout(clusters);

      const { nodes, edges } = expandCluster(clusters[0].id, clusters[0], clusterNodes);

      // Original cluster node + 2 host nodes
      expect(nodes).toHaveLength(3);
      // Edges from cluster to each host
      expect(edges).toHaveLength(2);
    });

    it('marks cluster node as expanded', () => {
      const devices = [createMockDevice({ ip: '192.168.1.1' })];
      const clusters = clusterDevicesBySubnet(devices);
      const { nodes: clusterNodes } = generateClusterLayout(clusters);

      const { nodes } = expandCluster(clusters[0].id, clusters[0], clusterNodes);
      const clusterNode = nodes.find((n) => n.id === clusters[0].id);
      const data = clusterNode?.data as Record<string, unknown>;

      expect(data.isExpanded).toBe(true);
    });

    it('returns existing nodes if cluster node not found', () => {
      const devices = [createMockDevice({ ip: '192.168.1.1' })];
      const clusters = clusterDevicesBySubnet(devices);

      const { nodes, edges } = expandCluster('non-existent', clusters[0], []);

      expect(nodes).toEqual([]);
      expect(edges).toEqual([]);
    });
  });

  describe('collapseCluster', () => {
    it('removes host nodes for the collapsed cluster', () => {
      const devices = [
        createMockDevice({ ip: '192.168.1.1' }),
        createMockDevice({ ip: '192.168.1.2' }),
      ];
      const clusters = clusterDevicesBySubnet(devices);
      const { nodes: clusterNodes } = generateClusterLayout(clusters);
      const { nodes: expandedNodes, edges: expandedEdges } = expandCluster(
        clusters[0].id,
        clusters[0],
        clusterNodes,
      );

      const { nodes, edges } = collapseCluster(clusters[0].id, clusters[0], expandedNodes, expandedEdges);

      // Only the cluster node should remain
      expect(nodes).toHaveLength(1);
      expect(nodes[0].id).toBe(clusters[0].id);
      expect(edges).toHaveLength(0);
    });

    it('marks cluster node as not expanded', () => {
      const devices = [createMockDevice({ ip: '192.168.1.1' })];
      const clusters = clusterDevicesBySubnet(devices);
      const { nodes: clusterNodes } = generateClusterLayout(clusters);
      const { nodes: expandedNodes, edges: expandedEdges } = expandCluster(
        clusters[0].id,
        clusters[0],
        clusterNodes,
      );

      const { nodes } = collapseCluster(clusters[0].id, clusters[0], expandedNodes, expandedEdges);
      const clusterNode = nodes.find((n) => n.id === clusters[0].id);
      const data = clusterNode?.data as Record<string, unknown>;

      expect(data.isExpanded).toBe(false);
    });
  });
});
