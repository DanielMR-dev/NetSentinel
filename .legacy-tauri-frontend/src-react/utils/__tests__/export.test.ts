import { describe, it, expect, vi, beforeEach } from 'vitest';
import { devicesToCSV, devicesToJSON, copyToClipboard } from '../export';
import type { Device } from '../../types/device';

function createMockDevice(overrides: Partial<Device> = {}): Device {
  return {
    ip: '192.168.1.1',
    mac: 'AA:BB:CC:DD:EE:FF',
    hostname: 'router.local',
    vendor: 'Cisco',
    status: 'online',
    ports: [
      { number: 80, protocol: 'tcp', service: 'http', state: 'open' },
      { number: 443, protocol: 'tcp', service: 'https', state: 'open' },
      { number: 22, protocol: 'tcp', service: 'ssh', state: 'closed' },
    ],
    lastSeen: 1700000000,
    banner_results: [],
    ...overrides,
  };
}

describe('export utilities', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('devicesToCSV', () => {
    it('generates correct CSV headers', () => {
      const csv = devicesToCSV([]);
      const headerLine = csv.split('\n')[0];
      expect(headerLine).toBe('IP Address,MAC Address,Hostname,Vendor,Status,Open Ports,Last Seen');
    });

    it('formats a single device correctly', () => {
      const csv = devicesToCSV([createMockDevice()]);
      const lines = csv.split('\n');

      expect(lines).toHaveLength(2); // header + 1 data row
      expect(lines[1]).toContain('"192.168.1.1"');
      expect(lines[1]).toContain('"AA:BB:CC:DD:EE:FF"');
      expect(lines[1]).toContain('"router.local"');
      expect(lines[1]).toContain('"Cisco"');
      expect(lines[1]).toContain('"online"');
    });

    it('only includes open ports in the Open Ports column', () => {
      const csv = devicesToCSV([createMockDevice()]);
      const dataLine = csv.split('\n')[1];

      // Should contain open ports 80/tcp and 443/tcp but not closed port 22
      expect(dataLine).toContain('80/tcp');
      expect(dataLine).toContain('443/tcp');
      expect(dataLine).not.toContain('22/tcp');
    });

    it('handles devices with no hostname or vendor', () => {
      const device = createMockDevice({ hostname: undefined, vendor: undefined });
      const csv = devicesToCSV([device]);
      const dataLine = csv.split('\n')[1];

      // Empty strings for missing fields
      expect(dataLine).toContain('""');
    });

    it('handles multiple devices', () => {
      const devices = [
        createMockDevice({ ip: '192.168.1.1' }),
        createMockDevice({ ip: '192.168.1.2' }),
        createMockDevice({ ip: '192.168.1.3' }),
      ];
      const csv = devicesToCSV(devices);
      const lines = csv.split('\n');

      expect(lines).toHaveLength(4); // header + 3 data rows
    });

    it('converts lastSeen timestamp to ISO string', () => {
      const csv = devicesToCSV([createMockDevice({ lastSeen: 1700000000 })]);
      const dataLine = csv.split('\n')[1];
      const expectedDate = new Date(1700000000 * 1000).toISOString();
      expect(dataLine).toContain(expectedDate);
    });
  });

  describe('devicesToJSON', () => {
    it('returns valid JSON string', () => {
      const devices = [createMockDevice()];
      const json = devicesToJSON(devices);
      const parsed = JSON.parse(json);

      expect(parsed).toHaveLength(1);
      expect(parsed[0].ip).toBe('192.168.1.1');
    });

    it('formats JSON with 2-space indentation', () => {
      const devices = [createMockDevice()];
      const json = devicesToJSON(devices);

      // Pretty-printed JSON should have newlines and indentation
      expect(json).toContain('\n');
      expect(json).toContain('  ');
    });

    it('handles empty device list', () => {
      const json = devicesToJSON([]);
      expect(JSON.parse(json)).toEqual([]);
    });
  });

  describe('copyToClipboard', () => {
    it('calls navigator.clipboard.writeText with content', async () => {
      const writeTextMock = vi.fn().mockResolvedValue(undefined);
      Object.assign(navigator, {
        clipboard: { writeText: writeTextMock },
      });

      await copyToClipboard('test content');

      expect(writeTextMock).toHaveBeenCalledWith('test content');
    });
  });
});
