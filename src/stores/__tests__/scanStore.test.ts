import { describe, it, expect, vi, beforeEach } from 'vitest';
import { useScanStore } from '../scanStore';
import type { Device, ScanLogEvent } from '../../types/device';
import type { ScanConfig } from '../../types/settings';

// Mock Tauri APIs
const mockInvoke = vi.fn();
vi.mock('@tauri-apps/api/core', () => ({
  invoke: (...args: unknown[]) => mockInvoke(...args),
}));

vi.mock('@tauri-apps/api/event', () => ({
  listen: vi.fn().mockResolvedValue(() => {}),
}));

// Mock the settings store dependency
vi.mock('../settingsStore', () => ({
  useSettingsStore: {
    getState: () => ({
      settings: {
        scanConfig: {
          maxConcurrentHosts: 50,
          discoveryMethods: ['arp', 'tcp_probe'],
          retryCount: 3,
        },
      },
    }),
  },
}));

// Mock the banner store dependency
vi.mock('../bannerStore', () => ({
  useBannerStore: {
    getState: () => ({
      addBanner: vi.fn(),
    }),
  },
}));

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

function createMockLog(overrides: Partial<ScanLogEvent> = {}): ScanLogEvent {
  return {
    level: 'info',
    message: 'Test log message',
    timestamp: Date.now(),
    ...overrides,
  };
}

function resetStore(): void {
  useScanStore.setState({
    cidr: '192.168.1.0/24',
    scanPorts: true,
    selectedPorts: [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 5900, 6379, 8080, 8443],
    timeoutMs: 1000,
    scanType: 'connect',
    timingTemplate: 'normal',
    isScanning: false,
    isPaused: false,
    scanStatus: 'idle',
    scanId: null,
    scannedCount: 0,
    totalHosts: 0,
    currentTarget: null,
    devices: [],
    selectedDeviceId: null,
    searchQuery: '',
    filterStatus: 'all',
    filterHasOpenPorts: false,
    logs: [],
    error: null,
  });
}

describe('scanStore', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    resetStore();
  });

  describe('initial state', () => {
    it('has correct default CIDR', () => {
      expect(useScanStore.getState().cidr).toBe('192.168.1.0/24');
    });

    it('has scanPorts enabled by default', () => {
      expect(useScanStore.getState().scanPorts).toBe(true);
    });

    it('has default timeout of 1000ms', () => {
      expect(useScanStore.getState().timeoutMs).toBe(1000);
    });

    it('has connect scan type by default', () => {
      expect(useScanStore.getState().scanType).toBe('connect');
    });

    it('has normal timing template by default', () => {
      expect(useScanStore.getState().timingTemplate).toBe('normal');
    });

    it('is not scanning initially', () => {
      expect(useScanStore.getState().isScanning).toBe(false);
      expect(useScanStore.getState().scanStatus).toBe('idle');
    });

    it('has empty devices and logs', () => {
      expect(useScanStore.getState().devices).toEqual([]);
      expect(useScanStore.getState().logs).toEqual([]);
    });

    it('has no error initially', () => {
      expect(useScanStore.getState().error).toBeNull();
    });
  });

  describe('setCidr', () => {
    it('updates the CIDR value', () => {
      useScanStore.getState().setCidr('10.0.0.0/16');
      expect(useScanStore.getState().cidr).toBe('10.0.0.0/16');
    });
  });

  describe('setScanPorts', () => {
    it('updates scanPorts flag', () => {
      useScanStore.getState().setScanPorts(false);
      expect(useScanStore.getState().scanPorts).toBe(false);
    });
  });

  describe('setSelectedPorts', () => {
    it('updates selected ports list', () => {
      useScanStore.getState().setSelectedPorts([80, 443]);
      expect(useScanStore.getState().selectedPorts).toEqual([80, 443]);
    });
  });

  describe('setTimeoutMs', () => {
    it('updates timeout value', () => {
      useScanStore.getState().setTimeoutMs(5000);
      expect(useScanStore.getState().timeoutMs).toBe(5000);
    });
  });

  describe('setScanType', () => {
    it('updates scan type', () => {
      useScanStore.getState().setScanType('syn');
      expect(useScanStore.getState().scanType).toBe('syn');
    });
  });

  describe('setTimingTemplate', () => {
    it('updates timing template', () => {
      useScanStore.getState().setTimingTemplate('aggressive');
      expect(useScanStore.getState().timingTemplate).toBe('aggressive');
    });
  });

  describe('startScan', () => {
    it('calls invoke with correct parameters', async () => {
      mockInvoke.mockResolvedValue({ scan_id: 'scan-123', status: 'started', scan_type: 'connect' });

      useScanStore.setState({ cidr: '10.0.0.0/24', timeoutMs: 2000, scanPorts: true, selectedPorts: [80, 443] });
      await useScanStore.getState().startScan();

      expect(mockInvoke).toHaveBeenCalledWith('start_scan', {
        cidr: '10.0.0.0/24',
        timeoutMs: 2000,
        scanPorts: true,
        ports: [80, 443],
        maxConcurrentHosts: 50,
        discoveryMethods: ['arp', 'tcp_probe'],
        retryCount: 3,
        scanType: 'connect',
        timingTemplate: 'normal',
      });
    });

    it('sets scanId on success', async () => {
      mockInvoke.mockResolvedValue({ scan_id: 'scan-456', status: 'started', scan_type: 'connect' });

      await useScanStore.getState().startScan();

      expect(useScanStore.getState().scanId).toBe('scan-456');
      expect(useScanStore.getState().isScanning).toBe(true);
      expect(useScanStore.getState().scanStatus).toBe('scanning');
    });

    it('resets state before starting scan', async () => {
      mockInvoke.mockResolvedValue({ scan_id: 'scan-789', status: 'started', scan_type: 'connect' });

      useScanStore.setState({
        devices: [createMockDevice()],
        logs: [createMockLog()],
        error: 'previous error',
      });

      await useScanStore.getState().startScan();

      expect(useScanStore.getState().devices).toEqual([]);
      expect(useScanStore.getState().logs).toEqual([]);
      expect(useScanStore.getState().error).toBeNull();
    });

    it('sets error state on failure', async () => {
      mockInvoke.mockRejectedValue(new Error('Network unreachable'));

      await useScanStore.getState().startScan();

      expect(useScanStore.getState().error).toBe('Network unreachable');
      expect(useScanStore.getState().isScanning).toBe(false);
      expect(useScanStore.getState().scanStatus).toBe('error');
    });

    it('passes empty ports array when scanPorts is false', async () => {
      mockInvoke.mockResolvedValue({ scan_id: 'scan-001', status: 'started', scan_type: 'connect' });

      useScanStore.setState({ scanPorts: false, selectedPorts: [80, 443] });
      await useScanStore.getState().startScan();

      expect(mockInvoke).toHaveBeenCalledWith('start_scan', expect.objectContaining({
        ports: [],
      }));
    });
  });

  describe('stopScan', () => {
    it('calls invoke stop_scan', async () => {
      mockInvoke.mockResolvedValue(undefined);

      await useScanStore.getState().stopScan();

      expect(mockInvoke).toHaveBeenCalledWith('stop_scan');
    });

    it('sets status to cancelled on success', async () => {
      mockInvoke.mockResolvedValue(undefined);

      useScanStore.setState({ isScanning: true, scanStatus: 'scanning' });
      await useScanStore.getState().stopScan();

      expect(useScanStore.getState().isScanning).toBe(false);
      expect(useScanStore.getState().scanStatus).toBe('cancelled');
    });

    it('sets error on failure', async () => {
      mockInvoke.mockRejectedValue(new Error('Stop failed'));

      await useScanStore.getState().stopScan();

      expect(useScanStore.getState().error).toBe('Stop failed');
    });
  });

  describe('_addDevice', () => {
    it('adds a new device to the list', () => {
      const device = createMockDevice({ ip: '192.168.1.10' });

      useScanStore.getState()._addDevice(device);

      expect(useScanStore.getState().devices).toHaveLength(1);
      expect(useScanStore.getState().devices[0].ip).toBe('192.168.1.10');
    });

    it('updates existing device by IP', () => {
      const device1 = createMockDevice({ ip: '192.168.1.10', hostname: 'old-host' });
      const device2 = createMockDevice({ ip: '192.168.1.10', hostname: 'new-host' });

      useScanStore.getState()._addDevice(device1);
      useScanStore.getState()._addDevice(device2);

      expect(useScanStore.getState().devices).toHaveLength(1);
      expect(useScanStore.getState().devices[0].hostname).toBe('new-host');
    });

    it('adds multiple different devices', () => {
      useScanStore.getState()._addDevice(createMockDevice({ ip: '192.168.1.1' }));
      useScanStore.getState()._addDevice(createMockDevice({ ip: '192.168.1.2' }));
      useScanStore.getState()._addDevice(createMockDevice({ ip: '192.168.1.3' }));

      expect(useScanStore.getState().devices).toHaveLength(3);
    });
  });

  describe('_updateProgress', () => {
    it('updates scannedCount, totalHosts, and currentTarget', () => {
      useScanStore.getState()._updateProgress(50, 254, '192.168.1.50');

      const state = useScanStore.getState();
      expect(state.scannedCount).toBe(50);
      expect(state.totalHosts).toBe(254);
      expect(state.currentTarget).toBe('192.168.1.50');
    });
  });

  describe('_setScanComplete', () => {
    it('sets status to completed and stops scanning', () => {
      useScanStore.setState({ isScanning: true, scanStatus: 'scanning' });

      useScanStore.getState()._setScanComplete('completed', 5000);

      const state = useScanStore.getState();
      expect(state.isScanning).toBe(false);
      expect(state.isPaused).toBe(false);
      expect(state.scanStatus).toBe('completed');
    });

    it('triggers history auto-save on completed status', () => {
      useScanStore.setState({
        isScanning: true,
        scanId: 'scan-123',
        cidr: '192.168.1.0/24',
        devices: [createMockDevice()],
      });

      useScanStore.getState()._setScanComplete('completed', 3000);

      expect(mockInvoke).toHaveBeenCalledWith('save_scan_history', expect.objectContaining({
        entry: expect.objectContaining({
          scanId: 'scan-123',
          cidr: '192.168.1.0/24',
          deviceCount: 1,
          durationMs: 3000,
          status: 'completed',
        }),
      }));
    });

    it('triggers history auto-save on cancelled status', () => {
      useScanStore.setState({
        isScanning: true,
        scanId: 'scan-456',
        cidr: '10.0.0.0/24',
        devices: [createMockDevice()],
      });

      useScanStore.getState()._setScanComplete('cancelled');

      expect(mockInvoke).toHaveBeenCalledWith('save_scan_history', expect.objectContaining({
        entry: expect.objectContaining({
          status: 'cancelled',
        }),
      }));
    });

    it('does not trigger history save for error status', () => {
      useScanStore.setState({ isScanning: true });

      useScanStore.getState()._setScanComplete('error');

      expect(mockInvoke).not.toHaveBeenCalled();
    });
  });

  describe('_addLog', () => {
    it('adds a log entry', () => {
      const log = createMockLog({ message: 'Scanning 192.168.1.1' });

      useScanStore.getState()._addLog(log);

      expect(useScanStore.getState().logs).toHaveLength(1);
      expect(useScanStore.getState().logs[0].message).toBe('Scanning 192.168.1.1');
    });

    it('caps logs at 500 entries', () => {
      for (let i = 0; i < 510; i++) {
        useScanStore.getState()._addLog(createMockLog({ message: `Log ${i}` }));
      }

      expect(useScanStore.getState().logs).toHaveLength(500);
      // The first 10 logs should have been shifted out
      expect(useScanStore.getState().logs[0].message).toBe('Log 10');
    });
  });

  describe('clearResults', () => {
    it('resets devices, progress, and status', () => {
      useScanStore.setState({
        devices: [createMockDevice()],
        selectedDeviceId: 'dev-1',
        scannedCount: 100,
        totalHosts: 254,
        currentTarget: '192.168.1.100',
        scanStatus: 'completed',
      });

      useScanStore.getState().clearResults();

      const state = useScanStore.getState();
      expect(state.devices).toEqual([]);
      expect(state.selectedDeviceId).toBeNull();
      expect(state.scannedCount).toBe(0);
      expect(state.totalHosts).toBe(0);
      expect(state.currentTarget).toBeNull();
      expect(state.scanStatus).toBe('idle');
    });
  });

  describe('clearFilters', () => {
    it('resets search query and filter state', () => {
      useScanStore.setState({
        searchQuery: 'router',
        filterStatus: 'online',
        filterHasOpenPorts: true,
      });

      useScanStore.getState().clearFilters();

      const state = useScanStore.getState();
      expect(state.searchQuery).toBe('');
      expect(state.filterStatus).toBe('all');
      expect(state.filterHasOpenPorts).toBe(false);
    });
  });

  describe('syncFromSettings', () => {
    it('updates scan config from settings when not scanning', () => {
      const scanConfig: ScanConfig = {
        defaultCidr: '10.0.0.0/8',
        timeoutMs: 5000,
        maxConcurrentHosts: 100,
        maxConcurrentPorts: 20,
        scanPortsEnabled: false,
        selectedPorts: [22, 80],
        discoveryMethods: ['arp'],
        retryCount: 5,
        defaultScanType: 'syn',
        defaultTimingTemplate: 'aggressive',
      };

      useScanStore.getState().syncFromSettings(scanConfig);

      const state = useScanStore.getState();
      expect(state.cidr).toBe('10.0.0.0/8');
      expect(state.timeoutMs).toBe(5000);
      expect(state.scanPorts).toBe(false);
      expect(state.selectedPorts).toEqual([22, 80]);
      expect(state.scanType).toBe('syn');
      expect(state.timingTemplate).toBe('aggressive');
    });

    it('does not update when scanning is in progress', () => {
      useScanStore.setState({ isScanning: true });

      const scanConfig: ScanConfig = {
        defaultCidr: '10.0.0.0/8',
        timeoutMs: 5000,
        maxConcurrentHosts: 100,
        maxConcurrentPorts: 20,
        scanPortsEnabled: false,
        selectedPorts: [22],
        discoveryMethods: ['arp'],
        retryCount: 5,
        defaultScanType: 'syn',
        defaultTimingTemplate: 'aggressive',
      };

      useScanStore.getState().syncFromSettings(scanConfig);

      // Should remain unchanged
      expect(useScanStore.getState().cidr).toBe('192.168.1.0/24');
      expect(useScanStore.getState().timeoutMs).toBe(1000);
    });
  });
});
