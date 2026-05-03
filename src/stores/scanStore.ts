import { create } from 'zustand';
import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import type {
  Device,
  DeviceFoundEvent,
  ScanCompleteEvent,
  ScanProgressEvent,
  ScanResponse,
  ScanLogEvent,
} from '../types/device';

type ScanStatus = 'idle' | 'scanning' | 'paused' | 'completed' | 'cancelled' | 'error';

interface ScanState {
  // Scan configuration
  cidr: string;
  scanPorts: boolean;
  selectedPorts: number[];
  timeoutMs: number;

  // Scan status
  isScanning: boolean;
  isPaused: boolean;
  scanStatus: ScanStatus;
  scanId: string | null;

  // Progress
  scannedCount: number;
  totalHosts: number;
  currentTarget: string | null;

  // Results
  devices: Device[];
  selectedDeviceId: string | null;

  // Logs
  logs: ScanLogEvent[];

  // Error handling
  error: string | null;
}

interface ScanActions {
  setCidr: (cidr: string) => void;
  setScanPorts: (scanPorts: boolean) => void;
  setSelectedPorts: (ports: number[]) => void;
  setTimeoutMs: (timeoutMs: number) => void;
  startScan: () => Promise<void>;
  stopScan: () => Promise<void>;
  pauseScan: () => Promise<void>;
  resumeScan: () => Promise<void>;
  selectDevice: (deviceId: string | null) => void;
  clearResults: () => void;
  clearError: () => void;
  // Internal updaters for events
  _addDevice: (device: Device) => void;
  _updateProgress: (scanned: number, total: number, currentTarget: string) => void;
  _setScanComplete: (status: ScanStatus) => void;
  _addLog: (log: ScanLogEvent) => void;
  _clearLogs: () => void;
}

type ScanStore = ScanState & ScanActions;

// Default common ports
const DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 5900, 6379, 8080, 8443];

export const useScanStore = create<ScanStore>((set, get) => ({
  // Initial state
  cidr: '192.168.1.0/24',
  scanPorts: true,
  selectedPorts: DEFAULT_PORTS,
  timeoutMs: 1000,

  isScanning: false,
  isPaused: false,
  scanStatus: 'idle',
  scanId: null,

  scannedCount: 0,
  totalHosts: 0,
  currentTarget: null,

  devices: [],
  selectedDeviceId: null,

  logs: [],

  error: null,

  // Actions
  setCidr: (cidr: string) => set({ cidr }),

  setScanPorts: (scanPorts: boolean) => set({ scanPorts }),

  setSelectedPorts: (ports: number[]) => set({ selectedPorts: ports }),

  setTimeoutMs: (timeoutMs: number) => set({ timeoutMs }),

  startScan: async () => {
    const { cidr, scanPorts, selectedPorts, timeoutMs } = get();

    // Reset state
    set({
      isScanning: true,
      isPaused: false,
      scanStatus: 'scanning',
      scanId: null,
      scannedCount: 0,
      totalHosts: 0,
      currentTarget: null,
      devices: [],
      selectedDeviceId: null,
      error: null,
      logs: [],
    });

    try {
      const response = await invoke<ScanResponse>('start_scan', {
        cidr,
        timeoutMs,
        scanPorts,
        ports: scanPorts ? selectedPorts : [],
      });

      set({ scanId: response.scan_id });
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Failed to start scan';
      set({ error: errorMessage, isScanning: false, scanStatus: 'error' });
    }
  },

  stopScan: async () => {
    try {
      await invoke('stop_scan');
      set({ isScanning: false, isPaused: false, scanStatus: 'cancelled' });
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Failed to stop scan';
      set({ error: errorMessage });
    }
  },

  pauseScan: async () => {
    try {
      await invoke('pause_scan');
      set({ isPaused: true, scanStatus: 'paused' });
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Failed to pause scan';
      set({ error: errorMessage });
    }
  },

  resumeScan: async () => {
    try {
      await invoke('resume_scan');
      set({ isPaused: false, scanStatus: 'scanning' });
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Failed to resume scan';
      set({ error: errorMessage });
    }
  },

  selectDevice: (deviceId: string | null) => {
    set({ selectedDeviceId: deviceId });
  },

  clearResults: () => {
    set({
      devices: [],
      selectedDeviceId: null,
      scannedCount: 0,
      totalHosts: 0,
      currentTarget: null,
      scanStatus: 'idle',
    });
  },

  clearError: () => {
    set({ error: null });
  },

  // Internal updaters for event-driven updates
  _addDevice: (device: Device) => {
    const state = get();
    const existingIndex = state.devices.findIndex((d) => d.ip === device.ip);
    if (existingIndex >= 0) {
      const updatedDevices = [...state.devices];
      updatedDevices[existingIndex] = device;
      set({ devices: updatedDevices });
    } else {
      set({ devices: [...state.devices, device] });
    }
  },

  _updateProgress: (scanned: number, total: number, currentTarget: string) => {
    set({ scannedCount: scanned, totalHosts: total, currentTarget });
  },

  _setScanComplete: (status: ScanStatus) => {
    set({ isScanning: false, isPaused: false, scanStatus: status });
  },

  _addLog: (log: ScanLogEvent) => {
    const state = get();
    const updatedLogs = [...state.logs, log];
    // Cap at 500 logs to prevent memory issues
    if (updatedLogs.length > 500) {
      updatedLogs.shift();
    }
    set({ logs: updatedLogs });
  },

  _clearLogs: () => {
    set({ logs: [] });
  },
}));

// Event listener setup helper
let unlistenDeviceFound: (() => void) | null = null;
let unlistenScanProgress: (() => void) | null = null;
let unlistenScanComplete: (() => void) | null = null;
let unlistenScanLog: (() => void) | null = null;

export async function setupScanEventListeners() {
  // Cleanup existing listeners
  cleanupScanEventListeners();

  // Listen for device found events
  unlistenDeviceFound = await listen<DeviceFoundEvent>('device_found', (event) => {
    const device: Device = {
      ip: event.payload.ip,
      mac: event.payload.mac,
      hostname: event.payload.hostname,
      status: 'online',
      ports: event.payload.ports || [],
      lastSeen: event.payload.timestamp,
    };

    useScanStore.getState()._addDevice(device);
  });

  // Listen for scan progress events
  unlistenScanProgress = await listen<ScanProgressEvent>('scan_progress', (event) => {
    useScanStore.getState()._updateProgress(
      event.payload.scanned,
      event.payload.total,
      event.payload.current_target
    );
  });

  // Listen for scan complete events
  unlistenScanComplete = await listen<ScanCompleteEvent>('scan_complete', (event) => {
    const status = event.payload.status as ScanStatus;
    useScanStore.getState()._setScanComplete(status);
  });

  // Listen for scan log events
  unlistenScanLog = await listen<ScanLogEvent>('scan_log', (event) => {
    useScanStore.getState()._addLog(event.payload);
  });
}

export function cleanupScanEventListeners() {
  if (unlistenDeviceFound) {
    unlistenDeviceFound();
    unlistenDeviceFound = null;
  }
  if (unlistenScanProgress) {
    unlistenScanProgress();
    unlistenScanProgress = null;
  }
  if (unlistenScanComplete) {
    unlistenScanComplete();
    unlistenScanComplete = null;
  }
  if (unlistenScanLog) {
    unlistenScanLog();
    unlistenScanLog = null;
  }
}

// Selector hooks for performance
export const useScanDevices = () => useScanStore((s) => s.devices);
export const useScanIsScanning = () => useScanStore((s) => s.isScanning);
export const useScanStatus = () => useScanStore((s) => s.scanStatus);
export const useScanLogs = () => useScanStore((s) => s.logs);