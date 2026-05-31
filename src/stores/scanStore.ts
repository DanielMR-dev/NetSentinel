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
  ScanHistoryEntry,
  ScanType,
  TimingTemplate,
} from '../types/device';
import type { ScanConfig } from '../types/settings';
import { useSettingsStore } from './settingsStore';

type ScanStatus = 'idle' | 'scanning' | 'paused' | 'completed' | 'cancelled' | 'error';

export type FilterStatus = 'all' | 'online' | 'offline' | 'unknown';

interface ScanState {
  // Scan configuration
  cidr: string;
  scanPorts: boolean;
  selectedPorts: number[];
  timeoutMs: number;
  scanType: ScanType;
  timingTemplate: TimingTemplate;

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

  // Search and filtering
  searchQuery: string;
  filterStatus: FilterStatus;
  filterHasOpenPorts: boolean;

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
  setScanType: (scanType: ScanType) => void;
  setTimingTemplate: (template: TimingTemplate) => void;
  startScan: () => Promise<void>;
  stopScan: () => Promise<void>;
  pauseScan: () => Promise<void>;
  resumeScan: () => Promise<void>;
  selectDevice: (deviceId: string | null) => void;
  clearResults: () => void;
  clearError: () => void;
  // Search and filtering
  setSearchQuery: (query: string) => void;
  setFilterStatus: (status: FilterStatus) => void;
  setFilterHasOpenPorts: (hasPorts: boolean) => void;
  clearFilters: () => void;
  // Settings sync
  syncFromSettings: (scanConfig: ScanConfig) => void;
  // Internal updaters for events
  _addDevice: (device: Device) => void;
  _updateProgress: (scanned: number, total: number, currentTarget: string) => void;
  _setScanComplete: (status: ScanStatus, durationMs?: number) => void;
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
  scanType: 'connect' as ScanType,
  timingTemplate: 'normal' as TimingTemplate,

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

  // Actions
  setCidr: (cidr: string) => set({ cidr }),

  setScanPorts: (scanPorts: boolean) => set({ scanPorts }),

  setSelectedPorts: (ports: number[]) => set({ selectedPorts: ports }),

  setTimeoutMs: (timeoutMs: number) => set({ timeoutMs }),

  setScanType: (scanType: ScanType) => set({ scanType }),

  setTimingTemplate: (template: TimingTemplate) => set({ timingTemplate: template }),

  startScan: async () => {
    const { cidr, scanPorts, selectedPorts, timeoutMs, scanType, timingTemplate } = get();

    // Read from settings store for advanced scan parameters
    const settings = useSettingsStore.getState().settings;
    const scanConfig = settings?.scanConfig;

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
        maxConcurrentHosts: scanConfig?.maxConcurrentHosts ?? null,
        discoveryMethods: scanConfig?.discoveryMethods ?? null,
        retryCount: scanConfig?.retryCount ?? null,
        scanType,
        timingTemplate,
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

  // Search and filtering actions
  setSearchQuery: (query: string) => set({ searchQuery: query }),

  setFilterStatus: (status: FilterStatus) => set({ filterStatus: status }),

  setFilterHasOpenPorts: (hasPorts: boolean) => set({ filterHasOpenPorts: hasPorts }),

  clearFilters: () => set({ searchQuery: '', filterStatus: 'all', filterHasOpenPorts: false }),

  // Settings sync — update scan defaults from the active settings profile
  syncFromSettings: (scanConfig: ScanConfig) => {
    const { isScanning } = get();
    // Only sync when NOT scanning to avoid overriding user's manual changes
    if (isScanning) return;

    const updates: Partial<ScanState> = {};
    if (scanConfig.defaultCidr) {
      updates.cidr = scanConfig.defaultCidr;
    }
    if (scanConfig.timeoutMs) {
      updates.timeoutMs = scanConfig.timeoutMs;
    }
    updates.scanPorts = scanConfig.scanPortsEnabled;
    if (scanConfig.selectedPorts?.length) {
      updates.selectedPorts = scanConfig.selectedPorts;
    }
    if (scanConfig.defaultScanType) {
      updates.scanType = scanConfig.defaultScanType;
    }
    if (scanConfig.defaultTimingTemplate) {
      updates.timingTemplate = scanConfig.defaultTimingTemplate;
    }
    set(updates);
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

  _setScanComplete: (status: ScanStatus, durationMs?: number) => {
    set({ isScanning: false, isPaused: false, scanStatus: status });

    // Auto-save to history if scan completed or was cancelled
    if (status === 'completed' || status === 'cancelled') {
      const state = get();
      if (state.devices.length > 0 || status === 'completed') {
        const entry: ScanHistoryEntry = {
          id: crypto.randomUUID(),
          scanId: state.scanId ?? '',
          cidr: state.cidr,
          deviceCount: state.devices.length,
          durationMs: durationMs ?? 0,
          status,
          devices: state.devices,
          timestamp: Date.now(),
        };
        // Fire and forget — don't block UI
        invoke('save_scan_history', { entry }).catch(console.error);
      }
    }
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
      vendor: event.payload.vendor,
      status: 'online',
      ports: event.payload.ports || [],
      lastSeen: event.payload.timestamp,
      banner_results: event.payload.banner_results || [],
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
    useScanStore.getState()._setScanComplete(status, event.payload.duration_ms);
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
export const useSearchQuery = () => useScanStore((s) => s.searchQuery);
export const useFilterStatus = () => useScanStore((s) => s.filterStatus);
export const useFilterHasOpenPorts = () => useScanStore((s) => s.filterHasOpenPorts);
export const useScanType = () => useScanStore((s) => s.scanType);
export const useTimingTemplate = () => useScanStore((s) => s.timingTemplate);