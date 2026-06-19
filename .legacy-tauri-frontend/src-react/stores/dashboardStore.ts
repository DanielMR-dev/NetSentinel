import { create } from 'zustand';
import { invoke } from '@tauri-apps/api/core';
import type { DeviceInfoResponse, NetworkInfoResponse } from '../types/dashboard';

export type TabId = 'dashboard' | 'scan' | 'settings' | 'history' | 'baseline';

interface DashboardState {
  // Device info fields
  hostname: string | null;
  osName: string | null;
  osVersion: string | null;
  uptime: string | null;
  // Network info fields
  ipAddress: string | null;
  macAddress: string | null;
  gateway: string | null;
  networkName: string | null;
  // UI state - SPLIT per card
  isDeviceLoading: boolean;
  isNetworkLoading: boolean;
  deviceError: string | null;
  networkError: string | null;
  // Tab navigation
  activeTab: TabId;
}

interface DashboardActions {
  fetchDeviceInfo: () => Promise<void>;
  fetchNetworkInfo: () => Promise<void>;
  fetchDashboardData: () => Promise<void>;
  clearDeviceError: () => void;
  clearNetworkError: () => void;
  setActiveTab: (tab: TabId) => void;
}

type DashboardStore = DashboardState & DashboardActions;

export const useDashboardStore = create<DashboardStore>((set) => ({
  // Initial state
  hostname: null,
  osName: null,
  osVersion: null,
  uptime: null,
  ipAddress: null,
  macAddress: null,
  gateway: null,
  networkName: null,
  isDeviceLoading: false,
  isNetworkLoading: false,
  deviceError: null,
  networkError: null,
  activeTab: 'dashboard',

  // Actions
  fetchDeviceInfo: async () => {
    // Skip if we already have device data
    const state = useDashboardStore.getState();
    if (state.hostname !== null && state.osName !== null) {
      return;
    }
    set({ isDeviceLoading: true, deviceError: null });
    try {
      const deviceInfo = await invoke<DeviceInfoResponse>('get_device_info');
      set({
        hostname: deviceInfo.hostname,
        osName: deviceInfo.osName,
        osVersion: deviceInfo.osVersion,
        uptime: deviceInfo.uptime,
        isDeviceLoading: false,
      });
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Failed to fetch device info';
      set({ deviceError: errorMessage, isDeviceLoading: false });
    }
  },

  fetchNetworkInfo: async () => {
    // Skip if we already have network data
    const state = useDashboardStore.getState();
    if (state.ipAddress !== null && state.macAddress !== null) {
      return;
    }
    set({ isNetworkLoading: true, networkError: null });
    try {
      const networkInfo = await invoke<NetworkInfoResponse>('get_network_info');
      set({
        ipAddress: networkInfo.ipAddress,
        macAddress: networkInfo.macAddress,
        gateway: networkInfo.gateway,
        networkName: networkInfo.networkName,
        isNetworkLoading: false,
      });
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Failed to fetch network info';
      set({ networkError: errorMessage, isNetworkLoading: false });
    }
  },

  fetchDashboardData: async () => {
    // Skip if we already have all data
    const state = useDashboardStore.getState();
    if (state.hostname !== null && state.ipAddress !== null) {
      return;
    }
    set({ isDeviceLoading: true, isNetworkLoading: true, deviceError: null, networkError: null });

    try {
      const [deviceInfo, networkInfo] = await Promise.all([
        invoke<DeviceInfoResponse>('get_device_info'),
        invoke<NetworkInfoResponse>('get_network_info'),
      ]);

      set({
        hostname: deviceInfo.hostname,
        osName: deviceInfo.osName,
        osVersion: deviceInfo.osVersion,
        uptime: deviceInfo.uptime,
        ipAddress: networkInfo.ipAddress,
        macAddress: networkInfo.macAddress,
        gateway: networkInfo.gateway,
        networkName: networkInfo.networkName,
        isDeviceLoading: false,
        isNetworkLoading: false,
      });
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Failed to fetch dashboard data';
      set({
        deviceError: errorMessage,
        networkError: errorMessage,
        isDeviceLoading: false,
        isNetworkLoading: false,
      });
    }
  },

  clearDeviceError: () => {
    set({ deviceError: null });
  },

  clearNetworkError: () => {
    set({ networkError: null });
  },

  setActiveTab: (tab: TabId) => {
    set({ activeTab: tab });
  },
}));