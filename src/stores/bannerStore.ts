import { create } from 'zustand';
import { listen } from '@tauri-apps/api/event';
import type { BannerResult, CveAlertEvent } from '../types/device';

interface BannerState {
  banners: Map<string, BannerResult[]>;
  cveAlerts: CveAlertEvent[];
  isLoading: boolean;
}

interface BannerActions {
  addBanner: (result: BannerResult) => void;
  addCveAlert: (alert: CveAlertEvent) => void;
  clearBanners: () => void;
  clearCveAlerts: () => void;
  getBannersForHost: (ip: string) => BannerResult[];
  getCveAlertsForHost: (ip: string) => CveAlertEvent[];
}

type BannerStore = BannerState & BannerActions;

export const useBannerStore = create<BannerStore>((set, get) => ({
  banners: new Map(),
  cveAlerts: [],
  isLoading: false,

  addBanner: (result: BannerResult) => {
    set((state) => {
      const newBanners = new Map(state.banners);
      const existing = newBanners.get(result.ip) ?? [];
      // Avoid duplicates by port
      const alreadyExists = existing.some((b) => b.port === result.port);
      if (!alreadyExists) {
        newBanners.set(result.ip, [...existing, result]);
      }
      return { banners: newBanners };
    });
  },

  addCveAlert: (alert: CveAlertEvent) => {
    set((state) => {
      // Avoid exact duplicates
      const alreadyExists = state.cveAlerts.some(
        (a) => a.cveId === alert.cveId && a.ip === alert.ip && a.port === alert.port
      );
      if (alreadyExists) return state;
      return { cveAlerts: [...state.cveAlerts, alert] };
    });
  },

  clearBanners: () => {
    set({ banners: new Map() });
  },

  clearCveAlerts: () => {
    set({ cveAlerts: [] });
  },

  getBannersForHost: (ip: string) => {
    return get().banners.get(ip) ?? [];
  },

  getCveAlertsForHost: (ip: string) => {
    return get().cveAlerts.filter((a) => a.ip === ip);
  },
}));

// Event listener setup/cleanup
let unlistenBannerFound: (() => void) | null = null;
let unlistenCveAlert: (() => void) | null = null;

export async function setupBannerEventListeners() {
  cleanupBannerEventListeners();

  unlistenBannerFound = await listen<BannerResult>('banner_found', (event) => {
    useBannerStore.getState().addBanner(event.payload);
  });

  unlistenCveAlert = await listen<CveAlertEvent>('cve_alert', (event) => {
    useBannerStore.getState().addCveAlert(event.payload);
  });
}

export function cleanupBannerEventListeners() {
  if (unlistenBannerFound) {
    unlistenBannerFound();
    unlistenBannerFound = null;
  }
  if (unlistenCveAlert) {
    unlistenCveAlert();
    unlistenCveAlert = null;
  }
}

// Selector hooks
export const useBannerMap = () => useBannerStore((s) => s.banners);
export const useCveAlerts = () => useBannerStore((s) => s.cveAlerts);
export const useBannerIsLoading = () => useBannerStore((s) => s.isLoading);
