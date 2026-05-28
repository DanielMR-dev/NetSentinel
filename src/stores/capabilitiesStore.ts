import { create } from 'zustand';
import { invoke } from '@tauri-apps/api/core';
import type { PlatformCapabilities } from '../types/platform';
import { DISCOVERY_CAPABILITY_MAP } from '../types/platform';

interface CapabilitiesState {
  /** The platform capabilities returned by the backend, or null if not yet loaded. */
  capabilities: PlatformCapabilities | null;
  /** Whether a fetch is currently in progress. */
  isLoading: boolean;
  /** Error message from the last failed fetch, if any. */
  error: string | null;
}

interface CapabilitiesActions {
  /**
   * Fetches platform capabilities from the Rust backend.
   * Idempotent — skips if capabilities are already loaded.
   */
  fetchCapabilities: () => Promise<void>;
  /** Returns true if the given capability string is present. */
  hasCapability: (capability: string) => boolean;
  /**
   * Returns true if the discovery method (by its ID) has the required
   * capability available on this platform.
   */
  isDiscoveryMethodAvailable: (methodId: string) => boolean;
  /** Clears the current error message. */
  clearError: () => void;
}

type CapabilitiesStore = CapabilitiesState & CapabilitiesActions;

export const useCapabilitiesStore = create<CapabilitiesStore>((set, get) => ({
  // Initial state
  capabilities: null,
  isLoading: false,
  error: null,

  // Actions
  fetchCapabilities: async () => {
    // Idempotent: skip if already loaded
    const state = get();
    if (state.capabilities !== null) {
      return;
    }

    set({ isLoading: true, error: null });

    try {
      const result = await invoke<PlatformCapabilities>('get_platform_capabilities');
      set({ capabilities: result, isLoading: false });
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : 'Failed to fetch platform capabilities';
      set({ error: errorMessage, isLoading: false });
    }
  },

  hasCapability: (capability: string) => {
    const { capabilities } = get();
    if (capabilities === null) {
      // If capabilities haven't been loaded yet, assume available
      // to avoid blocking the UI prematurely
      return true;
    }
    return capabilities.capabilities.includes(capability);
  },

  isDiscoveryMethodAvailable: (methodId: string) => {
    const requiredCapability = DISCOVERY_CAPABILITY_MAP[methodId];
    if (requiredCapability === undefined) {
      // Unknown method — assume available (defensive)
      return true;
    }
    return get().hasCapability(requiredCapability);
  },

  clearError: () => {
    set({ error: null });
  },
}));

// ── Selector hooks for performance ──────────────────────────────────

export const useCapabilities = () => useCapabilitiesStore((s) => s.capabilities);
export const useIsElevated = () => useCapabilitiesStore((s) => s.capabilities?.isElevated ?? true);
export const usePlatform = () => useCapabilitiesStore((s) => s.capabilities?.platform ?? null);
export const useCapabilitiesLoading = () => useCapabilitiesStore((s) => s.isLoading);
export const useCapabilitiesError = () => useCapabilitiesStore((s) => s.error);
