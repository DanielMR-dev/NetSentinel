import { create } from 'zustand';
import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import type { PlatformCapabilities } from '../types/platform';
import { DISCOVERY_CAPABILITY_MAP } from '../types/platform';
import type { PrivilegeStatus } from '../types/device';

interface CapabilitiesState {
  /** The platform capabilities returned by the backend, or null if not yet loaded. */
  capabilities: PlatformCapabilities | null;
  /** Detailed privilege status from the backend, or null if not yet loaded. */
  privilegeStatus: PrivilegeStatus | null;
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
  /**
   * Fetches detailed privilege status from the Rust backend.
   * Idempotent — skips if already loaded.
   */
  fetchPrivilegeStatus: () => Promise<void>;
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
  privilegeStatus: null,
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

  fetchPrivilegeStatus: async () => {
    // Idempotent: skip if already loaded
    const state = get();
    if (state.privilegeStatus !== null) {
      return;
    }

    set({ isLoading: true, error: null });

    try {
      const result = await invoke<PrivilegeStatus>('check_privilege_status');
      set({ privilegeStatus: result, isLoading: false });
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : 'Failed to fetch privilege status';
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

// Event listener for privilege_status updates from backend
let unlistenPrivilegeStatus: (() => void) | null = null;

export async function setupPrivilegeStatusListener() {
  if (unlistenPrivilegeStatus) {
    unlistenPrivilegeStatus();
    unlistenPrivilegeStatus = null;
  }

  unlistenPrivilegeStatus = await listen<PrivilegeStatus>('privilege_status', (event) => {
    useCapabilitiesStore.setState({ privilegeStatus: event.payload });
  });
}

export function cleanupPrivilegeStatusListener() {
  if (unlistenPrivilegeStatus) {
    unlistenPrivilegeStatus();
    unlistenPrivilegeStatus = null;
  }
}

// ── Selector hooks for performance ──────────────────────────────────

export const useCapabilities = () => useCapabilitiesStore((s) => s.capabilities);
export const useIsElevated = () => useCapabilitiesStore((s) => s.capabilities?.isElevated ?? true);
export const usePlatform = () => useCapabilitiesStore((s) => s.capabilities?.platform ?? null);
export const useCapabilitiesLoading = () => useCapabilitiesStore((s) => s.isLoading);
export const useCapabilitiesError = () => useCapabilitiesStore((s) => s.error);
export const usePrivilegeStatus = () => useCapabilitiesStore((s) => s.privilegeStatus);
export const useSynScanAvailable = () => useCapabilitiesStore((s) => s.privilegeStatus?.synScanAvailable ?? true);
export const usePrivilegeWarnings = () => useCapabilitiesStore((s) => s.privilegeStatus?.warnings ?? []);
