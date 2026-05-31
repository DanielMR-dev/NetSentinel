import { create } from 'zustand';
import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import type { Baseline, BaselineDiff } from '../types/device';

interface BaselineState {
  baselines: Baseline[];
  currentDiff: BaselineDiff | null;
  isLoading: boolean;
  error: string | null;
}

interface BaselineActions {
  fetchBaselines: () => Promise<void>;
  saveBaseline: (baseline: Baseline) => Promise<void>;
  deleteBaseline: (id: string) => Promise<void>;
  compareBaseline: (id: string) => Promise<void>;
  clearDiff: () => void;
  clearError: () => void;
}

type BaselineStore = BaselineState & BaselineActions;

export const useBaselineStore = create<BaselineStore>((set) => ({
  baselines: [],
  currentDiff: null,
  isLoading: false,
  error: null,

  fetchBaselines: async () => {
    set({ isLoading: true, error: null });
    try {
      const baselines = await invoke<Baseline[]>('get_baselines');
      set({ baselines, isLoading: false });
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Failed to fetch baselines';
      set({ error: errorMessage, isLoading: false });
    }
  },

  saveBaseline: async (baseline: Baseline) => {
    set({ isLoading: true, error: null });
    try {
      const id = await invoke<string>('save_baseline', { baseline });
      const savedBaseline = { ...baseline, id };
      set((state) => ({
        baselines: [...state.baselines, savedBaseline],
        isLoading: false,
      }));
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Failed to save baseline';
      set({ error: errorMessage, isLoading: false });
      throw error;
    }
  },

  deleteBaseline: async (id: string) => {
    set({ isLoading: true, error: null });
    try {
      await invoke('delete_baseline', { id });
      set((state) => ({
        baselines: state.baselines.filter((b) => b.id !== id),
        isLoading: false,
      }));
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Failed to delete baseline';
      set({ error: errorMessage, isLoading: false });
      throw error;
    }
  },

  compareBaseline: async (id: string) => {
    set({ isLoading: true, error: null, currentDiff: null });
    try {
      const diff = await invoke<BaselineDiff>('compare_baseline', { id });
      set({ currentDiff: diff, isLoading: false });
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Failed to compare baseline';
      set({ error: errorMessage, isLoading: false });
    }
  },

  clearDiff: () => {
    set({ currentDiff: null });
  },

  clearError: () => {
    set({ error: null });
  },
}));

// Event listener for baseline_diff_result
let unlistenBaselineDiff: (() => void) | null = null;

export async function setupBaselineEventListeners() {
  cleanupBaselineEventListeners();

  unlistenBaselineDiff = await listen<BaselineDiff>('baseline_diff_result', (event) => {
    useBaselineStore.setState({ currentDiff: event.payload });
  });
}

export function cleanupBaselineEventListeners() {
  if (unlistenBaselineDiff) {
    unlistenBaselineDiff();
    unlistenBaselineDiff = null;
  }
}

// Selector hooks
export const useBaselines = () => useBaselineStore((s) => s.baselines);
export const useBaselineDiff = () => useBaselineStore((s) => s.currentDiff);
export const useBaselineLoading = () => useBaselineStore((s) => s.isLoading);
export const useBaselineError = () => useBaselineStore((s) => s.error);
