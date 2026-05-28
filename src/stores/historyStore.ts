import { create } from 'zustand';
import { invoke } from '@tauri-apps/api/core';
import type { ScanHistoryEntry } from '../types/device';

interface HistoryState {
  entries: ScanHistoryEntry[];
  isLoading: boolean;
  error: string | null;
}

interface HistoryActions {
  fetchHistory: () => Promise<void>;
  saveEntry: (entry: ScanHistoryEntry) => Promise<void>;
  deleteEntry: (id: string) => Promise<void>;
  clearHistory: () => Promise<void>;
  clearError: () => void;
}

type HistoryStore = HistoryState & HistoryActions;

export const useHistoryStore = create<HistoryStore>((set) => ({
  entries: [],
  isLoading: false,
  error: null,

  fetchHistory: async () => {
    set({ isLoading: true, error: null });
    try {
      const entries = await invoke<ScanHistoryEntry[]>('get_scan_history');
      set({ entries, isLoading: false });
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Failed to fetch scan history';
      set({ error: errorMessage, isLoading: false });
    }
  },

  saveEntry: async (entry: ScanHistoryEntry) => {
    try {
      await invoke('save_scan_history', { entry });
      set((state) => ({ entries: [entry, ...state.entries] }));
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Failed to save scan history';
      set({ error: errorMessage });
    }
  },

  deleteEntry: async (id: string) => {
    try {
      await invoke('delete_scan_history_entry', { id });
      set((state) => ({
        entries: state.entries.filter((e) => e.id !== id),
      }));
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Failed to delete history entry';
      set({ error: errorMessage });
    }
  },

  clearHistory: async () => {
    try {
      await invoke('clear_scan_history');
      set({ entries: [] });
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Failed to clear scan history';
      set({ error: errorMessage });
    }
  },

  clearError: () => {
    set({ error: null });
  },
}));

// Selector hooks for performance
export const useHistoryEntries = () => useHistoryStore((s) => s.entries);
export const useHistoryLoading = () => useHistoryStore((s) => s.isLoading);
export const useHistoryError = () => useHistoryStore((s) => s.error);
