import { useEffect } from 'react';
import { useScanStore } from '../stores/scanStore';
import { useDashboardStore } from '../stores/dashboardStore';
import type { TabId } from '../stores/dashboardStore';

const TAB_MAP: Record<string, TabId> = {
  '1': 'dashboard',
  '2': 'scan',
  '3': 'settings',
  '4': 'history',
};

export function useKeyboardShortcuts() {
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      const target = e.target;
      if (
        target instanceof HTMLInputElement ||
        target instanceof HTMLTextAreaElement ||
        (target instanceof HTMLElement && target.isContentEditable)
      ) {
        return;
      }

      const isCtrlOrCmd = e.ctrlKey || e.metaKey;

      // Ctrl/Cmd + S → Start scan (or stop if scanning)
      if (isCtrlOrCmd && e.key === 's') {
        e.preventDefault();
        const store = useScanStore.getState();
        if (store.isScanning) {
          void store.stopScan();
        } else {
          void store.startScan();
        }
      }

      // Escape → Stop scan
      if (e.key === 'Escape') {
        const store = useScanStore.getState();
        if (store.isScanning) {
          void store.stopScan();
        }
      }

      // Ctrl/Cmd + F → Focus search input
      if (isCtrlOrCmd && e.key === 'f') {
        e.preventDefault();
        const searchInput = document.querySelector<HTMLInputElement>('[data-search-input]');
        searchInput?.focus();
      }

      // Ctrl/Cmd + 1/2/3/4 → Switch tabs
      if (isCtrlOrCmd && e.key in TAB_MAP) {
        e.preventDefault();
        const tabId = TAB_MAP[e.key];
        if (tabId) {
          useDashboardStore.getState().setActiveTab(tabId);
        }
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);
}
