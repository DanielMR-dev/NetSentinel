import { useEffect, useState, useCallback } from 'react';
import { listen } from '@tauri-apps/api/event';
import { useDashboardStore } from './stores/dashboardStore';
import { useCapabilitiesStore, setupPrivilegeStatusListener, cleanupPrivilegeStatusListener } from './stores/capabilitiesStore';
import { setupScanEventListeners, cleanupScanEventListeners } from './stores/scanStore';
import { setupBannerEventListeners, cleanupBannerEventListeners } from './stores/bannerStore';
import { DashboardView } from './components/dashboard/DashboardView';
import { ScanView } from './components/scan/ScanView';
import { TabNavigation } from './components/dashboard/TabNavigation';
import { SettingsView } from './components/settings/SettingsView';
import { HistoryView } from './components/dashboard/HistoryView';
import { BaselineView } from './components/baseline/BaselineView';
import { PrivilegeBanner } from './components/common/PrivilegeBanner';
import { useTheme } from './hooks/useTheme';
import { useKeyboardShortcuts } from './hooks/useKeyboardShortcuts';
import { useNotifications } from './hooks/useNotifications';
import type { ScanCompleteEvent } from './types/device';
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';

interface KeyboardShortcutsModalProps {
  onClose: () => void;
}

const SHORTCUTS = [
  { keys: 'Ctrl+S', description: 'Start / Stop scan' },
  { keys: 'Escape', description: 'Stop scan' },
  { keys: 'Ctrl+F', description: 'Focus search' },
  { keys: 'Ctrl+1', description: 'Dashboard tab' },
  { keys: 'Ctrl+2', description: 'Scan tab' },
  { keys: 'Ctrl+3', description: 'Baseline tab' },
  { keys: 'Ctrl+4', description: 'Settings tab' },
  { keys: 'Ctrl+5', description: 'History tab' },
] as const;

const KeyboardShortcutsModal: React.FC<KeyboardShortcutsModalProps> = ({ onClose }) => {
  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (e.key === 'Escape') {
        onClose();
      }
    },
    [onClose]
  );

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/50"
      onClick={onClose}
      onKeyDown={handleKeyDown}
      role="dialog"
      aria-modal="true"
      aria-label="Keyboard shortcuts"
    >
      <div
        className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-xl shadow-xl max-w-md w-full mx-4"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100">Keyboard Shortcuts</h3>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close shortcuts help"
            className="p-2 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 text-gray-500 dark:text-gray-400 transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
        <div className="px-6 py-4 space-y-3">
          {SHORTCUTS.map(({ keys, description }) => (
            <div key={keys} className="flex items-center justify-between">
              <span className="text-sm text-gray-700 dark:text-gray-300">{description}</span>
              <kbd className="px-2 py-1 text-xs font-mono bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded border border-gray-300 dark:border-gray-600">
                {keys}
              </kbd>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

export function App() {
  const activeTab = useDashboardStore((s) => s.activeTab);
  const setActiveTab = useDashboardStore((s) => s.setActiveTab);
  const fetchCapabilities = useCapabilitiesStore((s) => s.fetchCapabilities);
  const fetchPrivilegeStatus = useCapabilitiesStore((s) => s.fetchPrivilegeStatus);

  const { theme, toggleTheme } = useTheme();
  useKeyboardShortcuts();
  const { requestNotificationPermission, notify } = useNotifications();

  const [showShortcuts, setShowShortcuts] = useState(false);
  const [toastMessage, setToastMessage] = useState<string | null>(null);

  // Fetch platform capabilities and privilege status once on app mount
  useEffect(() => {
    fetchCapabilities();
    fetchPrivilegeStatus();
  }, [fetchCapabilities, fetchPrivilegeStatus]);

  // Set up all event listeners on mount
  useEffect(() => {
    const setupAll = async () => {
      try {
        await setupScanEventListeners();
        await setupBannerEventListeners();
        await setupPrivilegeStatusListener();
      } catch (error) {
        console.error('Failed to set up event listeners:', error);
      }
    };

    setupAll();

    return () => {
      cleanupScanEventListeners();
      cleanupBannerEventListeners();
      cleanupPrivilegeStatusListener();
    };
  }, []);

  // Request notification permission on mount
  useEffect(() => {
    requestNotificationPermission();
  }, [requestNotificationPermission]);

  // Listen for scan_complete events to show in-app toast and native notification
  useEffect(() => {
    let unlisten: (() => void) | undefined;

    const setup = async () => {
      try {
        unlisten = await listen<ScanCompleteEvent>('scan_complete', (event) => {
          const { status, device_count } = event.payload;
          const message = `Scan ${status}: ${device_count} device${device_count !== 1 ? 's' : ''} found`;
          setToastMessage(message);
          notify('NetSentinel', message);

          // Auto-dismiss toast after 5 seconds
          setTimeout(() => setToastMessage(null), 5000);
        });
      } catch (error) {
        console.error('Failed to set up scan_complete listener:', error);
      }
    };

    setup();

    return () => {
      if (unlisten) {
        unlisten();
        unlisten = undefined;
      }
    };
  }, [notify]);

  const handleToggleShortcuts = useCallback(() => {
    setShowShortcuts((prev) => !prev);
  }, []);

  const handleCloseShortcuts = useCallback(() => {
    setShowShortcuts(false);
  }, []);

  const handleDismissToast = useCallback(() => {
    setToastMessage(null);
  }, []);

  return (
    <div className="min-h-screen bg-white dark:bg-gray-900 text-gray-900 dark:text-gray-100 transition-colors">
      {/* Keyboard Shortcuts Modal */}
      {showShortcuts && <KeyboardShortcutsModal onClose={handleCloseShortcuts} />}

      {/* In-app toast notification */}
      {toastMessage && (
        <div
          role="status"
          aria-live="polite"
          className={twMerge(
            clsx(
              'fixed top-4 right-4 z-50 px-4 py-3 rounded-xl shadow-lg',
              'flex items-center gap-3 max-w-sm',
              'animate-slide-in',
              'bg-blue-50 dark:bg-blue-900/90 border border-blue-200 dark:border-blue-700/50 text-blue-800 dark:text-blue-100'
            )
          )}
        >
          <svg className="w-5 h-5 text-blue-500 dark:text-blue-400 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <span className="text-sm font-medium">{toastMessage}</span>
          <button
            onClick={handleDismissToast}
            className="ml-2 p-1 rounded-lg hover:bg-blue-100 dark:hover:bg-white/10 transition-colors"
            aria-label="Dismiss notification"
          >
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
      )}

      <header className="border-b border-gray-200 dark:border-gray-800 px-6 py-4 bg-white dark:bg-gray-900 transition-colors">
        <nav className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <img
              src="/netSentinel-logo.png"
              alt="NetSentinel logo"
              className="w-10 h-10 rounded-lg"
            />
            <h1 className="text-2xl font-bold text-blue-600 dark:text-blue-500">NetSentinel</h1>
          </div>
          <div className="flex items-center gap-2">
            {/* Keyboard shortcuts help */}
            <button
              type="button"
              onClick={handleToggleShortcuts}
              aria-label="Show keyboard shortcuts"
              className={twMerge(
                clsx(
                  'w-8 h-8 flex items-center justify-center rounded-lg text-sm font-bold',
                  'text-gray-500 dark:text-gray-400',
                  'hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors',
                  'focus:outline-none focus:ring-2 focus:ring-blue-500'
                )
              )}
            >
              ?
            </button>
            {/* Theme toggle */}
            <button
              type="button"
              onClick={toggleTheme}
              aria-label="Toggle theme"
              aria-pressed={theme === 'dark'}
              className={twMerge(
                clsx(
                  'w-8 h-8 flex items-center justify-center rounded-lg',
                  'text-gray-500 dark:text-gray-400',
                  'hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors',
                  'focus:outline-none focus:ring-2 focus:ring-blue-500'
                )
              )}
            >
              {theme === 'dark' ? (
                <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z" />
                </svg>
              ) : (
                <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z" />
                </svg>
              )}
            </button>
          </div>
        </nav>
      </header>
      <PrivilegeBanner />
      <main className="p-6">
        <TabNavigation activeTab={activeTab} onTabChange={setActiveTab} />
        {activeTab === 'dashboard' && <DashboardView />}
        {activeTab === 'scan' && <ScanView />}
        {activeTab === 'baseline' && <BaselineView />}
        {activeTab === 'settings' && <SettingsView />}
        {activeTab === 'history' && <HistoryView />}
      </main>
    </div>
  );
}
