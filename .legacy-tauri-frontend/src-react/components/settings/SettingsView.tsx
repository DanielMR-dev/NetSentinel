import React, { useEffect, useState, useMemo } from 'react';
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';
import { useSettingsStore } from '../../stores/settingsStore';
import { ScanConfigSection } from './ScanConfigSection';
import { UiPreferencesSection } from './UiPreferencesSection';
import { ProfileManager } from './ProfileManager';
import { ErrorBoundary } from '../common/ErrorBoundary';

type TabId = 'scan' | 'ui' | 'profiles';

interface Tab {
  id: TabId;
  label: string;
  icon: React.ReactNode;
}

const TABS: Tab[] = [
  {
    id: 'scan',
    label: 'Scan Configuration',
    icon: (
      <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path
          strokeLinecap="round"
          strokeLinejoin="round"
          strokeWidth={1.5}
          d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"
        />
      </svg>
    ),
  },
  {
    id: 'ui',
    label: 'UI Preferences',
    icon: (
      <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path
          strokeLinecap="round"
          strokeLinejoin="round"
          strokeWidth={1.5}
          d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"
        />
        <path
          strokeLinecap="round"
          strokeLinejoin="round"
          strokeWidth={1.5}
          d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"
        />
      </svg>
    ),
  },
  {
    id: 'profiles',
    label: 'Profiles',
    icon: (
      <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path
          strokeLinecap="round"
          strokeLinejoin="round"
          strokeWidth={1.5}
          d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0z"
        />
      </svg>
    ),
  },
];

// Error fallback component for individual tabs
const TabErrorFallback: React.FC<{ tabName: string }> = ({ tabName }) => (
  <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800/50 rounded-xl p-6 text-center">
    <svg
      className="w-10 h-10 mx-auto mb-3 text-red-500 dark:text-red-400"
      fill="none"
      viewBox="0 0 24 24"
      stroke="currentColor"
    >
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth={1.5}
        d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
      />
    </svg>
    <h3 className="text-lg font-medium text-red-700 dark:text-red-300 mb-1">
      {tabName} tab encountered an error
    </h3>
    <p className="text-sm text-red-500 dark:text-red-200/70">
      Please try refreshing the page or switching to another tab.
    </p>
  </div>
);

export const SettingsView: React.FC = () => {
  const fetchProfiles = useSettingsStore((s) => s.fetchProfiles);
  const isLoading = useSettingsStore((s) => s.isLoading);
  const error = useSettingsStore((s) => s.error);
  const clearError = useSettingsStore((s) => s.clearError);
  const lastSaved = useSettingsStore((s) => s.lastSaved);
  const [activeTab, setActiveTab] = useState<TabId>('scan');
  const [dismissedToastMessage, setDismissedToastMessage] = useState<string | null>(null);
  const [initialLoadDone, setInitialLoadDone] = useState(false);

  // Load initial data - only fetchProfiles, which handles both profiles AND settings
  useEffect(() => {
    let cancelled = false;

    const loadData = async () => {
      try {
        await fetchProfiles();
        if (!cancelled) {
          setInitialLoadDone(true);
        }
      } catch (err) {
        console.error('Failed to load settings:', err);
        if (!cancelled) {
          setInitialLoadDone(true);
        }
      }
    };

    loadData();

    return () => {
      cancelled = true;
    };
  }, [fetchProfiles]);

  // Derive raw toast state from store values (before dismissal filtering)
  const rawToastMessage = useMemo(() => {
    if (error) return error;
    if (lastSaved) return 'Settings saved successfully';
    return null;
  }, [error, lastSaved]);

  const toastType: 'success' | 'error' = error ? 'error' : 'success';

  // Only show toast if it hasn't been dismissed
  const toastMessage = rawToastMessage !== dismissedToastMessage ? rawToastMessage : null;

  // Auto-dismiss toast after a delay
  useEffect(() => {
    if (!toastMessage) return;

    const delay = toastType === 'error' ? 5000 : 3000;
    const timer = setTimeout(() => {
      setDismissedToastMessage(toastMessage);
      if (toastType === 'error') {
        clearError();
      }
    }, delay);
    return () => clearTimeout(timer);
  }, [toastMessage, toastType, clearError]);

  // Derive loading state
  const showLoading = !initialLoadDone || isLoading;

  return (
    <div className="space-y-6">
      {/* Toast Notification */}
      {toastMessage && (
        <div
          role="status"
          aria-live="polite"
          className={twMerge(
            clsx(
              'fixed top-4 right-4 z-50 px-4 py-3 rounded-xl shadow-lg',
              'flex items-center gap-3 max-w-sm',
              'animate-slide-in',
              toastType === 'success'
                ? 'bg-green-50 dark:bg-green-900/90 border border-green-200 dark:border-green-700/50 text-green-800 dark:text-green-100'
                : 'bg-red-50 dark:bg-red-900/90 border border-red-200 dark:border-red-700/50 text-red-800 dark:text-red-100'
            )
          )}
        >
          {toastType === 'success' ? (
            <svg className="w-5 h-5 text-green-500 dark:text-green-400 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
          ) : (
            <svg className="w-5 h-5 text-red-500 dark:text-red-400 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
          )}
          <span className="text-sm font-medium">{toastMessage}</span>
          <button
            onClick={() => {
              setDismissedToastMessage(rawToastMessage);
              if (toastType === 'error') clearError();
            }}
            className="ml-2 p-1 rounded-lg hover:bg-white/10 transition-colors"
            aria-label="Dismiss notification"
          >
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
      )}

      {/* Loading Overlay */}
      {showLoading && (
        <div className="flex items-center justify-center py-12">
          <div className="flex items-center gap-3 text-gray-400">
            <svg className="w-5 h-5 animate-spin" fill="none" viewBox="0 0 24 24">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
            </svg>
            <span>Loading settings...</span>
          </div>
        </div>
      )}

      {/* Tab Navigation */}
      <nav aria-label="Settings tabs" className="border-b border-gray-200 dark:border-gray-700/50">
        <div className="flex gap-1 -mb-px">
          {TABS.map((tab) => (
            <button
              key={tab.id}
              type="button"
              onClick={() => setActiveTab(tab.id)}
              aria-selected={activeTab === tab.id}
              role="tab"
              className={twMerge(
                clsx(
                  'flex items-center gap-2 px-4 py-3 text-sm font-medium',
                  'border-b-2 rounded-t-lg transition-all duration-200',
                  'focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-inset',
                  activeTab === tab.id
                    ? 'border-blue-500 text-blue-600 dark:text-blue-400 bg-blue-50 dark:bg-blue-900/20'
                    : 'border-transparent text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-200 hover:border-gray-300 dark:hover:border-gray-600'
                )
              )}
            >
              {tab.icon}
              {tab.label}
            </button>
          ))}
        </div>
      </nav>

      {/* Tab Content - Wrapped in ErrorBoundary for robustness */}
      <div role="tabpanel" aria-labelledby={`${activeTab}-tab`}>
        {activeTab === 'scan' && (
          <ErrorBoundary fallback={<TabErrorFallback tabName="Scan Configuration" />}>
            <ScanConfigSection />
          </ErrorBoundary>
        )}
        {activeTab === 'ui' && (
          <ErrorBoundary fallback={<TabErrorFallback tabName="UI Preferences" />}>
            <UiPreferencesSection />
          </ErrorBoundary>
        )}
        {activeTab === 'profiles' && (
          <ErrorBoundary fallback={<TabErrorFallback tabName="Profiles" />}>
            <ProfileManager />
          </ErrorBoundary>
        )}
      </div>

    </div>
  );
};