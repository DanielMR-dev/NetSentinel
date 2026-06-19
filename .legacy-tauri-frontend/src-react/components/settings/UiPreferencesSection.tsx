import React, { useCallback, useState, useMemo } from 'react';
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';
import { useSettingsStore } from '../../stores/settingsStore';
import { Toggle } from '../common/Toggle';
import { SettingsCard, SettingsSection } from './SettingsCard';
import {
  isValidRefreshRate,
  createDefaultUiPreferences,
  type UiPreferences,
} from '../../types/settings';

const REFRESH_RATE_PRESETS = [
  { value: 1000, label: '1s' },
  { value: 2000, label: '2s' },
  { value: 5000, label: '5s' },
  { value: 10000, label: '10s' },
];

export const UiPreferencesSection: React.FC = () => {
  const { settings, updateUiPreferences, saveSettings, isSaving } = useSettingsStore();

  // Safe access to uiPreferences with fallback to defaults
  const uiPreferences = useMemo<UiPreferences>(() => {
    const defaultPrefs = createDefaultUiPreferences();
    if (!settings?.uiPreferences) {
      return defaultPrefs;
    }
    // Validate and fill in missing fields
    return {
      refreshRateMs: typeof settings.uiPreferences.refreshRateMs === 'number'
        ? settings.uiPreferences.refreshRateMs
        : defaultPrefs.refreshRateMs,
      autoRefresh: typeof settings.uiPreferences.autoRefresh === 'boolean'
        ? settings.uiPreferences.autoRefresh
        : defaultPrefs.autoRefresh,
      showAdvancedOptions: typeof settings.uiPreferences.showAdvancedOptions === 'boolean'
        ? settings.uiPreferences.showAdvancedOptions
        : defaultPrefs.showAdvancedOptions,
      confirmBeforeScan: typeof settings.uiPreferences.confirmBeforeScan === 'boolean'
        ? settings.uiPreferences.confirmBeforeScan
        : defaultPrefs.confirmBeforeScan,
    };
  }, [settings?.uiPreferences]);

  const [validationError, setValidationError] = useState<string | null>(null);

  const validateAndUpdate = useCallback(
    (updates: Partial<UiPreferences>) => {
      if ('refreshRateMs' in updates && updates.refreshRateMs !== undefined) {
        if (!isValidRefreshRate(updates.refreshRateMs)) {
          setValidationError('Refresh rate must be between 500-10000ms');
          return;
        }
        setValidationError(null);
      }

      updateUiPreferences(updates);

      // Auto-save
      const updatedSettings = {
        ...settings,
        uiPreferences: { ...uiPreferences, ...updates },
        updatedAt: Date.now(),
      };
      saveSettings(updatedSettings).catch(console.error);
    },
    [updateUiPreferences, saveSettings, settings, uiPreferences]
  );

  const handleRefreshRateChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    validateAndUpdate({ refreshRateMs: Number(e.target.value) });
  };

  const handleRefreshRatePreset = (value: number) => {
    validateAndUpdate({ refreshRateMs: value });
  };

  const handleAutoRefreshToggle = (checked: boolean) => {
    validateAndUpdate({ autoRefresh: checked });
  };

  const handleAdvancedOptionsToggle = (checked: boolean) => {
    validateAndUpdate({ showAdvancedOptions: checked });
  };

  const handleConfirmBeforeScanToggle = (checked: boolean) => {
    validateAndUpdate({ confirmBeforeScan: checked });
  };

  return (
    <SettingsCard
      title="UI Preferences"
      description="Customize the user interface behavior"
    >
      <div className="space-y-6">
        {/* Refresh Rate */}
        <SettingsSection
          title="Dashboard Refresh Rate"
          description="How often the dashboard updates with new data"
        >
          <div className="space-y-3">
            <div className="flex flex-wrap gap-2">
              {REFRESH_RATE_PRESETS.map((preset) => (
                <button
                  key={preset.value}
                  type="button"
                  onClick={() => handleRefreshRatePreset(preset.value)}
                  disabled={isSaving}
                  className={twMerge(
                    clsx(
                      'px-4 py-2 text-sm font-medium rounded-lg',
                      'transition-all duration-200',
                      uiPreferences.refreshRateMs === preset.value
                        ? 'bg-gradient-to-b from-blue-600 to-blue-700 text-white shadow-md'
                        : 'bg-gray-700 hover:bg-gray-600 text-gray-300',
                      'focus:outline-none focus:ring-2 focus:ring-blue-500',
                      'disabled:opacity-50 disabled:cursor-not-allowed'
                    )
                  )}
                >
                  {preset.label}
                </button>
              ))}
            </div>

            <div className="max-w-[180px]">
              <input
                type="number"
                value={uiPreferences.refreshRateMs}
                onChange={handleRefreshRateChange}
                disabled={isSaving}
                min={500}
                max={10000}
                step={100}
                aria-label="Custom refresh rate in milliseconds"
                aria-invalid={!!validationError}
                aria-describedby={validationError ? 'refresh-error' : undefined}
                className={twMerge(
                  clsx(
                    'w-full px-4 py-2.5 bg-gray-900/80 border rounded-xl',
                    'text-gray-100',
                    'focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent',
                    'disabled:opacity-50 disabled:cursor-not-allowed',
                    'transition-all duration-200 hover:border-gray-500',
                    validationError ? 'border-red-500' : 'border-gray-600/50'
                  )
                )}
              />
              {validationError && (
                <p id="refresh-error" className="mt-1.5 text-xs text-red-400" role="alert">
                  {validationError}
                </p>
              )}
            </div>
          </div>
        </SettingsSection>

        {/* Auto Refresh Toggle */}
        <SettingsSection
          title="Auto Refresh"
          description="Automatically refresh scan results as devices are discovered"
        >
          <Toggle
            checked={uiPreferences.autoRefresh}
            onChange={handleAutoRefreshToggle}
            disabled={isSaving}
          />
        </SettingsSection>

        {/* Show Advanced Options Toggle */}
        <SettingsSection
          title="Show Advanced Options"
          description="Display advanced configuration options in the scan panel"
        >
          <Toggle
            checked={uiPreferences.showAdvancedOptions}
            onChange={handleAdvancedOptionsToggle}
            disabled={isSaving}
          />
        </SettingsSection>

        {/* Confirm Before Scan Toggle */}
        <SettingsSection
          title="Confirm Before Scan"
          description="Show a confirmation dialog before starting a new scan"
        >
          <Toggle
            checked={uiPreferences.confirmBeforeScan}
            onChange={handleConfirmBeforeScanToggle}
            disabled={isSaving}
          />
        </SettingsSection>
      </div>
    </SettingsCard>
  );
};