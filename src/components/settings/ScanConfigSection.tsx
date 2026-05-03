import React, { useState, useCallback, useMemo } from 'react';
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';
import { useSettingsStore } from '../../stores/settingsStore';
import { Toggle } from '../common/Toggle';
import { SettingsCard, SettingsSection } from './SettingsCard';
import {
  isValidCidr,
  isValidTimeout,
  isValidConcurrentValue,
  createDefaultScanConfig,
  type ScanConfig,
} from '../../types/settings';

const DISCOVERY_METHODS = [
  { id: 'arp', label: 'ARP Discovery', description: 'Local network ARP lookup' },
  { id: 'tcp_probe', label: 'TCP Probe', description: 'TCP handshake detection' },
  { id: 'icmp', label: 'ICMP Ping', description: 'ICMP echo request' },
];

const COMMON_PORTS = [
  21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 5900, 6379, 8080, 8443,
];

const PORT_GROUPS = {
  common: COMMON_PORTS,
  web: [80, 443, 8080, 8443, 8000, 3000],
  database: [3306, 5432, 6379, 27017, 1521, 1433],
  remote: [22, 3389, 5900, 5631, 22],
};

export const ScanConfigSection: React.FC = () => {
  const { settings, updateScanConfig, saveSettings, isSaving } = useSettingsStore();

  // Safe access to scanConfig with fallback to defaults
  const scanConfig = useMemo<ScanConfig>(() => {
    const defaultConfig = createDefaultScanConfig();
    if (!settings?.scanConfig) {
      return defaultConfig;
    }
    // Validate and fill in missing fields
    return {
      defaultCidr: typeof settings.scanConfig.defaultCidr === 'string' ? settings.scanConfig.defaultCidr : defaultConfig.defaultCidr,
      timeoutMs: typeof settings.scanConfig.timeoutMs === 'number' ? settings.scanConfig.timeoutMs : defaultConfig.timeoutMs,
      maxConcurrentHosts: typeof settings.scanConfig.maxConcurrentHosts === 'number' ? settings.scanConfig.maxConcurrentHosts : defaultConfig.maxConcurrentHosts,
      maxConcurrentPorts: typeof settings.scanConfig.maxConcurrentPorts === 'number' ? settings.scanConfig.maxConcurrentPorts : defaultConfig.maxConcurrentPorts,
      scanPortsEnabled: typeof settings.scanConfig.scanPortsEnabled === 'boolean' ? settings.scanConfig.scanPortsEnabled : defaultConfig.scanPortsEnabled,
      selectedPorts: Array.isArray(settings.scanConfig.selectedPorts) ? settings.scanConfig.selectedPorts : defaultConfig.selectedPorts,
      discoveryMethods: Array.isArray(settings.scanConfig.discoveryMethods) ? settings.scanConfig.discoveryMethods : defaultConfig.discoveryMethods,
      retryCount: typeof settings.scanConfig.retryCount === 'number' ? settings.scanConfig.retryCount : defaultConfig.retryCount,
    };
  }, [settings?.scanConfig]);

  const [validationErrors, setValidationErrors] = useState<Record<string, string>>({});
  const [showPortSelector, setShowPortSelector] = useState(false);

  const validateAndUpdate = useCallback(
    (updates: Partial<ScanConfig>) => {
      const newErrors = { ...validationErrors };

      if ('defaultCidr' in updates && updates.defaultCidr !== undefined) {
        if (!isValidCidr(updates.defaultCidr)) {
          newErrors.defaultCidr = 'Invalid CIDR format (e.g., 192.168.1.0/24)';
        } else {
          delete newErrors.defaultCidr;
        }
      }

      if ('timeoutMs' in updates && updates.timeoutMs !== undefined) {
        if (!isValidTimeout(updates.timeoutMs)) {
          newErrors.timeoutMs = 'Timeout must be between 100-30000ms';
        } else {
          delete newErrors.timeoutMs;
        }
      }

      if ('maxConcurrentHosts' in updates && updates.maxConcurrentHosts !== undefined) {
        if (!isValidConcurrentValue(updates.maxConcurrentHosts, 1, 256)) {
          newErrors.maxConcurrentHosts = 'Must be between 1-256';
        } else {
          delete newErrors.maxConcurrentHosts;
        }
      }

      if ('maxConcurrentPorts' in updates && updates.maxConcurrentPorts !== undefined) {
        if (!isValidConcurrentValue(updates.maxConcurrentPorts, 1, 100)) {
          newErrors.maxConcurrentPorts = 'Must be between 1-100';
        } else {
          delete newErrors.maxConcurrentPorts;
        }
      }

      if ('retryCount' in updates && updates.retryCount !== undefined) {
        if (!isValidConcurrentValue(updates.retryCount, 0, 5)) {
          newErrors.retryCount = 'Must be between 0-5';
        } else {
          delete newErrors.retryCount;
        }
      }

      setValidationErrors(newErrors);

      if (Object.keys(newErrors).length === 0) {
        updateScanConfig(updates);
        // Auto-save after validation
        const updatedSettings = {
          ...settings,
          scanConfig: { ...scanConfig, ...updates },
          updatedAt: Date.now(),
        };
        saveSettings(updatedSettings).catch(console.error);
      }
    },
    [validationErrors, updateScanConfig, saveSettings, settings, scanConfig]
  );

  const handleCidrChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    validateAndUpdate({ defaultCidr: e.target.value });
  };

  const handleTimeoutChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    validateAndUpdate({ timeoutMs: Number(e.target.value) });
  };

  const handleMaxHostsChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    validateAndUpdate({ maxConcurrentHosts: Number(e.target.value) });
  };

  const handleMaxPortsChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    validateAndUpdate({ maxConcurrentPorts: Number(e.target.value) });
  };

  const handleRetryCountChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    validateAndUpdate({ retryCount: Number(e.target.value) });
  };

  const handleScanPortsToggle = (checked: boolean) => {
    validateAndUpdate({ scanPortsEnabled: checked });
  };

  const handleDiscoveryMethodToggle = (methodId: string) => {
    const methods = scanConfig.discoveryMethods.includes(methodId)
      ? scanConfig.discoveryMethods.filter((m) => m !== methodId)
      : [...scanConfig.discoveryMethods, methodId];
    validateAndUpdate({ discoveryMethods: methods });
  };

  const handlePortToggle = (port: number) => {
    const ports = scanConfig.selectedPorts.includes(port)
      ? scanConfig.selectedPorts.filter((p) => p !== port)
      : [...scanConfig.selectedPorts, port].sort((a, b) => a - b);
    validateAndUpdate({ selectedPorts: ports });
  };

  const handlePortPreset = (preset: keyof typeof PORT_GROUPS) => {
    validateAndUpdate({ selectedPorts: PORT_GROUPS[preset] });
  };

  return (
    <SettingsCard
      title="Scan Configuration"
      description="Configure network scanning behavior and performance"
    >
      <div className="space-y-6">
        {/* CIDR Input */}
        <SettingsSection title="Default Target Network">
          <div className="max-w-xs">
            <input
              type="text"
              value={scanConfig.defaultCidr}
              onChange={handleCidrChange}
              disabled={isSaving}
              placeholder="192.168.1.0/24"
              aria-label="Default CIDR range"
              aria-invalid={!!validationErrors.defaultCidr}
              aria-describedby={validationErrors.defaultCidr ? 'cidr-error' : undefined}
              className={twMerge(
                clsx(
                  'w-full px-4 py-2.5 bg-gray-900/80 border rounded-xl',
                  'text-gray-100 placeholder-gray-500',
                  'focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent',
                  'disabled:opacity-50 disabled:cursor-not-allowed',
                  'transition-all duration-200 hover:border-gray-500',
                  validationErrors.defaultCidr ? 'border-red-500' : 'border-gray-600/50'
                )
              )}
            />
            {validationErrors.defaultCidr && (
              <p id="cidr-error" className="mt-1.5 text-xs text-red-400" role="alert">
                {validationErrors.defaultCidr}
              </p>
            )}
          </div>
        </SettingsSection>

        {/* Timeout */}
        <SettingsSection title="Timeout (ms)" description="Network timeout per host">
          <div className="max-w-[140px]">
            <input
              type="number"
              value={scanConfig.timeoutMs}
              onChange={handleTimeoutChange}
              disabled={isSaving}
              min={100}
              max={30000}
              step={100}
              aria-label="Timeout in milliseconds"
              aria-invalid={!!validationErrors.timeoutMs}
              className={twMerge(
                clsx(
                  'w-full px-4 py-2.5 bg-gray-900/80 border rounded-xl',
                  'text-gray-100',
                  'focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent',
                  'disabled:opacity-50 disabled:cursor-not-allowed',
                  'transition-all duration-200 hover:border-gray-500',
                  validationErrors.timeoutMs ? 'border-red-500' : 'border-gray-600/50'
                )
              )}
            />
            {validationErrors.timeoutMs && (
              <p className="mt-1.5 text-xs text-red-400" role="alert">
                {validationErrors.timeoutMs}
              </p>
            )}
          </div>
        </SettingsSection>

        {/* Concurrent Limits */}
        <SettingsSection title="Concurrency Limits">
          <div className="flex flex-wrap gap-6">
            <div>
              <label htmlFor="max-hosts" className="block text-sm text-gray-400 mb-1.5">
                Max Concurrent Hosts
              </label>
              <input
                id="max-hosts"
                type="number"
                value={scanConfig.maxConcurrentHosts}
                onChange={handleMaxHostsChange}
                disabled={isSaving}
                min={1}
                max={256}
                aria-label="Maximum concurrent hosts"
                className={twMerge(
                  clsx(
                    'w-28 px-4 py-2.5 bg-gray-900/80 border border-gray-600/50 rounded-xl',
                    'text-gray-100',
                    'focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent',
                    'disabled:opacity-50 disabled:cursor-not-allowed',
                    'transition-all duration-200 hover:border-gray-500'
                  )
                )}
              />
            </div>
            <div>
              <label htmlFor="max-ports" className="block text-sm text-gray-400 mb-1.5">
                Max Concurrent Ports
              </label>
              <input
                id="max-ports"
                type="number"
                value={scanConfig.maxConcurrentPorts}
                onChange={handleMaxPortsChange}
                disabled={isSaving}
                min={1}
                max={100}
                aria-label="Maximum concurrent ports"
                className={twMerge(
                  clsx(
                    'w-28 px-4 py-2.5 bg-gray-900/80 border border-gray-600/50 rounded-xl',
                    'text-gray-100',
                    'focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent',
                    'disabled:opacity-50 disabled:cursor-not-allowed',
                    'transition-all duration-200 hover:border-gray-500'
                  )
                )}
              />
            </div>
          </div>
        </SettingsSection>

        {/* Retry Count */}
        <SettingsSection title="Retry Count" description="Number of retry attempts for failed hosts">
          <div className="max-w-[140px]">
            <input
              type="number"
              value={scanConfig.retryCount}
              onChange={handleRetryCountChange}
              disabled={isSaving}
              min={0}
              max={5}
              aria-label="Retry count"
              className={twMerge(
                clsx(
                  'w-full px-4 py-2.5 bg-gray-900/80 border border-gray-600/50 rounded-xl',
                  'text-gray-100',
                  'focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent',
                  'disabled:opacity-50 disabled:cursor-not-allowed',
                  'transition-all duration-200 hover:border-gray-500'
                )
              )}
            />
          </div>
        </SettingsSection>

        {/* Scan Ports Toggle */}
        <SettingsSection title="Port Scanning">
          <Toggle
            checked={scanConfig.scanPortsEnabled}
            onChange={handleScanPortsToggle}
            label="Enable Port Scanning"
            description="Scan discovered hosts for open ports"
          />
        </SettingsSection>

        {/* Port Selection */}
        {scanConfig.scanPortsEnabled && (
          <SettingsSection title="Selected Ports">
            <div className="space-y-3">
              {/* Port presets */}
              <div className="flex flex-wrap gap-2">
                {Object.keys(PORT_GROUPS).map((preset) => (
                  <button
                    key={preset}
                    type="button"
                    onClick={() => handlePortPreset(preset as keyof typeof PORT_GROUPS)}
                    disabled={isSaving}
                    className={twMerge(
                      clsx(
                        'px-3 py-1.5 text-xs font-medium rounded-lg',
                        'bg-gray-700 hover:bg-gray-600 text-gray-300',
                        'focus:outline-none focus:ring-2 focus:ring-blue-500',
                        'disabled:opacity-50 disabled:cursor-not-allowed',
                        'transition-colors'
                      )
                    )}
                  >
                    {preset.charAt(0).toUpperCase() + preset.slice(1)}
                  </button>
                ))}
              </div>

              {/* Port selector */}
              <div className="relative">
                <button
                  type="button"
                  onClick={() => setShowPortSelector(!showPortSelector)}
                  disabled={isSaving}
                  className={twMerge(
                    clsx(
                      'px-4 py-2 bg-gray-700/50 border border-gray-600/50 rounded-xl',
                      'text-gray-100 text-sm font-medium',
                      'hover:bg-gray-700 hover:border-gray-500',
                      'disabled:opacity-50 disabled:cursor-not-allowed',
                      'focus:outline-none focus:ring-2 focus:ring-blue-500',
                      'transition-all duration-200'
                    )
                  )}
                >
                  {scanConfig.selectedPorts.length} ports selected
                  <svg
                    className="w-4 h-4 inline ml-1.5"
                    fill="none"
                    viewBox="0 0 24 24"
                    stroke="currentColor"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M19 9l-7 7-7-7"
                    />
                  </svg>
                </button>

                {showPortSelector && (
                  <div className="absolute top-full left-0 mt-2 w-96 bg-gradient-to-b from-gray-800 to-gray-800/95 border border-gray-700/50 rounded-xl shadow-xl z-10 p-4">
                    <div className="grid grid-cols-10 gap-1.5 max-h-64 overflow-y-auto">
                      {COMMON_PORTS.map((port) => {
                        const isSelected = scanConfig.selectedPorts.includes(port);
                        return (
                          <button
                            key={port}
                            type="button"
                            onClick={() => handlePortToggle(port)}
                            className={twMerge(
                              clsx(
                                'text-xs p-2 rounded-lg text-center transition-all duration-150',
                                'hover:scale-105 active:scale-95',
                                isSelected
                                  ? 'bg-gradient-to-b from-blue-600 to-blue-700 text-white shadow-md'
                                  : 'bg-gray-700/50 text-gray-400 hover:bg-gray-700 hover:text-gray-200'
                              )
                            )}
                          >
                            {port}
                          </button>
                        );
                      })}
                    </div>
                  </div>
                )}
              </div>

              {/* Selected ports display */}
              <div className="flex flex-wrap gap-1.5 mt-2">
                {scanConfig.selectedPorts.slice(0, 12).map((port) => (
                  <span
                    key={port}
                    className="inline-flex items-center px-2 py-1 bg-blue-900/30 text-blue-400 text-xs rounded-md"
                  >
                    {port}
                  </span>
                ))}
                {scanConfig.selectedPorts.length > 12 && (
                  <span className="text-xs text-gray-500 pl-1">
                    +{scanConfig.selectedPorts.length - 12} more
                  </span>
                )}
              </div>
            </div>
          </SettingsSection>
        )}

        {/* Discovery Methods */}
        <SettingsSection title="Discovery Methods" description="Methods used to discover devices on the network">
          <div className="space-y-3">
            {DISCOVERY_METHODS.map((method) => (
              <Toggle
                key={method.id}
                checked={scanConfig.discoveryMethods.includes(method.id)}
                onChange={() => handleDiscoveryMethodToggle(method.id)}
                label={method.label}
                description={method.description}
              />
            ))}
          </div>
        </SettingsSection>
      </div>
    </SettingsCard>
  );
};