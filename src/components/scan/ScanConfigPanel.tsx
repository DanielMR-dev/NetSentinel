import React, { useState, useMemo } from 'react';
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';
import { useScanStore } from '../../stores/scanStore';
import { useCapabilitiesStore } from '../../stores/capabilitiesStore';
import { useSettingsStore } from '../../stores/settingsStore';
import { Button } from '../common/Button';

// Common port groups for quick selection
const PORT_PRESETS = {
  common: [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 5900],
  web: [80, 443, 8080, 8443],
  database: [3306, 5432, 6379, 27017],
};

export const ScanConfigPanel: React.FC = () => {
  const {
    cidr,
    setCidr,
    scanPorts,
    setScanPorts,
    selectedPorts,
    setSelectedPorts,
    timeoutMs,
    setTimeoutMs,
    isScanning,
    isPaused,
    startScan,
    stopScan,
    pauseScan,
    resumeScan,
    scanStatus,
    error,
    clearError,
  } = useScanStore();

  const capabilities = useCapabilitiesStore((s) => s.capabilities);
  const discoveryMethods = useSettingsStore((s) => s.settings.scanConfig.discoveryMethods);

  // Check if ICMP is configured but unavailable
  const icmpUnavailable = useMemo(() => {
    if (capabilities === null) return false;
    const icmpConfigured = discoveryMethods.includes('icmp');
    const icmpAvailable = capabilities.capabilities.includes('icmp_ping');
    return icmpConfigured && !icmpAvailable;
  }, [capabilities, discoveryMethods]);

  const [showPortSelector, setShowPortSelector] = useState(false);

  const handleCidrChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setCidr(e.target.value);
  };

  const handleTimeoutChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setTimeoutMs(Number(e.target.value));
  };

  const handlePresetClick = (preset: keyof typeof PORT_PRESETS) => {
    setSelectedPorts(PORT_PRESETS[preset]);
  };

  const handleTogglePort = (port: number) => {
    if (selectedPorts.includes(port)) {
      setSelectedPorts(selectedPorts.filter((p) => p !== port));
    } else {
      setSelectedPorts([...selectedPorts, port].sort((a, b) => a - b));
    }
  };

  const handleStartStop = () => {
    if (isScanning || isPaused) {
      stopScan();
    } else {
      startScan();
    }
  };

  const handlePauseResume = () => {
    if (isPaused) {
      resumeScan();
    } else {
      pauseScan();
    }
  };

  return (
    <div className="bg-gradient-to-b from-gray-800 to-gray-800/95 rounded-2xl border border-gray-700/50 shadow-card p-5">
      {/* Error Display */}
      {error && (
        <div
          role="alert"
          className="mb-4 p-3 bg-red-900/30 border border-red-800/50 rounded-xl flex items-center justify-between"
        >
          <span className="text-red-300">{error}</span>
          <button
            onClick={clearError}
            className="text-red-400 hover:text-red-300 p-1 rounded-lg hover:bg-red-900/30 transition-colors"
            aria-label="Dismiss error"
          >
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
      )}

      <div className="flex flex-wrap gap-4 items-end">
        {/* CIDR Input */}
        <div className="flex-1 min-w-[200px]">
          <label htmlFor="cidr-input" className="block text-sm font-semibold text-gray-300 mb-2">
            Target Network <span className="text-gray-500 font-normal">(CIDR)</span>
          </label>
          <input
            id="cidr-input"
            type="text"
            value={cidr}
            onChange={handleCidrChange}
            disabled={isScanning}
            placeholder="192.168.1.0/24"
            className={twMerge(
              clsx(
                'w-full px-4 py-2.5 bg-gray-900/80 border border-gray-600/50 rounded-xl',
                'text-gray-100 placeholder-gray-500',
                'focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent',
                'disabled:opacity-50 disabled:cursor-not-allowed',
                'transition-all duration-200 hover:border-gray-500'
              )
            )}
          />
        </div>

        {/* Timeout Input */}
        <div className="w-36">
          <label htmlFor="timeout-input" className="block text-sm font-semibold text-gray-300 mb-2">
            Timeout <span className="text-gray-500 font-normal">(ms)</span>
          </label>
          <input
            id="timeout-input"
            type="number"
            value={timeoutMs}
            onChange={handleTimeoutChange}
            disabled={isScanning}
            min={100}
            max={10000}
            step={100}
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

        {/* Port Options */}
        <div className="relative">
          <button
            type="button"
            onClick={() => setShowPortSelector(!showPortSelector)}
            disabled={isScanning || !scanPorts}
            className={twMerge(
              clsx(
                'px-4 py-2.5 bg-gray-700/50 border border-gray-600/50 rounded-xl',
                'text-gray-100 text-sm font-semibold',
                'hover:bg-gray-700 hover:border-gray-500 transition-all duration-200',
                'disabled:opacity-50 disabled:cursor-not-allowed',
                'focus:outline-none focus:ring-2 focus:ring-blue-500'
              )
            )}
          >
            Ports ({selectedPorts.length})
            <svg className="w-4 h-4 inline ml-1.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
            </svg>
          </button>

          {showPortSelector && (
            <div className="absolute top-full left-0 mt-2 w-80 bg-gradient-to-b from-gray-800 to-gray-800/95 border border-gray-700/50 rounded-xl shadow-xl z-10 p-4">
              <div className="flex gap-2 mb-3">
                {Object.entries(PORT_PRESETS).map(([name]) => (
                  <button
                    key={name}
                    onClick={() => handlePresetClick(name as keyof typeof PORT_PRESETS)}
                    className="px-3 py-1.5 text-xs bg-gray-700 hover:bg-gray-600 rounded-lg text-gray-300 font-medium transition-colors"
                  >
                    {name}
                  </button>
                ))}
              </div>
              <div className="grid grid-cols-8 gap-1 max-h-48 overflow-y-auto">
                {[...Array(1024)].map((_, i) => {
                  const port = i + 1;
                  const isSelected = selectedPorts.includes(port);
                  return (
                    <button
                      key={port}
                      onClick={() => handleTogglePort(port)}
                      className={twMerge(
                        clsx(
                          'text-xs p-1.5 rounded-lg text-center transition-all duration-150',
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

        {/* Scan Ports Toggle */}
        <div className="flex items-center">
          <label className="flex items-center cursor-pointer">
            <input
              type="checkbox"
              checked={scanPorts}
              onChange={(e) => setScanPorts(e.target.checked)}
              disabled={isScanning}
              className="sr-only peer"
            />
            <div
              className={twMerge(
                clsx(
                  'w-11 h-6 rounded-full transition-all duration-300 relative',
                  'bg-gray-700 peer-checked:bg-gradient-to-r peer-checked:from-blue-600 peer-checked:to-blue-500',
                  'peer-focus:outline-none peer-focus:ring-2 peer-focus:ring-blue-500 peer-focus:ring-offset-2 peer-focus:ring-offset-gray-900',
                  isScanning && 'opacity-50'
                )
              )}
            >
              <div
                className={twMerge(
                  clsx(
                    'absolute left-0.5 top-0.5 w-5 h-5 bg-white rounded-full shadow-md transition-transform duration-300',
                    'peer-checked:translate-x-5'
                  )
                )}
              />
            </div>
            <span className="ml-3 text-sm text-gray-300 font-medium">Scan Ports</span>
          </label>
        </div>

        {/* Control Buttons */}
        <div className="flex gap-3">
          {/* Start/Stop Button */}
          <Button
            onClick={handleStartStop}
            variant={isScanning || isPaused ? 'danger' : 'primary'}
            size="md"
            aria-label={isScanning || isPaused ? 'Stop scan' : 'Start scan'}
          >
            {isScanning || isPaused ? (
              <>
                <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24">
                  <path d="M6 6h12v12H6z" />
                </svg>
                Stop
              </>
            ) : (
              <>
                <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24">
                  <path d="M8 5v14l11-7z" />
                </svg>
                Start Scan
              </>
            )}
          </Button>

          {/* Pause/Resume Button */}
          <Button
            onClick={handlePauseResume}
            disabled={!isScanning && !isPaused}
            variant="secondary"
            size="md"
            aria-label={isPaused ? 'Resume scan' : 'Pause scan'}
          >
            {isPaused ? (
              <>
                <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24">
                  <path d="M8 5v14l11-7z" />
                </svg>
                Resume
              </>
            ) : (
              <>
                <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24">
                  <path d="M6 19h4V5H6v14zm8-14v14h4V5h-4z" />
                </svg>
                Pause
              </>
            )}
          </Button>
        </div>
      </div>

      {/* ICMP Unavailable Warning */}
      {icmpUnavailable && (
        <div
          role="status"
          className="mt-3 flex items-center gap-2 px-3 py-2 bg-amber-900/20 border border-amber-700/30 rounded-lg"
        >
          <svg
            className="w-4 h-4 text-amber-400 flex-shrink-0"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
            aria-hidden="true"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M12 9v2m0 4h.01M10.29 3.86l-8.58 14.86A1 1 0 002.58 20h18.84a1 1 0 00.87-1.5L13.71 3.86a1 1 0 00-1.72 0z"
            />
          </svg>
          <span className="text-xs text-amber-300">
            ICMP ping is enabled in settings but unavailable without elevated privileges.
            Discovery will fall back to available methods.
          </span>
        </div>
      )}

      {/* Scan Status Display */}
      {isScanning && (
        <div className="mt-4 flex items-center gap-2 text-sm text-gray-400">
          <span className="w-2 h-2 rounded-full bg-blue-500 animate-pulse" />
          Status: <span className="text-blue-400 font-semibold capitalize">{scanStatus}</span>
        </div>
      )}
    </div>
  );
};
