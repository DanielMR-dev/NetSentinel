import React, { useState, useMemo, useCallback, useEffect } from 'react';
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';
import { useScanStore } from '../../stores/scanStore';
import { useCapabilitiesStore } from '../../stores/capabilitiesStore';
import { useSettingsStore } from '../../stores/settingsStore';
import { Button } from '../common/Button';
import { TimingTemplateSelector } from './TimingTemplateSelector';
import { ScanTypeSelector } from './ScanTypeSelector';

// Common TCP ports with service labels for the chip UI
const COMMON_TCP_PORTS: { port: number; label: string }[] = [
  { port: 21, label: 'FTP' },
  { port: 22, label: 'SSH' },
  { port: 23, label: 'Telnet' },
  { port: 25, label: 'SMTP' },
  { port: 53, label: 'DNS' },
  { port: 80, label: 'HTTP' },
  { port: 110, label: 'POP3' },
  { port: 143, label: 'IMAP' },
  { port: 443, label: 'HTTPS' },
  { port: 445, label: 'SMB' },
  { port: 993, label: 'IMAPS' },
  { port: 995, label: 'POP3S' },
  { port: 3306, label: 'MySQL' },
  { port: 3389, label: 'RDP' },
  { port: 5432, label: 'PgSQL' },
  { port: 5900, label: 'VNC' },
  { port: 6379, label: 'Redis' },
  { port: 8080, label: '8080' },
  { port: 8443, label: '8443' },
];

// Common UDP ports with service labels for the chip UI
const COMMON_UDP_PORTS: { port: number; label: string }[] = [
  { port: 53, label: 'DNS' },
  { port: 67, label: 'DHCP' },
  { port: 68, label: 'DHCP' },
  { port: 69, label: 'TFTP' },
  { port: 123, label: 'NTP' },
  { port: 161, label: 'SNMP' },
  { port: 162, label: 'SNMP Trap' },
  { port: 500, label: 'IKE' },
  { port: 514, label: 'Syslog' },
  { port: 1900, label: 'SSDP' },
  { port: 5353, label: 'mDNS' },
  { port: 5355, label: 'LLMNR' },
  { port: 4789, label: 'VXLAN' },
];

// Default UDP ports for scan
const DEFAULT_UDP_PORTS = [53, 67, 68, 69, 123, 161, 162, 500, 514, 1900, 5353, 5355, 4789];

// TCP port groups for preset buttons
const TCP_PORT_PRESETS: Record<string, number[]> = {
  common: [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 5900],
  web: [80, 443, 8080, 8443],
  database: [3306, 5432, 6379, 27017],
};

// UDP port groups for preset buttons
const UDP_PORT_PRESETS: Record<string, number[]> = {
  common: DEFAULT_UDP_PORTS,
  infrastructure: [53, 67, 68, 123, 161, 162],
  discovery: [1900, 5353, 5355],
};

/** Parse a port range string like "8000-8100" or single port "8080" into an array of port numbers */
function parsePortInput(input: string): number[] {
  const trimmed = input.trim();
  if (!trimmed) return [];

  const rangeMatch = trimmed.match(/^(\d+)\s*-\s*(\d+)$/);
  if (rangeMatch) {
    const start = Number(rangeMatch[1]);
    const end = Number(rangeMatch[2]);
    if (
      Number.isNaN(start) || Number.isNaN(end) ||
      start < 1 || end > 65535 || start > end ||
      end - start > 1000
    ) {
      return [];
    }
    const ports: number[] = [];
    for (let p = start; p <= end; p++) {
      ports.push(p);
    }
    return ports;
  }

  const single = Number(trimmed);
  if (Number.isNaN(single) || single < 1 || single > 65535) return [];
  return [single];
}

export const ScanConfigPanel: React.FC = () => {
  const cidr = useScanStore((s) => s.cidr);
  const setCidr = useScanStore((s) => s.setCidr);
  const scanPorts = useScanStore((s) => s.scanPorts);
  const setScanPorts = useScanStore((s) => s.setScanPorts);
  const selectedPorts = useScanStore((s) => s.selectedPorts);
  const setSelectedPorts = useScanStore((s) => s.setSelectedPorts);
  const timeoutMs = useScanStore((s) => s.timeoutMs);
  const setTimeoutMs = useScanStore((s) => s.setTimeoutMs);
  const isScanning = useScanStore((s) => s.isScanning);
  const isPaused = useScanStore((s) => s.isPaused);
  const startScan = useScanStore((s) => s.startScan);
  const stopScan = useScanStore((s) => s.stopScan);
  const pauseScan = useScanStore((s) => s.pauseScan);
  const resumeScan = useScanStore((s) => s.resumeScan);
  const scanStatus = useScanStore((s) => s.scanStatus);
  const error = useScanStore((s) => s.error);
  const clearError = useScanStore((s) => s.clearError);

  const scanType = useScanStore((s) => s.scanType);
  const capabilities = useCapabilitiesStore((s) => s.capabilities);
  const settings = useSettingsStore((s) => s.settings);
  const discoveryMethods = settings.scanConfig.discoveryMethods;
  const syncFromSettings = useScanStore((s) => s.syncFromSettings);

  // Switch between TCP and UDP port lists based on scan type
  const isUdpScan = scanType === 'udp';
  const commonPorts = isUdpScan ? COMMON_UDP_PORTS : COMMON_TCP_PORTS;
  const portPresets = isUdpScan ? UDP_PORT_PRESETS : TCP_PORT_PRESETS;

  // Sync scan config from the active settings profile on profile change
  useEffect(() => {
    if (settings?.scanConfig && !isScanning) {
      syncFromSettings(settings.scanConfig);
    }
    // Only re-sync when the profile ID changes, not on every settings edit
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [settings?.id]);

  // Check if ICMP is configured but unavailable
  const icmpUnavailable = useMemo(() => {
    if (capabilities === null) return false;
    const icmpConfigured = discoveryMethods.includes('icmp');
    const icmpAvailable = capabilities.capabilities.includes('icmp_ping');
    return icmpConfigured && !icmpAvailable;
  }, [capabilities, discoveryMethods]);

  const [showPortSelector, setShowPortSelector] = useState(false);
  const [customPortInput, setCustomPortInput] = useState('');

  const selectedPortsSet = useMemo(() => new Set(selectedPorts), [selectedPorts]);

  // Ports that are selected but not in the common ports list (custom ports)
  const customSelectedPorts = useMemo(() => {
    const commonPortNumbers = new Set(commonPorts.map((c) => c.port));
    return selectedPorts.filter((p) => !commonPortNumbers.has(p)).sort((a, b) => a - b);
  }, [selectedPorts, commonPorts]);

  const handleCidrChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    setCidr(e.target.value);
  }, [setCidr]);

  const handleTimeoutChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    setTimeoutMs(Number(e.target.value));
  }, [setTimeoutMs]);

  const handlePresetClick = useCallback((preset: string) => {
    const ports = portPresets[preset];
    if (ports) {
      setSelectedPorts(ports);
    }
  }, [setSelectedPorts, portPresets]);

  const handleTogglePort = useCallback((port: number) => {
    const current = useScanStore.getState().selectedPorts;
    if (current.includes(port)) {
      setSelectedPorts(current.filter((p) => p !== port));
    } else {
      setSelectedPorts([...current, port].sort((a, b) => a - b));
    }
  }, [setSelectedPorts]);

  const handleRemovePort = useCallback((port: number) => {
    const current = useScanStore.getState().selectedPorts;
    setSelectedPorts(current.filter((p) => p !== port));
  }, [setSelectedPorts]);

  const handleAddCustomPort = useCallback(() => {
    const parsed = parsePortInput(customPortInput);
    if (parsed.length === 0) return;
    const current = useScanStore.getState().selectedPorts;
    const existing = new Set(current);
    const merged = [...current];
    for (const p of parsed) {
      if (!existing.has(p)) {
        merged.push(p);
        existing.add(p);
      }
    }
    merged.sort((a, b) => a - b);
    setSelectedPorts(merged);
    setCustomPortInput('');
  }, [customPortInput, setSelectedPorts]);

  const handleCustomPortKeyDown = useCallback((e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      handleAddCustomPort();
    }
  }, [handleAddCustomPort]);

  const handleStartStop = useCallback(() => {
    if (isScanning || isPaused) {
      stopScan();
    } else {
      startScan();
    }
  }, [isScanning, isPaused, stopScan, startScan]);

  const handlePauseResume = useCallback(() => {
    if (isPaused) {
      resumeScan();
    } else {
      pauseScan();
    }
  }, [isPaused, resumeScan, pauseScan]);

  return (
    <div className="bg-gradient-to-b from-gray-50 to-gray-100 dark:from-gray-800 dark:to-gray-800/95 rounded-2xl border border-gray-200 dark:border-gray-700/50 shadow-card p-5 space-y-4">
      {/* Scan Type & Timing Template Selectors */}
      <ScanTypeSelector />
      <TimingTemplateSelector />

      {/* Error Display */}
      {error && (
        <div
          role="alert"
          className="mb-4 p-3 bg-red-50 dark:bg-red-900/30 border border-red-200 dark:border-red-800/50 rounded-xl flex items-center justify-between"
        >
          <span className="text-red-700 dark:text-red-300">{error}</span>
          <button
            onClick={clearError}
            className="text-red-500 dark:text-red-400 hover:text-red-700 dark:hover:text-red-300 p-1 rounded-lg hover:bg-red-100 dark:hover:bg-red-900/30 transition-colors"
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
          <label htmlFor="cidr-input" className="block text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2">
            Target Network <span className="text-gray-400 dark:text-gray-500 font-normal">(CIDR)</span>
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
                'w-full px-4 py-2.5 bg-white dark:bg-gray-900/80 border border-gray-300 dark:border-gray-600/50 rounded-xl',
                'text-gray-900 dark:text-gray-100 placeholder-gray-400 dark:placeholder-gray-500',
                'focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent',
                'disabled:opacity-50 disabled:cursor-not-allowed',
                'transition-all duration-200 hover:border-gray-400 dark:hover:border-gray-500'
              )
            )}
          />
        </div>

        {/* Timeout Input */}
        <div className="w-36">
          <label htmlFor="timeout-input" className="block text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2">
            Timeout <span className="text-gray-400 dark:text-gray-500 font-normal">(ms)</span>
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
                'w-full px-4 py-2.5 bg-white dark:bg-gray-900/80 border border-gray-300 dark:border-gray-600/50 rounded-xl',
                'text-gray-900 dark:text-gray-100',
                'focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent',
                'disabled:opacity-50 disabled:cursor-not-allowed',
                'transition-all duration-200 hover:border-gray-400 dark:hover:border-gray-500'
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
                'px-4 py-2.5 bg-gray-100 dark:bg-gray-700/50 border border-gray-300 dark:border-gray-600/50 rounded-xl',
                'text-gray-900 dark:text-gray-100 text-sm font-semibold',
                'hover:bg-gray-200 dark:hover:bg-gray-700 hover:border-gray-400 dark:hover:border-gray-500 transition-all duration-200',
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
            <div className="absolute top-full left-0 mt-2 w-96 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700/50 rounded-xl shadow-xl z-10 p-4">
              {/* Preset buttons */}
              <div className="flex gap-2 mb-3">
                {Object.keys(portPresets).map((name) => (
                  <button
                    key={name}
                    type="button"
                    onClick={() => handlePresetClick(name)}
                    className="px-3 py-1.5 text-xs bg-gray-100 dark:bg-gray-700 hover:bg-gray-200 dark:hover:bg-gray-600 rounded-lg text-gray-700 dark:text-gray-300 font-medium capitalize transition-colors"
                  >
                    {name}
                  </button>
                ))}
              </div>

              {/* Common port chips */}
              <div className="flex flex-wrap gap-1.5 mb-3">
                {commonPorts.map(({ port, label }) => {
                  const isSelected = selectedPortsSet.has(port);
                  return (
                    <button
                      key={port}
                      type="button"
                      onClick={() => handleTogglePort(port)}
                      className={twMerge(
                        clsx(
                          'px-2 py-1 rounded-lg text-xs font-medium transition-all duration-150',
                          'hover:scale-105 active:scale-95',
                          isSelected
                            ? isUdpScan
                              ? 'bg-gradient-to-b from-purple-600 to-purple-700 text-white shadow-md'
                              : 'bg-gradient-to-b from-blue-600 to-blue-700 text-white shadow-md'
                            : 'bg-gray-100 dark:bg-gray-700/50 text-gray-600 dark:text-gray-400 hover:bg-gray-200 dark:hover:bg-gray-700 hover:text-gray-900 dark:hover:text-gray-200'
                        )
                      )}
                    >
                      {port} {label}
                    </button>
                  );
                })}
              </div>

              {/* Custom port input */}
              <div className="flex gap-2 mb-3">
                <input
                  type="text"
                  value={customPortInput}
                  onChange={(e) => setCustomPortInput(e.target.value)}
                  onKeyDown={handleCustomPortKeyDown}
                  placeholder="e.g. 8080 or 8000-8100"
                  className={twMerge(
                    clsx(
                      'flex-1 px-3 py-1.5 bg-white dark:bg-gray-900/80 border border-gray-300 dark:border-gray-600/50 rounded-lg',
                      'text-gray-900 dark:text-gray-100 text-xs placeholder-gray-400 dark:placeholder-gray-500',
                      'focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent'
                    )
                  )}
                />
                <button
                  type="button"
                  onClick={handleAddCustomPort}
                  className="px-3 py-1.5 text-xs bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-medium transition-colors"
                >
                  Add
                </button>
              </div>

              {/* Selected ports as removable chips */}
              {selectedPorts.length > 0 && (
                <div>
                  <div className="text-xs text-gray-500 dark:text-gray-500 mb-1.5 font-medium">
                    Selected ({selectedPorts.length}):
                  </div>
                  <div className="flex flex-wrap gap-1 max-h-24 overflow-y-auto">
                    {customSelectedPorts.map((port) => (
                      <span
                        key={port}
                        className={twMerge(
                          clsx(
                            'inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-xs font-medium',
                            isUdpScan
                              ? 'bg-purple-50 dark:bg-purple-900/50 text-purple-700 dark:text-purple-300 border border-purple-200 dark:border-purple-700/50'
                              : 'bg-blue-50 dark:bg-blue-900/50 text-blue-700 dark:text-blue-300 border border-blue-200 dark:border-blue-700/50'
                          )
                        )}
                      >
                        {port}
                        <button
                          type="button"
                          onClick={() => handleRemovePort(port)}
                          className={twMerge(
                            clsx(
                              'transition-colors',
                              isUdpScan
                                ? 'text-purple-500 dark:text-purple-400 hover:text-purple-700 dark:hover:text-purple-200'
                                : 'text-blue-500 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-200'
                            )
                          )}
                          aria-label={`Remove port ${port}`}
                        >
                          &times;
                        </button>
                      </span>
                    ))}
                    {customSelectedPorts.length === 0 && (
                      <span className="text-xs text-gray-400 dark:text-gray-500 italic">
                        Toggle ports above or add custom ones
                      </span>
                    )}
                  </div>
                </div>
              )}
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
                  'bg-gray-300 dark:bg-gray-700 peer-checked:bg-gradient-to-r peer-checked:from-blue-600 peer-checked:to-blue-500',
                  'peer-focus:outline-none peer-focus:ring-2 peer-focus:ring-blue-500 peer-focus:ring-offset-2 peer-focus:ring-offset-white dark:peer-focus:ring-offset-gray-900',
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
            <span className="ml-3 text-sm text-gray-700 dark:text-gray-300 font-medium">Scan Ports</span>
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
          className="mt-3 flex items-center gap-2 px-3 py-2 bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-700/30 rounded-lg"
        >
          <svg
            className="w-4 h-4 text-amber-500 dark:text-amber-400 flex-shrink-0"
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
          <span className="text-xs text-amber-700 dark:text-amber-300">
            ICMP ping is enabled in settings but unavailable without elevated privileges.
            Discovery will fall back to available methods.
          </span>
        </div>
      )}

      {/* Scan Status Display */}
      {isScanning && (
        <div className="mt-4 flex items-center gap-2 text-sm text-gray-500 dark:text-gray-400">
          <span className="w-2 h-2 rounded-full bg-blue-500 animate-pulse" />
          Status: <span className="text-blue-600 dark:text-blue-400 font-semibold capitalize">{scanStatus}</span>
        </div>
      )}
    </div>
  );
};
