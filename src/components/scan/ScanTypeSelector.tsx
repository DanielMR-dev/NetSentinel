import React, { useCallback, useMemo } from 'react';
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';
import { useScanStore } from '../../stores/scanStore';
import { useCapabilitiesStore } from '../../stores/capabilitiesStore';
import type { ScanType } from '../../types/device';

interface ScanTypeOption {
  id: ScanType;
  label: string;
  description: string;
}

const SCAN_TYPE_OPTIONS: ScanTypeOption[] = [
  {
    id: 'connect',
    label: 'TCP Connect',
    description: 'Full TCP handshake. Reliable, no privileges required.',
  },
  {
    id: 'syn',
    label: 'SYN Stealth',
    description: 'Half-open scan. Faster, harder to detect. Requires elevated privileges.',
  },
  {
    id: 'udp',
    label: 'UDP Scan',
    description: 'ICMP-based UDP port discovery. DNS, DHCP, NTP, SNMP, and more.',
  },
];

export const ScanTypeSelector: React.FC = () => {
  const scanType = useScanStore((s) => s.scanType);
  const setScanType = useScanStore((s) => s.setScanType);
  const isScanning = useScanStore((s) => s.isScanning);
  const privilegeStatus = useCapabilitiesStore((s) => s.privilegeStatus);

  const synUnavailable = useMemo(() => {
    return privilegeStatus !== null && !privilegeStatus.synScanAvailable;
  }, [privilegeStatus]);

  const handleSelect = useCallback(
    (type: ScanType) => {
      if (!isScanning) {
        setScanType(type);
      }
    },
    [isScanning, setScanType]
  );

  return (
    <div className="space-y-2">
      <label className="block text-sm font-semibold text-gray-700 dark:text-gray-300">
        Scan Type
      </label>
      <div className="flex gap-3" role="radiogroup" aria-label="Scan type selection">
        {SCAN_TYPE_OPTIONS.map((option) => {
          const isSelected = scanType === option.id;
          const isDisabled = isScanning || (option.id === 'syn' && synUnavailable);

          return (
            <button
              key={option.id}
              type="button"
              role="radio"
              aria-checked={isSelected}
              disabled={isDisabled}
              onClick={() => handleSelect(option.id)}
              title={option.id === 'syn' && synUnavailable ? 'SYN scan requires elevated privileges' : option.description}
              className={twMerge(
                clsx(
                  'flex-1 px-4 py-3 rounded-xl border-2 text-left transition-all duration-200',
                  'focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-1 focus:ring-offset-white dark:focus:ring-offset-gray-900',
                  'disabled:opacity-50 disabled:cursor-not-allowed',
                  isSelected
                    ? 'border-blue-500 bg-blue-50 dark:bg-blue-900/20 text-blue-700 dark:text-blue-300'
                    : 'border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 text-gray-700 dark:text-gray-300 hover:border-blue-400 hover:bg-blue-50/50 dark:hover:bg-blue-900/10'
                )
              )}
            >
              <div className="text-sm font-bold">{option.label}</div>
              <div className="text-xs mt-1 opacity-75 leading-tight">{option.description}</div>
              {option.id === 'syn' && synUnavailable && (
                <div className="mt-1.5 flex items-center gap-1 text-xs text-amber-600 dark:text-amber-400">
                  <svg className="w-3 h-3 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                  </svg>
                  Requires elevated privileges
                </div>
              )}
            </button>
          );
        })}
      </div>
    </div>
  );
};
