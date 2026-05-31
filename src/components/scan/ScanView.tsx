import React from 'react';
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';
import { useScanStore } from '../../stores/scanStore';
import { ScanConfigPanel } from './ScanConfigPanel';
import { ScanProgress } from './ScanProgress';
import { ScanResultsTable } from './ScanResultsTable';
import { DeviceDetailPanel } from './DeviceDetailPanel';

export const ScanView: React.FC = () => {
  const devices = useScanStore((s) => s.devices);
  const selectedDeviceId = useScanStore((s) => s.selectedDeviceId);

  const selectedDevice = selectedDeviceId
    ? devices.find((d) => d.ip === selectedDeviceId)
    : null;

  return (
    <div className="flex flex-col h-full">
      {/* Scan Configuration Panel */}
      <ScanConfigPanel />

      {/* Progress Indicator */}
      <ScanProgress />

      {/* Results Area - Split view */}
      <div className="flex flex-1 gap-4 mt-4 min-h-0">
        {/* Results Table */}
        <div className={twMerge(
          clsx(
            'flex-1 bg-white dark:bg-gray-800 rounded-lg overflow-hidden',
            'border border-gray-200 dark:border-gray-700',
            devices.length === 0 && 'hidden'
          )
        )}>
          {devices.length > 0 && <ScanResultsTable />}
        </div>

        {/* Device Detail Panel */}
        <div className={twMerge(
          clsx(
            'w-96 bg-white dark:bg-gray-800 rounded-lg overflow-hidden',
            'border border-gray-200 dark:border-gray-700',
            !selectedDevice && 'hidden'
          )
        )}>
          {selectedDevice && <DeviceDetailPanel device={selectedDevice} />}
        </div>
      </div>

      {/* Empty state when no devices */}
      {devices.length === 0 && (
        <div className="flex-1 flex items-center justify-center text-gray-500 dark:text-gray-500">
          <div className="text-center">
            <svg
              className="w-16 h-16 mx-auto mb-4 text-gray-300 dark:text-gray-600"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={1.5}
                d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"
              />
            </svg>
            <p className="text-lg">No devices discovered yet</p>
            <p className="text-sm text-gray-400 dark:text-gray-600 mt-1">
              Enter a CIDR range and start a scan to discover devices
            </p>
          </div>
        </div>
      )}
    </div>
  );
};
