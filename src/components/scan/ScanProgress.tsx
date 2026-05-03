import React, { useMemo } from 'react';
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';
import { useScanStore } from '../../stores/scanStore';
import { ScanLogs } from './ScanLogs';

export const ScanProgress: React.FC = () => {
  const {
    isScanning,
    isPaused,
    scannedCount,
    totalHosts,
    currentTarget,
    devices,
  } = useScanStore();

  const progressPercent = useMemo(() => {
    if (totalHosts === 0) return 0;
    return Math.round((scannedCount / totalHosts) * 100);
  }, [scannedCount, totalHosts]);

  const shouldShow = isScanning || isPaused || scannedCount > 0;

  if (!shouldShow) return null;

  const getStatusBadgeClasses = () => {
    if (isScanning) {
      return 'bg-gradient-to-b from-blue-600 to-blue-700 text-white shadow-md';
    }
    if (isPaused) {
      return 'bg-gradient-to-b from-amber-500 to-amber-600 text-white shadow-md';
    }
    return 'bg-gradient-to-b from-gray-600 to-gray-700 text-gray-300';
  };

  const getProgressBarClasses = () => {
    if (isPaused) {
      return 'bg-gradient-to-r from-amber-600 to-amber-500';
    }
    return 'bg-gradient-to-r from-blue-600 to-blue-400';
  };

  return (
    <div className="bg-gradient-to-b from-gray-800 to-gray-800/95 rounded-2xl border border-gray-700/50 shadow-card p-5 mt-4">
      {/* Header Row */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-4">
          <span className="text-sm font-medium text-gray-300">
            Scanning: {currentTarget || 'Initializing...'}
          </span>
          <span
            className={twMerge(
              clsx(
                'px-2.5 py-1 rounded-lg text-xs font-semibold',
                getStatusBadgeClasses()
              )
            )}
          >
            {isScanning ? 'In Progress' : isPaused ? 'Paused' : 'Complete'}
          </span>
        </div>
        <div className="text-sm text-gray-400">
          <span className="font-medium">{scannedCount}</span>
          <span className="mx-1.5 text-gray-600">/</span>
          <span className="font-medium">{totalHosts}</span>
          <span className="mx-2 text-gray-600">•</span>
          <span className="text-blue-400 font-medium">{devices.length}</span>
          <span className="ml-1.5 text-gray-500">devices found</span>
        </div>
      </div>

      {/* Progress Bar */}
      <div className="relative w-full h-3 bg-gray-700/70 rounded-full overflow-hidden shadow-inner">
        <div
          className={twMerge(
            clsx(
              'h-full rounded-full transition-all duration-500 ease-out shadow-lg',
              getProgressBarClasses()
            )
          )}
          style={{ width: `${progressPercent}%` }}
        />
        {isScanning && (
          <div
            className="absolute inset-0 overflow-hidden pointer-events-none"
            style={{ width: `${progressPercent}%` }}
          >
            <div className="h-full w-full bg-gradient-to-r from-transparent via-white/30 to-transparent animate-shimmer" />
          </div>
        )}
      </div>

      {/* Progress Stats */}
      <div className="flex justify-between mt-3 text-xs text-gray-500 font-medium">
        <span className="text-blue-400">{progressPercent}% complete</span>
        <span className="text-gray-400">
          {devices.length > 0
            ? `Last device: ${devices[devices.length - 1]?.ip || 'N/A'}`
            : 'Waiting for devices...'}
        </span>
      </div>

      {/* Bottom Section: Stats + Logs */}
      <div className="flex gap-5 mt-5">
        {/* Central Stats Display */}
        <div className="flex-1 flex items-center justify-center">
          <div className="text-center p-4 bg-gray-900/50 rounded-xl border border-gray-700/30">
            <div className="text-4xl font-bold bg-gradient-to-r from-blue-500 to-blue-400 bg-clip-text text-transparent">
              {progressPercent}%
            </div>
            <div className="text-xs text-gray-500 mt-2 font-medium uppercase tracking-wider">
              {devices.length} devices discovered
            </div>
          </div>
        </div>

        {/* Logs Panel */}
        <div className="w-96">
          <div className="text-xs text-gray-400 mb-2 font-semibold uppercase tracking-wider">
            Live Logs
          </div>
          <ScanLogs maxHeight="h-44" />
        </div>
      </div>
    </div>
  );
};
