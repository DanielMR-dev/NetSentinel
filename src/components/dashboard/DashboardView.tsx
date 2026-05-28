import React, { useEffect, useCallback, useRef, memo } from 'react';
import { useDashboardStore } from '../../stores/dashboardStore';
import { DeviceInfoCard } from './DeviceInfoCard';
import { NetworkInfoCard } from './NetworkInfoCard';
import { NetworkTopology } from './NetworkTopology';
import { Card } from '../common/Card';

export const DashboardView: React.FC = memo(() => {
  const fetchDashboardData = useDashboardStore((s) => s.fetchDashboardData);
  const isDeviceLoading = useDashboardStore((s) => s.isDeviceLoading);
  const isNetworkLoading = useDashboardStore((s) => s.isNetworkLoading);
  const hostname = useDashboardStore((s) => s.hostname);
  const ipAddress = useDashboardStore((s) => s.ipAddress);
  const error = useDashboardStore((s) => s.deviceError || s.networkError);
  const clearError = useDashboardStore((s) => s.clearDeviceError);

  const hasFetched = useRef(false);

  useEffect(() => {
    if (!hasFetched.current) {
      hasFetched.current = true;
      fetchDashboardData();
    }
  }, [fetchDashboardData]);

  const handleRetry = useCallback(() => {
    clearError();
    fetchDashboardData();
  }, [clearError, fetchDashboardData]);

  const hasDeviceData = hostname !== null;
  const hasNetworkData = ipAddress !== null;
  const isInitialLoading = isDeviceLoading && isNetworkLoading;
  const hasError = error !== null;

  if (isInitialLoading && !hasError && !hasDeviceData && !hasNetworkData) {
    return (
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Device Info Skeleton */}
        <div className="bg-gray-100 dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-xl p-6 animate-pulse">
          <div className="h-6 bg-gray-200 dark:bg-gray-700 rounded w-1/3 mb-4" />
          <div className="space-y-3">
            {[1, 2, 3, 4].map((i) => (
              <div key={i} className="flex justify-between">
                <div className="h-4 bg-gray-200 dark:bg-gray-700 rounded w-1/4" />
                <div className="h-4 bg-gray-200 dark:bg-gray-700 rounded w-1/3" />
              </div>
            ))}
          </div>
        </div>

        {/* Network Info Skeleton */}
        <div className="bg-gray-100 dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-xl p-6 animate-pulse">
          <div className="h-6 bg-gray-200 dark:bg-gray-700 rounded w-1/3 mb-4" />
          <div className="space-y-3">
            {[1, 2, 3, 4].map((i) => (
              <div key={i} className="flex justify-between">
                <div className="h-4 bg-gray-200 dark:bg-gray-700 rounded w-1/4" />
                <div className="h-4 bg-gray-200 dark:bg-gray-700 rounded w-1/3" />
              </div>
            ))}
          </div>
        </div>
      </div>
    );
  }

  if (hasError && isDeviceLoading === false && isNetworkLoading === false) {
    return (
      <div className="space-y-6">
        <div
          role="alert"
          className="bg-red-50 dark:bg-red-900/50 border border-red-200 dark:border-red-700 rounded-lg p-4 mb-6"
        >
          <p className="text-red-700 dark:text-red-300">{error}</p>
          <button
            onClick={handleRetry}
            className="mt-2 text-sm text-red-500 dark:text-red-400 hover:text-red-700 dark:hover:text-red-300 focus:outline-none focus:ring-2 focus:ring-red-500 rounded px-2 py-1"
          >
            Retry
          </button>
        </div>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <DeviceInfoCard />
          <NetworkInfoCard />
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <DeviceInfoCard />
        <NetworkInfoCard />
      </div>
      <Card title="Network Topology">
        <NetworkTopology />
      </Card>
    </div>
  );
});

DashboardView.displayName = 'DashboardView';
