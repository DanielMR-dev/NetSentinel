import React, { useEffect, useCallback, useRef, memo, useMemo } from 'react';
import { useDashboardStore } from '../../stores/dashboardStore';
import { DeviceInfoCard } from './DeviceInfoCard';
import { NetworkInfoCard } from './NetworkInfoCard';
import { TopologyView } from '../topology/TopologyView';
import { Card } from '../common/Card';
import { useCveAlerts } from '../../stores/bannerStore';
import type { CveSeverity } from '../../types/device';

export const DashboardView: React.FC = memo(() => {
  const fetchDashboardData = useDashboardStore((s) => s.fetchDashboardData);
  const isDeviceLoading = useDashboardStore((s) => s.isDeviceLoading);
  const isNetworkLoading = useDashboardStore((s) => s.isNetworkLoading);
  const hostname = useDashboardStore((s) => s.hostname);
  const ipAddress = useDashboardStore((s) => s.ipAddress);
  const error = useDashboardStore((s) => s.deviceError || s.networkError);
  const clearError = useDashboardStore((s) => s.clearDeviceError);

  const cveAlerts = useCveAlerts();

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

  const cveSummary = useMemo(() => {
    if (cveAlerts.length === 0) return null;
    const uniqueHosts = new Set(cveAlerts.map((a) => a.ip));
    const bySeverity: Record<CveSeverity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const alert of cveAlerts) {
      bySeverity[alert.severity]++;
    }
    return {
      total: cveAlerts.length,
      hostCount: uniqueHosts.size,
      bySeverity,
    };
  }, [cveAlerts]);

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
      {/* CVE Summary Banner */}
      {cveSummary && (
        <div
          role="alert"
          className="px-4 py-3 bg-red-50 dark:bg-red-900/30 border border-red-300 dark:border-red-700/50 rounded-xl flex items-center gap-3"
        >
          <svg className="w-5 h-5 text-red-500 dark:text-red-400 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01M10.29 3.86l-8.58 14.86A1 1 0 002.58 20h18.84a1 1 0 00.87-1.5L13.71 3.86a1 1 0 00-1.72 0z" />
          </svg>
          <div className="flex-1">
            <p className="text-sm font-semibold text-red-800 dark:text-red-200">
              {cveSummary.total} vulnerabilit{cveSummary.total !== 1 ? 'ies' : 'y'} detected across {cveSummary.hostCount} host{cveSummary.hostCount !== 1 ? 's' : ''}
            </p>
            <div className="flex items-center gap-3 mt-1 text-xs">
              {cveSummary.bySeverity.critical > 0 && (
                <span className="text-red-600 dark:text-red-400 font-medium">{cveSummary.bySeverity.critical} critical</span>
              )}
              {cveSummary.bySeverity.high > 0 && (
                <span className="text-orange-600 dark:text-orange-400 font-medium">{cveSummary.bySeverity.high} high</span>
              )}
              {cveSummary.bySeverity.medium > 0 && (
                <span className="text-yellow-600 dark:text-yellow-400 font-medium">{cveSummary.bySeverity.medium} medium</span>
              )}
              {cveSummary.bySeverity.low > 0 && (
                <span className="text-blue-600 dark:text-blue-400 font-medium">{cveSummary.bySeverity.low} low</span>
              )}
            </div>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <DeviceInfoCard />
        <NetworkInfoCard />
      </div>
      <Card title="Network Topology">
        <TopologyView />
      </Card>
    </div>
  );
});

DashboardView.displayName = 'DashboardView';
