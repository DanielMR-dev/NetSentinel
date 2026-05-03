import React, { useCallback, memo } from 'react';
import { useDashboardStore } from '../../stores/dashboardStore';
import { Card } from '../common/Card';
import { InfoRow } from '../common/InfoRow';

export const NetworkInfoCard: React.FC = memo(() => {
  const ipAddress = useDashboardStore((s) => s.ipAddress);
  const macAddress = useDashboardStore((s) => s.macAddress);
  const gateway = useDashboardStore((s) => s.gateway);
  const networkName = useDashboardStore((s) => s.networkName);
  const isLoading = useDashboardStore((s) => s.isNetworkLoading);
  const error = useDashboardStore((s) => s.networkError);
  const fetchNetworkInfo = useDashboardStore((s) => s.fetchNetworkInfo);
  const clearError = useDashboardStore((s) => s.clearNetworkError);

  const handleReload = useCallback(() => {
    clearError();
    fetchNetworkInfo();
  }, [clearError, fetchNetworkInfo]);

  return (
    <Card
      title="Network Information"
      onReload={handleReload}
      isLoading={isLoading}
      error={error}
    >
      <dl className="divide-y divide-gray-700">
        <InfoRow label="IP Address" value={ipAddress} isLoading={isLoading} />
        <InfoRow label="MAC Address" value={macAddress} isLoading={isLoading} />
        <InfoRow label="Gateway" value={gateway} isLoading={isLoading} />
        <InfoRow label="Network Name" value={networkName} isLoading={isLoading} />
      </dl>
    </Card>
  );
});

NetworkInfoCard.displayName = 'NetworkInfoCard';