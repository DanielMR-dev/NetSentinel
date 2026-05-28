import React, { useCallback, memo } from 'react';
import { useDashboardStore } from '../../stores/dashboardStore';
import { Card } from '../common/Card';
import { InfoRow } from '../common/InfoRow';

export const DeviceInfoCard: React.FC = memo(() => {
  const hostname = useDashboardStore((s) => s.hostname);
  const osName = useDashboardStore((s) => s.osName);
  const osVersion = useDashboardStore((s) => s.osVersion);
  const uptime = useDashboardStore((s) => s.uptime);
  const isLoading = useDashboardStore((s) => s.isDeviceLoading);
  const error = useDashboardStore((s) => s.deviceError);
  const fetchDeviceInfo = useDashboardStore((s) => s.fetchDeviceInfo);
  const clearError = useDashboardStore((s) => s.clearDeviceError);

  const handleReload = useCallback(() => {
    clearError();
    fetchDeviceInfo();
  }, [clearError, fetchDeviceInfo]);

  return (
    <Card
      title="Device Information"
      onReload={handleReload}
      isLoading={isLoading}
      error={error}
    >
      <dl className="divide-y divide-gray-200 dark:divide-gray-700">
        <InfoRow label="Hostname" value={hostname} isLoading={isLoading} />
        <InfoRow label="Operating System" value={osName} isLoading={isLoading} />
        <InfoRow label="OS Version" value={osVersion} isLoading={isLoading} />
        <InfoRow label="Uptime" value={uptime} isLoading={isLoading} />
      </dl>
    </Card>
  );
});

DeviceInfoCard.displayName = 'DeviceInfoCard';
