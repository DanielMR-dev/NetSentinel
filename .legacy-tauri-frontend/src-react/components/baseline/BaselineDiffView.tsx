import React, { useMemo } from 'react';
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';
import type { BaselineDiff, Device, PortChange, BannerResult } from '../../types/device';

interface BaselineDiffViewProps {
  diff: BaselineDiff;
  onClose: () => void;
}

export const BaselineDiffView: React.FC<BaselineDiffViewProps> = ({ diff, onClose }) => {
  const summary = useMemo(() => ({
    newHosts: diff.newHosts.length,
    removedHosts: diff.removedHosts.length,
    portChanges: diff.changedPorts.length,
    newServices: diff.newServices.length,
  }), [diff]);

  const hasChanges = summary.newHosts > 0 || summary.removedHosts > 0 || summary.portChanges > 0 || summary.newServices > 0;

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100">
            Baseline Comparison: {diff.baselineName}
          </h3>
          <p className="text-xs text-gray-500 dark:text-gray-400 mt-0.5">
            Compared at {new Date(diff.scanTimestamp * 1000).toLocaleString()}
          </p>
        </div>
        <button
          type="button"
          onClick={onClose}
          className="px-3 py-1.5 text-xs font-medium text-gray-600 dark:text-gray-400 bg-gray-100 dark:bg-gray-700 hover:bg-gray-200 dark:hover:bg-gray-600 rounded-lg transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500"
          aria-label="Close diff view"
        >
          Close
        </button>
      </div>

      {/* Summary */}
      <div className="flex flex-wrap gap-3">
        <SummaryBadge label="New Hosts" count={summary.newHosts} color="green" />
        <SummaryBadge label="Removed" count={summary.removedHosts} color="red" />
        <SummaryBadge label="Port Changes" count={summary.portChanges} color="yellow" />
        <SummaryBadge label="New Services" count={summary.newServices} color="blue" />
      </div>

      {!hasChanges && (
        <div className="p-6 text-center text-gray-500 dark:text-gray-500 bg-gray-50 dark:bg-gray-750 rounded-xl">
          <svg className="w-10 h-10 mx-auto mb-2 text-green-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <p className="text-sm font-medium">No changes detected</p>
          <p className="text-xs text-gray-400 dark:text-gray-600 mt-1">
            The current scan matches the baseline exactly.
          </p>
        </div>
      )}

      {/* New Hosts */}
      {diff.newHosts.length > 0 && (
        <DiffSection title="New Hosts" color="green" count={diff.newHosts.length}>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            {diff.newHosts.map((device) => (
              <HostCard key={device.ip} device={device} variant="new" />
            ))}
          </div>
        </DiffSection>
      )}

      {/* Removed Hosts */}
      {diff.removedHosts.length > 0 && (
        <DiffSection title="Removed Hosts" color="red" count={diff.removedHosts.length}>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            {diff.removedHosts.map((device) => (
              <HostCard key={device.ip} device={device} variant="removed" />
            ))}
          </div>
        </DiffSection>
      )}

      {/* Changed Ports */}
      {diff.changedPorts.length > 0 && (
        <DiffSection title="Port Changes" color="yellow" count={diff.changedPorts.length}>
          <div className="space-y-1">
            {diff.changedPorts.map((change, i) => (
              <PortChangeRow key={`${change.ip}-${change.port.number}-${i}`} change={change} />
            ))}
          </div>
        </DiffSection>
      )}

      {/* New Services */}
      {diff.newServices.length > 0 && (
        <DiffSection title="New Services" color="blue" count={diff.newServices.length}>
          <div className="space-y-1">
            {diff.newServices.map((service, i) => (
              <ServiceRow key={`${service.ip}-${service.port}-${i}`} service={service} />
            ))}
          </div>
        </DiffSection>
      )}
    </div>
  );
};

// --- Sub-components ---

interface SummaryBadgeProps {
  label: string;
  count: number;
  color: 'green' | 'red' | 'yellow' | 'blue';
}

const SummaryBadge: React.FC<SummaryBadgeProps> = React.memo(({ label, count, color }) => {
  const colorClasses: Record<string, string> = {
    green: 'bg-green-100 dark:bg-green-900/50 text-green-700 dark:text-green-300 border-green-200 dark:border-green-700/50',
    red: 'bg-red-100 dark:bg-red-900/50 text-red-700 dark:text-red-300 border-red-200 dark:border-red-700/50',
    yellow: 'bg-yellow-100 dark:bg-yellow-900/50 text-yellow-700 dark:text-yellow-300 border-yellow-200 dark:border-yellow-700/50',
    blue: 'bg-blue-100 dark:bg-blue-900/50 text-blue-700 dark:text-blue-300 border-blue-200 dark:border-blue-700/50',
  };

  return (
    <div className={twMerge(clsx('px-3 py-2 rounded-lg border text-center min-w-[100px]', colorClasses[color]))}>
      <div className="text-lg font-bold">{count > 0 ? `+${count}` : count}</div>
      <div className="text-[10px] font-medium uppercase">{label}</div>
    </div>
  );
});
SummaryBadge.displayName = 'SummaryBadge';

interface DiffSectionProps {
  title: string;
  color: 'green' | 'red' | 'yellow' | 'blue';
  count: number;
  children: React.ReactNode;
}

const DiffSection: React.FC<DiffSectionProps> = ({ title, color, count, children }) => {
  const borderColor: Record<string, string> = {
    green: 'border-green-300 dark:border-green-700/50',
    red: 'border-red-300 dark:border-red-700/50',
    yellow: 'border-yellow-300 dark:border-yellow-700/50',
    blue: 'border-blue-300 dark:border-blue-700/50',
  };

  return (
    <section className={twMerge(clsx('border-l-4 rounded-r-lg bg-gray-50 dark:bg-gray-750 p-4', borderColor[color]))}>
      <h4 className="text-sm font-semibold text-gray-800 dark:text-gray-200 mb-3">
        {title} ({count})
      </h4>
      {children}
    </section>
  );
};

interface HostCardProps {
  device: Device;
  variant: 'new' | 'removed';
}

const HostCard: React.FC<HostCardProps> = React.memo(({ device, variant }) => {
  const bgClass = variant === 'new'
    ? 'bg-green-50 dark:bg-green-900/20 border-green-200 dark:border-green-700/30'
    : 'bg-red-50 dark:bg-red-900/20 border-red-200 dark:border-red-700/30';

  const openPorts = device.ports.filter((p) => p.state === 'open');

  return (
    <div className={twMerge(clsx('p-3 rounded-lg border', bgClass))}>
      <div className="flex items-center gap-2">
        <span className="text-sm font-mono font-bold text-gray-900 dark:text-gray-100">{device.ip}</span>
        {device.hostname && (
          <span className="text-xs text-gray-500 dark:text-gray-400">{device.hostname}</span>
        )}
      </div>
      {openPorts.length > 0 && (
        <div className="flex flex-wrap gap-1 mt-1.5">
          {openPorts.slice(0, 5).map((port) => (
            <span key={port.number} className="px-1.5 py-0.5 text-[10px] font-mono bg-white/50 dark:bg-gray-800/50 rounded">
              {port.number}{port.service ? `/${port.service}` : ''}
            </span>
          ))}
          {openPorts.length > 5 && (
            <span className="text-[10px] text-gray-500">+{openPorts.length - 5}</span>
          )}
        </div>
      )}
    </div>
  );
});
HostCard.displayName = 'HostCard';

interface PortChangeRowProps {
  change: PortChange;
}

const PortChangeRow: React.FC<PortChangeRowProps> = React.memo(({ change }) => (
  <div className="flex items-center gap-3 px-3 py-2 bg-yellow-50 dark:bg-yellow-900/20 rounded-lg border border-yellow-200 dark:border-yellow-700/30">
    <span className="text-sm font-mono text-gray-700 dark:text-gray-300">{change.ip}</span>
    <span className="text-sm font-mono font-bold text-blue-600 dark:text-blue-400">:{change.port.number}</span>
    {change.port.service && (
      <span className="text-xs text-gray-500 dark:text-gray-400">({change.port.service})</span>
    )}
    <span className="text-xs text-gray-500 dark:text-gray-400 ml-auto">
      {change.previousState ?? 'unknown'} → <span className="font-semibold">{change.currentState}</span>
    </span>
  </div>
));
PortChangeRow.displayName = 'PortChangeRow';

interface ServiceRowProps {
  service: BannerResult;
}

const ServiceRow: React.FC<ServiceRowProps> = React.memo(({ service }) => (
  <div className="flex items-center gap-3 px-3 py-2 bg-blue-50 dark:bg-blue-900/20 rounded-lg border border-blue-200 dark:border-blue-700/30">
    <span className="text-sm font-mono text-gray-700 dark:text-gray-300">{service.ip}</span>
    <span className="text-sm font-mono font-bold text-blue-600 dark:text-blue-400">:{service.port}</span>
    {service.service && (
      <span className="px-1.5 py-0.5 text-[10px] font-medium bg-green-100 dark:bg-green-900/50 text-green-700 dark:text-green-300 rounded">
        {service.service}
      </span>
    )}
    <span className="text-xs text-gray-500 dark:text-gray-400 truncate ml-auto max-w-[200px]">
      {service.banner}
    </span>
  </div>
));
ServiceRow.displayName = 'ServiceRow';
