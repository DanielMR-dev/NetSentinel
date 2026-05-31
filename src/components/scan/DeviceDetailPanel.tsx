import React, { useState, useCallback, useMemo } from 'react';
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';
import { useScanStore } from '../../stores/scanStore';
import { useBannerStore } from '../../stores/bannerStore';
import type { Device, Port } from '../../types/device';
import { BannerPanel } from './BannerPanel';
import { CveAlertPanel } from './CveAlertPanel';

type DetailTab = 'ports' | 'services' | 'vulnerabilities';

interface DeviceDetailPanelProps {
  device: Device;
}

export const DeviceDetailPanel: React.FC<DeviceDetailPanelProps> = ({ device }) => {
  const selectDevice = useScanStore((s) => s.selectDevice);
  const cveAlerts = useBannerStore((s) => s.cveAlerts);
  const banners = useBannerStore((s) => s.banners);

  const [activeTab, setActiveTab] = useState<DetailTab>('ports');

  const openPorts = device.ports.filter((p) => p.state === 'open');
  const filteredPorts = device.ports.filter((p) => p.state === 'filtered');

  const hostBanners = useMemo(() => banners.get(device.ip) ?? [], [banners, device.ip]);
  const hostCveAlerts = useMemo(() => cveAlerts.filter((a) => a.ip === device.ip), [cveAlerts, device.ip]);

  const handleTabChange = useCallback((tab: DetailTab) => {
    setActiveTab(tab);
  }, []);

  return (
    <div className="h-full flex flex-col">
      {/* Header */}
      <div className="px-4 py-3 border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-750 flex items-center justify-between">
        <h2 className="text-lg font-semibold text-gray-800 dark:text-gray-200">Device Details</h2>
        <button
          onClick={() => selectDevice(null)}
          className="p-1 hover:bg-gray-200 dark:hover:bg-gray-700 rounded text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-200 focus:outline-none focus:ring-2 focus:ring-blue-500"
          aria-label="Close panel"
        >
          <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
          </svg>
        </button>
      </div>

      {/* Device info summary */}
      <div className="px-4 py-3 border-b border-gray-200 dark:border-gray-700 space-y-2">
        {/* Status Badge */}
        <div className="flex items-center gap-2">
          <span
            className={twMerge(
              clsx(
                'px-2 py-1 rounded text-xs font-medium',
                device.status === 'online'
                  ? 'bg-green-100 dark:bg-green-900/50 text-green-700 dark:text-green-400'
                  : device.status === 'offline'
                  ? 'bg-red-100 dark:bg-red-900/50 text-red-700 dark:text-red-400'
                  : 'bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-400'
              )
            )}
          >
            {device.status.toUpperCase()}
          </span>
        </div>

        {/* IP Info */}
        <div className="space-y-1">
          <div className="flex justify-between">
            <span className="text-xs text-gray-500 dark:text-gray-400">IP</span>
            <span className="text-xs text-gray-900 dark:text-gray-200 font-mono">{device.ip}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-xs text-gray-500 dark:text-gray-400">MAC</span>
            <span className="text-xs text-gray-900 dark:text-gray-200 font-mono">{device.mac}</span>
          </div>
          {device.vendor && (
            <div className="flex justify-between">
              <span className="text-xs text-gray-500 dark:text-gray-400">Vendor</span>
              <span className="text-xs text-gray-900 dark:text-gray-200">{device.vendor}</span>
            </div>
          )}
          {device.hostname && (
            <div className="flex justify-between">
              <span className="text-xs text-gray-500 dark:text-gray-400">Hostname</span>
              <span className="text-xs text-gray-900 dark:text-gray-200">{device.hostname}</span>
            </div>
          )}
        </div>
      </div>

      {/* Tab navigation */}
      <div className="flex border-b border-gray-200 dark:border-gray-700" role="tablist" aria-label="Device detail tabs">
        <TabButton
          id="ports"
          label="Ports"
          count={openPorts.length}
          isActive={activeTab === 'ports'}
          onClick={handleTabChange}
        />
        <TabButton
          id="services"
          label="Services"
          count={hostBanners.length}
          isActive={activeTab === 'services'}
          onClick={handleTabChange}
        />
        <TabButton
          id="vulnerabilities"
          label="CVEs"
          count={hostCveAlerts.length}
          isActive={activeTab === 'vulnerabilities'}
          onClick={handleTabChange}
          alertCount={hostCveAlerts.length}
        />
      </div>

      {/* Tab content */}
      <div className="flex-1 overflow-y-auto" role="tabpanel" aria-label={`${activeTab} tab content`}>
        {activeTab === 'ports' && (
          <div className="p-4 space-y-4">
            {/* Open Ports */}
            <section>
              <h3 className="text-xs font-medium text-gray-500 dark:text-gray-500 uppercase mb-2">
                Open Ports ({openPorts.length})
              </h3>
              {openPorts.length > 0 ? (
                <div className="space-y-1">
                  {openPorts.map((port) => (
                    <PortRow key={port.number} port={port} />
                  ))}
                </div>
              ) : (
                <p className="text-sm text-gray-400 dark:text-gray-600 italic">No open ports detected</p>
              )}
            </section>

            {/* Filtered Ports */}
            {filteredPorts.length > 0 && (
              <section>
                <h3 className="text-xs font-medium text-gray-500 dark:text-gray-500 uppercase mb-2">
                  Filtered ({filteredPorts.length})
                </h3>
                <div className="space-y-1">
                  {filteredPorts.slice(0, 10).map((port) => (
                    <PortRow key={port.number} port={port} />
                  ))}
                  {filteredPorts.length > 10 && (
                    <p className="text-xs text-gray-400 dark:text-gray-600">+{filteredPorts.length - 10} more</p>
                  )}
                </div>
              </section>
            )}

            {/* Timestamps */}
            <section>
              <h3 className="text-xs font-medium text-gray-500 dark:text-gray-500 uppercase mb-2">Timestamps</h3>
              <div className="flex justify-between">
                <span className="text-xs text-gray-500 dark:text-gray-400">Last Seen</span>
                <span className="text-xs text-gray-700 dark:text-gray-300">
                  {new Date(device.lastSeen * 1000).toLocaleString()}
                </span>
              </div>
            </section>

            {/* Raw Data */}
            <details className="group">
              <summary className="text-xs font-medium text-gray-500 dark:text-gray-500 uppercase cursor-pointer hover:text-gray-700 dark:hover:text-gray-400">
                Raw Data
              </summary>
              <pre className="mt-2 p-2 bg-gray-100 dark:bg-gray-900 rounded text-xs text-gray-600 dark:text-gray-400 overflow-x-auto">
                {JSON.stringify(device, null, 2)}
              </pre>
            </details>
          </div>
        )}

        {activeTab === 'services' && <BannerPanel ip={device.ip} />}

        {activeTab === 'vulnerabilities' && <CveAlertPanel ip={device.ip} />}
      </div>
    </div>
  );
};

interface TabButtonProps {
  id: DetailTab;
  label: string;
  count: number;
  isActive: boolean;
  onClick: (tab: DetailTab) => void;
  alertCount?: number;
}

const TabButton: React.FC<TabButtonProps> = React.memo(({ id, label, count, isActive, onClick, alertCount }) => {
  const handleClick = useCallback(() => {
    onClick(id);
  }, [id, onClick]);

  return (
    <button
      role="tab"
      id={`tab-${id}`}
      aria-selected={isActive}
      aria-controls={`panel-${id}`}
      tabIndex={isActive ? 0 : -1}
      onClick={handleClick}
      className={twMerge(
        clsx(
          'flex-1 px-3 py-2 text-xs font-medium transition-colors relative',
          'border-b-2 -mb-px',
          'focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-inset',
          isActive
            ? 'border-blue-500 text-blue-600 dark:text-blue-400'
            : 'border-transparent text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-200'
        )
      )}
    >
      <span className="flex items-center justify-center gap-1.5">
        {label}
        {count > 0 && (
          <span className={twMerge(
            clsx(
              'px-1.5 py-0.5 text-[10px] font-bold rounded-full',
              alertCount && alertCount > 0
                ? 'bg-red-100 dark:bg-red-900/50 text-red-700 dark:text-red-300'
                : 'bg-gray-200 dark:bg-gray-700 text-gray-600 dark:text-gray-400'
            )
          )}>
            {count}
          </span>
        )}
      </span>
    </button>
  );
});
TabButton.displayName = 'TabButton';

interface PortRowProps {
  port: Port;
}

const PortRow: React.FC<PortRowProps> = ({ port }) => (
  <div className="flex items-center justify-between py-1 px-2 bg-gray-50 dark:bg-gray-750 rounded">
    <div className="flex items-center gap-2">
      <span className="text-blue-600 dark:text-blue-400 font-mono font-medium">{port.number}</span>
      <span className="text-gray-500 dark:text-gray-500 text-sm">/{port.protocol}</span>
      {port.service && <span className="text-gray-500 dark:text-gray-400 text-sm">({port.service})</span>}
    </div>
    <span
      className={twMerge(
        clsx(
          'text-xs px-2 py-0.5 rounded',
          port.state === 'open' && 'bg-green-100 dark:bg-green-900/50 text-green-700 dark:text-green-400',
          port.state === 'closed' && 'bg-red-100 dark:bg-red-900/50 text-red-700 dark:text-red-400',
          port.state === 'filtered' && 'bg-amber-100 dark:bg-amber-900/50 text-amber-700 dark:text-amber-400'
        )
      )}
    >
      {port.state}
    </span>
  </div>
);
