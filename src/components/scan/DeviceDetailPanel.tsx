import React from 'react';
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';
import { useScanStore } from '../../stores/scanStore';
import type { Device, Port } from '../../types/device';

interface DeviceDetailPanelProps {
  device: Device;
}

export const DeviceDetailPanel: React.FC<DeviceDetailPanelProps> = ({ device }) => {
  const selectDevice = useScanStore((s) => s.selectDevice);

  const openPorts = device.ports.filter((p) => p.state === 'open');
  const filteredPorts = device.ports.filter((p) => p.state === 'filtered');

  return (
    <div className="h-full flex flex-col">
      {/* Header */}
      <div className="px-4 py-3 border-b border-gray-700 bg-gray-750 flex items-center justify-between">
        <h2 className="text-lg font-semibold text-gray-200">Device Details</h2>
        <button
          onClick={() => selectDevice(null)}
          className="p-1 hover:bg-gray-700 rounded text-gray-400 hover:text-gray-200"
          aria-label="Close panel"
        >
          <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M6 18L18 6M6 6l12 12"
            />
          </svg>
        </button>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {/* Status Badge */}
        <div className="flex items-center gap-2">
          <span
            className={twMerge(
              clsx(
                'px-2 py-1 rounded text-xs font-medium',
                device.status === 'online'
                  ? 'bg-green-900/50 text-green-400'
                  : device.status === 'offline'
                  ? 'bg-red-900/50 text-red-400'
                  : 'bg-gray-700 text-gray-400'
              )
            )}
          >
            {device.status.toUpperCase()}
          </span>
        </div>

        {/* IP Info */}
        <section>
          <h3 className="text-xs font-medium text-gray-500 uppercase mb-2">Network</h3>
          <div className="space-y-2">
            <div className="flex justify-between">
              <span className="text-gray-400">IP Address</span>
              <span className="text-gray-200 font-mono">{device.ip}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-400">MAC Address</span>
              <span className="text-gray-200 font-mono">{device.mac}</span>
            </div>
            {device.hostname && (
              <div className="flex justify-between">
                <span className="text-gray-400">Hostname</span>
                <span className="text-gray-200">{device.hostname}</span>
              </div>
            )}
          </div>
        </section>

        {/* Open Ports */}
        <section>
          <h3 className="text-xs font-medium text-gray-500 uppercase mb-2">
            Open Ports ({openPorts.length})
          </h3>
          {openPorts.length > 0 ? (
            <div className="space-y-1">
              {openPorts.map((port) => (
                <PortRow key={port.number} port={port} />
              ))}
            </div>
          ) : (
            <p className="text-sm text-gray-600 italic">No open ports detected</p>
          )}
        </section>

        {/* Filtered Ports */}
        {filteredPorts.length > 0 && (
          <section>
            <h3 className="text-xs font-medium text-gray-500 uppercase mb-2">
              Filtered ({filteredPorts.length})
            </h3>
            <div className="space-y-1">
              {filteredPorts.slice(0, 10).map((port) => (
                <PortRow key={port.number} port={port} />
              ))}
              {filteredPorts.length > 10 && (
                <p className="text-xs text-gray-600">+{filteredPorts.length - 10} more</p>
              )}
            </div>
          </section>
        )}

        {/* Timestamps */}
        <section>
          <h3 className="text-xs font-medium text-gray-500 uppercase mb-2">Timestamps</h3>
          <div className="flex justify-between">
            <span className="text-gray-400">Last Seen</span>
            <span className="text-gray-300">
              {new Date(device.lastSeen * 1000).toLocaleString()}
            </span>
          </div>
        </section>

        {/* Raw Data (expandable in future) */}
        <details className="group">
          <summary className="text-xs font-medium text-gray-500 uppercase cursor-pointer hover:text-gray-400">
            Raw Data
          </summary>
          <pre className="mt-2 p-2 bg-gray-900 rounded text-xs text-gray-400 overflow-x-auto">
            {JSON.stringify(device, null, 2)}
          </pre>
        </details>
      </div>
    </div>
  );
};

interface PortRowProps {
  port: Port;
}

const PortRow: React.FC<PortRowProps> = ({ port }) => (
  <div className="flex items-center justify-between py-1 px-2 bg-gray-750 rounded">
    <div className="flex items-center gap-2">
      <span className="text-blue-400 font-mono font-medium">{port.number}</span>
      <span className="text-gray-500 text-sm">/{port.protocol}</span>
      {port.service && <span className="text-gray-400 text-sm">({port.service})</span>}
    </div>
    <span
      className={twMerge(
        clsx(
          'text-xs px-2 py-0.5 rounded',
          port.state === 'open' && 'bg-green-900/50 text-green-400',
          port.state === 'closed' && 'bg-red-900/50 text-red-400',
          port.state === 'filtered' && 'bg-amber-900/50 text-amber-400'
        )
      )}
    >
      {port.state}
    </span>
  </div>
);