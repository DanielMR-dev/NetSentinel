import React, { useMemo, useCallback } from 'react';
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';
import { useScanStore, useScanDevices } from '../../stores/scanStore';
import type { Device } from '../../types/device';

type SortField = 'ip' | 'mac' | 'hostname' | 'ports' | 'lastSeen';
type SortDirection = 'asc' | 'desc';

export const ScanResultsTable: React.FC = () => {
  const devices = useScanDevices();
  const selectedDeviceId = useScanStore((s) => s.selectedDeviceId);
  const selectDevice = useScanStore((s) => s.selectDevice);

  const [sortField, setSortField] = React.useState<SortField>('ip');
  const [sortDirection, setSortDirection] = React.useState<SortDirection>('asc');

  const handleSort = useCallback((field: SortField) => {
    if (sortField === field) {
      setSortDirection((d) => (d === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortField(field);
      setSortDirection('asc');
    }
  }, [sortField]);

  const sortedDevices = useMemo(() => {
    const sorted = [...devices];
    sorted.sort((a, b) => {
      let comparison = 0;
      switch (sortField) {
        case 'ip':
          comparison = a.ip.localeCompare(b.ip);
          break;
        case 'mac':
          comparison = a.mac.localeCompare(b.mac);
          break;
        case 'hostname':
          comparison = (a.hostname || '').localeCompare(b.hostname || '');
          break;
        case 'ports':
          comparison = a.ports.length - b.ports.length;
          break;
        case 'lastSeen':
          comparison = a.lastSeen - b.lastSeen;
          break;
      }
      return sortDirection === 'asc' ? comparison : -comparison;
    });
    return sorted;
  }, [devices, sortField, sortDirection]);

  const SortIcon: React.FC<{ field: SortField }> = ({ field }) => (
    <span className="ml-1 inline-block">
      {sortField === field ? (
        sortDirection === 'asc' ? '↑' : '↓'
      ) : (
        <span className="text-gray-600">↕</span>
      )}
    </span>
  );

  return (
    <div className="h-full flex flex-col">
      {/* Table Header */}
      <div className="px-4 py-3 border-b border-gray-700 bg-gray-750">
        <h2 className="text-lg font-semibold text-gray-200">
          Discovered Devices ({devices.length})
        </h2>
      </div>

      {/* Table Content - Scrollable */}
      <div className="flex-1 overflow-auto">
        <table className="w-full">
          <thead className="sticky top-0 bg-gray-750 border-b border-gray-700">
            <tr>
              <th
                className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider cursor-pointer hover:text-gray-200"
                onClick={() => handleSort('ip')}
              >
                IP Address
                <SortIcon field="ip" />
              </th>
              <th
                className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider cursor-pointer hover:text-gray-200"
                onClick={() => handleSort('mac')}
              >
                MAC Address
                <SortIcon field="mac" />
              </th>
              <th
                className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider cursor-pointer hover:text-gray-200"
                onClick={() => handleSort('hostname')}
              >
                Hostname
                <SortIcon field="hostname" />
              </th>
              <th
                className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider cursor-pointer hover:text-gray-200"
                onClick={() => handleSort('ports')}
              >
                Open Ports
                <SortIcon field="ports" />
              </th>
              <th
                className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider cursor-pointer hover:text-gray-200"
                onClick={() => handleSort('lastSeen')}
              >
                Last Seen
                <SortIcon field="lastSeen" />
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-700">
            {sortedDevices.map((device) => (
              <DeviceRow
                key={device.mac || device.ip}
                device={device}
                isSelected={selectedDeviceId === device.ip}
                onSelect={() => selectDevice(device.ip)}
              />
            ))}
          </tbody>
        </table>

        {devices.length === 0 && (
          <div className="p-8 text-center text-gray-500">
            No devices discovered yet
          </div>
        )}
      </div>
    </div>
  );
};

interface DeviceRowProps {
  device: Device;
  isSelected: boolean;
  onSelect: () => void;
}

const DeviceRow: React.FC<DeviceRowProps> = ({ device, isSelected, onSelect }) => {
  const openPortCount = device.ports.filter((p) => p.state === 'open').length;

  return (
    <tr
      onClick={onSelect}
      className={twMerge(
        clsx(
          'cursor-pointer transition-colors',
          isSelected ? 'bg-blue-900/30' : 'hover:bg-gray-700/50'
        )
      )}
    >
      <td className="px-4 py-3 text-sm text-gray-200 font-mono">{device.ip}</td>
      <td className="px-4 py-3 text-sm text-gray-400 font-mono">{device.mac}</td>
      <td className="px-4 py-3 text-sm text-gray-300">
        {device.hostname || <span className="text-gray-600 italic">Unknown</span>}
      </td>
      <td className="px-4 py-3">
        <div className="flex flex-wrap gap-1">
          {device.ports
            .filter((p) => p.state === 'open')
            .slice(0, 5)
            .map((port) => (
              <span
                key={port.number}
                className="px-2 py-0.5 bg-green-900/50 text-green-400 text-xs rounded"
                title={port.service || `Port ${port.number}`}
              >
                {port.number}
                {port.service && (
                  <span className="ml-1 text-green-400/70">{port.service}</span>
                )}
              </span>
            ))}
          {openPortCount > 5 && (
            <span className="px-2 py-0.5 bg-gray-700 text-gray-400 text-xs rounded">
              +{openPortCount - 5} more
            </span>
          )}
          {openPortCount === 0 && (
            <span className="px-2 py-0.5 bg-gray-700 text-gray-500 text-xs rounded">None</span>
          )}
        </div>
      </td>
      <td className="px-4 py-3 text-sm text-gray-500">
        {new Date(device.lastSeen * 1000).toLocaleTimeString()}
      </td>
    </tr>
  );
};