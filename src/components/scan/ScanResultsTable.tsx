import React, { useMemo, useCallback } from 'react';
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';
import { useScanStore, useScanDevices } from '../../stores/scanStore';
import type { FilterStatus } from '../../stores/scanStore';
import type { Device } from '../../types/device';

type SortField = 'ip' | 'mac' | 'hostname' | 'vendor' | 'ports' | 'lastSeen';
type SortDirection = 'asc' | 'desc';

/** Compare two IPv4 addresses numerically by octet */
function compareIPs(a: string, b: string): number {
  const aParts = a.split('.').map(Number);
  const bParts = b.split('.').map(Number);
  for (let i = 0; i < 4; i++) {
    const aOctet = aParts[i] ?? 0;
    const bOctet = bParts[i] ?? 0;
    if (aOctet !== bOctet) return aOctet - bOctet;
  }
  return 0;
}

interface SortIconProps {
  field: SortField;
  sortField: SortField;
  sortDirection: SortDirection;
}

const SortIcon: React.FC<SortIconProps> = React.memo(({ field, sortField, sortDirection }) => (
  <span className="ml-1 inline-block">
    {sortField === field ? (
      sortDirection === 'asc' ? '↑' : '↓'
    ) : (
      <span className="text-gray-600">↕</span>
    )}
  </span>
));
SortIcon.displayName = 'SortIcon';

const STATUS_FILTER_OPTIONS: { value: FilterStatus; label: string }[] = [
  { value: 'all', label: 'All' },
  { value: 'online', label: 'Online' },
  { value: 'offline', label: 'Offline' },
  { value: 'unknown', label: 'Unknown' },
];

export const ScanResultsTable: React.FC = () => {
  const devices = useScanDevices();
  const selectedDeviceId = useScanStore((s) => s.selectedDeviceId);
  const selectDevice = useScanStore((s) => s.selectDevice);
  const searchQuery = useScanStore((s) => s.searchQuery);
  const filterStatus = useScanStore((s) => s.filterStatus);
  const filterHasOpenPorts = useScanStore((s) => s.filterHasOpenPorts);
  const setSearchQuery = useScanStore((s) => s.setSearchQuery);
  const setFilterStatus = useScanStore((s) => s.setFilterStatus);
  const setFilterHasOpenPorts = useScanStore((s) => s.setFilterHasOpenPorts);
  const clearFilters = useScanStore((s) => s.clearFilters);

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

  const handleSelectDevice = useCallback((ip: string) => {
    selectDevice(ip);
  }, [selectDevice]);

  const handleSearchChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    setSearchQuery(e.target.value);
  }, [setSearchQuery]);

  const handleStatusFilterChange = useCallback((status: FilterStatus) => {
    setFilterStatus(status);
  }, [setFilterStatus]);

  const handleOpenPortsToggle = useCallback(() => {
    setFilterHasOpenPorts(!filterHasOpenPorts);
  }, [filterHasOpenPorts, setFilterHasOpenPorts]);

  const hasActiveFilters = searchQuery !== '' || filterStatus !== 'all' || filterHasOpenPorts;

  // Filter devices based on search query and filter state
  const filteredDevices = useMemo(() => {
    return devices.filter((device) => {
      // Search filter — case-insensitive substring match on IP, MAC, hostname, vendor
      if (searchQuery) {
        const query = searchQuery.toLowerCase();
        const matchesSearch =
          device.ip.toLowerCase().includes(query) ||
          device.mac.toLowerCase().includes(query) ||
          (device.hostname?.toLowerCase().includes(query) ?? false) ||
          (device.vendor?.toLowerCase().includes(query) ?? false);
        if (!matchesSearch) return false;
      }
      // Status filter
      if (filterStatus !== 'all' && device.status !== filterStatus) return false;
      // Open ports filter
      if (filterHasOpenPorts && !device.ports.some((p) => p.state === 'open')) return false;
      return true;
    });
  }, [devices, searchQuery, filterStatus, filterHasOpenPorts]);

  // Sort filtered devices
  const sortedDevices = useMemo(() => {
    const sorted = [...filteredDevices];
    sorted.sort((a, b) => {
      let comparison = 0;
      switch (sortField) {
        case 'ip':
          comparison = compareIPs(a.ip, b.ip);
          break;
        case 'mac':
          comparison = a.mac.localeCompare(b.mac);
          break;
        case 'hostname':
          comparison = (a.hostname ?? '').localeCompare(b.hostname ?? '');
          break;
        case 'vendor':
          comparison = (a.vendor ?? '').localeCompare(b.vendor ?? '');
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
  }, [filteredDevices, sortField, sortDirection]);

  return (
    <div className="h-full flex flex-col">
      {/* Table Header */}
      <div className="px-4 py-3 border-b border-gray-700 bg-gray-750">
        <h2 className="text-lg font-semibold text-gray-200">
          Discovered Devices ({devices.length})
        </h2>
      </div>

      {/* Search and Filter Bar */}
      <div className="px-4 py-2 border-b border-gray-700 bg-gray-800/50">
        <div className="flex flex-wrap items-center gap-3">
          {/* Search Input */}
          <div className="relative flex-1 min-w-[200px]">
            <svg
              className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
              aria-hidden="true"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"
              />
            </svg>
            <input
              type="text"
              value={searchQuery}
              onChange={handleSearchChange}
              placeholder="Search devices..."
              aria-label="Search devices"
              className={twMerge(
                clsx(
                  'w-full pl-9 pr-3 py-1.5 bg-gray-900/80 border border-gray-600/50 rounded-lg',
                  'text-sm text-gray-100 placeholder-gray-500',
                  'focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent',
                  'transition-all duration-200 hover:border-gray-500'
                )
              )}
            />
          </div>

          {/* Status Filter Buttons */}
          <div className="flex items-center gap-1" role="radiogroup" aria-label="Filter by status">
            {STATUS_FILTER_OPTIONS.map(({ value, label }) => (
              <button
                key={value}
                type="button"
                role="radio"
                aria-checked={filterStatus === value}
                onClick={() => handleStatusFilterChange(value)}
                className={twMerge(
                  clsx(
                    'px-2.5 py-1 text-xs font-medium rounded-md transition-colors',
                    'focus:outline-none focus:ring-2 focus:ring-blue-500',
                    filterStatus === value
                      ? 'bg-blue-600 text-white'
                      : 'bg-gray-700/50 text-gray-400 hover:bg-gray-700 hover:text-gray-200'
                  )
                )}
              >
                {label}
              </button>
            ))}
          </div>

          {/* Has Open Ports Toggle */}
          <button
            type="button"
            role="switch"
            aria-checked={filterHasOpenPorts}
            aria-label="Filter devices with open ports"
            onClick={handleOpenPortsToggle}
            className={twMerge(
              clsx(
                'flex items-center gap-2 px-2.5 py-1 text-xs font-medium rounded-md transition-colors',
                'focus:outline-none focus:ring-2 focus:ring-blue-500',
                filterHasOpenPorts
                  ? 'bg-green-900/50 text-green-400 border border-green-700/50'
                  : 'bg-gray-700/50 text-gray-400 hover:bg-gray-700 hover:text-gray-200 border border-transparent'
              )
            )}
          >
            <span
              className={twMerge(
                clsx(
                  'w-3 h-3 rounded-full transition-colors',
                  filterHasOpenPorts ? 'bg-green-400' : 'bg-gray-600'
                )
              )}
              aria-hidden="true"
            />
            Has open ports
          </button>

          {/* Clear Filters */}
          {hasActiveFilters && (
            <button
              type="button"
              onClick={clearFilters}
              className="px-2.5 py-1 text-xs font-medium text-gray-400 hover:text-gray-200 bg-gray-700/50 hover:bg-gray-700 rounded-md transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500"
              aria-label="Clear all filters"
            >
              Clear
            </button>
          )}

          {/* Result Count */}
          <span className="text-xs text-gray-500 ml-auto whitespace-nowrap" aria-live="polite">
            Showing {filteredDevices.length} of {devices.length} devices
          </span>
        </div>
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
                <SortIcon field="ip" sortField={sortField} sortDirection={sortDirection} />
              </th>
              <th
                className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider cursor-pointer hover:text-gray-200"
                onClick={() => handleSort('mac')}
              >
                MAC Address
                <SortIcon field="mac" sortField={sortField} sortDirection={sortDirection} />
              </th>
              <th
                className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider cursor-pointer hover:text-gray-200"
                onClick={() => handleSort('vendor')}
              >
                Vendor
                <SortIcon field="vendor" sortField={sortField} sortDirection={sortDirection} />
              </th>
              <th
                className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider cursor-pointer hover:text-gray-200"
                onClick={() => handleSort('hostname')}
              >
                Hostname
                <SortIcon field="hostname" sortField={sortField} sortDirection={sortDirection} />
              </th>
              <th
                className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider cursor-pointer hover:text-gray-200"
                onClick={() => handleSort('ports')}
              >
                Open Ports
                <SortIcon field="ports" sortField={sortField} sortDirection={sortDirection} />
              </th>
              <th
                className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider cursor-pointer hover:text-gray-200"
                onClick={() => handleSort('lastSeen')}
              >
                Last Seen
                <SortIcon field="lastSeen" sortField={sortField} sortDirection={sortDirection} />
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-700">
            {sortedDevices.map((device) => (
              <DeviceRow
                key={device.mac || device.ip}
                device={device}
                isSelected={selectedDeviceId === device.ip}
                onSelect={handleSelectDevice}
              />
            ))}
          </tbody>
        </table>

        {devices.length === 0 && (
          <div className="p-8 text-center text-gray-500">
            No devices discovered yet
          </div>
        )}

        {devices.length > 0 && filteredDevices.length === 0 && (
          <div className="p-8 text-center text-gray-500">
            No devices match the current filters
          </div>
        )}
      </div>
    </div>
  );
};

interface DeviceRowProps {
  device: Device;
  isSelected: boolean;
  onSelect: (ip: string) => void;
}

const DeviceRow: React.FC<DeviceRowProps> = React.memo(({ device, isSelected, onSelect }) => {
  const openPortCount = useMemo(
    () => device.ports.filter((p) => p.state === 'open').length,
    [device.ports]
  );

  const handleClick = useCallback(() => {
    onSelect(device.ip);
  }, [onSelect, device.ip]);

  return (
    <tr
      onClick={handleClick}
      className={twMerge(
        clsx(
          'cursor-pointer transition-colors',
          isSelected ? 'bg-blue-900/30' : 'hover:bg-gray-700/50'
        )
      )}
    >
      <td className="px-4 py-3 text-sm text-gray-200 font-mono">{device.ip}</td>
      <td className="px-4 py-3 text-sm text-gray-400 font-mono">{device.mac}</td>
      <td className="px-4 py-3 text-sm text-gray-300 max-w-[150px] truncate">
        {device.vendor || <span className="text-gray-600">—</span>}
      </td>
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
                title={port.service ?? `Port ${port.number}`}
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
});
DeviceRow.displayName = 'DeviceRow';
