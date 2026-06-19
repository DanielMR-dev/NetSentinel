import React, { useEffect, useState, useCallback, useMemo } from 'react';
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';
import { useHistoryStore } from '../../stores/historyStore';
import { useScanStore } from '../../stores/scanStore';
import { useDashboardStore } from '../../stores/dashboardStore';
import { Button } from '../common/Button';
import type { ScanHistoryEntry } from '../../types/device';
import type { Device } from '../../types/device';

function formatTimestamp(ts: number): string {
  return new Date(ts).toLocaleString();
}

function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  const seconds = Math.floor(ms / 1000);
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  const remainingSeconds = seconds % 60;
  return `${minutes}m ${remainingSeconds}s`;
}

function getStatusBadgeClasses(status: string): string {
  switch (status) {
    case 'completed':
      return 'bg-green-100 dark:bg-green-900/50 text-green-700 dark:text-green-400 border-green-200 dark:border-green-700/50';
    case 'cancelled':
      return 'bg-amber-100 dark:bg-amber-900/50 text-amber-700 dark:text-amber-400 border-amber-200 dark:border-amber-700/50';
    case 'error':
      return 'bg-red-100 dark:bg-red-900/50 text-red-700 dark:text-red-400 border-red-200 dark:border-red-700/50';
    default:
      return 'bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-400 border-gray-200 dark:border-gray-600';
  }
}

interface HistoryDetailModalProps {
  entry: ScanHistoryEntry;
  onClose: () => void;
}

const HistoryDetailModal: React.FC<HistoryDetailModalProps> = React.memo(({ entry, onClose }) => {
  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (e.key === 'Escape') {
        onClose();
      }
    },
    [onClose]
  );

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/50"
      onClick={onClose}
      onKeyDown={handleKeyDown}
      role="dialog"
      aria-modal="true"
      aria-label={`Scan details from ${formatTimestamp(entry.timestamp)}`}
    >
      <div
        className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-xl shadow-xl max-w-3xl w-full mx-4 max-h-[80vh] flex flex-col"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between">
          <div>
            <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100">Scan Details</h3>
            <p className="text-sm text-gray-500 dark:text-gray-400">{formatTimestamp(entry.timestamp)}</p>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close details"
            className="p-2 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 text-gray-500 dark:text-gray-400 transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        {/* Summary */}
        <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700 grid grid-cols-2 sm:grid-cols-4 gap-4">
          <div>
            <p className="text-xs text-gray-500 dark:text-gray-400 uppercase font-medium">CIDR</p>
            <p className="text-sm font-mono text-gray-900 dark:text-gray-100">{entry.cidr}</p>
          </div>
          <div>
            <p className="text-xs text-gray-500 dark:text-gray-400 uppercase font-medium">Devices</p>
            <p className="text-sm text-gray-900 dark:text-gray-100">{entry.deviceCount}</p>
          </div>
          <div>
            <p className="text-xs text-gray-500 dark:text-gray-400 uppercase font-medium">Duration</p>
            <p className="text-sm text-gray-900 dark:text-gray-100">{formatDuration(entry.durationMs)}</p>
          </div>
          <div>
            <p className="text-xs text-gray-500 dark:text-gray-400 uppercase font-medium">Status</p>
            <span className={twMerge(clsx('inline-block px-2 py-0.5 text-xs font-medium rounded border', getStatusBadgeClasses(entry.status)))}>
              {entry.status}
            </span>
          </div>
        </div>

        {/* Device list */}
        <div className="flex-1 overflow-auto px-6 py-4">
          {entry.devices.length === 0 ? (
            <p className="text-sm text-gray-500 dark:text-gray-400 text-center py-8">No devices in this scan</p>
          ) : (
            <table className="w-full text-sm">
              <thead className="sticky top-0 bg-white dark:bg-gray-800">
                <tr className="border-b border-gray-200 dark:border-gray-700">
                  <th className="text-left py-2 px-2 text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">IP</th>
                  <th className="text-left py-2 px-2 text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">MAC</th>
                  <th className="text-left py-2 px-2 text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Hostname</th>
                  <th className="text-left py-2 px-2 text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Vendor</th>
                  <th className="text-left py-2 px-2 text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100 dark:divide-gray-700">
                {entry.devices.map((device: Device) => (
                  <tr key={device.mac || device.ip}>
                    <td className="py-2 px-2 font-mono text-gray-900 dark:text-gray-200">{device.ip}</td>
                    <td className="py-2 px-2 font-mono text-gray-600 dark:text-gray-400">{device.mac}</td>
                    <td className="py-2 px-2 text-gray-700 dark:text-gray-300">{device.hostname ?? '—'}</td>
                    <td className="py-2 px-2 text-gray-700 dark:text-gray-300">{device.vendor ?? '—'}</td>
                    <td className="py-2 px-2">
                      <span
                        className={twMerge(
                          clsx(
                            'px-1.5 py-0.5 text-xs rounded',
                            device.status === 'online' && 'bg-green-100 dark:bg-green-900/50 text-green-700 dark:text-green-400',
                            device.status === 'offline' && 'bg-red-100 dark:bg-red-900/50 text-red-700 dark:text-red-400',
                            device.status === 'unknown' && 'bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-400'
                          )
                        )}
                      >
                        {device.status}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
});
HistoryDetailModal.displayName = 'HistoryDetailModal';

interface HistoryRowProps {
  entry: ScanHistoryEntry;
  onViewDetails: (entry: ScanHistoryEntry) => void;
  onRerun: (entry: ScanHistoryEntry) => void;
  onDelete: (id: string) => void;
}

const HistoryRow: React.FC<HistoryRowProps> = React.memo(({ entry, onViewDetails, onRerun, onDelete }) => {
  const handleView = useCallback(() => onViewDetails(entry), [onViewDetails, entry]);
  const handleRerun = useCallback(() => onRerun(entry), [onRerun, entry]);
  const handleDelete = useCallback(() => onDelete(entry.id), [onDelete, entry.id]);

  return (
    <tr className="hover:bg-gray-50 dark:hover:bg-gray-700/50 transition-colors">
      <td className="px-4 py-3 text-sm text-gray-700 dark:text-gray-300 whitespace-nowrap">
        {formatTimestamp(entry.timestamp)}
      </td>
      <td className="px-4 py-3 text-sm font-mono text-gray-900 dark:text-gray-200">{entry.cidr}</td>
      <td className="px-4 py-3 text-sm text-gray-700 dark:text-gray-300">{entry.deviceCount}</td>
      <td className="px-4 py-3 text-sm text-gray-600 dark:text-gray-400">{formatDuration(entry.durationMs)}</td>
      <td className="px-4 py-3">
        <span className={twMerge(clsx('px-2 py-0.5 text-xs font-medium rounded border', getStatusBadgeClasses(entry.status)))}>
          {entry.status}
        </span>
      </td>
      <td className="px-4 py-3">
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={handleView}
            aria-label={`View details for scan at ${formatTimestamp(entry.timestamp)}`}
            className="px-2 py-1 text-xs font-medium text-blue-600 dark:text-blue-400 hover:bg-blue-50 dark:hover:bg-blue-900/30 rounded transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            Details
          </button>
          <button
            type="button"
            onClick={handleRerun}
            aria-label={`Re-run scan for ${entry.cidr}`}
            className="px-2 py-1 text-xs font-medium text-green-600 dark:text-green-400 hover:bg-green-50 dark:hover:bg-green-900/30 rounded transition-colors focus:outline-none focus:ring-2 focus:ring-green-500"
          >
            Re-run
          </button>
          <button
            type="button"
            onClick={handleDelete}
            aria-label={`Delete scan from ${formatTimestamp(entry.timestamp)}`}
            className="px-2 py-1 text-xs font-medium text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/30 rounded transition-colors focus:outline-none focus:ring-2 focus:ring-red-500"
          >
            Delete
          </button>
        </div>
      </td>
    </tr>
  );
});
HistoryRow.displayName = 'HistoryRow';

export const HistoryView: React.FC = () => {
  const entries = useHistoryStore((s) => s.entries);
  const isLoading = useHistoryStore((s) => s.isLoading);
  const error = useHistoryStore((s) => s.error);
  const fetchHistory = useHistoryStore((s) => s.fetchHistory);
  const deleteEntry = useHistoryStore((s) => s.deleteEntry);
  const clearHistory = useHistoryStore((s) => s.clearHistory);
  const clearError = useHistoryStore((s) => s.clearError);

  const setCidr = useScanStore((s) => s.setCidr);
  const setActiveTab = useDashboardStore((s) => s.setActiveTab);

  const [detailEntry, setDetailEntry] = useState<ScanHistoryEntry | null>(null);
  const [confirmClear, setConfirmClear] = useState(false);

  useEffect(() => {
    fetchHistory();
  }, [fetchHistory]);

  const handleViewDetails = useCallback((entry: ScanHistoryEntry) => {
    setDetailEntry(entry);
  }, []);

  const handleCloseDetails = useCallback(() => {
    setDetailEntry(null);
  }, []);

  const handleRerun = useCallback(
    (entry: ScanHistoryEntry) => {
      setCidr(entry.cidr);
      setActiveTab('scan');
    },
    [setCidr, setActiveTab]
  );

  const handleDelete = useCallback(
    (id: string) => {
      deleteEntry(id);
    },
    [deleteEntry]
  );

  const handleClearAll = useCallback(() => {
    if (confirmClear) {
      clearHistory();
      setConfirmClear(false);
    } else {
      setConfirmClear(true);
      // Auto-reset confirm state after 3 seconds
      setTimeout(() => setConfirmClear(false), 3000);
    }
  }, [confirmClear, clearHistory]);

  const sortedEntries = useMemo(() => {
    return [...entries].sort((a, b) => b.timestamp - a.timestamp);
  }, [entries]);

  if (isLoading && entries.length === 0) {
    return (
      <div className="flex items-center justify-center py-12">
        <div className="flex items-center gap-3 text-gray-500 dark:text-gray-400">
          <svg className="w-5 h-5 animate-spin" fill="none" viewBox="0 0 24 24">
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
          </svg>
          <span>Loading history...</span>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Detail Modal */}
      {detailEntry && (
        <HistoryDetailModal entry={detailEntry} onClose={handleCloseDetails} />
      )}

      {/* Error display */}
      {error && (
        <div
          role="alert"
          className="bg-red-50 dark:bg-red-900/30 border border-red-200 dark:border-red-800/50 rounded-lg p-4 flex items-center justify-between"
        >
          <p className="text-sm text-red-700 dark:text-red-300">{error}</p>
          <button
            onClick={clearError}
            className="text-red-500 dark:text-red-400 hover:text-red-700 dark:hover:text-red-300 p-1 rounded-lg hover:bg-red-100 dark:hover:bg-red-900/30 transition-colors focus:outline-none focus:ring-2 focus:ring-red-500"
            aria-label="Dismiss error"
          >
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
      )}

      {/* Header */}
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold text-gray-900 dark:text-gray-100">
          Scan History ({entries.length})
        </h2>
        {entries.length > 0 && (
          <Button
            variant={confirmClear ? 'danger' : 'ghost'}
            size="sm"
            onClick={handleClearAll}
            aria-label={confirmClear ? 'Confirm clear all history' : 'Clear all history'}
          >
            {confirmClear ? 'Confirm Clear All' : 'Clear All'}
          </Button>
        )}
      </div>

      {/* Empty state */}
      {entries.length === 0 && !isLoading && (
        <div className="flex items-center justify-center py-16 text-gray-500 dark:text-gray-400">
          <div className="text-center">
            <svg
              className="w-16 h-16 mx-auto mb-4 text-gray-300 dark:text-gray-600"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
              aria-hidden="true"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={1.5}
                d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"
              />
            </svg>
            <p className="text-lg">No scan history yet</p>
            <p className="text-sm text-gray-400 dark:text-gray-500 mt-1">
              Completed scans will automatically appear here
            </p>
          </div>
        </div>
      )}

      {/* History table */}
      {entries.length > 0 && (
        <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-xl overflow-hidden shadow-sm">
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-gray-50 dark:bg-gray-750 border-b border-gray-200 dark:border-gray-700">
                <tr>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Date & Time
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    CIDR
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Devices
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Duration
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Status
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100 dark:divide-gray-700">
                {sortedEntries.map((entry) => (
                  <HistoryRow
                    key={entry.id}
                    entry={entry}
                    onViewDetails={handleViewDetails}
                    onRerun={handleRerun}
                    onDelete={handleDelete}
                  />
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};
