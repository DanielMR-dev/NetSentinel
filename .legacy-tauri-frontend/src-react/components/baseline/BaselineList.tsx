import React, { useCallback } from 'react';
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';
import type { Baseline } from '../../types/device';

interface BaselineListProps {
  baselines: Baseline[];
  onCompare: (id: string) => void;
  onDelete: (id: string) => void;
  isLoading: boolean;
}

export const BaselineList: React.FC<BaselineListProps> = ({ baselines, onCompare, onDelete, isLoading }) => {
  if (baselines.length === 0) {
    return (
      <div className="p-8 text-center text-gray-500 dark:text-gray-500">
        <svg className="w-12 h-12 mx-auto mb-3 text-gray-400 dark:text-gray-600" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
        </svg>
        <p className="text-sm">No baselines saved</p>
        <p className="text-xs text-gray-400 dark:text-gray-600 mt-1">
          Run a scan and create a baseline to start monitoring.
        </p>
      </div>
    );
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full">
        <thead className="bg-gray-50 dark:bg-gray-750 border-b border-gray-200 dark:border-gray-700">
          <tr>
            <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
              Name
            </th>
            <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
              CIDR
            </th>
            <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
              Devices
            </th>
            <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
              Created
            </th>
            <th className="px-4 py-3 text-right text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
              Actions
            </th>
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-100 dark:divide-gray-700">
          {baselines.map((baseline) => (
            <BaselineRow
              key={baseline.id}
              baseline={baseline}
              onCompare={onCompare}
              onDelete={onDelete}
              isLoading={isLoading}
            />
          ))}
        </tbody>
      </table>
    </div>
  );
};

interface BaselineRowProps {
  baseline: Baseline;
  onCompare: (id: string) => void;
  onDelete: (id: string) => void;
  isLoading: boolean;
}

const BaselineRow: React.FC<BaselineRowProps> = React.memo(({ baseline, onCompare, onDelete, isLoading }) => {
  const handleCompare = useCallback(() => {
    onCompare(baseline.id);
  }, [baseline.id, onCompare]);

  const handleDelete = useCallback(() => {
    onDelete(baseline.id);
  }, [baseline.id, onDelete]);

  return (
    <tr className="hover:bg-gray-50 dark:hover:bg-gray-700/50 transition-colors">
      <td className="px-4 py-3">
        <div>
          <span className="text-sm font-medium text-gray-900 dark:text-gray-200">{baseline.name}</span>
          {baseline.description && (
            <p className="text-xs text-gray-500 dark:text-gray-400 mt-0.5">{baseline.description}</p>
          )}
        </div>
      </td>
      <td className="px-4 py-3 text-sm text-gray-700 dark:text-gray-300 font-mono">{baseline.scanCidr}</td>
      <td className="px-4 py-3 text-sm text-gray-700 dark:text-gray-300">{baseline.devices.length}</td>
      <td className="px-4 py-3 text-sm text-gray-500 dark:text-gray-400">
        {new Date(baseline.createdAt * 1000).toLocaleDateString()}
      </td>
      <td className="px-4 py-3 text-right">
        <div className="flex items-center justify-end gap-2">
          <button
            type="button"
            onClick={handleCompare}
            disabled={isLoading}
            className={twMerge(
              clsx(
                'px-3 py-1.5 text-xs font-medium rounded-lg transition-colors',
                'bg-blue-600 text-white hover:bg-blue-700',
                'focus:outline-none focus:ring-2 focus:ring-blue-500',
                'disabled:opacity-50 disabled:cursor-not-allowed'
              )
            )}
          >
            Compare
          </button>
          <button
            type="button"
            onClick={handleDelete}
            disabled={isLoading}
            className={twMerge(
              clsx(
                'px-3 py-1.5 text-xs font-medium rounded-lg transition-colors',
                'bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300 hover:bg-red-200 dark:hover:bg-red-900/50',
                'focus:outline-none focus:ring-2 focus:ring-red-500',
                'disabled:opacity-50 disabled:cursor-not-allowed'
              )
            )}
            aria-label={`Delete baseline ${baseline.name}`}
          >
            Delete
          </button>
        </div>
      </td>
    </tr>
  );
});
BaselineRow.displayName = 'BaselineRow';
