import React, { useCallback } from 'react';
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';
import {
  useTopologyStore,
  useTopologyViewMode,
  useTopologyClusterBy,
} from '../../stores/topologyStore';
import type { ViewMode, ClusterBy } from '../../stores/topologyStore';

interface TopologyControlsProps {
  onFitView: () => void;
}

export const TopologyControls: React.FC<TopologyControlsProps> = ({ onFitView }) => {
  const viewMode = useTopologyViewMode();
  const clusterBy = useTopologyClusterBy();
  const setViewMode = useTopologyStore((s) => s.setViewMode);
  const setClusterBy = useTopologyStore((s) => s.setClusterBy);
  const expandAll = useTopologyStore((s) => s.expandAll);
  const collapseAll = useTopologyStore((s) => s.collapseAll);

  const handleViewModeChange = useCallback(
    (mode: ViewMode) => {
      setViewMode(mode);
    },
    [setViewMode]
  );

  const handleClusterByChange = useCallback(
    (by: ClusterBy) => {
      setClusterBy(by);
    },
    [setClusterBy]
  );

  return (
    <div className="flex flex-wrap items-center gap-3 p-3 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-xl shadow-sm">
      {/* View mode toggle */}
      <div className="flex items-center gap-1 bg-gray-100 dark:bg-gray-700 rounded-lg p-0.5" role="radiogroup" aria-label="View mode">
        <button
          type="button"
          role="radio"
          aria-checked={viewMode === 'flat'}
          onClick={() => handleViewModeChange('flat')}
          className={twMerge(
            clsx(
              'px-3 py-1.5 text-xs font-medium rounded-md transition-colors',
              'focus:outline-none focus:ring-2 focus:ring-blue-500',
              viewMode === 'flat'
                ? 'bg-white dark:bg-gray-600 text-gray-900 dark:text-gray-100 shadow-sm'
                : 'text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-200'
            )
          )}
        >
          Flat
        </button>
        <button
          type="button"
          role="radio"
          aria-checked={viewMode === 'clustered'}
          onClick={() => handleViewModeChange('clustered')}
          className={twMerge(
            clsx(
              'px-3 py-1.5 text-xs font-medium rounded-md transition-colors',
              'focus:outline-none focus:ring-2 focus:ring-blue-500',
              viewMode === 'clustered'
                ? 'bg-white dark:bg-gray-600 text-gray-900 dark:text-gray-100 shadow-sm'
                : 'text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-200'
            )
          )}
        >
          Clustered
        </button>
      </div>

      {/* Cluster by selector (only in clustered mode) */}
      {viewMode === 'clustered' && (
        <>
          <div className="h-5 w-px bg-gray-300 dark:bg-gray-600" aria-hidden="true" />

          <div className="flex items-center gap-2">
            <span className="text-xs text-gray-500 dark:text-gray-400">Group by:</span>
            <div className="flex items-center gap-1 bg-gray-100 dark:bg-gray-700 rounded-lg p-0.5" role="radiogroup" aria-label="Cluster by">
              <button
                type="button"
                role="radio"
                aria-checked={clusterBy === 'subnet'}
                onClick={() => handleClusterByChange('subnet')}
                className={twMerge(
                  clsx(
                    'px-2.5 py-1 text-xs font-medium rounded-md transition-colors',
                    'focus:outline-none focus:ring-2 focus:ring-blue-500',
                    clusterBy === 'subnet'
                      ? 'bg-white dark:bg-gray-600 text-gray-900 dark:text-gray-100 shadow-sm'
                      : 'text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-200'
                  )
                )}
              >
                Subnet
              </button>
              <button
                type="button"
                role="radio"
                aria-checked={clusterBy === 'vendor'}
                onClick={() => handleClusterByChange('vendor')}
                className={twMerge(
                  clsx(
                    'px-2.5 py-1 text-xs font-medium rounded-md transition-colors',
                    'focus:outline-none focus:ring-2 focus:ring-blue-500',
                    clusterBy === 'vendor'
                      ? 'bg-white dark:bg-gray-600 text-gray-900 dark:text-gray-100 shadow-sm'
                      : 'text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-200'
                  )
                )}
              >
                Vendor
              </button>
            </div>
          </div>

          <div className="h-5 w-px bg-gray-300 dark:bg-gray-600" aria-hidden="true" />

          <button
            type="button"
            onClick={expandAll}
            className="px-2.5 py-1 text-xs font-medium text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-200 bg-gray-100 dark:bg-gray-700 hover:bg-gray-200 dark:hover:bg-gray-600 rounded-md transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500"
            aria-label="Expand all clusters"
          >
            Expand All
          </button>
          <button
            type="button"
            onClick={collapseAll}
            className="px-2.5 py-1 text-xs font-medium text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-200 bg-gray-100 dark:bg-gray-700 hover:bg-gray-200 dark:hover:bg-gray-600 rounded-md transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500"
            aria-label="Collapse all clusters"
          >
            Collapse All
          </button>
        </>
      )}

      {/* Fit view button */}
      <div className="ml-auto">
        <button
          type="button"
          onClick={onFitView}
          className="px-2.5 py-1 text-xs font-medium text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-200 bg-gray-100 dark:bg-gray-700 hover:bg-gray-200 dark:hover:bg-gray-600 rounded-md transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500"
          aria-label="Fit view to screen"
        >
          Fit View
        </button>
      </div>
    </div>
  );
};
