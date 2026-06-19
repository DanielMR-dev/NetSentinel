import React, { useEffect, useCallback, useRef, useState } from 'react';
import { useBaselineStore, useBaselines, useBaselineDiff, useBaselineLoading, useBaselineError } from '../../stores/baselineStore';
import { BaselineList } from './BaselineList';
import { BaselineCreateModal } from './BaselineCreateModal';
import { BaselineDiffView } from './BaselineDiffView';
import { useScanStore } from '../../stores/scanStore';

export const BaselineView: React.FC = () => {
  const fetchBaselines = useBaselineStore((s) => s.fetchBaselines);
  const deleteBaseline = useBaselineStore((s) => s.deleteBaseline);
  const compareBaseline = useBaselineStore((s) => s.compareBaseline);
  const clearDiff = useBaselineStore((s) => s.clearDiff);
  const clearError = useBaselineStore((s) => s.clearError);

  const baselines = useBaselines();
  const currentDiff = useBaselineDiff();
  const isLoading = useBaselineLoading();
  const error = useBaselineError();

  const devices = useScanStore((s) => s.devices);

  const [showCreateModal, setShowCreateModal] = useState(false);
  const hasFetched = useRef(false);

  useEffect(() => {
    if (!hasFetched.current) {
      hasFetched.current = true;
      fetchBaselines();
    }
  }, [fetchBaselines]);

  const handleCreate = useCallback(() => {
    setShowCreateModal(true);
  }, []);

  const handleCloseCreate = useCallback(() => {
    setShowCreateModal(false);
  }, []);

  const handleCompare = useCallback(
    (id: string) => {
      compareBaseline(id);
    },
    [compareBaseline]
  );

  const handleDelete = useCallback(
    async (id: string) => {
      try {
        await deleteBaseline(id);
      } catch {
        // Error is handled by the store
      }
    },
    [deleteBaseline]
  );

  const handleCloseDiff = useCallback(() => {
    clearDiff();
  }, [clearDiff]);

  const canCreateBaseline = devices.length > 0;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-gray-900 dark:text-gray-100">Baseline Integrity Monitor</h2>
          <p className="text-sm text-gray-500 dark:text-gray-400 mt-0.5">
            Save network snapshots and compare future scans to detect changes.
          </p>
        </div>
        <button
          type="button"
          onClick={handleCreate}
          disabled={!canCreateBaseline || isLoading}
          className="px-4 py-2 text-sm font-medium bg-blue-600 text-white rounded-xl hover:bg-blue-700 transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed"
          title={!canCreateBaseline ? 'Run a scan first to create a baseline' : 'Save current scan as baseline'}
        >
          Create Baseline
        </button>
      </div>

      {/* Error display */}
      {error && (
        <div
          role="alert"
          className="p-3 bg-red-50 dark:bg-red-900/30 border border-red-200 dark:border-red-800/50 rounded-xl flex items-center justify-between"
        >
          <span className="text-sm text-red-700 dark:text-red-300">{error}</span>
          <button
            onClick={clearError}
            className="text-red-500 dark:text-red-400 hover:text-red-700 dark:hover:text-red-300 p-1 rounded-lg hover:bg-red-100 dark:hover:bg-red-900/30 transition-colors"
            aria-label="Dismiss error"
          >
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
      )}

      {/* Diff view (shown when comparing) */}
      {currentDiff && (
        <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-xl p-5">
          <BaselineDiffView diff={currentDiff} onClose={handleCloseDiff} />
        </div>
      )}

      {/* Baseline list */}
      <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-xl overflow-hidden">
        {isLoading && baselines.length === 0 ? (
          <div className="p-8 text-center">
            <div className="w-8 h-8 border-2 border-blue-500 border-t-transparent rounded-full animate-spin mx-auto mb-3" />
            <p className="text-sm text-gray-500 dark:text-gray-500">Loading baselines...</p>
          </div>
        ) : (
          <BaselineList
            baselines={baselines}
            onCompare={handleCompare}
            onDelete={handleDelete}
            isLoading={isLoading}
          />
        )}
      </div>

      {/* Create modal */}
      {showCreateModal && <BaselineCreateModal onClose={handleCloseCreate} />}
    </div>
  );
};
