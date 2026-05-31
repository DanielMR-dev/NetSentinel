import React, { useState, useCallback, useRef, useEffect } from 'react';
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';
import { useScanStore } from '../../stores/scanStore';
import { useBaselineStore } from '../../stores/baselineStore';
import type { Baseline } from '../../types/device';

interface BaselineCreateModalProps {
  onClose: () => void;
}

export const BaselineCreateModal: React.FC<BaselineCreateModalProps> = ({ onClose }) => {
  const devices = useScanStore((s) => s.devices);
  const cidr = useScanStore((s) => s.cidr);
  const saveBaseline = useBaselineStore((s) => s.saveBaseline);
  const isLoading = useBaselineStore((s) => s.isLoading);

  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [error, setError] = useState<string | null>(null);
  const nameInputRef = useRef<HTMLInputElement>(null);

  // Focus name input on mount
  useEffect(() => {
    nameInputRef.current?.focus();
  }, []);

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (e.key === 'Escape') {
        onClose();
      }
    },
    [onClose]
  );

  const handleSave = useCallback(async () => {
    if (!name.trim()) {
      setError('Name is required');
      return;
    }

    const baseline: Baseline = {
      id: crypto.randomUUID(),
      name: name.trim(),
      description: description.trim() || null,
      devices,
      scanCidr: cidr,
      createdAt: Math.floor(Date.now() / 1000),
    };

    try {
      await saveBaseline(baseline);
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to save baseline');
    }
  }, [name, description, devices, cidr, saveBaseline, onClose]);

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/50"
      onClick={onClose}
      onKeyDown={handleKeyDown}
      role="dialog"
      aria-modal="true"
      aria-label="Create baseline"
    >
      <div
        className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-xl shadow-xl max-w-md w-full mx-4"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100">Create Baseline</h3>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close modal"
            className="p-2 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 text-gray-500 dark:text-gray-400 transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        {/* Content */}
        <div className="px-6 py-4 space-y-4">
          {/* Scan summary */}
          <div className="p-3 bg-gray-50 dark:bg-gray-750 rounded-lg">
            <p className="text-xs text-gray-500 dark:text-gray-400 uppercase font-medium mb-1">Current Scan Summary</p>
            <div className="flex items-center gap-4 text-sm">
              <span className="text-gray-700 dark:text-gray-300">
                <span className="font-semibold">{devices.length}</span> devices
              </span>
              <span className="text-gray-700 dark:text-gray-300 font-mono">{cidr}</span>
            </div>
          </div>

          {/* Name input */}
          <div>
            <label htmlFor="baseline-name" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1.5">
              Name <span className="text-red-500">*</span>
            </label>
            <input
              ref={nameInputRef}
              id="baseline-name"
              type="text"
              value={name}
              onChange={(e) => { setName(e.target.value); setError(null); }}
              placeholder="e.g., Production Network - Jan 2026"
              disabled={isLoading}
              className={twMerge(
                clsx(
                  'w-full px-4 py-2.5 bg-white dark:bg-gray-900/80 border rounded-xl',
                  'text-gray-900 dark:text-gray-100 placeholder-gray-400 dark:placeholder-gray-500',
                  'focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent',
                  'disabled:opacity-50 disabled:cursor-not-allowed',
                  error ? 'border-red-500' : 'border-gray-300 dark:border-gray-600/50'
                )
              )}
            />
            {error && (
              <p className="mt-1 text-xs text-red-500" role="alert">{error}</p>
            )}
          </div>

          {/* Description input */}
          <div>
            <label htmlFor="baseline-description" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1.5">
              Description <span className="text-gray-400 dark:text-gray-500 font-normal">(optional)</span>
            </label>
            <textarea
              id="baseline-description"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Describe this baseline..."
              disabled={isLoading}
              rows={2}
              className={twMerge(
                clsx(
                  'w-full px-4 py-2.5 bg-white dark:bg-gray-900/80 border border-gray-300 dark:border-gray-600/50 rounded-xl',
                  'text-gray-900 dark:text-gray-100 placeholder-gray-400 dark:placeholder-gray-500',
                  'focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent',
                  'disabled:opacity-50 disabled:cursor-not-allowed',
                  'resize-none'
                )
              )}
            />
          </div>
        </div>

        {/* Footer */}
        <div className="px-6 py-4 border-t border-gray-200 dark:border-gray-700 flex items-center justify-end gap-3">
          <button
            type="button"
            onClick={onClose}
            disabled={isLoading}
            className="px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 bg-gray-100 dark:bg-gray-700 hover:bg-gray-200 dark:hover:bg-gray-600 rounded-xl transition-colors focus:outline-none focus:ring-2 focus:ring-gray-500 disabled:opacity-50"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={handleSave}
            disabled={isLoading || !name.trim()}
            className={twMerge(
              clsx(
                'px-4 py-2 text-sm font-medium rounded-xl transition-colors',
                'bg-blue-600 text-white hover:bg-blue-700',
                'focus:outline-none focus:ring-2 focus:ring-blue-500',
                'disabled:opacity-50 disabled:cursor-not-allowed'
              )
            )}
          >
            {isLoading ? 'Saving...' : 'Save Baseline'}
          </button>
        </div>
      </div>
    </div>
  );
};
