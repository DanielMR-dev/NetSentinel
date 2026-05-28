import React, { useState, useCallback } from 'react';
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';
import { useCapabilities } from '../../stores/capabilitiesStore';

/**
 * A dismissible banner shown when the app is running without elevated privileges.
 * Displays the first warning from the platform capabilities.
 */
export const PrivilegeBanner: React.FC = () => {
  const capabilities = useCapabilities();
  const [dismissed, setDismissed] = useState(false);

  const handleDismiss = useCallback(() => {
    setDismissed(true);
  }, []);

  // Don't render if:
  // - Capabilities haven't loaded yet
  // - Running with elevated privileges
  // - No warnings to display
  // - User has dismissed the banner
  if (
    capabilities === null ||
    capabilities.isElevated ||
    capabilities.warnings.length === 0 ||
    dismissed
  ) {
    return null;
  }

  const primaryWarning = capabilities.warnings[0];

  return (
    <div
      role="alert"
      aria-live="polite"
      className={twMerge(
        clsx(
          'mx-6 mt-4 px-4 py-3 rounded-lg',
          'bg-amber-50 dark:bg-amber-900/30 border border-amber-300 dark:border-amber-700/50',
          'flex items-start gap-3'
        )
      )}
    >
      {/* Warning icon (inline SVG, no external deps) */}
      <svg
        className="w-5 h-5 text-amber-500 dark:text-amber-400 flex-shrink-0 mt-0.5"
        fill="none"
        viewBox="0 0 24 24"
        stroke="currentColor"
        aria-hidden="true"
      >
        <path
          strokeLinecap="round"
          strokeLinejoin="round"
          strokeWidth={2}
          d="M12 9v2m0 4h.01M10.29 3.86l-8.58 14.86A1 1 0 002.58 20h18.84a1 1 0 00.87-1.5L13.71 3.86a1 1 0 00-1.72 0z"
        />
      </svg>

      {/* Warning text */}
      <div className="flex-1 min-w-0">
        <p className="text-sm text-amber-800 dark:text-amber-200">
          <span className="font-semibold">Limited Privileges: </span>
          {primaryWarning}
        </p>
        {capabilities.warnings.length > 1 && (
          <p className="text-xs text-amber-600 dark:text-amber-300/70 mt-1">
            +{capabilities.warnings.length - 1} additional warning{capabilities.warnings.length > 2 ? 's' : ''}
          </p>
        )}
      </div>

      {/* Dismiss button */}
      <button
        type="button"
        onClick={handleDismiss}
        aria-label="Dismiss privilege warning"
        className={twMerge(
          clsx(
            'flex-shrink-0 p-1 rounded-md',
            'text-amber-500 dark:text-amber-400 hover:text-amber-700 dark:hover:text-amber-200',
            'hover:bg-amber-100 dark:hover:bg-amber-800/30',
            'focus:outline-none focus:ring-2 focus:ring-amber-500 focus:ring-offset-1 focus:ring-offset-white dark:focus:ring-offset-gray-900',
            'transition-colors duration-150'
          )
        )}
      >
        <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
        </svg>
      </button>
    </div>
  );
};
