import React from 'react';
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';
import { LoadingSpinner } from './LoadingSpinner';

interface CardProps {
  title: string;
  children: React.ReactNode;
  className?: string;
  onReload?: () => void;
  isLoading?: boolean;
  error?: string | null;
}

export const Card: React.FC<CardProps> = ({
  title,
  children,
  className,
  onReload,
  isLoading = false,
  error = null,
}) => {
  const mergedClassName = twMerge(
    clsx(
      // Base container with gradient and shadow
      'bg-gradient-to-b from-gray-50 to-gray-100 dark:from-gray-800 dark:to-gray-800/95',
      'border border-gray-200 dark:border-gray-700/50 rounded-2xl',
      'shadow-card hover:shadow-card-hover transition-shadow duration-300',
      // Inner content area
      'overflow-hidden',
      className
    )
  );

  return (
    <div className={mergedClassName}>
      {/* Header with subtle gradient */}
      <div className="relative px-6 py-4 border-b border-gray-200 dark:border-gray-700/30">
        <div className="absolute inset-0 bg-gradient-to-r from-blue-600/5 via-transparent to-transparent" />
        <div className="relative flex items-center justify-between">
          <h2 className="text-lg font-semibold text-gray-900 dark:text-gray-100">{title}</h2>
          {onReload && (
            <button
              onClick={onReload}
              disabled={isLoading}
              aria-label={`Reload ${title}`}
              className={twMerge(
                clsx(
                  'p-2 rounded-xl transition-all duration-200',
                  'hover:bg-gray-200 dark:hover:bg-gray-700/50 focus:outline-none focus:ring-2 focus:ring-blue-500',
                  'text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-200',
                  'disabled:opacity-50 disabled:cursor-not-allowed',
                  'hover:scale-105 active:scale-95'
                )
              )}
            >
              {isLoading ? (
                <LoadingSpinner size="sm" color="gray" />
              ) : (
                <svg
                  className="w-5 h-5"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                  aria-hidden="true"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"
                  />
                </svg>
              )}
            </button>
          )}
        </div>
      </div>

      {/* Content area */}
      <div className="px-6 py-5">
        {error && (
          <div
            role="alert"
            className="mb-4 p-3 bg-red-50 dark:bg-red-900/30 border border-red-200 dark:border-red-800/50 rounded-xl text-sm text-red-700 dark:text-red-300"
          >
            {error}
          </div>
        )}
        <div>{children}</div>
      </div>
    </div>
  );
};
