import React, { Component, type ReactNode } from 'react';
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';

interface ErrorBoundaryProps {
  children: ReactNode;
  fallback?: ReactNode;
  onError?: (error: Error, errorInfo: React.ErrorInfo) => void;
}

interface ErrorBoundaryState {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  constructor(props: ErrorBoundaryProps) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo): void {
    console.error('ErrorBoundary caught an error:', error, errorInfo);
    this.props.onError?.(error, errorInfo);
  }

  render(): ReactNode {
    if (this.state.hasError) {
      if (this.props.fallback) {
        return this.props.fallback;
      }

      return (
        <div className="flex flex-col items-center justify-center py-12 px-4">
          <div className="max-w-md w-full">
            <div className="bg-red-900/30 border border-red-800/50 rounded-xl p-6 text-center">
              <svg
                className="w-12 h-12 mx-auto mb-4 text-red-400"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={1.5}
                  d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
                />
              </svg>
              <h2 className="text-lg font-semibold text-red-300 mb-2">
                Something went wrong
              </h2>
              <p className="text-sm text-red-200/70 mb-4">
                {this.state.error?.message || 'An unexpected error occurred'}
              </p>
              <button
                onClick={() => this.setState({ hasError: false, error: null })}
                className={twMerge(
                  clsx(
                    'px-4 py-2 bg-red-800/50 hover:bg-red-800/70',
                    'text-red-200 text-sm font-medium rounded-lg',
                    'transition-colors duration-200'
                  )
                )}
              >
                Try again
              </button>
            </div>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

// Helper to check if a value is null or undefined
export function isNullOrUndefined<T>(value: T | null | undefined): value is null | undefined {
  return value === null || value === undefined;
}

// Helper to safely access nested properties
export function safeAccess<T, K extends keyof T>(
  obj: T | null | undefined,
  key: K
): T[K] | undefined {
  if (isNullOrUndefined(obj)) return undefined;
  return obj[key];
}

// Safe getter for settings that ensures defaults
export function getSafeSettings<T extends { scanConfig?: unknown; uiPreferences?: unknown }>(
  settings: T | null | undefined,
  defaults: { scanConfig: NonNullable<T['scanConfig']>; uiPreferences: NonNullable<T['uiPreferences']> }
): { scanConfig: NonNullable<T['scanConfig']>; uiPreferences: NonNullable<T['uiPreferences']> } {
  if (isNullOrUndefined(settings)) {
    return defaults;
  }

  return {
    scanConfig: settings.scanConfig ?? defaults.scanConfig,
    uiPreferences: settings.uiPreferences ?? defaults.uiPreferences,
  };
}