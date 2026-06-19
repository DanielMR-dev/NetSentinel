import React, { useState, useCallback, useMemo } from 'react';
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';
import { useCapabilities, usePrivilegeStatus } from '../../stores/capabilitiesStore';

type PrivilegeLevel = 'full' | 'partial' | 'none';

function getPrivilegeLevel(
  capabilities: ReturnType<typeof useCapabilities>,
  privilegeStatus: ReturnType<typeof usePrivilegeStatus>
): PrivilegeLevel {
  if (privilegeStatus !== null) {
    if (privilegeStatus.isElevated && privilegeStatus.hasRawSocket) return 'full';
    if (privilegeStatus.isElevated || privilegeStatus.hasCapNetRaw) return 'partial';
    return 'none';
  }
  if (capabilities !== null) {
    if (capabilities.isElevated) return 'full';
    return 'none';
  }
  return 'full'; // assume full before data loads
}

function getPlatformInstructions(platform: string): string {
  switch (platform) {
    case 'linux':
      return 'Run with sudo or grant CAP_NET_RAW: sudo setcap cap_net_raw+ep ./netsentinel';
    case 'macos':
      return 'Run with sudo for full scanning capabilities';
    case 'windows':
      return 'Run as Administrator for full scanning capabilities';
    default:
      return 'Run with elevated privileges for full scanning capabilities';
  }
}

function getLevelStyles(level: PrivilegeLevel) {
  switch (level) {
    case 'full':
      return {
        container: 'bg-green-50 dark:bg-green-900/30 border-green-300 dark:border-green-700/50',
        icon: 'text-green-500 dark:text-green-400',
        title: 'text-green-800 dark:text-green-200',
        text: 'text-green-700 dark:text-green-300',
      };
    case 'partial':
      return {
        container: 'bg-amber-50 dark:bg-amber-900/30 border-amber-300 dark:border-amber-700/50',
        icon: 'text-amber-500 dark:text-amber-400',
        title: 'text-amber-800 dark:text-amber-200',
        text: 'text-amber-700 dark:text-amber-300',
      };
    case 'none':
      return {
        container: 'bg-red-50 dark:bg-red-900/30 border-red-300 dark:border-red-700/50',
        icon: 'text-red-500 dark:text-red-400',
        title: 'text-red-800 dark:text-red-200',
        text: 'text-red-700 dark:text-red-300',
      };
  }
}

export const PrivilegeBanner: React.FC = () => {
  const capabilities = useCapabilities();
  const privilegeStatus = usePrivilegeStatus();
  const [dismissed, setDismissed] = useState(false);

  const handleDismiss = useCallback(() => {
    setDismissed(true);
  }, []);

  const level = useMemo(
    () => getPrivilegeLevel(capabilities, privilegeStatus),
    [capabilities, privilegeStatus]
  );

  const styles = useMemo(() => getLevelStyles(level), [level]);

  // Don't render if fully privileged or dismissed or not yet loaded
  if (level === 'full' || dismissed) {
    return null;
  }

  // Gather warnings from both sources
  const warnings: string[] = [];
  if (privilegeStatus !== null) {
    warnings.push(...privilegeStatus.warnings);
  } else if (capabilities !== null) {
    warnings.push(...capabilities.warnings);
  }

  const platform = privilegeStatus?.platform ?? capabilities?.platform ?? 'unknown';
  const instructions = getPlatformInstructions(platform);

  return (
    <div
      role="alert"
      aria-live="polite"
      className={twMerge(
        clsx(
          'mx-6 mt-4 px-4 py-3 rounded-lg border',
          'flex items-start gap-3',
          styles.container
        )
      )}
    >
      {/* Status icon */}
      {level === 'partial' ? (
        <svg
          className={clsx('w-5 h-5 flex-shrink-0 mt-0.5', styles.icon)}
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
      ) : (
        <svg
          className={clsx('w-5 h-5 flex-shrink-0 mt-0.5', styles.icon)}
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
          aria-hidden="true"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
          />
        </svg>
      )}

      {/* Content */}
      <div className="flex-1 min-w-0">
        <p className={clsx('text-sm font-semibold', styles.title)}>
          {level === 'partial' ? 'Partially Elevated Privileges' : 'No Elevated Privileges'}
        </p>

        {/* Privilege details grid */}
        {privilegeStatus !== null && (
          <div className="mt-2 grid grid-cols-2 sm:grid-cols-4 gap-2">
            <PrivilegeIndicator label="Elevated" value={privilegeStatus.isElevated} />
            <PrivilegeIndicator label="Raw Socket" value={privilegeStatus.hasRawSocket} />
            <PrivilegeIndicator label="CAP_NET_RAW" value={privilegeStatus.hasCapNetRaw} />
            <PrivilegeIndicator label="SYN Scan" value={privilegeStatus.synScanAvailable} />
          </div>
        )}

        {/* Warnings */}
        {warnings.length > 0 && (
          <div className="mt-2 space-y-1">
            {warnings.map((warning, i) => (
              <p key={i} className={clsx('text-xs', styles.text)}>
                {warning}
              </p>
            ))}
          </div>
        )}

        {/* Platform-specific instructions */}
        <p className={clsx('text-xs mt-2 font-mono', styles.text)}>
          {instructions}
        </p>
      </div>

      {/* Dismiss button */}
      <button
        type="button"
        onClick={handleDismiss}
        aria-label="Dismiss privilege warning"
        className={twMerge(
          clsx(
            'flex-shrink-0 p-1 rounded-md',
            styles.icon,
            'hover:opacity-70',
            'focus:outline-none focus:ring-2 focus:ring-offset-1 focus:ring-offset-white dark:focus:ring-offset-gray-900',
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

interface PrivilegeIndicatorProps {
  label: string;
  value: boolean;
}

const PrivilegeIndicator: React.FC<PrivilegeIndicatorProps> = React.memo(({ label, value }) => (
  <div className="flex items-center gap-1.5">
    {value ? (
      <svg className="w-3.5 h-3.5 text-green-500 dark:text-green-400" fill="currentColor" viewBox="0 0 20 20" aria-hidden="true">
        <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
      </svg>
    ) : (
      <svg className="w-3.5 h-3.5 text-red-500 dark:text-red-400" fill="currentColor" viewBox="0 0 20 20" aria-hidden="true">
        <path fillRule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clipRule="evenodd" />
      </svg>
    )}
    <span className="text-xs text-gray-600 dark:text-gray-400">{label}</span>
  </div>
));
PrivilegeIndicator.displayName = 'PrivilegeIndicator';
