import React, { useState, useCallback } from 'react';
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';
import type { CveMatch, CveSeverity } from '../../types/device';

interface CveAlertCardProps {
  cve: CveMatch;
}

function getSeverityStyles(severity: CveSeverity) {
  switch (severity) {
    case 'critical':
      return {
        border: 'border-red-500',
        bg: 'bg-red-50 dark:bg-red-900/20',
        badge: 'bg-red-600 text-white',
        text: 'text-red-800 dark:text-red-200',
        score: 'bg-red-600 text-white',
      };
    case 'high':
      return {
        border: 'border-orange-500',
        bg: 'bg-orange-50 dark:bg-orange-900/20',
        badge: 'bg-orange-500 text-white',
        text: 'text-orange-800 dark:text-orange-200',
        score: 'bg-orange-500 text-white',
      };
    case 'medium':
      return {
        border: 'border-yellow-500',
        bg: 'bg-yellow-50 dark:bg-yellow-900/20',
        badge: 'bg-yellow-500 text-white',
        text: 'text-yellow-800 dark:text-yellow-200',
        score: 'bg-yellow-500 text-white',
      };
    case 'low':
      return {
        border: 'border-blue-500',
        bg: 'bg-blue-50 dark:bg-blue-900/20',
        badge: 'bg-blue-500 text-white',
        text: 'text-blue-800 dark:text-blue-200',
        score: 'bg-blue-500 text-white',
      };
  }
}

export const CveAlertCard: React.FC<CveAlertCardProps> = React.memo(({ cve }) => {
  const [expanded, setExpanded] = useState(false);
  const styles = getSeverityStyles(cve.severity);

  const handleToggle = useCallback(() => {
    setExpanded((prev) => !prev);
  }, []);

  return (
    <div
      className={twMerge(
        clsx(
          'border-l-4 rounded-lg overflow-hidden',
          styles.border,
          styles.bg
        )
      )}
    >
      <button
        type="button"
        onClick={handleToggle}
        className="w-full px-3 py-2 flex items-start gap-3 text-left hover:brightness-95 transition-all focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-inset"
        aria-expanded={expanded}
      >
        {/* Severity badge */}
        <span className={clsx('px-1.5 py-0.5 text-[10px] font-bold rounded uppercase flex-shrink-0', styles.badge)}>
          {cve.severity}
        </span>

        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className={clsx('text-sm font-bold font-mono', styles.text)}>
              {cve.cveId}
            </span>
            {/* CVSS Score badge */}
            <span className={clsx('px-1.5 py-0.5 text-[10px] font-bold rounded', styles.score)}>
              {cve.cvssScore.toFixed(1)}
            </span>
          </div>
          <p className="text-xs text-gray-600 dark:text-gray-400 mt-0.5 line-clamp-2">
            {cve.description}
          </p>
        </div>

        <svg
          className={clsx('w-4 h-4 text-gray-400 flex-shrink-0 mt-1 transition-transform duration-200', expanded && 'rotate-180')}
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
          aria-hidden="true"
        >
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </button>

      {expanded && (
        <div className="px-3 pb-3 space-y-2 border-t border-gray-200 dark:border-gray-700/50">
          <div className="mt-2">
            <span className="text-[10px] font-medium text-gray-500 dark:text-gray-400 uppercase">Affected Software</span>
            <p className="text-xs text-gray-700 dark:text-gray-300">{cve.affectedSoftware}</p>
          </div>
          {cve.affectedVersions.length > 0 && (
            <div>
              <span className="text-[10px] font-medium text-gray-500 dark:text-gray-400 uppercase">Affected Versions</span>
              <div className="flex flex-wrap gap-1 mt-0.5">
                {cve.affectedVersions.map((version, i) => (
                  <span key={i} className="px-1.5 py-0.5 text-[10px] font-mono bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded">
                    {version}
                  </span>
                ))}
              </div>
            </div>
          )}
          <div>
            <span className="text-[10px] font-medium text-gray-500 dark:text-gray-400 uppercase">Description</span>
            <p className="text-xs text-gray-600 dark:text-gray-400 mt-0.5">{cve.description}</p>
          </div>
        </div>
      )}
    </div>
  );
});
CveAlertCard.displayName = 'CveAlertCard';
