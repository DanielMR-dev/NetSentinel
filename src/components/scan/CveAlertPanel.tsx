import React, { useMemo, useState, useCallback } from 'react';
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';
import { useBannerStore } from '../../stores/bannerStore';
import { CveAlertCard } from './CveAlertCard';
import type { CveSeverity, CveAlertEvent } from '../../types/device';

interface CveAlertPanelProps {
  ip?: string; // If provided, filter to a specific host
}

type SeverityFilter = 'all' | CveSeverity;

const SEVERITY_FILTER_OPTIONS: { value: SeverityFilter; label: string }[] = [
  { value: 'all', label: 'All' },
  { value: 'critical', label: 'Critical' },
  { value: 'high', label: 'High' },
  { value: 'medium', label: 'Medium' },
  { value: 'low', label: 'Low' },
];

function sortAlertsBySeverity(alerts: CveAlertEvent[]): CveAlertEvent[] {
  const order: Record<CveSeverity, number> = { critical: 0, high: 1, medium: 2, low: 3 };
  return [...alerts].sort((a, b) => order[a.severity] - order[b.severity]);
}

export const CveAlertPanel: React.FC<CveAlertPanelProps> = ({ ip }) => {
  const cveAlerts = useBannerStore((s) => s.cveAlerts);
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>('all');

  const filteredAlerts = useMemo(() => {
    let alerts = ip ? cveAlerts.filter((a) => a.ip === ip) : cveAlerts;
    if (severityFilter !== 'all') {
      alerts = alerts.filter((a) => a.severity === severityFilter);
    }
    return sortAlertsBySeverity(alerts);
  }, [cveAlerts, ip, severityFilter]);

  const summary = useMemo(() => {
    const allAlerts = ip ? cveAlerts.filter((a) => a.ip === ip) : cveAlerts;
    const bySeverity: Record<CveSeverity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const alert of allAlerts) {
      bySeverity[alert.severity]++;
    }
    return { total: allAlerts.length, bySeverity };
  }, [cveAlerts, ip]);

  const handleFilterChange = useCallback((filter: SeverityFilter) => {
    setSeverityFilter(filter);
  }, []);

  if (summary.total === 0) {
    return (
      <div className="p-4 text-center text-gray-500 dark:text-gray-500">
        <svg className="w-8 h-8 mx-auto mb-2 text-gray-400 dark:text-gray-600" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
        </svg>
        <p className="text-sm">No vulnerabilities detected</p>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {/* Summary header */}
      <div className="px-3 py-2 bg-gray-50 dark:bg-gray-750 rounded-lg">
        <p className="text-sm font-semibold text-gray-800 dark:text-gray-200">
          {summary.total} vulnerabilit{summary.total !== 1 ? 'ies' : 'y'} found
          {summary.bySeverity.critical > 0 && (
            <span className="text-red-600 dark:text-red-400"> ({summary.bySeverity.critical} critical</span>
          )}
          {summary.bySeverity.high > 0 && (
            <span className="text-orange-600 dark:text-orange-400">
              {summary.bySeverity.critical > 0 ? ', ' : ' ('}{summary.bySeverity.high} high
            </span>
          )}
          {(summary.bySeverity.critical > 0 || summary.bySeverity.high > 0) && ')'}
        </p>
      </div>

      {/* Severity filter */}
      <div className="flex items-center gap-1 px-1" role="radiogroup" aria-label="Filter by severity">
        {SEVERITY_FILTER_OPTIONS.map(({ value, label }) => (
          <button
            key={value}
            type="button"
            role="radio"
            aria-checked={severityFilter === value}
            onClick={() => handleFilterChange(value)}
            className={twMerge(
              clsx(
                'px-2 py-1 text-[10px] font-medium rounded-md transition-colors',
                'focus:outline-none focus:ring-2 focus:ring-blue-500',
                severityFilter === value
                  ? 'bg-blue-600 text-white'
                  : 'bg-gray-100 dark:bg-gray-700/50 text-gray-600 dark:text-gray-400 hover:bg-gray-200 dark:hover:bg-gray-700'
              )
            )}
          >
            {label}
          </button>
        ))}
      </div>

      {/* Alert cards */}
      <div className="space-y-2">
        {filteredAlerts.map((alert) => (
          <CveAlertCard key={`${alert.cveId}-${alert.ip}-${alert.port}`} cve={alert} />
        ))}
      </div>

      {filteredAlerts.length === 0 && severityFilter !== 'all' && (
        <p className="text-xs text-gray-500 dark:text-gray-500 text-center py-2">
          No {severityFilter} severity vulnerabilities
        </p>
      )}
    </div>
  );
};
