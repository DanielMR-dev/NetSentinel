import React, { useCallback, useMemo } from 'react';
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';
import { useScanStore } from '../../stores/scanStore';
import { useCapabilitiesStore } from '../../stores/capabilitiesStore';
import { TIMING_TEMPLATES } from '../../types/device';
import type { TimingTemplate } from '../../types/device';

function getTemplateColorClass(id: TimingTemplate): string {
  switch (id) {
    case 'paranoid':
    case 'sneaky':
    case 'polite':
      return 'border-green-500 bg-green-50 dark:bg-green-900/20 text-green-700 dark:text-green-300';
    case 'normal':
      return 'border-blue-500 bg-blue-50 dark:bg-blue-900/20 text-blue-700 dark:text-blue-300';
    case 'aggressive':
      return 'border-orange-500 bg-orange-50 dark:bg-orange-900/20 text-orange-700 dark:text-orange-300';
    case 'insane':
      return 'border-red-500 bg-red-50 dark:bg-red-900/20 text-red-700 dark:text-red-300';
  }
}

function getTemplateInactiveClass(id: TimingTemplate): string {
  switch (id) {
    case 'paranoid':
    case 'sneaky':
    case 'polite':
      return 'hover:border-green-400 hover:bg-green-50/50 dark:hover:bg-green-900/10';
    case 'normal':
      return 'hover:border-blue-400 hover:bg-blue-50/50 dark:hover:bg-blue-900/10';
    case 'aggressive':
      return 'hover:border-orange-400 hover:bg-orange-50/50 dark:hover:bg-orange-900/10';
    case 'insane':
      return 'hover:border-red-400 hover:bg-red-50/50 dark:hover:bg-red-900/10';
  }
}

function isAggressiveTemplate(id: TimingTemplate): boolean {
  return id === 'aggressive' || id === 'insane';
}

export const TimingTemplateSelector: React.FC = () => {
  const timingTemplate = useScanStore((s) => s.timingTemplate);
  const setTimingTemplate = useScanStore((s) => s.setTimingTemplate);
  const scanType = useScanStore((s) => s.scanType);
  const isScanning = useScanStore((s) => s.isScanning);
  const privilegeStatus = useCapabilitiesStore((s) => s.privilegeStatus);

  const synUnavailable = useMemo(() => {
    return scanType === 'syn' && privilegeStatus !== null && !privilegeStatus.synScanAvailable;
  }, [scanType, privilegeStatus]);

  const handleSelect = useCallback(
    (id: TimingTemplate) => {
      if (!isScanning) {
        setTimingTemplate(id);
      }
    },
    [isScanning, setTimingTemplate]
  );

  return (
    <div className="space-y-2">
      <label className="block text-sm font-semibold text-gray-700 dark:text-gray-300">
        Timing Template
      </label>
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2" role="radiogroup" aria-label="Timing template selection">
        {TIMING_TEMPLATES.map((template) => {
          const isSelected = timingTemplate === template.id;
          const isDisabled = isScanning || synUnavailable;

          return (
            <button
              key={template.id}
              type="button"
              role="radio"
              aria-checked={isSelected}
              disabled={isDisabled}
              onClick={() => handleSelect(template.id)}
              title={template.description}
              className={twMerge(
                clsx(
                  'relative px-3 py-2 rounded-xl border-2 text-left transition-all duration-200',
                  'focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-1 focus:ring-offset-white dark:focus:ring-offset-gray-900',
                  'disabled:opacity-50 disabled:cursor-not-allowed',
                  isSelected
                    ? getTemplateColorClass(template.id)
                    : clsx(
                        'border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800',
                        'text-gray-700 dark:text-gray-300',
                        getTemplateInactiveClass(template.id)
                      )
                )
              )}
            >
              <div className="text-xs font-bold">{template.label}</div>
              <div className="text-[10px] mt-0.5 opacity-75 leading-tight">
                {template.maxConcurrent} concurrent
              </div>
              {isAggressiveTemplate(template.id) && (
                <div className="absolute -top-1 -right-1 w-3 h-3 rounded-full bg-orange-500 border-2 border-white dark:border-gray-800" title="May trigger IDS alerts" />
              )}
            </button>
          );
        })}
      </div>
      {isAggressiveTemplate(timingTemplate) && (
        <p className="text-xs text-orange-600 dark:text-orange-400 flex items-center gap-1" role="status">
          <svg className="w-3 h-3 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01M10.29 3.86l-8.58 14.86A1 1 0 002.58 20h18.84a1 1 0 00.87-1.5L13.71 3.86a1 1 0 00-1.72 0z" />
          </svg>
          Aggressive timing may trigger IDS/IPS alerts and cause network disruption.
        </p>
      )}
    </div>
  );
};
