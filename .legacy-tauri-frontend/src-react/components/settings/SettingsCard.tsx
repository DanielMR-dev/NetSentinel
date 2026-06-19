import React from 'react';
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';

interface SettingsCardProps {
  title: string;
  description?: string;
  children: React.ReactNode;
  className?: string;
  actions?: React.ReactNode;
  noPadding?: boolean;
}

export const SettingsCard: React.FC<SettingsCardProps> = ({
  title,
  description,
  children,
  className,
  actions,
  noPadding = false,
}) => {
  return (
    <div
      className={twMerge(
        clsx(
          'bg-gradient-to-b from-gray-50 to-white dark:from-gray-800/80 dark:to-gray-800/95',
          'border border-gray-200 dark:border-gray-700/50 rounded-xl',
          'shadow-lg',
          className
        )
      )}
    >
      {/* Header */}
      <div className="px-5 py-4 border-b border-gray-200 dark:border-gray-700/30">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-base font-semibold text-gray-900 dark:text-gray-100">{title}</h3>
            {description && (
              <p className="mt-1 text-sm text-gray-500 dark:text-gray-500">{description}</p>
            )}
          </div>
          {actions && <div className="flex items-center gap-2">{actions}</div>}
        </div>
      </div>

      {/* Content */}
      <div className={noPadding ? '' : 'p-5'}>
        {children}
      </div>
    </div>
  );
};

interface SettingsSectionProps {
  title: string;
  description?: string;
  children: React.ReactNode;
  className?: string;
}

export const SettingsSection: React.FC<SettingsSectionProps> = ({
  title,
  description,
  children,
  className,
}) => {
  return (
    <div className={twMerge(clsx('space-y-4', className))}>
      <div>
        <h4 className="text-sm font-medium text-gray-700 dark:text-gray-300">{title}</h4>
        {description && (
          <p className="mt-0.5 text-xs text-gray-500 dark:text-gray-500">{description}</p>
        )}
      </div>
      {children}
    </div>
  );
};
