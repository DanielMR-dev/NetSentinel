import React from 'react';
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';

interface InfoRowProps {
  label: string;
  value: string | null;
  isLoading?: boolean;
}

export const InfoRow: React.FC<InfoRowProps> = ({ label, value, isLoading = false }) => {
  return (
    <div className="flex justify-between items-center py-2">
      <dt className="text-sm text-gray-400">{label}</dt>
      <dd
        className={twMerge(
          clsx(
            'text-sm font-medium text-gray-100',
            isLoading && 'text-gray-500 italic'
          )
        )}
      >
        {isLoading ? 'Loading...' : value ?? 'Unknown'}
      </dd>
    </div>
  );
};
