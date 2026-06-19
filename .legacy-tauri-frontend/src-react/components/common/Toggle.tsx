import React from 'react';
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';

interface ToggleProps {
  checked: boolean;
  onChange: (checked: boolean) => void;
  disabled?: boolean;
  label?: string;
  description?: string;
  id?: string;
}

export const Toggle: React.FC<ToggleProps> = ({
  checked,
  onChange,
  disabled = false,
  label,
  description,
  id,
}) => {
  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      if (!disabled) {
        onChange(!checked);
      }
    }
  };

  return (
    <div className="flex items-start gap-3">
      <button
        type="button"
        role="switch"
        aria-checked={checked}
        aria-label={label}
        id={id}
        disabled={disabled}
        onClick={() => onChange(!checked)}
        onKeyDown={handleKeyDown}
        className={twMerge(
          clsx(
            'relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full',
            'border-2 border-transparent transition-colors duration-300 ease-in-out',
            'focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 focus:ring-offset-gray-900',
            'disabled:opacity-50 disabled:cursor-not-allowed',
            checked
              ? 'bg-gradient-to-r from-blue-600 to-blue-500'
              : 'bg-gray-700 hover:bg-gray-600'
          )
        )}
      >
        <span
          className={twMerge(
            clsx(
              'pointer-events-none inline-block h-5 w-5 transform rounded-full shadow-md',
              'bg-white ring-0 transition duration-300 ease-in-out',
              checked ? 'translate-x-5' : 'translate-x-0'
            )
          )}
        />
      </button>
      {(label || description) && (
        <div className="flex flex-col">
          {label && (
            <label htmlFor={id} className="text-sm font-medium text-gray-200 cursor-pointer">
              {label}
            </label>
          )}
          {description && (
            <p className="text-sm text-gray-500">{description}</p>
          )}
        </div>
      )}
    </div>
  );
};