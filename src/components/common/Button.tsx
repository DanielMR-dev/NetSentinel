import React from 'react';
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';
import { LoadingSpinner } from './LoadingSpinner';

type ButtonVariant = 'primary' | 'secondary' | 'danger' | 'ghost';
type ButtonSize = 'sm' | 'md' | 'lg';

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
  isLoading?: boolean;
  loadingText?: string;
  leftIcon?: React.ReactNode;
  rightIcon?: React.ReactNode;
}

const variantClasses: Record<ButtonVariant, string> = {
  primary:
    'bg-gradient-to-b from-blue-600 to-blue-700 text-white shadow-md hover:from-blue-600 hover:to-blue-700 hover:shadow-lg hover:brightness-110 active:from-blue-700 active:to-blue-800 active:shadow-sm focus:ring-blue-500',
  secondary:
    'bg-gradient-to-b from-gray-200 to-gray-300 text-gray-800 dark:from-gray-600 dark:to-gray-700 dark:text-gray-100 shadow-md hover:brightness-110 active:shadow-sm focus:ring-gray-500',
  danger:
    'bg-gradient-to-b from-red-600 to-red-700 text-white shadow-md hover:from-red-600 hover:to-red-700 hover:shadow-lg hover:brightness-110 active:from-red-700 active:to-red-800 active:shadow-sm focus:ring-red-500',
  ghost:
    'bg-transparent text-gray-600 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700/50 hover:text-gray-900 dark:hover:text-gray-100 active:bg-gray-200 dark:active:bg-gray-700/70 focus:ring-gray-500',
};

const sizeClasses: Record<ButtonSize, string> = {
  sm: 'px-3 py-1.5 text-sm gap-1.5',
  md: 'px-4 py-2 text-base gap-2',
  lg: 'px-6 py-3 text-lg gap-2.5',
};

export const Button: React.FC<ButtonProps> = ({
  variant = 'primary',
  size = 'md',
  isLoading = false,
  loadingText,
  leftIcon,
  rightIcon,
  children,
  disabled,
  className,
  ...props
}) => {
  const isDisabled = disabled || isLoading;

  const mergedClassName = twMerge(
    clsx(
      // Base styles
      'inline-flex items-center justify-center',
      'font-medium rounded-xl transition-all duration-200',
      'focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-white dark:focus:ring-offset-gray-900',
      'disabled:opacity-50 disabled:cursor-not-allowed disabled:shadow-none',
      // Transform on hover/active
      'hover:scale-[1.02] active:scale-[0.98]',
      // Variant
      variantClasses[variant],
      // Size
      sizeClasses[size],
      // Custom className
      className
    )
  );

  return (
    <button
      {...props}
      disabled={isDisabled}
      className={mergedClassName}
      aria-busy={isLoading}
      aria-disabled={isDisabled}
    >
      {isLoading ? (
        <>
          <LoadingSpinner size={size === 'sm' ? 'sm' : size === 'lg' ? 'md' : 'sm'} />
          {loadingText && <span>{loadingText}</span>}
          {!loadingText && children && <span>{children}</span>}
        </>
      ) : (
        <>
          {leftIcon && <span className="flex-shrink-0">{leftIcon}</span>}
          <span>{children}</span>
          {rightIcon && <span className="flex-shrink-0">{rightIcon}</span>}
        </>
      )}
    </button>
  );
};
