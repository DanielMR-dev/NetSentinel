import React, { useCallback, useRef, useEffect } from 'react';
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';
import type { TabId } from '../../stores/dashboardStore';

interface Tab {
  id: TabId;
  label: string;
}

const TABS: Tab[] = [
  { id: 'dashboard', label: 'Dashboard' },
  { id: 'scan', label: 'Scan' },
  { id: 'settings', label: 'Settings' },
  { id: 'history', label: 'History' },
];

interface TabNavigationProps {
  activeTab: TabId;
  onTabChange: (tab: TabId) => void;
}

export const TabNavigation: React.FC<TabNavigationProps> = ({ activeTab, onTabChange }) => {
  const tabListRef = useRef<HTMLUListElement>(null);

  const handleKeyDown = useCallback(
    (event: React.KeyboardEvent<HTMLButtonElement>) => {
      const currentIndex = TABS.findIndex((tab) => tab.id === activeTab);
      let nextIndex: number;

      if (event.key === 'ArrowRight') {
        nextIndex = (currentIndex + 1) % TABS.length;
        event.preventDefault();
      } else if (event.key === 'ArrowLeft') {
        nextIndex = (currentIndex - 1 + TABS.length) % TABS.length;
        event.preventDefault();
      } else if (event.key === 'Home') {
        nextIndex = 0;
        event.preventDefault();
      } else if (event.key === 'End') {
        nextIndex = TABS.length - 1;
        event.preventDefault();
      } else {
        return;
      }

      onTabChange(TABS[nextIndex].id);
      const nextButton = tabListRef.current?.children[nextIndex]?.querySelector<HTMLButtonElement>('button');
      nextButton?.focus();
    },
    [activeTab, onTabChange]
  );

  useEffect(() => {
    const currentButton = tabListRef.current?.querySelector<HTMLButtonElement>(
      `[aria-selected="true"]`
    );
    currentButton?.focus();
  }, [activeTab]);

  return (
    <nav aria-label="Main navigation" className="mb-6">
      <ul
        ref={tabListRef}
        role="tablist"
        className="flex border-b border-gray-200 dark:border-gray-700"
      >
        {TABS.map((tab) => {
          const isActive = tab.id === activeTab;
          return (
            <li key={tab.id} role="presentation">
              <button
                role="tab"
                id={`tab-${tab.id}`}
                aria-selected={isActive}
                aria-controls={`panel-${tab.id}`}
                tabIndex={isActive ? 0 : -1}
                onClick={() => onTabChange(tab.id)}
                onKeyDown={handleKeyDown}
                className={twMerge(
                  clsx(
                    'px-4 py-3 text-sm font-medium transition-colors',
                    'border-b-2 -mb-px',
                    'focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-inset',
                    isActive
                      ? 'border-blue-500 text-blue-600 dark:text-blue-400'
                      : 'border-transparent text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-200 hover:border-gray-400 dark:hover:border-gray-500'
                  )
                )}
              >
                {tab.label}
              </button>
            </li>
          );
        })}
      </ul>
    </nav>
  );
};
