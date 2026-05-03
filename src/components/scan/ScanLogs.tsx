import React, { useEffect, useRef } from 'react';
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';
import { useScanStore } from '../../stores/scanStore';
import type { LogLevel } from '../../types/device';

interface ScanLogsProps {
  maxHeight?: string;
}

interface LogEntryProps {
  level: LogLevel;
  message: string;
  timestamp: number;
  target?: string;
}

const LOG_COLORS: Record<LogLevel, { text: string; bg: string; border: string }> = {
  info: { text: 'text-blue-400', bg: 'bg-blue-900/20', border: 'border-blue-800/30' },
  warn: { text: 'text-amber-400', bg: 'bg-amber-900/20', border: 'border-amber-800/30' },
  error: { text: 'text-red-400', bg: 'bg-red-900/20', border: 'border-red-800/30' },
  debug: { text: 'text-gray-400', bg: 'bg-gray-800/30', border: 'border-gray-700/30' },
};

const LEVEL_LABELS: Record<LogLevel, string> = {
  info: 'INFO',
  warn: 'WARN',
  error: 'ERR',
  debug: 'DBG',
};

function formatTimestamp(timestamp: number): string {
  const date = new Date(timestamp);
  const hours = date.getHours().toString().padStart(2, '0');
  const minutes = date.getMinutes().toString().padStart(2, '0');
  const seconds = date.getSeconds().toString().padStart(2, '0');
  const ms = date.getMilliseconds().toString().padStart(3, '0');
  return `${hours}:${minutes}:${seconds}.${ms}`;
}

const LogEntry: React.FC<LogEntryProps> = ({ level, message, timestamp, target }) => {
  const colors = LOG_COLORS[level];

  return (
    <div
      className={twMerge(
        clsx(
          'flex items-start gap-2 py-1.5 px-3 text-xs font-mono rounded-lg mx-1 my-0.5',
          colors.bg,
          colors.border,
          'border-l-2'
        )
      )}
    >
      <span className={twMerge(clsx('shrink-0 text-gray-500', colors.text))}>
        [{formatTimestamp(timestamp)}]
      </span>
      <span
        className={twMerge(
          clsx(
            'shrink-0 px-1.5 py-0.5 rounded text-xs font-bold uppercase tracking-wider',
            colors.text,
            colors.bg
          )
        )}
      >
        {LEVEL_LABELS[level]}
      </span>
      {target && (
        <span className="shrink-0 text-purple-400/80">
          [{target}]
        </span>
      )}
      <span className="text-gray-300 break-all leading-relaxed">{message}</span>
    </div>
  );
};

export const ScanLogs: React.FC<ScanLogsProps> = ({ maxHeight = 'h-48' }) => {
  const logs = useScanStore((s) => s.logs);
  const containerRef = useRef<HTMLDivElement>(null);

  // Auto-scroll to bottom when new logs arrive
  useEffect(() => {
    if (containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
    }
  }, [logs]);

  return (
    <div
      ref={containerRef}
      className={twMerge(
        clsx(
          'overflow-y-auto bg-gray-900/80 rounded-xl border border-gray-700/50',
          maxHeight
        )
      )}
      aria-label="Scan logs"
      role="log"
      aria-live="polite"
    >
      {logs.length === 0 ? (
        <div className="flex items-center justify-center h-full text-gray-500 text-sm">
          <div className="text-center">
            <div className="w-8 h-8 mx-auto mb-2 rounded-full bg-gray-800 flex items-center justify-center">
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
              </svg>
            </div>
            No logs yet
          </div>
        </div>
      ) : (
        <div className="py-2">
          {logs.map((log, index) => (
            <LogEntry
              key={`${log.timestamp}-${index}`}
              level={log.level}
              message={log.message}
              timestamp={log.timestamp}
              target={log.target}
            />
          ))}
        </div>
      )}
    </div>
  );
};
