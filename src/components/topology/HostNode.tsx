import React, { memo, useCallback } from 'react';
import { Handle, Position, type NodeProps, type Node } from '@xyflow/react';
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';
import type { HostNodeData } from '../../utils/clustering';

type HostNodeType = Node<HostNodeData, 'hostNode'>;

function getStatusBorderColor(status: string): string {
  switch (status) {
    case 'online':
      return 'border-green-500';
    case 'offline':
      return 'border-red-500';
    default:
      return 'border-gray-500';
  }
}

function getStatusDotColor(status: string): string {
  switch (status) {
    case 'online':
      return 'bg-green-500';
    case 'offline':
      return 'bg-red-500';
    default:
      return 'bg-gray-500';
  }
}

const HostNodeComponent: React.FC<NodeProps<HostNodeType>> = ({ data }) => {
  const handleClick = useCallback(() => {
    // Could dispatch an event to select the device
  }, []);

  return (
    <div
      onClick={handleClick}
      className={twMerge(
        clsx(
          'px-3 py-2 rounded-xl border-2 bg-white dark:bg-gray-800 shadow-md',
          'min-w-[160px] max-w-[220px] cursor-pointer',
          'transition-all duration-200 hover:shadow-lg hover:scale-105',
          data.hasChanges ? 'border-yellow-500' : getStatusBorderColor(data.status)
        )
      )}
      role="button"
      tabIndex={0}
      aria-label={`Host ${data.ip}${data.hostname ? `, ${data.hostname}` : ''}, status ${data.status}`}
    >
      <Handle type="target" position={Position.Top} className="!bg-gray-400 !w-2 !h-2" />

      <div className="flex items-center gap-2">
        {/* Status dot */}
        <div className={clsx('w-2.5 h-2.5 rounded-full flex-shrink-0', getStatusDotColor(data.status))} />

        {/* IP Address */}
        <span className="text-xs font-mono font-bold text-gray-900 dark:text-gray-100 truncate">
          {data.ip}
        </span>
      </div>

      {/* Hostname */}
      {data.hostname && (
        <div className="text-[10px] text-gray-500 dark:text-gray-400 truncate mt-0.5 ml-4.5">
          {data.hostname}
        </div>
      )}

      {/* Vendor */}
      {data.vendor && (
        <div className="text-[10px] text-gray-400 dark:text-gray-500 truncate mt-0.5 ml-4.5">
          {data.vendor}
        </div>
      )}

      {/* Badges row */}
      <div className="flex items-center gap-1.5 mt-1.5 ml-4.5">
        {/* Port count badge */}
        {data.openPortCount > 0 && (
          <span className="px-1.5 py-0.5 text-[9px] font-medium rounded bg-blue-100 dark:bg-blue-900/50 text-blue-700 dark:text-blue-300">
            {data.openPortCount} ports
          </span>
        )}

        {/* CVE alert icon */}
        {data.hasCveAlerts && (
          <span className="flex items-center gap-0.5 px-1.5 py-0.5 text-[9px] font-medium rounded bg-red-100 dark:bg-red-900/50 text-red-700 dark:text-red-300" title="Vulnerabilities detected">
            <svg className="w-2.5 h-2.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01M10.29 3.86l-8.58 14.86A1 1 0 002.58 20h18.84a1 1 0 00.87-1.5L13.71 3.86a1 1 0 00-1.72 0z" />
            </svg>
            CVE
          </span>
        )}
      </div>

      <Handle type="source" position={Position.Bottom} className="!bg-gray-400 !w-2 !h-2" />
    </div>
  );
};

export const HostNode = memo(HostNodeComponent);
HostNode.displayName = 'HostNode';
