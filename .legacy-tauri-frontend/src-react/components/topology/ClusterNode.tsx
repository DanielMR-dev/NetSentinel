import React, { memo, useCallback, useMemo } from 'react';
import { Handle, Position, type NodeProps, type Node } from '@xyflow/react';
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';
import { useTopologyStore } from '../../stores/topologyStore';
import type { ClusterNodeData } from '../../utils/clustering';

type ClusterNodeType = Node<ClusterNodeData, 'clusterNode'>;

const PIE_SIZE = 36;
const PIE_RADIUS = 14;

interface PieSegment {
  color: string;
  startAngle: number;
  endAngle: number;
}

function computeSegments(online: number, offline: number, unknown: number, total: number): PieSegment[] {
  if (total === 0) return [];
  const result: PieSegment[] = [];
  let currentAngle = -Math.PI / 2;

  const addSegment = (count: number, color: string) => {
    if (count === 0) return;
    const angle = (count / total) * 2 * Math.PI;
    result.push({ color, startAngle: currentAngle, endAngle: currentAngle + angle });
    currentAngle += angle;
  };

  addSegment(online, '#22c55e');
  addSegment(offline, '#ef4444');
  addSegment(unknown, '#6b7280');

  return result;
}

function PieChart({ online, offline, unknown }: { online: number; offline: number; unknown: number }) {
  const total = online + offline + unknown;

  const segments = useMemo(
    () => computeSegments(online, offline, unknown, total),
    [online, offline, unknown, total]
  );

  if (total === 0) return null;

  const center = PIE_SIZE / 2;

  return (
    <svg width={PIE_SIZE} height={PIE_SIZE} viewBox={`0 0 ${PIE_SIZE} ${PIE_SIZE}`} aria-hidden="true">
      {segments.length === 1 ? (
        <circle
          cx={center}
          cy={center}
          r={PIE_RADIUS}
          fill={segments[0].color}
          opacity={0.8}
        />
      ) : (
        segments.map((seg, i) => {
          const x1 = center + PIE_RADIUS * Math.cos(seg.startAngle);
          const y1 = center + PIE_RADIUS * Math.sin(seg.startAngle);
          const x2 = center + PIE_RADIUS * Math.cos(seg.endAngle);
          const y2 = center + PIE_RADIUS * Math.sin(seg.endAngle);
          const largeArc = seg.endAngle - seg.startAngle > Math.PI ? 1 : 0;

          const d = [
            `M ${center} ${center}`,
            `L ${x1} ${y1}`,
            `A ${PIE_RADIUS} ${PIE_RADIUS} 0 ${largeArc} 1 ${x2} ${y2}`,
            'Z',
          ].join(' ');

          return <path key={i} d={d} fill={seg.color} opacity={0.8} />;
        })
      )}
    </svg>
  );
}

const ClusterNodeComponent: React.FC<NodeProps<ClusterNodeType>> = ({ id, data }) => {
  const toggleCluster = useTopologyStore((s) => s.toggleCluster);

  const handleClick = useCallback(() => {
    toggleCluster(id);
  }, [id, toggleCluster]);

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        toggleCluster(id);
      }
    },
    [id, toggleCluster]
  );

  return (
    <div
      onClick={handleClick}
      onKeyDown={handleKeyDown}
      className={twMerge(
        clsx(
          'px-4 py-3 rounded-2xl border-2 bg-white dark:bg-gray-800 shadow-lg',
          'min-w-[180px] cursor-pointer',
          'transition-all duration-200 hover:shadow-xl hover:scale-105',
          data.isExpanded
            ? 'border-blue-500 ring-2 ring-blue-200 dark:ring-blue-800'
            : 'border-gray-300 dark:border-gray-600'
        )
      )}
      role="button"
      tabIndex={0}
      aria-label={`Cluster ${data.label}, ${data.deviceCount} devices. ${data.isExpanded ? 'Click to collapse' : 'Click to expand'}`}
      aria-expanded={data.isExpanded}
    >
      <Handle type="target" position={Position.Top} className="!bg-gray-400 !w-2 !h-2" />

      <div className="flex items-center gap-3">
        {/* Pie chart */}
        <PieChart
          online={data.onlineCount}
          offline={data.offlineCount}
          unknown={data.unknownCount}
        />

        {/* Label and count */}
        <div className="flex-1 min-w-0">
          <div className="text-sm font-bold text-gray-900 dark:text-gray-100 truncate">
            {data.label}
          </div>
          <div className="text-xs text-gray-500 dark:text-gray-400">
            {data.deviceCount} device{data.deviceCount !== 1 ? 's' : ''}
          </div>
        </div>

        {/* Expand/collapse icon */}
        <svg
          className={clsx(
            'w-4 h-4 text-gray-400 transition-transform duration-200',
            data.isExpanded && 'rotate-180'
          )}
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
          aria-hidden="true"
        >
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </div>

      {/* Status summary */}
      <div className="flex items-center gap-3 mt-2 text-[10px]">
        <span className="flex items-center gap-1 text-green-600 dark:text-green-400">
          <span className="w-2 h-2 rounded-full bg-green-500" />
          {data.onlineCount}
        </span>
        <span className="flex items-center gap-1 text-red-600 dark:text-red-400">
          <span className="w-2 h-2 rounded-full bg-red-500" />
          {data.offlineCount}
        </span>
        {data.unknownCount > 0 && (
          <span className="flex items-center gap-1 text-gray-500 dark:text-gray-400">
            <span className="w-2 h-2 rounded-full bg-gray-500" />
            {data.unknownCount}
          </span>
        )}
      </div>

      <Handle type="source" position={Position.Bottom} className="!bg-gray-400 !w-2 !h-2" />
    </div>
  );
};

export const ClusterNode = memo(ClusterNodeComponent);
ClusterNode.displayName = 'ClusterNode';
