import React, { useMemo, useState, useCallback, useRef, useEffect } from 'react';
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';
import { useScanStore } from '../../stores/scanStore';
import { useDashboardStore } from '../../stores/dashboardStore';
import type { Device, DeviceStatus } from '../../types/device';

const BASE_VIEWBOX_WIDTH = 800;
const BASE_VIEWBOX_HEIGHT = 600;
const CENTER_X = BASE_VIEWBOX_WIDTH / 2;
const CENTER_Y = BASE_VIEWBOX_HEIGHT / 2;
const BASE_RADIUS = 200;
const GATEWAY_RADIUS = 30;
const DEVICE_RADIUS = 20;
const MIN_ZOOM = 0.5;
const MAX_ZOOM = 2.0;
const ZOOM_STEP = 0.25;

function getStatusColor(status: DeviceStatus): string {
  switch (status) {
    case 'online':
      return 'fill-green-500';
    case 'offline':
      return 'fill-red-500';
    case 'unknown':
      return 'fill-gray-500';
  }
}

function getStatusStroke(status: DeviceStatus): string {
  switch (status) {
    case 'online':
      return 'stroke-green-400';
    case 'offline':
      return 'stroke-red-400';
    case 'unknown':
      return 'stroke-gray-400';
  }
}

interface DeviceNodeProps {
  device: Device;
  x: number;
  y: number;
  isSelected: boolean;
  onSelect: (ip: string) => void;
}

const DeviceNode: React.FC<DeviceNodeProps> = React.memo(({ device, x, y, isSelected, onSelect }) => {
  const handleClick = useCallback(() => {
    onSelect(device.ip);
  }, [onSelect, device.ip]);

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        onSelect(device.ip);
      }
    },
    [onSelect, device.ip]
  );

  const label = device.hostname ?? device.ip;
  const sublabel = device.vendor ?? device.ip;

  return (
    <g
      onClick={handleClick}
      onKeyDown={handleKeyDown}
      className="cursor-pointer"
      role="button"
      tabIndex={0}
      aria-label={`Device ${device.ip}${device.hostname ? `, ${device.hostname}` : ''}, status ${device.status}`}
    >
      {/* Connection line to gateway */}
      <line
        x1={CENTER_X}
        y1={CENTER_Y}
        x2={x}
        y2={y}
        className={twMerge(clsx('stroke-gray-600 dark:stroke-gray-600', getStatusStroke(device.status)))}
        strokeWidth={1}
        strokeOpacity={0.5}
      />
      {/* Selection ring */}
      {isSelected && (
        <circle
          cx={x}
          cy={y}
          r={DEVICE_RADIUS + 4}
          fill="none"
          className="stroke-blue-400"
          strokeWidth={2}
          strokeDasharray="4 2"
        />
      )}
      {/* Device circle */}
      <circle
        cx={x}
        cy={y}
        r={DEVICE_RADIUS}
        className={getStatusColor(device.status)}
        strokeOpacity={0.8}
      />
      {/* Status icon */}
      <text
        x={x}
        y={y + 1}
        textAnchor="middle"
        dominantBaseline="central"
        className="fill-white text-xs font-bold pointer-events-none select-none"
        fontSize={10}
      >
        {device.status === 'online' ? '●' : device.status === 'offline' ? '✕' : '?'}
      </text>
      {/* Device label */}
      <text
        x={x}
        y={y + DEVICE_RADIUS + 14}
        textAnchor="middle"
        className="fill-gray-700 dark:fill-gray-300 pointer-events-none select-none"
        fontSize={10}
        fontWeight={500}
      >
        {label.length > 18 ? label.slice(0, 16) + '…' : label}
      </text>
      {/* Vendor / IP sublabel */}
      <text
        x={x}
        y={y + DEVICE_RADIUS + 26}
        textAnchor="middle"
        className="fill-gray-500 dark:fill-gray-500 pointer-events-none select-none"
        fontSize={8}
      >
        {sublabel.length > 22 ? sublabel.slice(0, 20) + '…' : sublabel}
      </text>
    </g>
  );
});
DeviceNode.displayName = 'DeviceNode';

export const NetworkTopology: React.FC = () => {
  const devices = useScanStore((s) => s.devices);
  const gateway = useDashboardStore((s) => s.gateway);
  const selectedDeviceId = useScanStore((s) => s.selectedDeviceId);
  const selectDevice = useScanStore((s) => s.selectDevice);

  const [zoom, setZoom] = useState(1);
  const containerRef = useRef<HTMLDivElement>(null);

  const handleZoomIn = useCallback(() => {
    setZoom((prev) => Math.min(prev + ZOOM_STEP, MAX_ZOOM));
  }, []);

  const handleZoomOut = useCallback(() => {
    setZoom((prev) => Math.max(prev - ZOOM_STEP, MIN_ZOOM));
  }, []);

  const handleResetZoom = useCallback(() => {
    setZoom(1);
  }, []);

  const handleSelectDevice = useCallback(
    (ip: string) => {
      selectDevice(selectedDeviceId === ip ? null : ip);
    },
    [selectDevice, selectedDeviceId]
  );

  // Compute device positions
  const devicePositions = useMemo(() => {
    const radius = BASE_RADIUS;
    return devices.map((device, i) => {
      const angle = (2 * Math.PI * i) / Math.max(devices.length, 1) - Math.PI / 2;
      return {
        device,
        x: CENTER_X + radius * Math.cos(angle),
        y: CENTER_Y + radius * Math.sin(angle),
      };
    });
  }, [devices]);

  // Observe container for responsive behavior
  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    const observer = new ResizeObserver(() => {
      // Force re-render on resize for responsive layout
    });

    observer.observe(container);
    return () => observer.disconnect();
  }, []);

  if (devices.length === 0) {
    return (
      <div className="flex items-center justify-center h-64 text-gray-500 dark:text-gray-500">
        <div className="text-center">
          <svg
            className="w-12 h-12 mx-auto mb-3 text-gray-400 dark:text-gray-600"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
            aria-hidden="true"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={1.5}
              d="M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
            />
          </svg>
          <p className="text-sm">Start a scan to see your network topology</p>
        </div>
      </div>
    );
  }

  // Compute viewBox based on zoom
  const viewWidth = BASE_VIEWBOX_WIDTH / zoom;
  const viewHeight = BASE_VIEWBOX_HEIGHT / zoom;
  const viewBoxX = CENTER_X - viewWidth / 2;
  const viewBoxY = CENTER_Y - viewHeight / 2;

  return (
    <div ref={containerRef} className="relative w-full" style={{ minHeight: '400px' }}>
      {/* Zoom controls */}
      <div className="absolute top-2 right-2 z-10 flex flex-col gap-1">
        <button
          type="button"
          onClick={handleZoomIn}
          disabled={zoom >= MAX_ZOOM}
          aria-label="Zoom in"
          className={twMerge(
            clsx(
              'w-8 h-8 flex items-center justify-center rounded-lg text-sm font-bold',
              'bg-white/80 dark:bg-gray-800/80 border border-gray-300 dark:border-gray-600',
              'text-gray-700 dark:text-gray-300',
              'hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors',
              'focus:outline-none focus:ring-2 focus:ring-blue-500',
              'disabled:opacity-50 disabled:cursor-not-allowed'
            )
          )}
        >
          +
        </button>
        <button
          type="button"
          onClick={handleResetZoom}
          aria-label="Reset zoom"
          className={twMerge(
            clsx(
              'w-8 h-8 flex items-center justify-center rounded-lg text-xs font-medium',
              'bg-white/80 dark:bg-gray-800/80 border border-gray-300 dark:border-gray-600',
              'text-gray-700 dark:text-gray-300',
              'hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors',
              'focus:outline-none focus:ring-2 focus:ring-blue-500'
            )
          )}
        >
          {Math.round(zoom * 100)}%
        </button>
        <button
          type="button"
          onClick={handleZoomOut}
          disabled={zoom <= MIN_ZOOM}
          aria-label="Zoom out"
          className={twMerge(
            clsx(
              'w-8 h-8 flex items-center justify-center rounded-lg text-sm font-bold',
              'bg-white/80 dark:bg-gray-800/80 border border-gray-300 dark:border-gray-600',
              'text-gray-700 dark:text-gray-300',
              'hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors',
              'focus:outline-none focus:ring-2 focus:ring-blue-500',
              'disabled:opacity-50 disabled:cursor-not-allowed'
            )
          )}
        >
          −
        </button>
      </div>

      {/* Device count badge */}
      <div className="absolute top-2 left-2 z-10">
        <span className="px-2 py-1 text-xs font-medium rounded-md bg-blue-100 dark:bg-blue-900/50 text-blue-700 dark:text-blue-300 border border-blue-200 dark:border-blue-700/50">
          {devices.length} device{devices.length !== 1 ? 's' : ''}
        </span>
      </div>

      <svg
        viewBox={`${viewBoxX} ${viewBoxY} ${viewWidth} ${viewHeight}`}
        className="w-full h-full"
        style={{ minHeight: '400px' }}
        role="img"
        aria-label={`Network topology showing ${devices.length} devices connected to gateway`}
      >
        {/* Device nodes with connection lines */}
        {devicePositions.map(({ device, x, y }) => (
          <DeviceNode
            key={device.mac || device.ip}
            device={device}
            x={x}
            y={y}
            isSelected={selectedDeviceId === device.ip}
            onSelect={handleSelectDevice}
          />
        ))}

        {/* Gateway node (rendered last so it's on top) */}
        <circle
          cx={CENTER_X}
          cy={CENTER_Y}
          r={GATEWAY_RADIUS}
          className="fill-blue-600"
          stroke="currentColor"
          strokeWidth={2}
          strokeOpacity={0.3}
        />
        <text
          x={CENTER_X}
          y={CENTER_Y - 4}
          textAnchor="middle"
          className="fill-white pointer-events-none select-none"
          fontSize={10}
          fontWeight={700}
        >
          Gateway
        </text>
        <text
          x={CENTER_X}
          y={CENTER_Y + 8}
          textAnchor="middle"
          className="fill-blue-200 pointer-events-none select-none"
          fontSize={8}
        >
          {gateway ?? '—'}
        </text>
      </svg>
    </div>
  );
};
