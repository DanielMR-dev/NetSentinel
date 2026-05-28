export type DeviceStatus = 'online' | 'offline' | 'unknown';

export type PortState = 'open' | 'closed' | 'filtered';

export interface Port {
  number: number;
  protocol: string;
  service?: string;
  state: PortState;
}

export interface Device {
  ip: string;
  mac: string;
  hostname?: string;
  vendor?: string;
  status: DeviceStatus;
  ports: Port[];
  lastSeen: number;
}

// Rust sends snake_case, so we need to match
export interface ScanResponse {
  scan_id: string;
  status: string;
}

export interface ScanResultsResponse {
  devices: Device[];
  scanned_count: number;
  total_hosts: number;
}

export interface DeviceFoundEvent {
  ip: string;
  mac: string;
  hostname?: string;
  vendor?: string;
  timestamp: number;
  ports: Port[];
}

export interface ScanProgressEvent {
  scanned: number;
  total: number;
  current_target: string;
  devices_found: number;
}

export interface ScanCompleteEvent {
  scan_id: string;
  device_count: number;
  duration_ms: number;
  status: string;
}

export interface ScanError {
  code: string;
  message: string;
}

export interface ScanLogEvent {
  level: 'info' | 'warn' | 'error' | 'debug';
  message: string;
  timestamp: number;
  target?: string;
}

export type LogLevel = ScanLogEvent['level'];