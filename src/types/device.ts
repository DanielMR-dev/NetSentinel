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
  status: DeviceStatus;
  ports: Port[];
  lastSeen: number;
}

export interface ScanRequest {
  cidr: string;
  timeoutMs: number;
  scanPorts: boolean;
}

export interface ScanResponse {
  scanId: string;
  status: 'started' | 'completed' | 'cancelled' | 'error';
  devices: Device[];
  durationMs: number;
}

export interface DeviceFoundEvent {
  ip: string;
  mac: string;
  hostname?: string;
  timestamp: number;
}

export interface ScanProgressEvent {
  scanned: number;
  total: number;
  currentTarget: string;
  devicesFound: number;
}

export interface ScanCompleteEvent {
  scanId: string;
  deviceCount: number;
  durationMs: number;
}

export interface ScanError {
  code: string;
  message: string;
}