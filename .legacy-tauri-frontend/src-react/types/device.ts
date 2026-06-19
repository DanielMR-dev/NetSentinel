export type DeviceStatus = 'online' | 'offline' | 'unknown';

export type PortState = 'open' | 'closed' | 'filtered';

export interface Port {
  number: number;
  protocol: string;
  service?: string;
  state: PortState;
}

// --- Scan Type ---
export type ScanType = 'connect' | 'syn' | 'udp';

// --- Timing Templates ---
export type TimingTemplate = 'paranoid' | 'sneaky' | 'polite' | 'normal' | 'aggressive' | 'insane';

export interface TimingTemplateInfo {
  id: TimingTemplate;
  label: string;
  description: string;
  maxConcurrent: number;
  delayMs: number;
}

export const TIMING_TEMPLATES: TimingTemplateInfo[] = [
  { id: 'paranoid', label: 'T0 - Paranoid', description: '5 min delay, 1 concurrent. IDS evasion.', maxConcurrent: 1, delayMs: 300000 },
  { id: 'sneaky', label: 'T1 - Sneaky', description: '15s delay, 1 concurrent. Low detection.', maxConcurrent: 1, delayMs: 15000 },
  { id: 'polite', label: 'T2 - Polite', description: '400ms delay, 10 concurrent. Conservative.', maxConcurrent: 10, delayMs: 400 },
  { id: 'normal', label: 'T3 - Normal', description: 'Default speed. Balanced.', maxConcurrent: 100, delayMs: 0 },
  { id: 'aggressive', label: 'T4 - Aggressive', description: '10ms delay, 500 concurrent. Fast.', maxConcurrent: 500, delayMs: 10 },
  { id: 'insane', label: 'T5 - Insane', description: 'No delay, 1000 concurrent. Maximum speed.', maxConcurrent: 1000, delayMs: 0 },
];

// --- TLS/SSL Analysis ---
// Rust: #[serde(rename_all = "camelCase")] on TlsInfo
export interface TlsInfo {
  version: string;
  cipherSuite: string;
  issuer: string;
  subject: string;
  notBefore: number;
  notAfter: number;
  selfSigned: boolean;
  sanDomains: string[];
  expired: boolean;
  daysUntilExpiry: number;
}

// --- Banner Grabbing ---
// Rust: #[serde(rename_all = "camelCase")] on BannerResult
export interface BannerResult {
  ip: string;
  port: number;
  banner: string;
  service: string | null;
  osFingerprint: string | null;
  timestamp: number;
  tlsInfo: TlsInfo | null;
}

// --- CVE Engine ---
export type CveSeverity = 'critical' | 'high' | 'medium' | 'low';

// Rust: #[serde(rename_all = "camelCase")] on CveMatch
export interface CveMatch {
  cveId: string;
  severity: CveSeverity;
  description: string;
  affectedSoftware: string;
  affectedVersions: string[];
  cvssScore: number;
}

// --- Baseline / Snapshot ---
// Rust: #[serde(rename_all = "camelCase")] on Baseline
export interface Baseline {
  id: string;
  name: string;
  description: string | null;
  devices: Device[];
  scanCidr: string;
  createdAt: number;
}

// Rust: #[serde(rename_all = "camelCase")] on BaselineDiff
export interface BaselineDiff {
  baselineId: string;
  baselineName: string;
  newHosts: Device[];
  removedHosts: Device[];
  changedPorts: PortChange[];
  newServices: BannerResult[];
  scanTimestamp: number;
}

// Rust: #[serde(rename_all = "camelCase")] on PortChange
export interface PortChange {
  ip: string;
  hostname: string | null;
  port: Port;
  previousState: PortState | null;
  currentState: PortState;
}

// --- Privilege Status ---
// Rust: #[serde(rename_all = "camelCase")] on PrivilegeStatus
export interface PrivilegeStatus {
  isElevated: boolean;
  hasRawSocket: boolean;
  hasCapNetRaw: boolean;
  synScanAvailable: boolean;
  icmpAvailable: boolean;
  warnings: string[];
  platform: string;
}

// --- CVE Alert Event (extends CveMatch with source info) ---
export interface CveAlertEvent extends CveMatch {
  ip: string;
  port: number;
}

export interface Device {
  ip: string;
  mac: string;
  hostname?: string;
  vendor?: string;
  status: DeviceStatus;
  ports: Port[];
  lastSeen: number;
  banner_results: BannerResult[];
}

// Rust sends snake_case, so we need to match
export interface ScanResponse {
  scan_id: string;
  status: string;
  scan_type: ScanType;
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
  banner_results: BannerResult[];
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

export interface ScanHistoryEntry {
  id: string;
  scanId: string;
  cidr: string;
  deviceCount: number;
  durationMs: number;
  status: string;
  devices: Device[];
  timestamp: number;
}