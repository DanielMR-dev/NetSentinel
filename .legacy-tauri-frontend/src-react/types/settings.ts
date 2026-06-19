import type { ScanType, TimingTemplate } from './device';

export interface ScanConfig {
  defaultCidr: string;
  timeoutMs: number;
  maxConcurrentHosts: number;
  maxConcurrentPorts: number;
  scanPortsEnabled: boolean;
  selectedPorts: number[];
  discoveryMethods: string[];
  retryCount: number;
  defaultScanType: ScanType;
  defaultTimingTemplate: TimingTemplate;
}

export interface UiPreferences {
  refreshRateMs: number;
  autoRefresh: boolean;
  showAdvancedOptions: boolean;
  confirmBeforeScan: boolean;
}

export interface SettingsProfile {
  id: string;
  name: string;
  isDefault: boolean;
  scanConfig: ScanConfig;
  uiPreferences: UiPreferences;
  createdAt: number;
  updatedAt: number;
}

// IPC Response types
export interface ProfilesResponse {
  profiles: SettingsProfile[];
}

export interface SettingsResponse {
  settings: SettingsProfile;
}

// Helper to create default scan config
export function createDefaultScanConfig(): ScanConfig {
  return {
    defaultCidr: '192.168.1.0/24',
    timeoutMs: 1000,
    maxConcurrentHosts: 50,
    maxConcurrentPorts: 10,
    scanPortsEnabled: true,
    selectedPorts: [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 5900, 6379, 8080, 8443],
    discoveryMethods: ['arp', 'tcp_probe', 'icmp'],
    retryCount: 3,
    defaultScanType: 'connect',
    defaultTimingTemplate: 'normal',
  };
}

// Helper to create default UI preferences
export function createDefaultUiPreferences(): UiPreferences {
  return {
    refreshRateMs: 2000,
    autoRefresh: false,
    showAdvancedOptions: false,
    confirmBeforeScan: true,
  };
}

// Generate UUID safely - works in browser and Tauri
function generateUUID(): string {
  // Try crypto.randomUUID first (modern browsers, Tauri)
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }
  // Fallback for older environments
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    const v = c === 'x' ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}

// Helper to create a new profile with defaults
export function createDefaultProfile(name: string, isDefault = false): SettingsProfile {
  const now = Date.now();
  return {
    id: generateUUID(),
    name,
    isDefault,
    scanConfig: createDefaultScanConfig(),
    uiPreferences: createDefaultUiPreferences(),
    createdAt: now,
    updatedAt: now,
  };
}

// Validation helpers
export function isValidCidr(cidr: string): boolean {
  const cidrRegex = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/;
  if (!cidrRegex.test(cidr)) return false;
  const [ip, mask] = cidr.split('/');
  const octets = ip.split('.').map(Number);
  return octets.every((o) => o >= 0 && o <= 255) && Number(mask) >= 0 && Number(mask) <= 32;
}

export function isValidPort(port: number): boolean {
  return Number.isInteger(port) && port >= 1 && port <= 65535;
}

export function isValidTimeout(ms: number): boolean {
  return ms >= 100 && ms <= 30000;
}

export function isValidRefreshRate(ms: number): boolean {
  return ms >= 500 && ms <= 10000;
}

export function isValidConcurrentValue(value: number, min: number, max: number): boolean {
  return Number.isInteger(value) && value >= min && value <= max;
}

// Type guard to check if an object is a valid ScanConfig
export function isValidScanConfig(obj: unknown): obj is ScanConfig {
  if (!obj || typeof obj !== 'object') return false;
  const config = obj as Record<string, unknown>;
  return (
    typeof config.defaultCidr === 'string' &&
    typeof config.timeoutMs === 'number' &&
    typeof config.maxConcurrentHosts === 'number' &&
    typeof config.maxConcurrentPorts === 'number' &&
    typeof config.scanPortsEnabled === 'boolean' &&
    Array.isArray(config.selectedPorts) &&
    Array.isArray(config.discoveryMethods) &&
    typeof config.retryCount === 'number' &&
    typeof config.defaultScanType === 'string' &&
    typeof config.defaultTimingTemplate === 'string'
  );
}

// Type guard to check if an object is a valid UiPreferences
export function isValidUiPreferences(obj: unknown): obj is UiPreferences {
  if (!obj || typeof obj !== 'object') return false;
  const prefs = obj as Record<string, unknown>;
  return (
    typeof prefs.refreshRateMs === 'number' &&
    typeof prefs.autoRefresh === 'boolean' &&
    typeof prefs.showAdvancedOptions === 'boolean' &&
    typeof prefs.confirmBeforeScan === 'boolean'
  );
}

// Type guard to check if an object is a valid SettingsProfile
export function isValidSettingsProfile(obj: unknown): obj is SettingsProfile {
  if (!obj || typeof obj !== 'object') return false;
  const profile = obj as Record<string, unknown>;
  return (
    typeof profile.id === 'string' &&
    typeof profile.name === 'string' &&
    typeof profile.isDefault === 'boolean' &&
    isValidScanConfig(profile.scanConfig) &&
    isValidUiPreferences(profile.uiPreferences) &&
    typeof profile.createdAt === 'number' &&
    typeof profile.updatedAt === 'number'
  );
}

// Safe profile creation from any input (used when loading from backend)
export function safeProfileFromObject(obj: unknown, fallbackName = 'Unknown'): SettingsProfile {
  if (isValidSettingsProfile(obj)) {
    return obj;
  }

  // Return a minimal valid profile if input is invalid
  const defaultProfile = createDefaultProfile(fallbackName, true);

  // Try to extract valid parts from malformed input
  if (obj && typeof obj === 'object') {
    const input = obj as Record<string, unknown>;

    // Try to salvage scanConfig
    if (isValidScanConfig(input.scanConfig)) {
      defaultProfile.scanConfig = input.scanConfig;
    }

    // Try to salvage uiPreferences
    if (isValidUiPreferences(input.uiPreferences)) {
      defaultProfile.uiPreferences = input.uiPreferences;
    }

    // Try to salvage basic fields
    if (typeof input.id === 'string' && input.id.length > 0) {
      defaultProfile.id = input.id;
    }
    if (typeof input.name === 'string' && input.name.length > 0) {
      defaultProfile.name = input.name;
    }
    if (typeof input.isDefault === 'boolean') {
      defaultProfile.isDefault = input.isDefault;
    }
    if (typeof input.createdAt === 'number') {
      defaultProfile.createdAt = input.createdAt;
    }
    if (typeof input.updatedAt === 'number') {
      defaultProfile.updatedAt = input.updatedAt;
    }
  }

  return defaultProfile;
}