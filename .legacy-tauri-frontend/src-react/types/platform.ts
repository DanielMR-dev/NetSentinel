/**
 * Platform capability types for privilege-aware UI.
 *
 * The backend serializes with #[serde(rename_all = "camelCase")],
 * so all field names use camelCase (e.g., isElevated, not is_elevated).
 */

export type Platform = 'linux' | 'windows' | 'macos';

export interface PlatformCapabilities {
  platform: Platform;
  isElevated: boolean;
  capabilities: string[];
  warnings: string[];
}

/**
 * Maps discovery method IDs (as used in ScanConfig.discoveryMethods)
 * to the capability strings returned by the backend.
 */
export const DISCOVERY_CAPABILITY_MAP: Record<string, string> = {
  arp: 'arp_scan',
  tcp_probe: 'tcp_probe',
  icmp: 'icmp_ping',
} as const;
