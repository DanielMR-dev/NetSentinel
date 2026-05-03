export interface DeviceInfoResponse {
  hostname: string;
  osName: string;
  osVersion: string;
  uptime: string;
}

export interface NetworkInfoResponse {
  ipAddress: string;
  macAddress: string;
  gateway: string;
  networkName: string;
}
