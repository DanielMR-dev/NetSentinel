import type { Device } from '../types/device';

export function devicesToCSV(devices: Device[]): string {
  const headers = ['IP Address', 'MAC Address', 'Hostname', 'Vendor', 'Status', 'Open Ports', 'Last Seen'];
  const rows = devices.map((d) => [
    d.ip,
    d.mac,
    d.hostname ?? '',
    d.vendor ?? '',
    d.status,
    d.ports.filter((p) => p.state === 'open').map((p) => `${p.number}/${p.protocol}`).join('; '),
    new Date(d.lastSeen * 1000).toISOString(),
  ]);
  return [headers.join(','), ...rows.map((r) => r.map((cell) => `"${cell}"`).join(','))].join('\n');
}

export function devicesToJSON(devices: Device[]): string {
  return JSON.stringify(devices, null, 2);
}

export function downloadFile(content: string, filename: string, mimeType: string): void {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

export async function copyToClipboard(content: string): Promise<void> {
  await navigator.clipboard.writeText(content);
}
