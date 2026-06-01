/**
 * Tauri API mocks for Vitest.
 *
 * Import this file in test files that interact with Tauri APIs.
 * Each mock is a vi.fn() that can be overridden per test.
 */

// Mock @tauri-apps/api/core — invoke
export const mockInvoke = vi.fn();

vi.mock('@tauri-apps/api/core', () => ({
  invoke: (...args: unknown[]) => mockInvoke(...args),
}));

// Mock @tauri-apps/api/event — listen returns a cleanup function
export const mockListen = vi.fn().mockResolvedValue(() => {
  /* cleanup no-op */
});

vi.mock('@tauri-apps/api/event', () => ({
  listen: (...args: unknown[]) => mockListen(...args),
}));

// Mock @tauri-apps/plugin-notification
export const mockIsPermissionGranted = vi.fn().mockResolvedValue(true);
export const mockRequestPermission = vi.fn().mockResolvedValue('granted');
export const mockSendNotification = vi.fn();

vi.mock('@tauri-apps/plugin-notification', () => ({
  isPermissionGranted: () => mockIsPermissionGranted(),
  requestPermission: () => mockRequestPermission(),
  sendNotification: (...args: unknown[]) => mockSendNotification(...args),
}));
