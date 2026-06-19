import { useCallback } from 'react';
import {
  isPermissionGranted,
  requestPermission,
  sendNotification,
} from '@tauri-apps/plugin-notification';

export function useNotifications() {
  const requestNotificationPermission = useCallback(async () => {
    try {
      const granted = await isPermissionGranted();
      if (!granted) {
        const permission = await requestPermission();
        return permission === 'granted';
      }
      return true;
    } catch (error) {
      console.error('Failed to check notification permission:', error);
      return false;
    }
  }, []);

  const notify = useCallback(async (title: string, body: string) => {
    try {
      const granted = await isPermissionGranted();
      if (granted) {
        sendNotification({ title, body });
      }
    } catch (error) {
      console.error('Failed to send notification:', error);
    }
  }, []);

  return { requestNotificationPermission, notify } as const;
}
