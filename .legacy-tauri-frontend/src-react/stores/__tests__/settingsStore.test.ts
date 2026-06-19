import { describe, it, expect, vi, beforeEach } from 'vitest';
import { useSettingsStore } from '../settingsStore';
import { createDefaultProfile, createDefaultScanConfig } from '../../types/settings';

// Mock Tauri APIs
const mockInvoke = vi.fn();
vi.mock('@tauri-apps/api/core', () => ({
  invoke: (...args: unknown[]) => mockInvoke(...args),
}));

function resetStore(): void {
  // Clear localStorage to avoid persist middleware interference
  localStorage.clear();

  useSettingsStore.setState({
    profiles: [],
    currentProfileId: null,
    settings: createDefaultProfile('Default', true),
    isLoading: false,
    error: null,
    isSaving: false,
    lastSaved: null,
  });
}

describe('settingsStore', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    resetStore();
  });

  describe('fetchProfiles', () => {
    it('calls invoke get_settings_profiles', async () => {
      const profile = createDefaultProfile('Test', true);
      mockInvoke.mockResolvedValue([profile]);

      await useSettingsStore.getState().fetchProfiles();

      expect(mockInvoke).toHaveBeenCalledWith('get_settings_profiles');
    });

    it('sets profiles from backend response', async () => {
      const profile1 = createDefaultProfile('Profile 1', true);
      const profile2 = createDefaultProfile('Profile 2', false);
      mockInvoke.mockResolvedValue([profile1, profile2]);

      await useSettingsStore.getState().fetchProfiles();

      expect(useSettingsStore.getState().profiles).toHaveLength(2);
      expect(useSettingsStore.getState().isLoading).toBe(false);
    });

    it('creates default profile when backend returns empty list', async () => {
      mockInvoke.mockResolvedValueOnce([]); // get_settings_profiles
      mockInvoke.mockResolvedValueOnce(undefined); // save_profile

      await useSettingsStore.getState().fetchProfiles();

      expect(useSettingsStore.getState().profiles).toHaveLength(1);
      expect(useSettingsStore.getState().profiles[0].name).toBe('Default');
      expect(useSettingsStore.getState().profiles[0].isDefault).toBe(true);
    });

    it('sets error on failed invoke', async () => {
      mockInvoke.mockRejectedValue(new Error('Backend error'));

      await useSettingsStore.getState().fetchProfiles();

      expect(useSettingsStore.getState().error).toBe('Backend error');
      expect(useSettingsStore.getState().isLoading).toBe(false);
    });
  });

  describe('saveProfile', () => {
    it('calls invoke save_profile', async () => {
      mockInvoke.mockResolvedValue(undefined);
      const profile = createDefaultProfile('My Profile');

      await useSettingsStore.getState().saveProfile(profile);

      expect(mockInvoke).toHaveBeenCalledWith('save_profile', { profile });
    });

    it('adds new profile to list', async () => {
      mockInvoke.mockResolvedValue(undefined);
      const profile = createDefaultProfile('New Profile');

      await useSettingsStore.getState().saveProfile(profile);

      expect(useSettingsStore.getState().profiles).toHaveLength(1);
      expect(useSettingsStore.getState().profiles[0].name).toBe('New Profile');
    });

    it('updates existing profile in list', async () => {
      const existing = createDefaultProfile('Existing');
      useSettingsStore.setState({ profiles: [existing] });
      mockInvoke.mockResolvedValue(undefined);

      const updated = { ...existing, name: 'Updated Name' };
      await useSettingsStore.getState().saveProfile(updated);

      expect(useSettingsStore.getState().profiles).toHaveLength(1);
      expect(useSettingsStore.getState().profiles[0].name).toBe('Updated Name');
    });

    it('sets lastSaved timestamp', async () => {
      mockInvoke.mockResolvedValue(undefined);
      const profile = createDefaultProfile('Test');

      await useSettingsStore.getState().saveProfile(profile);

      expect(useSettingsStore.getState().lastSaved).toBeTypeOf('number');
    });

    it('throws and sets error on failure', async () => {
      mockInvoke.mockRejectedValue(new Error('Save failed'));
      const profile = createDefaultProfile('Test');

      await expect(useSettingsStore.getState().saveProfile(profile)).rejects.toThrow('Save failed');

      expect(useSettingsStore.getState().error).toBe('Save failed');
    });
  });

  describe('deleteProfile', () => {
    it('calls invoke delete_profile and removes from list', async () => {
      const profile1 = createDefaultProfile('Keep', true);
      const profile2 = createDefaultProfile('Delete', false);
      useSettingsStore.setState({
        profiles: [profile1, profile2],
        currentProfileId: profile1.id,
      });
      mockInvoke.mockResolvedValue(undefined);

      await useSettingsStore.getState().deleteProfile(profile2.id);

      expect(mockInvoke).toHaveBeenCalledWith('delete_profile', { id: profile2.id });
      expect(useSettingsStore.getState().profiles).toHaveLength(1);
      expect(useSettingsStore.getState().profiles[0].id).toBe(profile1.id);
    });

    it('prevents deleting the default profile', async () => {
      const defaultProfile = createDefaultProfile('Default', true);
      useSettingsStore.setState({ profiles: [defaultProfile] });

      await expect(useSettingsStore.getState().deleteProfile(defaultProfile.id))
        .rejects.toThrow('Cannot delete the default profile');

      expect(useSettingsStore.getState().error).toBe('Cannot delete the default profile');
    });

    it('throws on backend failure', async () => {
      const profile = createDefaultProfile('Test', false);
      useSettingsStore.setState({ profiles: [profile] });
      mockInvoke.mockRejectedValue(new Error('Delete failed'));

      await expect(useSettingsStore.getState().deleteProfile(profile.id)).rejects.toThrow('Delete failed');

      expect(useSettingsStore.getState().error).toBe('Delete failed');
    });
  });

  describe('resetToDefaults', () => {
    it('restores default settings', () => {
      useSettingsStore.setState({
        settings: {
          ...createDefaultProfile('Custom'),
          scanConfig: {
            ...createDefaultScanConfig(),
            defaultCidr: '10.0.0.0/8',
            timeoutMs: 9999,
          },
        },
      });

      useSettingsStore.getState().resetToDefaults();

      const settings = useSettingsStore.getState().settings;
      expect(settings.name).toBe('Default');
      expect(settings.isDefault).toBe(true);
      expect(settings.scanConfig.defaultCidr).toBe('192.168.1.0/24');
      expect(settings.scanConfig.timeoutMs).toBe(1000);
    });

    it('calls invoke to persist defaults', () => {
      mockInvoke.mockResolvedValue(undefined);

      useSettingsStore.getState().resetToDefaults();

      expect(mockInvoke).toHaveBeenCalledWith('save_settings', expect.objectContaining({
        settings: expect.objectContaining({ name: 'Default' }),
      }));
      expect(mockInvoke).toHaveBeenCalledWith('save_profile', expect.objectContaining({
        profile: expect.objectContaining({ name: 'Default' }),
      }));
    });
  });

  describe('updateScanConfig', () => {
    it('merges partial scan config updates', () => {
      useSettingsStore.getState().updateScanConfig({ timeoutMs: 5000, defaultCidr: '10.0.0.0/8' });

      const scanConfig = useSettingsStore.getState().settings.scanConfig;
      expect(scanConfig.timeoutMs).toBe(5000);
      expect(scanConfig.defaultCidr).toBe('10.0.0.0/8');
      // Other fields should remain default
      expect(scanConfig.maxConcurrentHosts).toBe(50);
    });
  });

  describe('updateUiPreferences', () => {
    it('merges partial UI preference updates', () => {
      useSettingsStore.getState().updateUiPreferences({ autoRefresh: true, refreshRateMs: 5000 });

      const uiPrefs = useSettingsStore.getState().settings.uiPreferences;
      expect(uiPrefs.autoRefresh).toBe(true);
      expect(uiPrefs.refreshRateMs).toBe(5000);
      // Other fields should remain default
      expect(uiPrefs.confirmBeforeScan).toBe(true);
    });
  });

  describe('clearError', () => {
    it('resets error to null', () => {
      useSettingsStore.setState({ error: 'Some error' });

      useSettingsStore.getState().clearError();

      expect(useSettingsStore.getState().error).toBeNull();
    });
  });

  describe('setActiveProfile', () => {
    it('switches to the selected profile', () => {
      const profile1 = createDefaultProfile('Profile 1', true);
      const profile2 = createDefaultProfile('Profile 2', false);
      useSettingsStore.setState({
        profiles: [profile1, profile2],
        currentProfileId: profile1.id,
        settings: profile1,
      });

      useSettingsStore.getState().setActiveProfile(profile2.id);

      expect(useSettingsStore.getState().currentProfileId).toBe(profile2.id);
      expect(useSettingsStore.getState().settings.name).toBe('Profile 2');
    });

    it('does nothing for non-existent profile', () => {
      const profile1 = createDefaultProfile('Profile 1', true);
      useSettingsStore.setState({
        profiles: [profile1],
        currentProfileId: profile1.id,
        settings: profile1,
      });

      useSettingsStore.getState().setActiveProfile('non-existent');

      expect(useSettingsStore.getState().currentProfileId).toBe(profile1.id);
    });
  });
});
