import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import { invoke } from '@tauri-apps/api/core';
import type {
  SettingsProfile,
  ScanConfig,
  UiPreferences,
} from '../types/settings';
import {
  createDefaultProfile,
  createDefaultScanConfig,
  createDefaultUiPreferences,
  isValidSettingsProfile,
  safeProfileFromObject,
} from '../types/settings';

interface SettingsState {
  // State
  profiles: SettingsProfile[];
  currentProfileId: string | null;
  settings: SettingsProfile;
  isLoading: boolean;
  error: string | null;
  isSaving: boolean;
  lastSaved: number | null;

  // Actions
  fetchProfiles: () => Promise<void>;
  saveProfile: (profile: SettingsProfile) => Promise<void>;
  deleteProfile: (id: string) => Promise<void>;
  loadSettings: () => Promise<void>;
  saveSettings: (settings: SettingsProfile) => Promise<void>;
  setActiveProfile: (id: string) => void;
  resetToDefaults: () => void;
  updateScanConfig: (config: Partial<ScanConfig>) => void;
  updateUiPreferences: (prefs: Partial<UiPreferences>) => void;
  clearError: () => void;
  createProfile: (name: string) => Promise<SettingsProfile>;
  setDefaultProfile: (id: string) => Promise<void>;
  updateProfileName: (id: string, name: string) => Promise<void>;
}

// Safe getter for settings with fallback defaults
function getDefaultSettings(): SettingsProfile {
  return createDefaultProfile('Default', true);
}

// Validate and normalize a profile from backend
function normalizeProfile(profile: unknown, fallbackName = 'Profile'): SettingsProfile {
  if (isValidSettingsProfile(profile)) {
    return profile;
  }
  // Log warning for debugging but return a safe profile
  console.warn('[settingsStore] Received malformed profile from backend, normalizing:', profile);
  return safeProfileFromObject(profile, fallbackName);
}

export const useSettingsStore = create<SettingsState>()(
  persist(
    (set, get) => ({
      // Initial state - always have valid defaults
      profiles: [],
      currentProfileId: null,
      settings: getDefaultSettings(),
      isLoading: false,
      error: null,
      isSaving: false,
      lastSaved: null,

      // Fetch all profiles from backend
      fetchProfiles: async () => {
        set({ isLoading: true, error: null });
        try {
          const result = await invoke<unknown[]>('get_settings_profiles');

          // Normalize profiles to handle malformed backend data
          const normalizedProfiles: SettingsProfile[] = result.map((p, index) =>
            normalizeProfile(p, `Profile ${index + 1}`)
          );

          // If no profiles exist, create default
          if (normalizedProfiles.length === 0) {
            const defaultProfile = createDefaultProfile('Default', true);
            await invoke('save_profile', { profile: defaultProfile });
            set({
              profiles: [defaultProfile],
              currentProfileId: defaultProfile.id,
              settings: defaultProfile,
              isLoading: false,
            });
          } else {
            // Backend returned profiles - sync state properly
            // Determine which profile should be active
            const persistedSettings = get().settings;
            const persistedCurrentId = get().currentProfileId;

            // Check if current settings ID matches any backend profile
            const currentMatchesBackend = normalizedProfiles.some(p => p.id === persistedSettings.id);
            const persistedProfileStillExists = persistedCurrentId && normalizedProfiles.some(p => p.id === persistedCurrentId);

            let newCurrentId = persistedProfileStillExists ? persistedCurrentId : normalizedProfiles[0].id;
            let newSettings = currentMatchesBackend ? persistedSettings : normalizedProfiles[0];

            set({
              profiles: normalizedProfiles,
              currentProfileId: newCurrentId,
              settings: newSettings,
              isLoading: false,
            });
          }
        } catch (error) {
          const errorMessage = error instanceof Error ? error.message : 'Failed to fetch profiles';
          set({ error: errorMessage, isLoading: false });
          // Load from local cache on error
          const cached = localStorage.getItem('netsentinel-settings');
          if (cached) {
            try {
              const parsed = JSON.parse(cached);
              const cachedProfiles = parsed.state?.profiles;
              set({
                profiles: Array.isArray(cachedProfiles)
                  ? cachedProfiles.map((p: unknown) => normalizeProfile(p))
                  : [],
                currentProfileId: parsed.state?.currentProfileId ?? null,
                settings: normalizeProfile(parsed.state?.settings) ?? getDefaultSettings(),
              });
            } catch {
              // Ignore cache parse errors
            }
          }
        }
      },

      // Save a profile to backend
      saveProfile: async (profile: SettingsProfile) => {
        set({ isSaving: true, error: null });
        try {
          await invoke('save_profile', { profile });
          set((state) => ({
            profiles: state.profiles.some((p) => p.id === profile.id)
              ? state.profiles.map((p) => (p.id === profile.id ? profile : p))
              : [...state.profiles, profile],
            isSaving: false,
            lastSaved: Date.now(),
          }));
        } catch (error) {
          const errorMessage = error instanceof Error ? error.message : 'Failed to save profile';
          set({ error: errorMessage, isSaving: false });
          throw error;
        }
      },

      // Delete a profile
      deleteProfile: async (id: string) => {
        const state = get();
        const profile = state.profiles.find((p) => p.id === id);

        if (profile?.isDefault) {
          set({ error: 'Cannot delete the default profile' });
          throw new Error('Cannot delete the default profile');
        }

        set({ isLoading: true, error: null });
        try {
          await invoke('delete_profile', { id });
          const newProfiles = state.profiles.filter((p) => p.id !== id);
          const newCurrentId = state.currentProfileId === id
            ? (newProfiles[0]?.id ?? null)
            : state.currentProfileId;

          set({
            profiles: newProfiles,
            currentProfileId: newCurrentId,
            settings: newProfiles.find((p) => p.id === newCurrentId) ?? state.settings,
            isLoading: false,
          });
        } catch (error) {
          const errorMessage = error instanceof Error ? error.message : 'Failed to delete profile';
          set({ error: errorMessage, isLoading: false });
          throw error;
        }
      },

      // Load current settings from backend
      loadSettings: async () => {
        set({ isLoading: true, error: null });
        try {
          const settings = await invoke<unknown>('load_settings');
          const normalizedSettings = normalizeProfile(settings, 'Current');
          set({ settings: normalizedSettings, isLoading: false });
        } catch (error) {
          const errorMessage = error instanceof Error ? error.message : 'Failed to load settings';
          set({ error: errorMessage, isLoading: false });
        }
      },

      // Save current settings to backend
      saveSettings: async (settings: SettingsProfile) => {
        set({ isSaving: true, error: null });
        try {
          await invoke('save_settings', { settings });
          const updatedSettings = { ...settings, updatedAt: Date.now() };
          set((state) => ({
            settings: updatedSettings,
            profiles: state.profiles.map((p) =>
              p.id === updatedSettings.id ? updatedSettings : p
            ),
            isSaving: false,
            lastSaved: Date.now(),
          }));
        } catch (error) {
          const errorMessage = error instanceof Error ? error.message : 'Failed to save settings';
          set({ error: errorMessage, isSaving: false });
          throw error;
        }
      },

      // Set active profile
      setActiveProfile: (id: string) => {
        const state = get();
        const profile = state.profiles.find((p) => p.id === id);
        if (profile) {
          set({ currentProfileId: id, settings: profile });
        }
      },

      // Reset to defaults
      resetToDefaults: () => {
        const defaultProfile = createDefaultProfile('Default', true);
        set({
          settings: defaultProfile,
          currentProfileId: defaultProfile.id,
        });
        // Save to backend
        invoke('save_settings', { settings: defaultProfile }).catch(console.error);
        invoke('save_profile', { profile: defaultProfile }).catch(console.error);
      },

      // Update scan config partial - with null safety
      updateScanConfig: (config: Partial<ScanConfig>) => {
        set((state) => {
          // Ensure we have valid base objects before spreading
          const currentScanConfig = state.settings?.scanConfig ?? createDefaultScanConfig();
          return {
            settings: {
              ...state.settings,
              scanConfig: { ...currentScanConfig, ...config },
              updatedAt: Date.now(),
            },
          };
        });
      },

      // Update UI preferences partial - with null safety
      updateUiPreferences: (prefs: Partial<UiPreferences>) => {
        set((state) => {
          // Ensure we have valid base objects before spreading
          const currentUiPrefs = state.settings?.uiPreferences ?? createDefaultUiPreferences();
          return {
            settings: {
              ...state.settings,
              uiPreferences: { ...currentUiPrefs, ...prefs },
              updatedAt: Date.now(),
            },
          };
        });
      },

      // Clear error
      clearError: () => {
        set({ error: null });
      },

      // Create a new profile
      createProfile: async (name: string) => {
        const state = get();
        const newProfile = createDefaultProfile(name);

        // Copy current settings to new profile with null safety
        const currentScanConfig = state.settings?.scanConfig ?? createDefaultScanConfig();
        const currentUiPrefs = state.settings?.uiPreferences ?? createDefaultUiPreferences();
        newProfile.scanConfig = { ...currentScanConfig };
        newProfile.uiPreferences = { ...currentUiPrefs };

        try {
          await invoke('save_profile', { profile: newProfile });
          set((s) => ({
            profiles: [...s.profiles, newProfile],
          }));
          return newProfile;
        } catch (error) {
          const errorMessage = error instanceof Error ? error.message : 'Failed to create profile';
          set({ error: errorMessage });
          throw error;
        }
      },

      // Set a profile as default
      setDefaultProfile: async (id: string) => {
        const state = get();
        const updatedProfiles = state.profiles.map((p) => ({
          ...p,
          isDefault: p.id === id,
        }));

        const newDefault = updatedProfiles.find((p) => p.id === id);
        if (!newDefault) return;

        try {
          // Update all profiles to reflect new default
          for (const profile of updatedProfiles) {
            await invoke('save_profile', { profile });
          }
          set({ profiles: updatedProfiles });
        } catch (error) {
          const errorMessage = error instanceof Error ? error.message : 'Failed to set default profile';
          set({ error: errorMessage });
        }
      },

      // Update profile name
      updateProfileName: async (id: string, name: string) => {
        const state = get();
        const profile = state.profiles.find((p) => p.id === id);
        if (!profile) return;

        const updatedProfile = { ...profile, name, updatedAt: Date.now() };

        try {
          await invoke('save_profile', { profile: updatedProfile });
          set((s) => ({
            profiles: s.profiles.map((p) => (p.id === id ? updatedProfile : p)),
            settings: s.currentProfileId === id ? updatedProfile : s.settings,
          }));
        } catch (error) {
          const errorMessage = error instanceof Error ? error.message : 'Failed to update profile name';
          set({ error: errorMessage });
        }
      },
    }),
    {
      name: 'netsentinel-settings',
      partialize: (state) => ({
        profiles: state.profiles,
        currentProfileId: state.currentProfileId,
        settings: state.settings,
      }),
      // Handle version migrations if needed
      version: 1,
    }
  )
);

// Selectors for performance
export const useSettingsProfiles = () => useSettingsStore((s) => s.profiles);
export const useCurrentSettings = () => useSettingsStore((s) => s.settings);
export const useSettingsLoading = () => useSettingsStore((s) => s.isLoading);
export const useSettingsError = () => useSettingsStore((s) => s.error);
export const useIsSaving = () => useSettingsStore((s) => s.isSaving);