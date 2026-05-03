import React, { useState, useCallback, useMemo } from 'react';
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';
import { useSettingsStore } from '../../stores/settingsStore';
import { Button } from '../common/Button';
import { SettingsCard } from './SettingsCard';
import { type SettingsProfile } from '../../types/settings';

export const ProfileManager: React.FC = () => {
  const {
    profiles,
    currentProfileId,
    setActiveProfile,
    createProfile,
    updateProfileName,
    deleteProfile,
    setDefaultProfile,
    error,
    clearError,
  } = useSettingsStore();

  // Safe access to profiles with fallback to empty array
  const safeProfiles = useMemo<SettingsProfile[]>(() => {
    if (!Array.isArray(profiles)) {
      console.warn('[ProfileManager] profiles is not an array:', profiles);
      return [];
    }
    // Filter out any invalid profile entries
    return profiles.filter((p): p is SettingsProfile => {
      return (
        p !== null &&
        typeof p === 'object' &&
        typeof p.id === 'string' &&
        typeof p.name === 'string'
      );
    });
  }, [profiles]);

  // Safe access to currentProfileId
  const safeCurrentProfileId = useMemo<string | null>(() => {
    return typeof currentProfileId === 'string' ? currentProfileId : null;
  }, [currentProfileId]);

  const [isCreating, setIsCreating] = useState(false);
  const [newProfileName, setNewProfileName] = useState('');
  const [editingProfileId, setEditingProfileId] = useState<string | null>(null);
  const [editingName, setEditingName] = useState('');
  const [deleteConfirmId, setDeleteConfirmId] = useState<string | null>(null);

  const handleCreateProfile = useCallback(async () => {
    if (!newProfileName.trim()) return;

    try {
      const newProfile = await createProfile(newProfileName.trim());
      setNewProfileName('');
      setIsCreating(false);
      setActiveProfile(newProfile.id);
    } catch {
      // Error handled by store
    }
  }, [newProfileName, createProfile, setActiveProfile]);

  const handleStartEdit = (profileId: string, currentName: string) => {
    setEditingProfileId(profileId);
    setEditingName(currentName);
  };

  const handleCancelEdit = () => {
    setEditingProfileId(null);
    setEditingName('');
  };

  const handleSaveEdit = useCallback(async () => {
    if (!editingProfileId || !editingName.trim()) return;

    try {
      await updateProfileName(editingProfileId, editingName.trim());
      setEditingProfileId(null);
      setEditingName('');
    } catch {
      // Error handled by store
    }
  }, [editingProfileId, editingName, updateProfileName]);

  const handleDeleteConfirm = useCallback(async () => {
    if (!deleteConfirmId) return;

    try {
      await deleteProfile(deleteConfirmId);
      setDeleteConfirmId(null);
    } catch {
      // Error handled by store
    }
  }, [deleteConfirmId, deleteProfile]);

  const handleSetDefault = useCallback(
    async (profileId: string) => {
      try {
        await setDefaultProfile(profileId);
      } catch {
        // Error handled by store
      }
    },
    [setDefaultProfile]
  );

  const handleSelectProfile = (profileId: string) => {
    if (profileId !== safeCurrentProfileId) {
      setActiveProfile(profileId);
    }
  };

  // Safe getter for profile display data with defaults
  const getProfileDisplayData = (profile: SettingsProfile) => {
    const defaultCidr = profile?.scanConfig?.defaultCidr ?? '192.168.1.0/24';
    const defaultTimeout = profile?.scanConfig?.timeoutMs ?? 1000;
    return { defaultCidr, defaultTimeout };
  };

  return (
    <SettingsCard
      title="Profile Management"
      description="Manage scan configuration profiles"
      actions={
        <Button
          variant="primary"
          size="sm"
          onClick={() => setIsCreating(true)}
          disabled={isCreating}
        >
          <svg className="w-4 h-4 mr-1.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
          </svg>
          New Profile
        </Button>
      }
    >
      <div className="space-y-4">
        {/* Error Display */}
        {error && (
          <div
            role="alert"
            className="p-3 bg-red-900/30 border border-red-800/50 rounded-xl flex items-center justify-between"
          >
            <span className="text-red-300 text-sm">{error}</span>
            <button
              onClick={clearError}
              className="text-red-400 hover:text-red-300 p-1 rounded-lg hover:bg-red-900/30 transition-colors"
              aria-label="Dismiss error"
            >
              <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>
        )}

        {/* Create New Profile Form */}
        {isCreating && (
          <div className="p-4 bg-gray-900/50 border border-gray-700/50 rounded-xl">
            <div className="flex items-center gap-3">
              <input
                type="text"
                value={newProfileName}
                onChange={(e) => setNewProfileName(e.target.value)}
                placeholder="Profile name"
                className={twMerge(
                  clsx(
                    'flex-1 px-4 py-2.5 bg-gray-800 border border-gray-600/50 rounded-xl',
                    'text-gray-100 placeholder-gray-500',
                    'focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent',
                    'transition-all duration-200 hover:border-gray-500'
                  )
                )}
                aria-label="New profile name"
                autoFocus
              />
              <Button variant="primary" size="sm" onClick={handleCreateProfile}>
                Create
              </Button>
              <Button variant="ghost" size="sm" onClick={() => setIsCreating(false)}>
                Cancel
              </Button>
            </div>
          </div>
        )}

        {/* Profile List */}
        {safeProfiles.length === 0 ? (
          <div className="text-center py-8 text-gray-500">
            <svg className="w-12 h-12 mx-auto mb-3 text-gray-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" />
            </svg>
            <p>No profiles yet</p>
            <p className="text-sm mt-1">Create a profile to get started</p>
          </div>
        ) : (
          <div className="space-y-2">
            {safeProfiles.map((profile) => {
              const isActive = profile.id === safeCurrentProfileId;
              const isEditing = editingProfileId === profile.id;
              const isDeleteConfirm = deleteConfirmId === profile.id;
              const { defaultCidr, defaultTimeout } = getProfileDisplayData(profile);

              return (
                <div
                  key={profile.id}
                  className={twMerge(
                    clsx(
                      'p-4 rounded-xl border transition-all duration-200',
                      isActive
                        ? 'bg-blue-900/20 border-blue-700/50'
                        : 'bg-gray-900/30 border-gray-700/30 hover:border-gray-600/50'
                    )
                  )}
                >
                  {isEditing ? (
                    /* Edit Mode */
                    <div className="flex items-center gap-3">
                      <input
                        type="text"
                        value={editingName}
                        onChange={(e) => setEditingName(e.target.value)}
                        className={twMerge(
                          clsx(
                            'flex-1 px-4 py-2 bg-gray-800 border border-gray-600/50 rounded-xl',
                            'text-gray-100',
                            'focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent'
                          )
                        )}
                        aria-label="Edit profile name"
                        autoFocus
                      />
                      <Button variant="primary" size="sm" onClick={handleSaveEdit}>
                        Save
                      </Button>
                      <Button variant="ghost" size="sm" onClick={handleCancelEdit}>
                        Cancel
                      </Button>
                    </div>
                  ) : isDeleteConfirm ? (
                    /* Delete Confirmation */
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-300">Delete &quot;{profile.name}&quot;?</span>
                      <div className="flex items-center gap-2">
                        <Button variant="danger" size="sm" onClick={handleDeleteConfirm}>
                          Delete
                        </Button>
                        <Button variant="ghost" size="sm" onClick={() => setDeleteConfirmId(null)}>
                          Cancel
                        </Button>
                      </div>
                    </div>
                  ) : (
                    /* Normal Mode */
                    <div className="flex items-center justify-between">
                      <button
                        type="button"
                        onClick={() => handleSelectProfile(profile.id)}
                        className="flex-1 text-left"
                        aria-current={isActive ? 'true' : undefined}
                      >
                        <div className="flex items-center gap-2">
                          <span className={twMerge(clsx('font-medium', isActive ? 'text-blue-400' : 'text-gray-200'))}>
                            {profile.name}
                          </span>
                          {profile.isDefault && (
                            <span className="px-2 py-0.5 text-xs bg-blue-600/30 text-blue-400 rounded-full">
                              Default
                            </span>
                          )}
                          {isActive && (
                            <span className="sr-only">(active)</span>
                          )}
                        </div>
                        <div className="text-xs text-gray-500 mt-0.5">
                          {defaultCidr} &bull; {defaultTimeout}ms timeout
                        </div>
                      </button>

                      <div className="flex items-center gap-1">
                        {!profile.isDefault && (
                          <button
                            type="button"
                            onClick={() => handleSetDefault(profile.id)}
                            className={twMerge(
                              clsx(
                                'p-2 rounded-lg transition-colors',
                                'text-gray-500 hover:text-blue-400 hover:bg-gray-700/50',
                                'focus:outline-none focus:ring-2 focus:ring-blue-500'
                              )
                            )}
                            aria-label={`Set ${profile.name} as default`}
                            title="Set as default"
                          >
                            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11.049 2.927c.3-.921 1.603-.921 1.902 0l1.519 4.674a1 1 0 00.95.69h4.915c.969 0 1.371 1.24.588 1.81l-3.976 2.888a1 1 0 00-.363 1.118l1.518 4.674c.3.922-.755 1.688-1.538 1.118l-3.976-2.888a1 1 0 00-1.176 0l-3.976 2.888c-.783.57-1.838-.197-1.538-1.118l1.518-4.674a1 1 0 00-.363-1.118l-3.976-2.888c-.784-.57-.38-1.81.588-1.81h4.914a1 1 0 00.951-.69l1.519-4.674z" />
                            </svg>
                          </button>
                        )}

                        <button
                          type="button"
                          onClick={() => handleStartEdit(profile.id, profile.name)}
                          className={twMerge(
                            clsx(
                              'p-2 rounded-lg transition-colors',
                              'text-gray-500 hover:text-gray-300 hover:bg-gray-700/50',
                              'focus:outline-none focus:ring-2 focus:ring-blue-500'
                            )
                          )}
                          aria-label={`Edit ${profile.name}`}
                          title="Edit name"
                        >
                          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
                          </svg>
                        </button>

                        {!profile.isDefault && (
                          <button
                            type="button"
                            onClick={() => setDeleteConfirmId(profile.id)}
                            className={twMerge(
                              clsx(
                                'p-2 rounded-lg transition-colors',
                                'text-gray-500 hover:text-red-400 hover:bg-red-900/20',
                                'focus:outline-none focus:ring-2 focus:ring-red-500'
                              )
                            )}
                            aria-label={`Delete ${profile.name}`}
                            title="Delete profile"
                          >
                            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                            </svg>
                          </button>
                        )}
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}

        {/* Reset to Defaults */}
        <div className="pt-4 border-t border-gray-700/30">
          <Button
            variant="secondary"
            size="sm"
            onClick={() => {
              if (confirm('Reset all settings to defaults?')) {
                useSettingsStore.getState().resetToDefaults();
              }
            }}
          >
            <svg className="w-4 h-4 mr-1.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
            </svg>
            Reset to Defaults
          </Button>
        </div>
      </div>
    </SettingsCard>
  );
};