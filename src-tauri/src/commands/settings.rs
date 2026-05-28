//! Settings-related Tauri commands

use std::path::PathBuf;
use log::{info, error};

use crate::error::ScanError;
use crate::settings::{default_settings, SettingsManager, SettingsProfile};

/// Get the configuration directory for NetSentinel
pub(crate) fn get_config_dir() -> Result<PathBuf, ScanError> {
    dirs::config_dir()
        .map(|p| p.join("netsentinel"))
        .ok_or_else(|| ScanError::NetworkError("Could not determine config directory".to_string()))
}

/// Create a new settings manager with the appropriate config directory
pub fn create_settings_manager() -> Result<SettingsManager, ScanError> {
    let config_dir = get_config_dir()?;
    Ok(SettingsManager::new(config_dir))
}

/// Get all saved settings profiles
#[tauri::command]
pub async fn get_settings_profiles() -> Result<Vec<SettingsProfile>, ScanError> {
    info!("[SETTINGS] get_settings_profiles called");
    let manager = create_settings_manager()?;
    info!("[SETTINGS] SettingsManager created, loading profiles...");
    let container = manager.load_profiles().await?;
    info!("[SETTINGS] Loaded {} profiles from disk", container.profiles.len());

    let profiles: Vec<SettingsProfile> = container.profiles.into_values().collect();
    info!("[SETTINGS] Returning {} profiles to frontend", profiles.len());
    Ok(profiles)
}

/// Save a settings profile
#[tauri::command]
pub async fn save_profile(profile: SettingsProfile) -> Result<(), ScanError> {
    let manager = create_settings_manager()?;
    let mut container = manager.load_profiles().await?;

    // Update the profile's updated_at timestamp to current time
    let mut updated_profile = profile;
    updated_profile.updated_at = chrono::Utc::now().timestamp();

    // Add or update the profile
    container.profiles.insert(updated_profile.id.clone(), updated_profile);

    // If this is the first profile, make it the default and active
    if container.profiles.len() == 1 {
        if container.default_profile_id.is_none() {
            container.default_profile_id = container.profiles.keys().next().cloned();
        }
        if container.active_profile_id.is_none() {
            container.active_profile_id = container.profiles.keys().next().cloned();
        }
    }

    manager.save_profiles(&container).await
}

/// Delete a settings profile by ID
#[tauri::command]
pub async fn delete_profile(id: String) -> Result<(), ScanError> {
    // Cannot delete the default profile
    if id == "default" {
        return Err(ScanError::InvalidInput(
            "Cannot delete the default profile".to_string(),
        ));
    }

    let manager = create_settings_manager()?;
    let mut container = manager.load_profiles().await?;

    // Remove the profile
    let removed = container.profiles.remove(&id);

    if removed.is_none() {
        return Err(ScanError::InvalidInput(format!(
            "Profile with ID '{}' not found",
            id
        )));
    }

    // If the deleted profile was the active one, reset active to default
    if container.active_profile_id.as_ref() == Some(&id) {
        container.active_profile_id = container.default_profile_id.clone();
    }

    // If the deleted profile was the default, reset default
    if container.default_profile_id.as_ref() == Some(&id) {
        container.default_profile_id = container.profiles.keys().next().cloned();
    }

    manager.save_profiles(&container).await
}

/// Load the current active settings
#[tauri::command]
pub async fn load_settings() -> Result<SettingsProfile, ScanError> {
    info!("[SETTINGS] load_settings called");
    let manager = create_settings_manager()?;
    info!("[SETTINGS] SettingsManager created, loading current settings...");
    let settings = manager.load_current_settings().await;
    match &settings {
        Ok(profile) => info!("[SETTINGS] Loaded current settings: {} (id={})", profile.name, profile.id),
        Err(e) => error!("[SETTINGS] Failed to load current settings: {}", e),
    }
    settings
}

/// Save the current active settings
#[tauri::command]
pub async fn save_settings(profile: SettingsProfile) -> Result<(), ScanError> {
    let manager = create_settings_manager()?;
    manager.save_current_settings(&profile).await
}

/// Get the default settings
#[tauri::command]
pub fn get_default_settings() -> Result<SettingsProfile, ScanError> {
    Ok(default_settings())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_default_settings() {
        let settings = get_default_settings().expect("Should get default settings");
        assert_eq!(settings.name, "Default");
        assert!(settings.is_default);
    }
}
#[cfg(test)]
mod command_tests {
    use super::*;

    #[test]
    fn test_get_config_dir() {
        let config_dir = get_config_dir().expect("Should get config dir");
        println!("Config dir: {:?}", config_dir);
        assert!(config_dir.to_str().unwrap().contains("netsentinel"));
    }
}
