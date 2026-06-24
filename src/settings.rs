//! Settings management module for NetSentinel
//!
//! This module provides settings profiles, scan configuration, and UI preferences
//! that can be saved and loaded from disk.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

use crate::error::ScanError;

/// Discovery method enumeration - serialized as lowercase strings
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum SettingsDiscoveryMethod {
    #[serde(rename = "arp")]
    ArpTable,
    #[serde(rename = "tcp_probe")]
    TcpProbe,
    #[serde(rename = "icmp")]
    IcmpPing,
    #[serde(rename = "all")]
    All,
}

impl Default for SettingsDiscoveryMethod {
    fn default() -> Self {
        SettingsDiscoveryMethod::All
    }
}

/// Scan configuration for a settings profile
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ScanConfig {
    /// Default CIDR block for scanning (e.g., "192.168.1.0/24")
    pub default_cidr: String,
    /// Timeout in milliseconds for each host/port check
    pub timeout_ms: u64,
    /// Maximum concurrent hosts to scan
    pub max_concurrent_hosts: usize,
    /// Maximum concurrent ports per host
    pub max_concurrent_ports: usize,
    /// Whether port scanning is enabled
    pub scan_ports_enabled: bool,
    /// Selected ports to scan (empty means default ports)
    pub selected_ports: Vec<u16>,
    /// Discovery methods to use
    pub discovery_methods: Vec<SettingsDiscoveryMethod>,
    /// Number of retries for failed connections
    pub retry_count: u32,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            default_cidr: "192.168.1.0/24".to_string(),
            timeout_ms: 3000,
            max_concurrent_hosts: 50,
            max_concurrent_ports: 100,
            scan_ports_enabled: true,
            selected_ports: Vec::new(),
            discovery_methods: vec![SettingsDiscoveryMethod::All],
            retry_count: 1,
        }
    }
}

/// UI preferences for a settings profile
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct UiPreferences {
    /// Refresh rate in milliseconds for UI updates
    pub refresh_rate_ms: u64,
    /// Whether to auto-refresh scan results
    pub auto_refresh: bool,
    /// Whether to show advanced options
    pub show_advanced_options: bool,
    /// Whether to confirm before starting a scan
    pub confirm_before_scan: bool,
}

impl Default for UiPreferences {
    fn default() -> Self {
        Self {
            refresh_rate_ms: 1000,
            auto_refresh: true,
            show_advanced_options: false,
            confirm_before_scan: true,
        }
    }
}

/// A settings profile with unique identifier
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SettingsProfile {
    /// Unique profile identifier
    pub id: String,
    /// Profile display name
    pub name: String,
    /// Whether this is the default profile
    pub is_default: bool,
    /// Scan configuration
    pub scan_config: ScanConfig,
    /// UI preferences
    pub ui_preferences: UiPreferences,
    /// When the profile was created (Unix timestamp in seconds)
    pub created_at: i64,
    /// When the profile was last updated (Unix timestamp in seconds)
    pub updated_at: i64,
}

impl SettingsProfile {
    /// Create a new profile with generated ID and current timestamp
    pub fn new(name: String) -> Self {
        let now = chrono::Utc::now().timestamp();
        Self {
            id: Uuid::new_v4().to_string(),
            name,
            is_default: false,
            scan_config: ScanConfig::default(),
            ui_preferences: UiPreferences::default(),
            created_at: now,
            updated_at: now,
        }
    }

    /// Create a default profile
    pub fn default_profile() -> Self {
        let now = chrono::Utc::now().timestamp();
        Self {
            id: "default".to_string(),
            name: "Default".to_string(),
            is_default: true,
            scan_config: ScanConfig::default(),
            ui_preferences: UiPreferences::default(),
            created_at: now,
            updated_at: now,
        }
    }
}

/// Container for all profiles
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct ProfilesContainer {
    /// Map of profile ID to profile
    pub profiles: HashMap<String, SettingsProfile>,
    /// ID of the default profile
    pub default_profile_id: Option<String>,
    /// ID of the currently active profile
    pub active_profile_id: Option<String>,
}

impl ProfilesContainer {
    /// Create a new empty container
    pub fn new() -> Self {
        Self {
            profiles: HashMap::new(),
            default_profile_id: None,
            active_profile_id: None,
        }
    }
}

/// Settings manager for loading and saving profiles
pub struct SettingsManager {
    config_dir: PathBuf,
}

impl SettingsManager {
    /// Create a new settings manager with the given config directory
    pub fn new(config_dir: PathBuf) -> Self {
        Self { config_dir }
    }

    /// Get the path to the profiles file
    fn profiles_path(&self) -> PathBuf {
        self.config_dir.join("profiles.json")
    }

    /// Get the path to the current settings file
    fn current_settings_path(&self) -> PathBuf {
        self.config_dir.join("current_settings.json")
    }

    /// Load all profiles from disk
    pub async fn load_profiles(&self) -> Result<ProfilesContainer, ScanError> {
        let path = self.profiles_path();

        if !path.exists() {
            // Return default container if no profiles file exists
            return Ok(ProfilesContainer::new());
        }

        let mut file = fs::File::open(&path)
            .await
            .map_err(|e| ScanError::NetworkError(format!("Failed to open profiles file: {}", e)))?;

        let mut contents = String::new();
        file.read_to_string(&mut contents)
            .await
            .map_err(|e| ScanError::NetworkError(format!("Failed to read profiles file: {}", e)))?;

        serde_json::from_str(&contents)
            .map_err(|e| ScanError::InvalidInput(format!("Failed to parse profiles: {}", e)))
    }

    /// Save all profiles to disk
    pub async fn save_profiles(&self, container: &ProfilesContainer) -> Result<(), ScanError> {
        // Ensure directory exists
        fs::create_dir_all(&self.config_dir).await.map_err(|e| {
            ScanError::NetworkError(format!("Failed to create config directory: {}", e))
        })?;

        let json = serde_json::to_string_pretty(container)
            .map_err(|e| ScanError::NetworkError(format!("Failed to serialize profiles: {}", e)))?;

        let mut file = fs::File::create(&self.profiles_path()).await.map_err(|e| {
            ScanError::NetworkError(format!("Failed to create profiles file: {}", e))
        })?;

        file.write_all(json.as_bytes()).await.map_err(|e| {
            ScanError::NetworkError(format!("Failed to write profiles file: {}", e))
        })?;

        Ok(())
    }

    /// Load the current active settings
    pub async fn load_current_settings(&self) -> Result<SettingsProfile, ScanError> {
        let path = self.current_settings_path();

        if !path.exists() {
            // Return default profile if no current settings file exists
            return Ok(SettingsProfile::default_profile());
        }

        let mut file = fs::File::open(&path).await.map_err(|e| {
            ScanError::NetworkError(format!("Failed to open current settings file: {}", e))
        })?;

        let mut contents = String::new();
        file.read_to_string(&mut contents).await.map_err(|e| {
            ScanError::NetworkError(format!("Failed to read current settings: {}", e))
        })?;

        serde_json::from_str(&contents).map_err(|e| {
            ScanError::InvalidInput(format!("Failed to parse current settings: {}", e))
        })
    }

    /// Save the current active settings
    pub async fn save_current_settings(&self, profile: &SettingsProfile) -> Result<(), ScanError> {
        // Ensure directory exists
        fs::create_dir_all(&self.config_dir).await.map_err(|e| {
            ScanError::NetworkError(format!("Failed to create config directory: {}", e))
        })?;

        let json = serde_json::to_string_pretty(profile).map_err(|e| {
            ScanError::NetworkError(format!("Failed to serialize current settings: {}", e))
        })?;

        let mut file = fs::File::create(&self.current_settings_path())
            .await
            .map_err(|e| {
                ScanError::NetworkError(format!("Failed to create current settings file: {}", e))
            })?;

        file.write_all(json.as_bytes()).await.map_err(|e| {
            ScanError::NetworkError(format!("Failed to write current settings: {}", e))
        })?;

        Ok(())
    }
}

/// Default settings instance
pub fn default_settings() -> SettingsProfile {
    SettingsProfile::default_profile()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_settings() {
        let settings = default_settings();
        assert_eq!(settings.name, "Default");
        assert!(settings.is_default);
    }

    #[test]
    fn test_new_profile() {
        let profile = SettingsProfile::new("Test Profile".to_string());
        assert_eq!(profile.name, "Test Profile");
        assert!(!profile.is_default);
        assert!(!profile.id.is_empty());
    }

    #[test]
    fn test_scan_config_defaults() {
        let config = ScanConfig::default();
        assert_eq!(config.default_cidr, "192.168.1.0/24");
        assert_eq!(config.timeout_ms, 3000);
        assert!(config.scan_ports_enabled);
    }

    #[test]
    fn test_ui_preferences_defaults() {
        let prefs = UiPreferences::default();
        assert_eq!(prefs.refresh_rate_ms, 1000);
        assert!(prefs.auto_refresh);
        assert!(prefs.confirm_before_scan);
    }

    #[test]
    fn test_profiles_container_default() {
        let container = ProfilesContainer::new();
        assert!(container.profiles.is_empty());
        assert!(container.default_profile_id.is_none());
        assert!(container.active_profile_id.is_none());
    }
}
#[cfg(test)]
mod serialization_tests {
    use super::*;

    #[test]
    fn test_profile_serialization_roundtrip() {
        let profile = SettingsProfile::default_profile();

        // Serialize to JSON
        let json = serde_json::to_string(&profile).unwrap();
        println!("Serialized profile: {}", json);

        // Deserialize back
        let deserialized: SettingsProfile = serde_json::from_str(&json).unwrap();
        println!("Deserialized profile: name={}", deserialized.name);

        assert_eq!(profile.name, deserialized.name);
        assert_eq!(profile.id, deserialized.id);
        assert_eq!(profile.is_default, deserialized.is_default);
    }

    #[test]
    fn test_profiles_container_serialization_roundtrip() {
        let mut container = ProfilesContainer::new();
        let profile = SettingsProfile::default_profile();
        container
            .profiles
            .insert(profile.id.clone(), profile.clone());
        container.default_profile_id = Some(profile.id.clone());
        container.active_profile_id = Some(profile.id.clone());

        // Serialize to JSON
        let json = serde_json::to_string_pretty(&container).unwrap();
        println!("Container JSON:\n{}", json);

        // Deserialize back
        let deserialized: ProfilesContainer = serde_json::from_str(&json).unwrap();
        assert_eq!(container.profiles.len(), deserialized.profiles.len());
        assert_eq!(
            container.default_profile_id,
            deserialized.default_profile_id
        );
        assert_eq!(container.active_profile_id, deserialized.active_profile_id);
    }

    #[test]
    fn test_vec_profiles_from_container() {
        let mut container = ProfilesContainer::new();
        let profile1 = SettingsProfile::default_profile();
        let mut profile2 = SettingsProfile::new("Test".to_string());
        profile2.is_default = false;

        container
            .profiles
            .insert(profile1.id.clone(), profile1.clone());
        container
            .profiles
            .insert(profile2.id.clone(), profile2.clone());

        let profiles: Vec<SettingsProfile> = container.profiles.into_values().collect();
        let json = serde_json::to_string_pretty(&profiles).unwrap();
        println!("Profiles array JSON:\n{}", json);

        assert_eq!(profiles.len(), 2);
    }
}
