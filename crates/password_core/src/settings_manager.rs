// crates/password_core/src/settings_manager.rs

use std::{fs, path::PathBuf}; // Removed 'Path'
use serde::{Serialize, Deserialize};
use crate::error::PasswordManagerError; // Use your custom error type
use dirs_next::{config_dir, data_dir}; // For finding OS-specific paths
use log; // For logging

// Default file names for settings and data
const APP_CONFIG_FILE_NAME: &str = "config.json";
const APP_DATA_DIR_NAME: &str = "heikkinen_password_manager"; // Application's data directory name

/// Represents a single user profile with its associated vault path.
/// This would be part of the application's configuration, not the vault itself.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppUserProfile {
    pub id: String, // A unique ID for the profile, e.g., a username
    pub name: String, // Display name for the profile
    pub vault_path: PathBuf, // Path to the encrypted vault file for this profile
    pub last_accessed: chrono::DateTime<chrono::Utc>, // Last time this profile was used
    pub is_admin: bool, // Indicates if this profile has admin privileges
}

impl AppUserProfile {
    pub fn new(id: String, name: String, vault_path: PathBuf, is_admin: bool) -> Self {
        AppUserProfile {
            id,
            name,
            vault_path,
            last_accessed: chrono::Utc::now(),
            is_admin,
        }
    }
}

/// Represents the global application configuration data.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct AppConfig {
    pub profiles: Vec<AppUserProfile>,
    pub last_active_profile_id: Option<String>,
    pub theme: String,
    pub language: String,
}

impl AppConfig {
    // Default implementation for AppConfig
    pub fn default() -> Self {
        AppConfig {
            profiles: Vec::new(),
            last_active_profile_id: None,
            theme: "default".to_string(),
            language: "en".to_string(),
        }
    }

    /// Finds a profile by its ID.
    pub fn get_profile_by_id(&self, id: &str) -> Option<&AppUserProfile> {
        self.profiles.iter().find(|p| p.id == id)
    }

    /// Finds a mutable profile by its ID.
    pub fn get_profile_by_id_mut(&mut self, id: &str) -> Option<&mut AppUserProfile> {
        self.profiles.iter_mut().find(|p| p.id == id)
    }

    /// Adds or updates a profile. If a profile with the same ID exists, it's replaced.
    pub fn add_or_update_profile(&mut self, profile: AppUserProfile) {
        // Clone the ID before 'profile' is potentially moved
        let profile_id_for_last_active = profile.id.clone();

        if let Some(existing_profile) = self.profiles.iter_mut().find(|p| p.id == profile.id) {
            *existing_profile = profile; // 'profile' is moved here
        } else {
            self.profiles.push(profile); // 'profile' is moved here
        }
        // Use the cloned ID for last_active_profile_id
        self.last_active_profile_id = Some(profile_id_for_last_active);
    }

    /// Removes a profile by ID. Returns true if removed, false if not found.
    pub fn remove_profile(&mut self, id: &str) -> bool {
        let original_len = self.profiles.len();
        self.profiles.retain(|p| p.id != id);
        if self.last_active_profile_id.as_deref() == Some(id) {
            self.last_active_profile_id = None; // Clear last active if it was the removed profile
        }
        self.profiles.len() < original_len
    }
}

/// Manages loading and saving of application settings (AppConfig).
pub struct SettingsManager {
    config_file_path: PathBuf,
    pub config: AppConfig, // Public access to the loaded configuration
}

impl SettingsManager {
    /// Initializes the SettingsManager.
    /// Determines config file path and loads existing AppConfig or creates a default.
    ///
    /// `is_portable`: If true, looks for config in current executable directory.
    ///                If false, uses OS-specific app data directory.
    pub fn new(is_portable: bool) -> Result<Self, PasswordManagerError> {
        let config_file_path = Self::get_default_config_file_path(is_portable)?;
        Self::from_path(config_file_path)
    }

    /// Initializes SettingsManager from a specific config file path.
    /// Useful for testing or custom configurations.
    pub fn from_path(config_file_path: PathBuf) -> Result<Self, PasswordManagerError> {
        let config = match Self::load_config_from_path(&config_file_path) {
            Ok(data) => {
                log::info!("Loaded existing app configuration from: {:?}", config_file_path);
                data
            },
            Err(PasswordManagerError::IoError(ref e)) if e.kind() == std::io::ErrorKind::NotFound => {
                log::info!("App configuration file not found. Creating default configuration.");
                let default_config = AppConfig::default();
                // Ensure the directory exists before saving
                if let Some(parent) = config_file_path.parent() {
                    fs::create_dir_all(parent)?;
                }
                Self::save_config_to_path(&config_file_path, &default_config)?;
                default_config
            },
            Err(e) => {
                log::error!("Error loading app configuration: {:?}", e);
                return Err(e);
            }
        };

        Ok(Self {
            config_file_path,
            config,
        })
    }

    /// Saves the current in-memory AppConfig to the configuration file.
    pub fn save(&self) -> Result<(), PasswordManagerError> {
        Self::save_config_to_path(&self.config_file_path, &self.config)
    }

    /// Helper function to load AppConfig from a specific path.
    fn load_config_from_path(path: &PathBuf) -> Result<AppConfig, PasswordManagerError> { // Use PathBuf for consistency
        let contents = fs::read_to_string(path)?;
        let app_config: AppConfig = serde_json::from_str(&contents)?;
        Ok(app_config)
    }

    /// Helper function to save AppConfig to a specific path.
    /// This is a basic save. We will enhance it later with transactional saving (backup, write temp, replace).
    fn save_config_to_path(path: &PathBuf, app_config: &AppConfig) -> Result<(), PasswordManagerError> { // Use PathBuf for consistency
        let json_string = serde_json::to_string_pretty(app_config)?; // Use pretty for readability
        fs::write(path, json_string)?;
        Ok(())
    }

    /// Determines the appropriate default configuration file path based on portable mode.
    pub fn get_default_config_file_path(is_portable: bool) -> Result<PathBuf, PasswordManagerError> {
        let mut path = if is_portable {
            // In portable mode, config is next to the executable
            let current_exe = std::env::current_exe()?;
            current_exe.parent()
                .ok_or(PasswordManagerError::Other("Could not determine executable's parent directory.".to_string()))?
                .to_path_buf()
        } else {
            // In installed mode, use OS-specific app config directory
            let base_dirs = config_dir()
                .ok_or(PasswordManagerError::Other("Could not determine OS config directory.".to_string()))?;
            base_dirs.join(APP_DATA_DIR_NAME) // Your app's specific config folder
        };

        path.push(APP_CONFIG_FILE_NAME); // The configuration file name
        Ok(path)
    }

    /// Returns the path to the application's default data directory (for vaults, etc.).
    pub fn get_default_data_dir() -> Result<PathBuf, PasswordManagerError> {
        let mut path = data_dir()
            .ok_or_else(|| PasswordManagerError::Other("Could not determine OS data directory.".to_string()))?;
        path.push(APP_DATA_DIR_NAME);
        Ok(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Utc, Duration as ChronoDuration};
    use std::fs;
    use tempfile::tempdir; // For creating temporary directories for tests

    // Helper function to create a temporary settings file path for tests
    fn get_temp_settings_file_path(temp_dir: &std::path::Path) -> PathBuf { // Use std::path::Path here
        let mut path = PathBuf::from(temp_dir);
        path.push(APP_DATA_DIR_NAME);
        path.push(APP_CONFIG_FILE_NAME);
        path
    }

    #[test]
    fn test_app_user_profile_new() {
        let profile = AppUserProfile::new(
            "test_user".to_string(),
            "Test User".to_string(),
            PathBuf::from("/path/to/vault.json"),
            false, // not admin
        );
        assert_eq!(profile.id, "test_user");
        assert_eq!(profile.name, "Test User");
        assert_eq!(profile.vault_path, PathBuf::from("/path/to/vault.json"));
        assert!(!profile.is_admin);
        assert!(profile.last_accessed <= Utc::now());
        assert!(profile.last_accessed > Utc::now() - ChronoDuration::seconds(5));
    }

    #[test]
    fn test_app_config_default() {
        let config = AppConfig::default();
        assert!(config.profiles.is_empty());
        assert_eq!(config.last_active_profile_id, None);
        assert_eq!(config.theme, "default");
        assert_eq!(config.language, "en");
    }

    #[test]
    fn test_settings_manager_new_and_save_load() {
        let temp_dir = tempdir().unwrap();
        let test_file_path = get_temp_settings_file_path(temp_dir.path());

        // Test loading default (non-existent file)
        let manager_default = SettingsManager::from_path(test_file_path.clone()).unwrap();
        assert!(manager_default.config.profiles.is_empty());
        assert_eq!(manager_default.config.last_active_profile_id, None);
        assert!(test_file_path.exists()); // File should be created with default settings

        // Test adding a profile and saving
        let mut manager = manager_default; // Take ownership
        let profile1 = AppUserProfile::new(
            "user1".to_string(),
            "User One".to_string(),
            PathBuf::from("v1.vault"),
            false,
        );
        manager.config.add_or_update_profile(profile1.clone());
        manager.save().unwrap();

        // Test loading the saved settings
        let loaded_manager = SettingsManager::from_path(test_file_path.clone()).unwrap();
        assert_eq!(loaded_manager.config.profiles.len(), 1);
        assert_eq!(loaded_manager.config.profiles[0].id, profile1.id);
        assert_eq!(loaded_manager.config.profiles[0].name, profile1.name);
        assert_eq!(loaded_manager.config.profiles[0].vault_path, profile1.vault_path);
        assert_eq!(loaded_manager.config.last_active_profile_id, Some("user1".to_string()));

        temp_dir.close().unwrap();
    }

    #[test]
    fn test_app_config_add_or_update_profile() {
        let mut config = AppConfig::default();
        let profile1 = AppUserProfile::new("user1".to_string(), "User One".to_string(), PathBuf::from("v1.vault"), false);
        let profile2 = AppUserProfile::new("user2".to_string(), "User Two".to_string(), PathBuf::from("v2.vault"), true);

        config.add_or_update_profile(profile1.clone());
        assert_eq!(config.profiles.len(), 1);
        assert_eq!(config.get_profile_by_id("user1").unwrap().name, "User One");
        assert_eq!(config.last_active_profile_id, Some("user1".to_string()));

        config.add_or_update_profile(profile2.clone());
        assert_eq!(config.profiles.len(), 2);
        assert_eq!(config.get_profile_by_id("user2").unwrap().name, "User Two");
        assert_eq!(config.last_active_profile_id, Some("user2".to_string()));


        // Update existing profile
        let updated_profile1 = AppUserProfile::new("user1".to_string(), "Updated User One".to_string(), PathBuf::from("v1_new.vault"), true);
        config.add_or_update_profile(updated_profile1.clone());
        assert_eq!(config.profiles.len(), 2); // Still 2 profiles
        assert_eq!(config.get_profile_by_id("user1").unwrap().name, "Updated User One");
        assert_eq!(config.get_profile_by_id("user1").unwrap().vault_path, PathBuf::from("v1_new.vault"));
        assert_eq!(config.last_active_profile_id, Some("user1".to_string()));
    }

    #[test]
    fn test_app_config_remove_profile() {
        let mut config = AppConfig::default();
        config.add_or_update_profile(AppUserProfile::new("user1".to_string(), "User One".to_string(), PathBuf::from("v1.vault"), false));
        config.add_or_update_profile(AppUserProfile::new("user2".to_string(), "User Two".to_string(), PathBuf::from("v2.vault"), false));
        config.last_active_profile_id = Some("user1".to_string());

        assert_eq!(config.profiles.len(), 2);

        // Remove a profile that exists
        let removed = config.remove_profile("user1");
        assert!(removed);
        assert_eq!(config.profiles.len(), 1);
        assert!(config.get_profile_by_id("user1").is_none());
        assert!(config.get_profile_by_id("user2").is_some());
        assert_eq!(config.last_active_profile_id, None); // last_active_profile_id should be cleared if removed

        // Try to remove a profile that doesn't exist
        let removed_non_existent = config.remove_profile("user3");
        assert!(!removed_non_existent);
        assert_eq!(config.profiles.len(), 1); // Length should remain unchanged
    }

    #[test]
    fn test_app_config_get_profile_by_id() {
        let mut config = AppConfig::default();
        let profile1 = AppUserProfile::new("user1".to_string(), "User One".to_string(), PathBuf::from("v1.vault"), false);
        config.add_or_update_profile(profile1.clone());

        let retrieved_profile = config.get_profile_by_id("user1").unwrap();
        assert_eq!(retrieved_profile, &profile1);

        let non_existent_profile = config.get_profile_by_id("user_x");
        assert!(non_existent_profile.is_none());
    }

    #[test]
    fn test_app_config_get_profile_by_id_mut() {
        let mut config = AppConfig::default();
        let profile1 = AppUserProfile::new("user1".to_string(), "User One".to_string(), PathBuf::from("v1.vault"), false);
        config.add_or_update_profile(profile1.clone());

        let retrieved_profile_mut = config.get_profile_by_id_mut("user1").unwrap();
        retrieved_profile_mut.name = "Mutated User".to_string();

        assert_eq!(config.get_profile_by_id("user1").unwrap().name, "Mutated User");
    }
}