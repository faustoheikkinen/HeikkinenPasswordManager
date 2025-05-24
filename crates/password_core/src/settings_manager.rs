// crates/password_core/src/settings_manager.rs

//! Manages application configuration and user profiles for the Heikkinen Password Manager.
//!
//! This module handles the loading, saving, and management of global application settings
//! and individual user profiles, including their associated vault paths. It abstracts
//! away the details of file system interaction and serialization.

use std::{fs, path::PathBuf};
use serde::{Serialize, Deserialize};
use crate::error::PasswordManagerError;
use dirs_next::{config_dir, data_dir};
use log;

// Default file names for settings and data
const APP_CONFIG_FILE_NAME: &str = "config.json";
const APP_DATA_DIR_NAME: &str = "heikkinen_password_manager"; // Application's data directory name

/// Represents a single user profile with its associated vault path and other metadata.
///
/// This struct holds information pertinent to a specific user's interaction with the
/// password manager, such as their unique ID, display name, the location of their
/// encrypted vault, and administrative privileges.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppUserProfile {
    /// A unique identifier for the profile, typically a username.
    pub id: String,
    /// A human-readable display name for the profile.
    pub name: String,
    /// The file system path to the encrypted vault file associated with this profile.
    pub vault_path: PathBuf,
    /// The last time this profile was accessed, recorded in UTC.
    pub last_accessed: chrono::DateTime<chrono::Utc>,
    /// A flag indicating if this profile has administrative privileges.
    pub is_admin: bool,
}

impl AppUserProfile {
    /// Creates a new `AppUserProfile` instance.
    ///
    /// The `last_accessed` field is automatically set to the current UTC time upon creation.
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
///
/// This struct holds application-wide settings, including a list of defined user profiles,
/// the ID of the last active profile, and UI preferences like theme and language.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct AppConfig {
    /// A list of all configured user profiles.
    pub profiles: Vec<AppUserProfile>,
    /// The ID of the last user profile that was active. `None` if no profile has been active.
    pub last_active_profile_id: Option<String>,
    /// The selected UI theme (e.g., "default", "dark").
    pub theme: String,
    /// The selected application language (e.g., "en", "es").
    pub language: String,
}

impl AppConfig {
    /// Provides a default `AppConfig` instance.
    ///
    /// Initializes with an empty list of profiles, no active profile, and default theme/language.
    pub fn default() -> Self {
        AppConfig {
            profiles: Vec::new(),
            last_active_profile_id: None,
            theme: "default".to_string(),
            language: "en".to_string(),
        }
    }

    /// Finds a user profile by its ID.
    ///
    /// Returns an immutable reference to the `AppUserProfile` if found, otherwise `None`.
    pub fn get_profile_by_id(&self, id: &str) -> Option<&AppUserProfile> {
        self.profiles.iter().find(|p| p.id == id)
    }

    /// Finds a mutable user profile by its ID.
    ///
    /// Returns a mutable reference to the `AppUserProfile` if found, otherwise `None`.
    pub fn get_profile_by_id_mut(&mut self, id: &str) -> Option<&mut AppUserProfile> {
        self.profiles.iter_mut().find(|p| p.id == id)
    }

    /// Adds a new profile or updates an existing one.
    ///
    /// If a profile with the same ID already exists, its data is replaced with the new `profile`.
    /// The `last_active_profile_id` is updated to the ID of the profile just added or updated.
    pub fn add_or_update_profile(&mut self, profile: AppUserProfile) {
        let profile_id_for_last_active = profile.id.clone();

        if let Some(existing_profile) = self.profiles.iter_mut().find(|p| p.id == profile.id) {
            *existing_profile = profile;
        } else {
            self.profiles.push(profile);
        }
        self.last_active_profile_id = Some(profile_id_for_last_active);
    }

    /// Removes a profile by its ID.
    ///
    /// Returns `true` if the profile was found and removed, `false` otherwise.
    /// If the removed profile was the `last_active_profile_id`, it is cleared.
    pub fn remove_profile(&mut self, id: &str) -> bool {
        let original_len = self.profiles.len();
        self.profiles.retain(|p| p.id != id);
        if self.last_active_profile_id.as_deref() == Some(id) {
            self.last_active_profile_id = None;
        }
        self.profiles.len() < original_len
    }
}

/// Manages the loading and saving of the `AppConfig`.
///
/// This struct encapsulates the logic for interacting with the file system to
/// persist and retrieve application settings.
pub struct SettingsManager {
    config_file_path: PathBuf,
    /// The currently loaded application configuration.
    pub config: AppConfig,
}

impl SettingsManager {
    /// Initializes the `SettingsManager`.
    ///
    /// Determines the appropriate configuration file path based on `is_portable` mode.
    /// It then attempts to load an existing `AppConfig` from this path. If the file
    /// doesn't exist, a default configuration is created and saved.
    ///
    /// Arguments:
    /// - `is_portable`: If `true`, the config file is expected to be in the same
    ///   directory as the executable. If `false`, OS-specific configuration directories
    ///   are used (`dirs_next::config_dir`).
    pub fn new(is_portable: bool) -> Result<Self, PasswordManagerError> {
        let config_file_path = Self::get_default_config_file_path(is_portable)?;
        Self::from_path(config_file_path)
    }

    /// Initializes `SettingsManager` from a specific configuration file path.
    ///
    /// This is useful for testing or when a custom configuration file location is desired.
    /// If the file at `config_file_path` does not exist, a default configuration is created
    /// and saved to that location.
    pub fn from_path(config_file_path: PathBuf) -> Result<Self, PasswordManagerError> {
        let config = match Self::load_config_from_path(&config_file_path) {
            Ok(data) => {
                log::info!("Loaded existing app configuration from: {:?}", config_file_path);
                data
            },
            Err(PasswordManagerError::IoError(ref e)) if e.kind() == std::io::ErrorKind::NotFound => {
                log::info!("App configuration file not found. Creating default configuration.");
                let default_config = AppConfig::default();
                // Ensure the parent directory for the config file exists
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

    /// Saves the current in-memory `AppConfig` to the configuration file path
    /// associated with this `SettingsManager` instance.
    pub fn save(&self) -> Result<(), PasswordManagerError> {
        Self::save_config_to_path(&self.config_file_path, &self.config)
    }

    /// Helper function to load `AppConfig` from a specified `PathBuf`.
    fn load_config_from_path(path: &PathBuf) -> Result<AppConfig, PasswordManagerError> {
        let contents = fs::read_to_string(path)?;
        let app_config: AppConfig = serde_json::from_str(&contents)?;
        Ok(app_config)
    }

    /// Helper function to save `AppConfig` to a specified `PathBuf`.
    ///
    /// The configuration is serialized to a pretty-printed JSON string.
    /// This is a basic save operation; future enhancements might include transactional saving
    /// (e.g., writing to a temporary file and then replacing the original).
    fn save_config_to_path(path: &PathBuf, app_config: &AppConfig) -> Result<(), PasswordManagerError> {
        let json_string = serde_json::to_string_pretty(app_config)?;
        fs::write(path, json_string)?;
        Ok(())
    }

    /// Determines the appropriate default configuration file path.
    ///
    /// In `is_portable` mode, the path is relative to the current executable.
    /// Otherwise, it uses the OS-specific configuration directory (`dirs_next::config_dir`).
    pub fn get_default_config_file_path(is_portable: bool) -> Result<PathBuf, PasswordManagerError> {
        let mut path = if is_portable {
            let current_exe = std::env::current_exe()?;
            current_exe.parent()
                .ok_or(PasswordManagerError::Other("Could not determine executable's parent directory.".to_string()))?
                .to_path_buf()
        } else {
            let base_dirs = config_dir()
                .ok_or(PasswordManagerError::Other("Could not determine OS config directory.".to_string()))?;
            base_dirs.join(APP_DATA_DIR_NAME) // App's specific config folder
        };

        path.push(APP_CONFIG_FILE_NAME);
        Ok(path)
    }

    /// Returns the path to the application's default data directory.
    ///
    /// This directory is typically used for storing vaults and other persistent application data.
    /// It uses the OS-specific data directory (`dirs_next::data_dir`).
    pub fn get_default_data_dir() -> Result<PathBuf, PasswordManagerError> {
        let mut path = data_dir()
            .ok_or_else(|| PasswordManagerError::Other("Could not determine OS data directory.".to_string()))?;
        path.push(APP_DATA_DIR_NAME);
        Ok(path)
    }
}

/// Unit tests for the `settings_manager` module.
#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Utc, Duration as ChronoDuration};
    // use std::fs;
    use tempfile::tempdir; // For creating temporary directories for tests

    /// Helper function to construct a temporary settings file path within a given temporary directory.
    fn get_temp_settings_file_path(temp_dir: &std::path::Path) -> PathBuf {
        let mut path = PathBuf::from(temp_dir);
        path.push(APP_DATA_DIR_NAME);
        path.push(APP_CONFIG_FILE_NAME);
        path
    }

    /// Tests the `AppUserProfile::new` constructor.
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
        // Check that last_accessed is recent (within a small time window)
        assert!(profile.last_accessed <= Utc::now());
        assert!(profile.last_accessed > Utc::now() - ChronoDuration::seconds(5));
    }

    /// Tests the `AppConfig::default` implementation.
    #[test]
    fn test_app_config_default() {
        let config = AppConfig::default();
        assert!(config.profiles.is_empty());
        assert_eq!(config.last_active_profile_id, None);
        assert_eq!(config.theme, "default");
        assert_eq!(config.language, "en");
    }

    /// Tests the `SettingsManager`'s ability to initialize, save, and load configuration.
    ///
    /// This test covers:
    /// 1. Initialization when no config file exists (creates a default).
    /// 2. Adding a profile and saving the configuration.
    /// 3. Loading the previously saved configuration to verify persistence.
    #[test]
    fn test_settings_manager_new_and_save_load() {
        let temp_dir = tempdir().unwrap();
        let test_file_path = get_temp_settings_file_path(temp_dir.path());

        // Test loading default (non-existent file initially)
        let manager_default = SettingsManager::from_path(test_file_path.clone()).unwrap();
        assert!(manager_default.config.profiles.is_empty());
        assert_eq!(manager_default.config.last_active_profile_id, None);
        assert!(test_file_path.exists()); // File should be created with default settings

        // Test adding a profile and saving
        let mut manager = manager_default; // Take ownership to modify
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

        temp_dir.close().unwrap(); // Clean up the temporary directory
    }

    /// Tests the `AppConfig::add_or_update_profile` method.
    ///
    /// Verifies that profiles can be added and existing ones updated, and that
    /// `last_active_profile_id` is correctly maintained.
    #[test]
    fn test_app_config_add_or_update_profile() {
        let mut config = AppConfig::default();
        let profile1 = AppUserProfile::new("user1".to_string(), "User One".to_string(), PathBuf::from("v1.vault"), false);
        let profile2 = AppUserProfile::new("user2".to_string(), "User Two".to_string(), PathBuf::from("v2.vault"), true);

        // Add first profile
        config.add_or_update_profile(profile1.clone());
        assert_eq!(config.profiles.len(), 1);
        assert_eq!(config.get_profile_by_id("user1").unwrap().name, "User One");
        assert_eq!(config.last_active_profile_id, Some("user1".to_string()));

        // Add second profile
        config.add_or_update_profile(profile2.clone());
        assert_eq!(config.profiles.len(), 2);
        assert_eq!(config.get_profile_by_id("user2").unwrap().name, "User Two");
        assert_eq!(config.last_active_profile_id, Some("user2".to_string()));


        // Update existing profile (profile1)
        let updated_profile1 = AppUserProfile::new("user1".to_string(), "Updated User One".to_string(), PathBuf::from("v1_new.vault"), true);
        config.add_or_update_profile(updated_profile1.clone());
        assert_eq!(config.profiles.len(), 2); // Number of profiles should remain 2
        assert_eq!(config.get_profile_by_id("user1").unwrap().name, "Updated User One");
        assert_eq!(config.get_profile_by_id("user1").unwrap().vault_path, PathBuf::from("v1_new.vault"));
        assert_eq!(config.last_active_profile_id, Some("user1".to_string())); // Should update to the updated profile
    }

    /// Tests the `AppConfig::remove_profile` method.
    ///
    /// Verifies that profiles can be removed and that `last_active_profile_id`
    /// is cleared if the removed profile was the last active one.
    #[test]
    fn test_app_config_remove_profile() {
        let mut config = AppConfig::default();
        config.add_or_update_profile(AppUserProfile::new("user1".to_string(), "User One".to_string(), PathBuf::from("v1.vault"), false));
        config.add_or_update_profile(AppUserProfile::new("user2".to_string(), "User Two".to_string(), PathBuf::from("v2.vault"), false));
        config.last_active_profile_id = Some("user1".to_string()); // Set an initial last active

        assert_eq!(config.profiles.len(), 2);

        // Remove a profile that exists and is the last active
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

    /// Tests the `AppConfig::get_profile_by_id` method for immutable access.
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

    /// Tests the `AppConfig::get_profile_by_id_mut` method for mutable access.
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