// crates/password_core/src/data_types.rs

// --- Removed incorrect imports that tried to reference 'password_core' from within itself. ---
// These types are defined *in this file*, or imported from external crates.
// For example, this file defines EncryptedVault, so it doesn't import it from 'password_core::data_types'.

use zeroize::{Zeroize, ZeroizeOnDrop};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize, Deserializer, Serializer};
use serde::de::Error as SerdeError;
use std::fmt;
use base64::{engine::general_purpose, Engine as _};

/// A wrapper struct for sensitive byte arrays that implements Zeroize and custom Serde.
/// This replaces the functionality of secrecy::Secret<Vec<u8>>.
#[derive(Clone)]
pub struct PasswordBytes(pub Vec<u8>);

impl Zeroize for PasswordBytes {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for PasswordBytes {}

// Implement Debug trait to redact sensitive data from debug output.
impl fmt::Debug for PasswordBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PasswordBytes([REDACTED])")
    }
}

// Manual implementation of Serialize for PasswordBytes.
impl Serialize for PasswordBytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Use the new base64::Engine API for encoding.
        let encoded = general_purpose::STANDARD.encode(&self.0);
        serializer.serialize_str(&encoded)
    }
}

// Manual implementation of Deserialize for PasswordBytes.
impl<'de> Deserialize<'de> for PasswordBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Deserialize from a string (which we expect to be base64).
        let s = String::deserialize(deserializer)?;
        // Use the new base64::Engine API for decoding.
        let decoded = general_purpose::STANDARD.decode(s.as_bytes()).map_err(SerdeError::custom)?;
        Ok(PasswordBytes(decoded))
    }
}

// PartialEq for PasswordBytes (can compare inner Vec<u8> directly).
impl PartialEq for PasswordBytes {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}
impl Eq for PasswordBytes {}


/// Enum to categorize different types of credentials.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CredentialType {
    Website,
    Database,
    Passkey,
    SoftwareLicense,
    SSHKey,
    APIKey,
    Wifi,
    Other,
}

impl Default for CredentialType {
    fn default() -> Self {
        CredentialType::Website
    }
}

/// Represents a specific version of a password.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordVersion {
    // Now uses our custom PasswordBytes type.
    pub password: PasswordBytes,
    pub version: u32,
    pub is_current: bool,
    pub created_at: DateTime<Utc>,
    pub last_accessed_at: Option<DateTime<Utc>>,
}

impl Zeroize for PasswordVersion {
    fn zeroize(&mut self) {
        self.password.zeroize();
    }
}

/// The main data structure representing a single password record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordEntry {
    pub id: Uuid,
    pub name: String,
    pub url: Option<String>,
    pub username: Option<String>,
    pub password_versions: Vec<PasswordVersion>,
    pub notes: Option<String>,
    pub company: Option<String>,
    pub custom_key: Option<String>,
    pub credential_type: CredentialType,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl PasswordEntry {
    /// Returns the current password if available.
    pub fn get_current_password(&self) -> Option<&PasswordBytes> {
        self.password_versions.iter()
            .find(|v| v.is_current)
            .map(|v| &v.password)
    }

    /// Returns a mutable reference to the current password if available.
    pub fn get_current_password_mut(&mut self) -> Option<&mut PasswordBytes> {
        self.password_versions.iter_mut()
            .find(|v| v.is_current)
            .map(|v| &mut v.password)
    }

    /// Creates a new PasswordEntry with default values and a new UUID.
    pub fn new(name: String, initial_password: Option<PasswordBytes>) -> Self {
        let now = Utc::now();
        let mut versions = Vec::new();
        if let Some(password) = initial_password {
            versions.push(PasswordVersion {
                password,
                version: 1,
                is_current: true,
                created_at: now,
                last_accessed_at: None,
            });
        }

        PasswordEntry {
            id: Uuid::new_v4(),
            name,
            url: None,
            username: None,
            password_versions: versions,
            notes: None,
            company: None,
            custom_key: None,
            credential_type: CredentialType::default(),
            created_at: now,
            updated_at: now,
        }
    }

    /// Deactivates the current password version, if one exists.
    /// After this call, no password version in this entry will be marked as current.
    pub fn deactivate_current_password(&mut self) {
        if let Some(current_version) = self.password_versions.iter_mut().find(|v| v.is_current) {
            current_version.is_current = false;
        }
        self.updated_at = Utc::now(); // Mark the entry as updated
    }

    /// Sets a specific password version as the current one.
    /// All other password versions will be marked as not current.
    /// Returns true if the version was found and set as current, false otherwise.
    pub fn set_version_as_current(&mut self, version_number: u32) -> bool {
        // First, check if the target version exists at all.
        let target_idx = self.password_versions.iter().position(|v| v.version == version_number);

        if let Some(idx) = target_idx {
            // Target version was found, so proceed with modification.
            // Iterate through all versions to set the correct is_current flags.
            for (i, version) in self.password_versions.iter_mut().enumerate() {
                version.is_current = i == idx; // Set true only for the target index, false for others
            }
            self.updated_at = Utc::now(); // Mark the entry as updated
            true // Successfully updated
        } else {
            // Target version was not found, do nothing and return false.
            false
        }
    }
}

impl Zeroize for PasswordEntry {
    fn zeroize(&mut self) {
        for version in &mut self.password_versions {
            version.zeroize();
        }
    }
}

/// Represents the entire encrypted vault data stored in a file.
/// This acts as the container for all PasswordEntry items after they are encrypted.
/// It also stores the master key salt needed for deriving the master key.
#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedVault {
    pub salt: Vec<u8>, // Salt used for master password derivation
    pub encrypted_payload: Vec<u8>, // The encrypted ciphertext (data + tag)
    pub nonce: Vec<u8>, // The nonce used for this encryption
    pub vault_version: u32, // Version of the vault's internal data structure format
}

/// Represents a simple note entry in the vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Note {
    pub id: String,
    pub content: String,
    // You might add fields like created_at: DateTime<Utc>, updated_at: DateTime<Utc> later
}

#[cfg(test)]
mod tests {
    use super::*; // Import items from the parent module (data_types.rs)
    use serde_json;
    use std::time::Duration; // For testing time differences
    use chrono::Duration as ChronoDuration; // For chrono durations

    // Helper function to create a new password version
    fn create_password_version(bytes: Vec<u8>, version: u32, is_current: bool) -> PasswordVersion {
        PasswordVersion {
            password: PasswordBytes(bytes),
            version,
            is_current,
            created_at: Utc::now(),
            last_accessed_at: None,
        }
    }

    #[test]
    fn test_password_bytes_creation() {
        let pb = PasswordBytes(vec![1, 2, 3, 4, 5]);
        assert_eq!(pb.0, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_password_bytes_zeroize() {
        let mut pb = PasswordBytes(vec![10, 20, 30, 40]);
        assert_eq!(pb.0.len(), 4);
        assert_eq!(pb.0, vec![10, 20, 30, 40]);

        pb.zeroize();
        assert_eq!(pb.0.len(), 0);
        assert!(pb.0.is_empty());

        let mut pb_empty = PasswordBytes(vec![]);
        pb_empty.zeroize();
        assert_eq!(pb_empty.0.len(), 0);
        assert!(pb_empty.0.is_empty());
    }

    #[test]
    fn test_password_bytes_debug_redaction() {
        let pb = PasswordBytes(vec![1, 2, 3, 4, 5]);
        let debug_output = format!("{:?}", pb);
        assert!(debug_output.contains("[REDACTED]"));
        assert!(!debug_output.contains("1, 2, 3, 4, 5"));
    }

    #[test]
    fn test_password_bytes_serialization_deserialization() {
        let original_bytes = vec![0, 1, 2, 3, 255, 128, 64];
        let pb = PasswordBytes(original_bytes.clone());

        let serialized = serde_json::to_string(&pb).expect("Failed to serialize PasswordBytes");
        // println!("Serialized PasswordBytes: {}", serialized); // Debug print removed

        let expected_base64 = general_purpose::STANDARD.encode(&original_bytes);
        let expected_json = format!("\"{}\"", expected_base64);

        assert_eq!(serialized, expected_json);

        let deserialized_pb: PasswordBytes = serde_json::from_str(&serialized)
            .expect("Failed to deserialize PasswordBytes");

        assert_eq!(deserialized_pb.0, original_bytes);
    }

    // NEW TEST: Test PartialEq for PasswordBytes
    #[test]
    fn test_password_bytes_equality() {
        let pb1 = PasswordBytes(vec![1, 2, 3]);
        let pb2 = PasswordBytes(vec![1, 2, 3]);
        let pb3 = PasswordBytes(vec![4, 5, 6]);

        assert_eq!(pb1, pb2);
        assert_ne!(pb1, pb3);
    }

    #[test]
    fn test_password_entry_creation_and_access() {
        let initial_password_bytes = PasswordBytes(vec![100, 101, 102]);
        let mut entry = PasswordEntry::new(
            "My Test Site".to_string(),
            Some(initial_password_bytes.clone()),
        );

        assert_eq!(entry.name, "My Test Site");
        assert!(entry.id != Uuid::nil());
        assert_eq!(entry.password_versions.len(), 1);

        let current_password = entry.get_current_password();
        assert!(current_password.is_some());
        assert_eq!(current_password.unwrap().0, initial_password_bytes.0);

        let mut_current_password = entry.get_current_password_mut().expect("Should get mutable password");
        mut_current_password.0.push(200);
        assert_eq!(entry.get_current_password().unwrap().0, vec![100, 101, 102, 200]);
    }

    #[test]
    fn test_password_entry_zeroize() {
        let initial_password_bytes = PasswordBytes(vec![1, 2, 3]);
        let mut entry = PasswordEntry::new(
            "Site".to_string(),
            Some(initial_password_bytes),
        );

        assert_eq!(entry.password_versions[0].password.0, vec![1, 2, 3]);

        entry.zeroize();

        assert_eq!(entry.password_versions[0].password.0.len(), 0);
        assert!(entry.password_versions[0].password.0.is_empty());
    }

    #[test]
    fn test_password_entry_serialization_deserialization() {
        let initial_password_bytes = PasswordBytes(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        let mut entry = PasswordEntry::new(
            "Another Test Site".to_string(),
            Some(initial_password_bytes),
        );
        entry.username = Some("testuser".to_string());
        entry.notes = Some("Some notes here".to_string());
        entry.credential_type = CredentialType::Database;
        entry.url = Some("http://example.com".to_string());
        entry.company = Some("TestCo".to_string());
        entry.custom_key = Some("CustomVal".to_string());

        let serialized = serde_json::to_string(&entry).expect("Failed to serialize PasswordEntry");
        // println!("Serialized PasswordEntry: {}", serialized); // Debug print removed

        let deserialized_entry: PasswordEntry = serde_json::from_str(&serialized)
            .expect("Failed to deserialize PasswordEntry");

        assert_eq!(deserialized_entry.id, entry.id);
        assert_eq!(deserialized_entry.name, entry.name);
        assert_eq!(deserialized_entry.username, entry.username);
        assert_eq!(deserialized_entry.notes, entry.notes);
        assert_eq!(deserialized_entry.credential_type, entry.credential_type);
        assert_eq!(deserialized_entry.url, entry.url);
        assert_eq!(deserialized_entry.company, entry.company);
        assert_eq!(deserialized_entry.custom_key, entry.custom_key);

        // For timestamps, allow a small delta for comparison due to serialization/deserialization precision
        let time_diff = (deserialized_entry.created_at - entry.created_at).abs();
        assert!(time_diff < ChronoDuration::milliseconds(1), "Created_at differs too much: {:?}", time_diff);
        let time_diff = (deserialized_entry.updated_at - entry.updated_at).abs();
        assert!(time_diff < ChronoDuration::milliseconds(1), "Updated_at differs too much: {:?}", time_diff);


        assert_eq!(deserialized_entry.get_current_password().unwrap().0, entry.get_current_password().unwrap().0);

        let original_password = entry.get_current_password().unwrap().0.clone();
        let deserialized_password = deserialized_entry.get_current_password().unwrap().0.clone();
        assert_eq!(original_password, deserialized_password);
        if !original_password.is_empty() {
            assert_ne!(original_password, vec![0; original_password.len()]);
        }
    }

    #[test]
    fn test_password_entry_no_initial_password() {
        let mut entry = PasswordEntry::new(
            "Site without password".to_string(),
            None,
        );

        assert_eq!(entry.name, "Site without password");
        assert!(entry.id != Uuid::nil());
        assert!(entry.password_versions.is_empty());
        assert!(entry.get_current_password().is_none());
        assert!(entry.get_current_password_mut().is_none());
    }

    #[test]
    fn test_password_entry_multiple_versions() {
        let mut entry = PasswordEntry::new(
            "Multi-version Site".to_string(),
            Some(PasswordBytes(vec![1, 2, 3])), // Initial password using PasswordBytes
        );

        // Add some historical versions
        entry.password_versions[0].is_current = false; // Old version is no longer current
        entry.password_versions.push(create_password_version(vec![4, 5, 6], 2, true)); // New current

        // Add another old version for good measure
        entry.password_versions.push(create_password_version(vec![7, 8, 9], 3, false));

        assert_eq!(entry.password_versions.len(), 3);

        // Verify that get_current_password finds the correct one
        let current_password = entry.get_current_password().expect("Should find current password");
        assert_eq!(current_password.0, vec![4, 5, 6]);
        assert_eq!(
            entry.password_versions.iter().filter(|v| v.is_current).count(),
            1,
            "Only one password version should be current"
        );

        // Test mutable access and modification of the current password
        let mut_current_password = entry.get_current_password_mut().expect("Should get mutable current password");
        mut_current_password.0.push(10);
        assert_eq!(entry.get_current_password().unwrap().0, vec![4, 5, 6, 10]);

        // Ensure other versions are untouched and remain not current
        assert_eq!(entry.password_versions[0].password.0, vec![1, 2, 3]);
        assert!(!entry.password_versions[0].is_current);
        assert_eq!(entry.password_versions[2].password.0, vec![7, 8, 9]);
        assert!(!entry.password_versions[2].is_current);
    }

    #[test]
    fn test_password_entry_update_fields() {
        let mut entry = PasswordEntry::new(
            "Initial Name".to_string(),
            Some(PasswordBytes(vec![1, 2, 3])),
        );
        let initial_updated_at = entry.updated_at;

        // Simulate a small delay for time difference
        std::thread::sleep(Duration::from_millis(10));

        // Update some fields
        entry.name = "Updated Name".to_string();
        entry.username = Some("new_user".to_string());
        entry.url = Some("http://newurl.com".to_string());
        entry.updated_at = Utc::now(); // Manually update the timestamp

        assert_eq!(entry.name, "Updated Name");
        assert_eq!(entry.username, Some("new_user".to_string()));
        assert_eq!(entry.url, Some("http://newurl.com".to_string()));

        // Ensure updated_at has actually changed (allowing for some potential system time resolution)
        assert!(entry.updated_at > initial_updated_at);
        assert!((entry.updated_at - initial_updated_at).num_milliseconds() >= 10);
    }


    #[test]
    fn test_password_entry_deactivate_current_password() {
        let mut entry = PasswordEntry::new(
            "Site to deactivate".to_string(),
            Some(PasswordBytes(vec![1, 2, 3])), // Initial password using PasswordBytes
        );
        let initial_updated_at = entry.updated_at;

        // Ensure there is a current password initially
        assert!(entry.get_current_password().is_some());
        assert!(entry.password_versions[0].is_current);

        std::thread::sleep(Duration::from_millis(10)); // Simulate time passing

        entry.deactivate_current_password();

        // After deactivation, no password should be current
        assert!(entry.get_current_password().is_none());
        assert!(!entry.password_versions[0].is_current); // Explicitly check the flag

        // Ensure updated_at has changed
        assert!(entry.updated_at > initial_updated_at);

        // Test deactivating when no password is current
        entry.deactivate_current_password(); // Should do nothing
        assert!(entry.get_current_password().is_none());
    }

    #[test]
    fn test_password_entry_set_version_as_current() {
        let mut entry = PasswordEntry::new(
            "Site with versions".to_string(),
            Some(PasswordBytes(vec![10])), // V1 current
        );

        // Add some historical versions
        entry.password_versions[0].is_current = false; // V1 not current
        entry.password_versions.push(create_password_version(vec![20], 2, false)); // V2 not current
        entry.password_versions.push(create_password_version(vec![30], 3, true)); // V3 current
        entry.password_versions.push(create_password_version(vec![40], 4, false)); // V4 not current

        // 1. Set an older version (2) as current
        let success = entry.set_version_as_current(2);
        assert!(success, "set_version_as_current(2) should return true");

        let current_after_set = entry.get_current_password();
        assert!(current_after_set.is_some(), "Expected a current password after setting version 2");
        assert_eq!(current_after_set.unwrap().0, vec![20]);

        let v2_idx = entry.password_versions.iter().position(|v| v.version == 2).expect("Version 2 should exist");
        assert!(entry.password_versions[v2_idx].is_current, "Version 2 should be current directly");

        assert_eq!(entry.password_versions.iter().filter(|v| v.is_current).count(), 1, "Only one password version should be current");
        let initial_updated_at_after_first_set = entry.updated_at; // Capture updated_at after a successful set
        std::thread::sleep(Duration::from_millis(10)); // Simulate time passing

        // 2. Set a non-existent version
        let success_non_existent = entry.set_version_as_current(99);
        assert!(!success_non_existent, "set_version_as_current(99) should return false for non-existent version");

        let current_after_non_existent = entry.get_current_password();
        assert!(current_after_non_existent.is_some(), "Current password should still be present after failed set");
        assert_eq!(current_after_non_existent.unwrap().0, vec![20], "Current should not change after non-existent version set");
        assert!(entry.updated_at == initial_updated_at_after_first_set, "updated_at should not change if version not found");
        assert_eq!(entry.password_versions.iter().filter(|v| v.is_current).count(), 1, "Only one password version should remain current");
    }

    // NEW TEST: Test PasswordEntry::set_version_as_current when already current
    #[test]
    fn test_password_entry_set_already_current_version_as_current() {
        let mut entry = PasswordEntry::new(
            "Site with versions".to_string(),
            Some(PasswordBytes(vec![10])), // V1 current
        );
        entry.password_versions.push(create_password_version(vec![20], 2, false)); // V2 not current

        // Ensure V1 is current
        assert!(entry.password_versions.iter().find(|v| v.version == 1).unwrap().is_current);

        let initial_updated_at = entry.updated_at;
        std::thread::sleep(Duration::from_millis(10)); // Simulate time passing

        // Set V1 as current (it already is)
        let success = entry.set_version_as_current(1);
        assert!(success, "set_version_as_current(1) for already current should return true");

        let current_password = entry.get_current_password();
        assert!(current_password.is_some());
        assert_eq!(current_password.unwrap().0, vec![10]); // Should still be V1

        // Verify only one is current
        assert_eq!(entry.password_versions.iter().filter(|v| v.is_current).count(), 1);
        assert!(entry.password_versions.iter().find(|v| v.version == 1).unwrap().is_current);

        // Ensure updated_at changed even if it was already current
        assert!(entry.updated_at > initial_updated_at);
    }


    #[test]
    fn test_encrypted_vault_serialization_deserialization() {
        let vault = EncryptedVault {
            salt: vec![10, 11, 12, 13, 14, 15],
            encrypted_payload: vec![20, 21, 22, 23, 24, 25, 26, 27],
            nonce: vec![30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41], // Example nonce
            vault_version: 1,
        };

        let serialized = serde_json::to_string(&vault).expect("Failed to serialize EncryptedVault");
        // println!("Serialized EncryptedVault: {}", serialized); // Debug print removed

        let deserialized_vault: EncryptedVault = serde_json::from_str(&serialized)
            .expect("Failed to deserialize EncryptedVault");

        assert_eq!(deserialized_vault.salt, vault.salt);
        assert_eq!(deserialized_vault.encrypted_payload, vault.encrypted_payload);
        assert_eq!(deserialized_vault.nonce, vault.nonce);
        assert_eq!(deserialized_vault.vault_version, vault.vault_version);
    }

    // --- NEW TESTS FOR PasswordBytes DESERIALIZATION ERRORS ---

    #[test]
    fn test_password_bytes_deserialization_invalid_base64() {
        // Attempt to deserialize an invalid base64 string
        let invalid_base64_str = "\"not-valid-base64!\"";
        let result: Result<PasswordBytes, serde_json::Error> = serde_json::from_str(invalid_base64_str);

        assert!(result.is_err(), "Deserialization should fail for invalid Base64 input");
        let err = result.unwrap_err();
        // The error message for base64 decoding usually contains "Invalid symbol" or "Invalid byte".
        // Let's check for these keywords, as the exact error string can be platform/version dependent.
        let error_msg = err.to_string();
        assert!(
            error_msg.contains("Invalid symbol") || error_msg.contains("Invalid byte") || error_msg.contains("Invalid character"),
            "Error message should indicate a Base64 decoding problem. Actual: {:?}", err
        );
    }


    #[test]
    fn test_password_bytes_deserialization_non_string_input() {
        // Attempt to deserialize non-string input (e.g., a number or boolean)
        let non_string_input = "12345"; // This is valid JSON for an integer, but not for PasswordBytes
        let result: Result<PasswordBytes, serde_json::Error> = serde_json::from_str(non_string_input);

        assert!(result.is_err(), "Deserialization should fail for non-string input");
        let err = result.unwrap_err();
        // The error indicates a type mismatch in Serde
        assert!(err.to_string().contains("invalid type: integer") || err.to_string().contains("expected a string"),
                "Error message should indicate type mismatch: {}", err);
    }

    // NEW TEST: Test CredentialType Default
    #[test]
    fn test_credential_type_default() {
        assert_eq!(CredentialType::default(), CredentialType::Website);
    }
}