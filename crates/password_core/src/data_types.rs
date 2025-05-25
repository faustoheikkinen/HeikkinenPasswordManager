// crates/password_core/src/data_types.rs

//! This module defines the core data structures used throughout the Heikkinen Password Manager.
//! It includes types for handling sensitive data securely (`PasswordBytes`),
//! representing individual password entries, notes, and the overall encrypted vault structure.
//!
//! Special attention is given to the `Zeroize` trait for ensuring sensitive data is
//! securely erased from memory when no longer needed.

use zeroize::{Zeroize, ZeroizeOnDrop};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize, Deserializer, Serializer};
use serde::de::Error as SerdeError;
use std::fmt;
use base64::{engine::general_purpose, Engine as _};

/// A wrapper struct for sensitive byte arrays (e.g., passwords, keys) that
/// automatically zeroes out its contents when dropped or explicitly requested.
///
/// This helps prevent sensitive data from lingering in memory. It also includes
/// custom `Serialize` and `Deserialize` implementations to handle Base64 encoding/decoding
/// for storage, and a redacted `Debug` implementation for safety.
//#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[derive(Clone)]
pub struct PasswordBytes(pub Vec<u8>);

impl Zeroize for PasswordBytes {
    /// Zeroes out the underlying byte vector, filling it with zeros.
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for PasswordBytes {}

/// Implements the `Debug` trait to prevent sensitive data from being printed
/// in debug output.
impl fmt::Debug for PasswordBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PasswordBytes([REDACTED])")
    }
}

// Implement `From<Vec<u8>>` for `PasswordBytes`.
// This allows `Vec<u8>` to be converted into `PasswordBytes` using `.into()`.
impl From<Vec<u8>> for PasswordBytes {
    fn from(bytes: Vec<u8>) -> Self {
        PasswordBytes(bytes)
    }
}

/// Implements custom serialization for `PasswordBytes`.
///
/// The inner `Vec<u8>` is Base64 encoded into a string before serialization,
/// making it safe for text-based formats like JSON.
impl Serialize for PasswordBytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded = general_purpose::STANDARD.encode(&self.0);
        serializer.serialize_str(&encoded)
    }
}

/// Implements custom deserialization for `PasswordBytes`.
///
/// It expects a Base64 encoded string and decodes it back into a `Vec<u8>`.
impl<'de> Deserialize<'de> for PasswordBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let decoded = general_purpose::STANDARD.decode(s.as_bytes()).map_err(SerdeError::custom)?;
        Ok(PasswordBytes(decoded))
    }
}

/// Implements equality comparison for `PasswordBytes`, comparing their inner byte vectors.
impl PartialEq for PasswordBytes {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}
/// Implements `Eq` for `PasswordBytes`, signifying that `PartialEq` implies a total equivalence relation.
impl Eq for PasswordBytes {}


/// An enumeration to categorize different types of credentials a password entry might represent.
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
    /// Returns `CredentialType::Website` as the default type.
    fn default() -> Self {
        CredentialType::Website
    }
}

/// Represents a specific version of a password within a `PasswordEntry`.
/// This allows for password history and tracking of changes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordVersion {
    /// The password bytes, securely handled by `PasswordBytes`.
    pub password: PasswordBytes,
    /// The version number of this password (e.g., 1, 2, 3).
    pub version: u32,
    /// A flag indicating if this is the currently active password version.
    pub is_current: bool,
    /// The timestamp when this password version was created.
    pub created_at: DateTime<Utc>,
    /// The last time this specific password version was accessed (optional).
    pub last_accessed_at: Option<DateTime<Utc>>,
}

impl Zeroize for PasswordVersion {
    /// Zeroes out the sensitive password data within this version.
    fn zeroize(&mut self) {
        self.password.zeroize();
    }
}

/// The main data structure representing a single password record in the vault.
/// It contains details about the credential, its history, and associated notes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordEntry {
    /// A unique identifier for this password entry.
    pub id: Uuid,
    /// The human-readable name of the entry (e.g., "Google", "My Bank Account").
    pub name: String,
    /// The URL associated with the credential (optional).
    pub url: Option<String>,
    /// The username for this credential (optional).
    pub username: Option<String>,
    /// A list of `PasswordVersion`s, storing the current and historical passwords.
    pub password_versions: Vec<PasswordVersion>,
    /// Any additional notes or information (optional).
    pub notes: Option<String>,
    /// The company or service associated with the credential (optional).
    pub company: Option<String>,
    /// A custom key-value field for extra metadata (optional).
    pub custom_key: Option<String>,
    /// The type of credential this entry represents.
    pub credential_type: CredentialType,
    /// The timestamp when this entry was created.
    pub created_at: DateTime<Utc>,
    /// The timestamp when this entry was last updated.
    pub updated_at: DateTime<Utc>,
}

impl PasswordEntry {
    /// Returns an immutable reference to the currently active password if available.
    ///
    /// # Returns
    ///
    /// `Some(&PasswordBytes)` if a current password exists, otherwise `None`.
    pub fn get_current_password(&self) -> Option<&PasswordBytes> {
        self.password_versions.iter()
            .find(|v| v.is_current)
            .map(|v| &v.password)
    }

    /// Returns a mutable reference to the currently active password if available.
    ///
    /// # Returns
    ///
    /// `Some(&mut PasswordBytes)` if a current password exists, otherwise `None`.
    pub fn get_current_password_mut(&mut self) -> Option<&mut PasswordBytes> {
        self.password_versions.iter_mut()
            .find(|v| v.is_current)
            .map(|v| &mut v.password)
    }

    /// Creates a new `PasswordEntry` with a unique ID and initial details.
    ///
    /// The `created_at` and `updated_at` timestamps are set to the current UTC time.
    /// If an `initial_password` is provided, it's added as the first and current `PasswordVersion`.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the new entry.
    /// * `initial_password` - An optional `PasswordBytes` representing the first password for this entry.
    ///
    /// # Returns
    ///
    /// A new `PasswordEntry` instance.
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

    /// Deactivates the currently active password version within this entry.
    ///
    /// After this call, no `PasswordVersion` in this entry will be marked as current.
    /// The `updated_at` timestamp of the entry is also updated.
    pub fn deactivate_current_password(&mut self) {
        if let Some(current_version) = self.password_versions.iter_mut().find(|v| v.is_current) {
            current_version.is_current = false;
        }
        self.updated_at = Utc::now();
    }

    /// Sets a specific `PasswordVersion` (identified by its version number) as the current one.
    ///
    /// All other password versions within this entry will be marked as not current.
    /// The `updated_at` timestamp of the entry is updated if the operation is successful.
    ///
    /// # Arguments
    ///
    /// * `version_number` - The `version` field of the `PasswordVersion` to set as current.
    ///
    /// # Returns
    ///
    /// `true` if the version was found and successfully set as current; `false` otherwise.
    pub fn set_version_as_current(&mut self, version_number: u32) -> bool {
        let target_idx = self.password_versions.iter().position(|v| v.version == version_number);

        if let Some(idx) = target_idx {
            for (i, version) in self.password_versions.iter_mut().enumerate() {
                version.is_current = i == idx;
            }
            self.updated_at = Utc::now();
            true
        } else {
            false
        }
    }
}

impl Zeroize for PasswordEntry {
    /// Zeroes out all sensitive `PasswordBytes` contained within the entry's password versions.
    fn zeroize(&mut self) {
        for version in &mut self.password_versions {
            version.zeroize();
        }
    }
}

/// Represents the entire encrypted vault data as it's stored in a file.
///
/// This struct acts as the top-level container for the encrypted payload
/// and the cryptographic metadata (salt, nonce) required for decryption.
#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedVault {
    /// The cryptographic salt used for master password derivation.
    pub salt: Vec<u8>,
    /// The actual encrypted ciphertext (contains the serialized `Vault` data and an authentication tag).
    pub encrypted_payload: Vec<u8>,
    /// The nonce used for the encryption of the `encrypted_payload`.
    pub nonce: Vec<u8>,
    /// A version number for the vault's internal data structure format.
    /// This allows for future migrations if the data format changes.
    pub vault_version: u32,
}

/// Represents a simple secure note entry in the vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Note {
    /// A unique identifier for the note.
    pub id: String,
    /// The content of the note.
    pub content: String,
    // Future: pub created_at: DateTime<Utc>, pub updated_at: DateTime<Utc>
}

/// Unit tests for the `data_types` module.
///
/// These tests verify the correct behavior of data structures, their serialization/deserialization,
/// secure memory handling (`Zeroize`), and the methods implemented on `PasswordEntry`.
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;
    use std::time::Duration;
    use chrono::Duration as ChronoDuration;

    /// Helper function to create a new `PasswordVersion` for testing.
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
        // After zeroize, the inner vector is cleared.
        // It's important to understand that `zeroize` for `Vec<u8>` generally clears the memory,
        // but it might also truncate the vector to 0 length. The `Zeroize` trait itself for `Vec<T>`
        // often calls `clear()` then `shrink_to_fit()`, which is what leads to `len()` being 0.
        // For `ZeroizeOnDrop`, it's primarily about ensuring the *memory* is zeroed before deallocation.
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
        let expected_base64 = general_purpose::STANDARD.encode(&original_bytes);
        let expected_json = format!("\"{}\"", expected_base64);

        assert_eq!(serialized, expected_json);

        let deserialized_pb: PasswordBytes = serde_json::from_str(&serialized)
            .expect("Failed to deserialize PasswordBytes");

        assert_eq!(deserialized_pb.0, original_bytes);
    }

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
            Some(PasswordBytes(vec![1, 2, 3])),
        );

        entry.password_versions[0].is_current = false;
        entry.password_versions.push(create_password_version(vec![4, 5, 6], 2, true));

        entry.password_versions.push(create_password_version(vec![7, 8, 9], 3, false));

        assert_eq!(entry.password_versions.len(), 3);

        let current_password = entry.get_current_password().expect("Should find current password");
        assert_eq!(current_password.0, vec![4, 5, 6]);
        assert_eq!(
            entry.password_versions.iter().filter(|v| v.is_current).count(),
            1,
            "Only one password version should be current"
        );

        let mut_current_password = entry.get_current_password_mut().expect("Should get mutable current password");
        mut_current_password.0.push(10);
        assert_eq!(entry.get_current_password().unwrap().0, vec![4, 5, 6, 10]);

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

        std::thread::sleep(Duration::from_millis(10));

        entry.name = "Updated Name".to_string();
        entry.username = Some("new_user".to_string());
        entry.url = Some("http://newurl.com".to_string());
        entry.updated_at = Utc::now();

        assert_eq!(entry.name, "Updated Name");
        assert_eq!(entry.username, Some("new_user".to_string()));
        assert_eq!(entry.url, Some("http://newurl.com".to_string()));

        assert!(entry.updated_at > initial_updated_at);
        assert!((entry.updated_at - initial_updated_at).num_milliseconds() >= 10);
    }

    #[test]
    fn test_password_entry_deactivate_current_password() {
        let mut entry = PasswordEntry::new(
            "Site to deactivate".to_string(),
            Some(PasswordBytes(vec![1, 2, 3])),
        );
        let initial_updated_at = entry.updated_at;

        assert!(entry.get_current_password().is_some());
        assert!(entry.password_versions[0].is_current);

        std::thread::sleep(Duration::from_millis(10));

        entry.deactivate_current_password();

        assert!(entry.get_current_password().is_none());
        assert!(!entry.password_versions[0].is_current);

        assert!(entry.updated_at > initial_updated_at);

        entry.deactivate_current_password();
        assert!(entry.get_current_password().is_none());
    }

    #[test]
    fn test_password_entry_set_version_as_current() {
        let mut entry = PasswordEntry::new(
            "Site with versions".to_string(),
            Some(PasswordBytes(vec![10])),
        );

        entry.password_versions[0].is_current = false;
        entry.password_versions.push(create_password_version(vec![20], 2, false));
        entry.password_versions.push(create_password_version(vec![30], 3, true));
        entry.password_versions.push(create_password_version(vec![40], 4, false));

        let success = entry.set_version_as_current(2);
        assert!(success, "set_version_as_current(2) should return true");

        let current_after_set = entry.get_current_password();
        assert!(current_after_set.is_some(), "Expected a current password after setting version 2");
        assert_eq!(current_after_set.unwrap().0, vec![20]);

        let v2_idx = entry.password_versions.iter().position(|v| v.version == 2).expect("Version 2 should exist");
        assert!(entry.password_versions[v2_idx].is_current, "Version 2 should be current directly");

        assert_eq!(entry.password_versions.iter().filter(|v| v.is_current).count(), 1, "Only one password version should be current");
        let initial_updated_at_after_first_set = entry.updated_at;
        std::thread::sleep(Duration::from_millis(10));

        let success_non_existent = entry.set_version_as_current(99);
        assert!(!success_non_existent, "set_version_as_current(99) should return false for non-existent version");

        let current_after_non_existent = entry.get_current_password();
        assert!(current_after_non_existent.is_some(), "Current password should still be present after failed set");
        assert_eq!(current_after_non_existent.unwrap().0, vec![20], "Current should not change after non-existent version set");
        assert!(entry.updated_at == initial_updated_at_after_first_set, "updated_at should not change if version not found");
        assert_eq!(entry.password_versions.iter().filter(|v| v.is_current).count(), 1, "Only one password version should remain current");
    }

    #[test]
    fn test_password_entry_set_already_current_version_as_current() {
        let mut entry = PasswordEntry::new(
            "Site with versions".to_string(),
            Some(PasswordBytes(vec![10])),
        );
        entry.password_versions.push(create_password_version(vec![20], 2, false));

        assert!(entry.password_versions.iter().find(|v| v.version == 1).unwrap().is_current);

        let initial_updated_at = entry.updated_at;
        std::thread::sleep(Duration::from_millis(10));

        let success = entry.set_version_as_current(1);
        assert!(success, "set_version_as_current(1) for already current should return true");

        let current_password = entry.get_current_password();
        assert!(current_password.is_some());
        assert_eq!(current_password.unwrap().0, vec![10]);

        assert_eq!(entry.password_versions.iter().filter(|v| v.is_current).count(), 1);
        assert!(entry.password_versions.iter().find(|v| v.version == 1).unwrap().is_current);

        assert!(entry.updated_at > initial_updated_at);
    }

    #[test]
    fn test_encrypted_vault_serialization_deserialization() {
        let vault = EncryptedVault {
            salt: vec![10, 11, 12, 13, 14, 15],
            encrypted_payload: vec![20, 21, 22, 23, 24, 25, 26, 27],
            nonce: vec![30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41],
            vault_version: 1,
        };

        let serialized = serde_json::to_string(&vault).expect("Failed to serialize EncryptedVault");

        let deserialized_vault: EncryptedVault = serde_json::from_str(&serialized)
            .expect("Failed to deserialize EncryptedVault");

        assert_eq!(deserialized_vault.salt, vault.salt);
        assert_eq!(deserialized_vault.encrypted_payload, vault.encrypted_payload);
        assert_eq!(deserialized_vault.nonce, vault.nonce);
        assert_eq!(deserialized_vault.vault_version, vault.vault_version);
    }

    #[test]
    fn test_password_bytes_deserialization_invalid_base64() {
        let invalid_base64_str = "\"not-valid-base64!\"";
        let result: Result<PasswordBytes, serde_json::Error> = serde_json::from_str(invalid_base64_str);

        assert!(result.is_err(), "Deserialization should fail for invalid Base64 input");
        let err = result.unwrap_err();
        let error_msg = err.to_string();
        assert!(
            error_msg.contains("Invalid symbol") || error_msg.contains("Invalid byte") || error_msg.contains("Invalid character"),
            "Error message should indicate a Base64 decoding problem. Actual: {:?}", err
        );
    }

    #[test]
    fn test_password_bytes_deserialization_non_string_input() {
        let non_string_input = "12345";
        let result: Result<PasswordBytes, serde_json::Error> = serde_json::from_str(non_string_input);

        assert!(result.is_err(), "Deserialization should fail for non-string input");
        let err = result.unwrap_err();
        assert!(err.to_string().contains("invalid type: integer") || err.to_string().contains("expected a string"),
                        "Error message should indicate type mismatch: {}", err);
    }

    #[test]
    fn test_credential_type_default() {
        assert_eq!(CredentialType::default(), CredentialType::Website);
    }
}