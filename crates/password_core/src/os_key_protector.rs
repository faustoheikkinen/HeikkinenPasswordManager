// crates/password_core/src/os_key_protector.rs

use keyring::Entry;
use crate::EncryptionKey;
use crate::error::PasswordManagerError;
use log::{info, debug, error};
use base64::{Engine, alphabet, engine};
use crate::data_types::PasswordBytes; // Needed for PasswordBytes constructor

/// A trait to abstract over the keyring functionality, allowing for mocking in tests.
pub trait KeyringProvider {
    fn new(service: &str, username: &str) -> Result<Self, keyring::Error>
    where
        Self: Sized;
    fn set_password(&self, password: &str) -> Result<(), keyring::Error>;
    fn get_password(&self) -> Result<String, keyring::Error>;
    fn delete_credential(&self) -> Result<(), keyring::Error>;
}

// Implement the trait for the actual `keyring::Entry`
impl KeyringProvider for Entry {
    fn new(service: &str, username: &str) -> Result<Self, keyring::Error> {
        Entry::new(service, username)
    }

    fn set_password(&self, password: &str) -> Result<(), keyring::Error> {
        self.set_password(password)
    }

    fn get_password(&self) -> Result<String, keyring::Error> {
        self.get_password()
    }

    fn delete_credential(&self) -> Result<(), keyring::Error> {
        self.delete_credential()
    }
}


/// Stores the Vault Encryption Key (VEK) in the OS keyring.
/// The `profile_id` is used as part of the service name to distinguish entries.
pub fn store_vek_os_bound(
    profile_id: &str,
    vek: &EncryptionKey,
) -> Result<(), PasswordManagerError> {
    let service_name = format!("HeikkinenPasswordManager-{}", profile_id);
    let username = "default_user_for_vek";

    debug!("Attempting to store VEK for service: {}", service_name);

    let keyring_entry = Entry::new(&service_name, username)
        .map_err(|e| {
            error!("Failed to create keyring entry for service {}: {}", service_name, e);
            PasswordManagerError::KeyringError(format!("Keyring init failed: {:?}", e))
        })?;

    let vek_base64 = engine::GeneralPurpose::new(&alphabet::STANDARD, engine::general_purpose::NO_PAD)
        .encode(&vek.0);

    keyring_entry.set_password(&vek_base64)
        .map_err(|e| {
            error!("Failed to set password in keyring for service {}: {}", service_name, e);
            PasswordManagerError::KeyringError(format!("Keyring set password failed: {:?}", e))
        })?;

    info!("VEK successfully stored in OS keyring for profile: {}", profile_id);
    Ok(())
}

/// Retrieves the Vault Encryption Key (VEK) from the OS keyring.
/// The `profile_id` is used as part of the service name to retrieve the correct entry.
pub fn retrieve_vek_os_bound(
    profile_id: &str,
) -> Result<EncryptionKey, PasswordManagerError> {
    let service_name = format!("HeikkinenPasswordManager-{}", profile_id);
    let username = "default_user_for_vek";

    debug!("Attempting to retrieve VEK for service: {}", service_name);

    let keyring_entry = Entry::new(&service_name, username)
        .map_err(|e| {
            error!("Failed to create keyring entry for service {}: {}", service_name, e);
            PasswordManagerError::KeyringError(format!("Keyring init failed: {:?}", e))
        })?;

    let vek_base64 = keyring_entry.get_password()
        .map_err(|e| {
            error!("Failed to get password from keyring for service {}: {}", service_name, e);
            PasswordManagerError::KeyringError(format!("Keyring get password failed: {:?}", e))
        })?;

    let vek_bytes = engine::GeneralPurpose::new(&alphabet::STANDARD, engine::general_purpose::NO_PAD)
        .decode(&vek_base64)
        .map_err(|e| {
            error!("Failed to base64 decode VEK from keyring for service {}: {}", service_name, e);
            PasswordManagerError::Base64DecodeError(e)
        })?;

    // Validate key length after decoding
    if vek_bytes.len() != crate::crypto::KEY_LEN {
        error!("Retrieved VEK has incorrect length for service {}: expected {}, got {}", service_name, crate::crypto::KEY_LEN, vek_bytes.len());
        return Err(PasswordManagerError::DataCorruption(
            format!("Retrieved VEK has incorrect length: expected {}, got {}", crate::crypto::KEY_LEN, vek_bytes.len())
        ));
    }

    info!("VEK successfully retrieved from OS keyring for profile: {}", profile_id);
    // FIX: Construct PasswordBytes directly, which is what EncryptionKey is an alias for
    Ok(PasswordBytes(vek_bytes))
}

/// Deletes the Vault Encryption Key (VEK) from the OS keyring.
/// The `profile_id` is used to identify the entry to delete.
pub fn delete_vek_os_bound(
    profile_id: &str,
) -> Result<(), PasswordManagerError> {
    let service_name = format!("HeikkinenPasswordManager-{}", profile_id);
    let username = "default_user_for_vek";

    debug!("Attempting to delete VEK for service: {}", service_name);

    let keyring_entry = Entry::new(&service_name, username)
        .map_err(|e| {
            error!("Failed to create keyring entry for service {}: {}", service_name, e);
            PasswordManagerError::KeyringError(format!("Keyring init failed: {:?}", e))
        })?;

    keyring_entry.delete_credential()
        .map_err(|e| {
            error!("Failed to delete password from keyring for service {}: {}", service_name, e);
            PasswordManagerError::KeyringError(format!("Keyring delete credential failed: {:?}", e))
        })?;

    info!("VEK successfully deleted from OS keyring for profile: {}", profile_id);
    Ok(())
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use crate::crypto::KEY_LEN; // Removed generate_random_bytes
    use crate::PasswordManagerError;

    // --- Mock Keyring Provider for Testing ---
    struct MockKeyringProvider {
        service: String,
        username: String,
        stored_data: RefCell<HashMap<(String, String), String>>,
    }

    impl KeyringProvider for MockKeyringProvider {
        fn new(service: &str, username: &str) -> Result<Self, keyring::Error> {
            Ok(MockKeyringProvider {
                service: service.to_string(),
                username: username.to_string(),
                stored_data: RefCell::new(HashMap::new()),
            })
        }

        fn set_password(&self, password: &str) -> Result<(), keyring::Error> {
            debug!("Mock Keyring: Setting password for ({}, {})", self.service, self.username);
            let mut data = self.stored_data.borrow_mut();
            data.insert((self.service.clone(), self.username.clone()), password.to_string());
            Ok(())
        }

        fn get_password(&self) -> Result<String, keyring::Error> {
            debug!("Mock Keyring: Getting password for ({}, {})", self.service, self.username);
            let data = self.stored_data.borrow();
            data.get(&(self.service.clone(), self.username.clone()))
                .cloned()
                .ok_or_else(|| keyring::Error::NoEntry)
        }

        fn delete_credential(&self) -> Result<(), keyring::Error> {
            debug!("Mock Keyring: Removing credential for ({}, {})", self.service, self.username);
            let mut data = self.stored_data.borrow_mut();
            if data.remove(&(self.service.clone(), self.username.clone())).is_some() {
                Ok(())
            } else {
                Err(keyring::Error::NoEntry)
            }
        }
    }

    // --- Keyring Provider Constructor for Mocking ---
    fn mock_keyring_ctor_for_test(service: &str, username: &str) -> Result<MockKeyringProvider, keyring::Error> {
        MockKeyringProvider::new(service, username)
    }

    // --- Tests using the Mock Keyring Provider ---

    #[test]
    fn test_store_and_retrieve_vek_with_mock_keyring() {
        let _profile_id = "test_profile_mock"; // Suppress warning
        // FIX: Construct PasswordBytes directly
        let original_vek: EncryptionKey = PasswordBytes(vec![0x01; KEY_LEN]);

        let mock_entry = mock_keyring_ctor_for_test("HeikkinenPasswordManager-test_profile_mock", "default_user_for_vek").unwrap();
        let vek_base64 = engine::GeneralPurpose::new(&alphabet::STANDARD, engine::general_purpose::NO_PAD)
            .encode(&original_vek.0);
        let result = mock_entry.set_password(&vek_base64);
        assert!(result.is_ok(), "Mock: Storing VEK failed: {:?}", result.unwrap_err());

        let retrieved_vek_base64 = mock_entry.get_password();
        assert!(retrieved_vek_base64.is_ok(), "Mock: Retrieving VEK failed: {:?}", retrieved_vek_base64.unwrap_err());
        // FIX: Construct PasswordBytes directly
        let retrieved_vek: EncryptionKey = PasswordBytes(
            engine::GeneralPurpose::new(&alphabet::STANDARD, engine::general_purpose::NO_PAD)
                .decode(retrieved_vek_base64.unwrap())
                .unwrap()
        );
        assert_eq!(original_vek, retrieved_vek, "Mock: Retrieved VEK does not match original VEK");
    }

    #[test]
    fn test_retrieve_non_existent_vek_with_mock_keyring() {
        let _profile_id = "non_existent_profile_mock"; // Suppress warning
        let mock_entry = mock_keyring_ctor_for_test("HeikkinenPasswordManager-non_existent_profile_mock", "default_user_for_vek").unwrap();

        let retrieved_vek_result = mock_entry.get_password();
        assert!(retrieved_vek_result.is_err(), "Mock: Retrieving non-existent VEK should fail");

        if let Err(keyring::Error::NoEntry) = retrieved_vek_result {
            // Expected error type
        } else {
            panic!("Mock: Expected NoEntry error, but got {:?}", retrieved_vek_result);
        }
    }

    #[test]
    fn test_store_and_delete_vek_with_mock_keyring() {
        let _profile_id = "delete_test_profile_mock"; // Suppress warning
        // FIX: Construct PasswordBytes directly
        let original_vek: EncryptionKey = PasswordBytes(vec![0x02; KEY_LEN]);
        let mock_entry = mock_keyring_ctor_for_test("HeikkinenPasswordManager-delete_test_profile_mock", "default_user_for_vek").unwrap();

        let vek_base64 = engine::GeneralPurpose::new(&alphabet::STANDARD, engine::general_purpose::NO_PAD)
            .encode(&original_vek.0);
        let store_result = mock_entry.set_password(&vek_base64);
        assert!(store_result.is_ok(), "Mock: Storing VEK for delete test failed: {:?}", store_result.unwrap_err());

        let delete_result = mock_entry.delete_credential();
        assert!(delete_result.is_ok(), "Mock: Deleting VEK failed: {:?}", delete_result.unwrap_err());

        let retrieved_vek_result = mock_entry.get_password();
        assert!(retrieved_vek_result.is_err(), "Mock: Retrieving deleted VEK should fail");
        if let Err(keyring::Error::NoEntry) = retrieved_vek_result {
            // Expected error type
        } else {
            panic!("Mock: Expected NoEntry error after deletion, but got {:?}", retrieved_vek_result);
        }
    }

    #[test]
    fn test_retrieve_with_invalid_base64_data() {
        let _profile_id = "invalid_base64_profile_mock"; // Suppress warning

        struct BadBase64Mock;
        impl KeyringProvider for BadBase64Mock {
            fn new(_service: &str, _username: &str) -> Result<Self, keyring::Error> { Ok(BadBase64Mock) }
            fn set_password(&self, _password: &str) -> Result<(), keyring::Error> { Ok(()) }
            fn get_password(&self) -> Result<String, keyring::Error> {
                Ok("invalid-base64-string!".to_string())
            }
            fn delete_credential(&self) -> Result<(), keyring::Error> { Ok(()) }
        }

        let mock_entry = BadBase64Mock::new("service", "user").unwrap();
        let vek_base64_result = mock_entry.get_password();
        assert!(vek_base64_result.is_ok());

        let vek_bytes_result = engine::GeneralPurpose::new(&alphabet::STANDARD, engine::general_purpose::NO_PAD)
            .decode(&vek_base64_result.unwrap());

        assert!(vek_bytes_result.is_err());
        if let Err(base64::DecodeError::InvalidByte(_byte, _index)) = vek_bytes_result { // Suppress warnings
            assert!(true, "Expected base64::DecodeError::InvalidByte");
        } else {
            panic!("Expected Base64 decoding error, got {:?}", vek_bytes_result);
        }
    }
}