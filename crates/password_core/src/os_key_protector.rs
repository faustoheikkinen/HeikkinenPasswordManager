use keyring::{Entry, Keyring as SystemKeyring};
use crate::data_types::EncryptionKey;
use crate::error::PasswordManagerError;
use log::{info, debug, error};

/// A trait to abstract over the keyring functionality, allowing for mocking in tests.
pub trait KeyringProvider {
    fn new(service: &str, username: &str) -> Result<Self, keyring::Error>
    where
        Self: Sized;
    fn set_password(&self, password: &str) -> Result<(), keyring::Error>;
    fn get_password(&self) -> Result<String, keyring::Error>;
    fn delete_password(&self) -> Result<(), keyring::Error>;
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

    fn delete_password(&self) -> Result<(), keyring::Error> {
        self.delete_password()
    }
}

/// Stores the Vault Encryption Key (VEK) in the OS keyring.
/// The `profile_id` is used as part of the service name to distinguish entries.
/// The `keyring_provider_ctor` is a constructor for the KeyringProvider trait,
/// allowing dependency injection for testing.
pub fn store_vek_os_bound(
    profile_id: &str,
    vek: &EncryptionKey,
    keyring_provider_ctor: impl FnOnce(&str, &str) -> Result<impl KeyringProvider, keyring::Error>,
) -> Result<(), PasswordManagerError> {
    let service_name = format!("HeikkinenPasswordManager-{}", profile_id);
    let username = "default_user_for_vek"; // Or derive from current user, if relevant

    debug!("Attempting to store VEK for service: {}", service_name);

    let keyring_entry = keyring_provider_ctor(&service_name, username)
        .map_err(|e| {
            error!("Failed to create keyring entry for service {}: {}", service_name, e);
            PasswordManagerError::KeyringError(format!("Keyring init failed: {}", e))
        })?;

    let vek_base64 = base64::encode(&vek.0); // Encode bytes to base64 string
    keyring_entry.set_password(&vek_base64)
        .map_err(|e| {
            error!("Failed to set password in keyring for service {}: {}", service_name, e);
            PasswordManagerError::KeyringError(format!("Keyring set password failed: {}", e))
        })?;

    info!("VEK successfully stored in OS keyring for profile: {}", profile_id);
    Ok(())
}

/// Retrieves the Vault Encryption Key (VEK) from the OS keyring.
/// The `profile_id` is used as part of the service name to retrieve the correct entry.
/// The `keyring_provider_ctor` is a constructor for the KeyringProvider trait,
/// allowing dependency injection for testing.
pub fn retrieve_vek_os_bound(
    profile_id: &str,
    keyring_provider_ctor: impl FnOnce(&str, &str) -> Result<impl KeyringProvider, keyring::Error>,
) -> Result<EncryptionKey, PasswordManagerError> {
    let service_name = format!("HeikkinenPasswordManager-{}", profile_id);
    let username = "default_user_for_vek";

    debug!("Attempting to retrieve VEK for service: {}", service_name);

    let keyring_entry = keyring_provider_ctor(&service_name, username)
        .map_err(|e| {
            error!("Failed to create keyring entry for service {}: {}", service_name, e);
            PasswordManagerError::KeyringError(format!("Keyring init failed: {}", e))
        })?;

    let vek_base64 = keyring_entry.get_password()
        .map_err(|e| {
            error!("Failed to get password from keyring for service {}: {}", service_name, e);
            PasswordManagerError::KeyringError(format!("Keyring get password failed: {}", e))
        })?;

    let vek_bytes = base64::decode(&vek_base64)
        .map_err(|e| {
            error!("Failed to base64 decode VEK from keyring for service {}: {}", service_name, e);
            PasswordManagerError::DataCorruption(format!("Base64 decoding failed: {}", e))
        })?;

    // Validate key length after decoding
    if vek_bytes.len() != 32 { // Assuming VEK_LEN is 32 bytes as per crypto.rs
        error!("Retrieved VEK has incorrect length for service {}: expected 32, got {}", service_name, vek_bytes.len());
        return Err(PasswordManagerError::DataCorruption(
            format!("Retrieved VEK has incorrect length: expected 32, got {}", vek_bytes.len())
        ));
    }

    info!("VEK successfully retrieved from OS keyring for profile: {}", profile_id);
    Ok(PasswordBytes(vek_bytes))
}


/// Deletes the Vault Encryption Key (VEK) from the OS keyring.
/// The `profile_id` is used to identify the entry to delete.
/// The `keyring_provider_ctor` is a constructor for the KeyringProvider trait,
/// allowing dependency injection for testing.
pub fn delete_vek_os_bound(
    profile_id: &str,
    keyring_provider_ctor: impl FnOnce(&str, &str) -> Result<impl KeyringProvider, keyring::Error>,
) -> Result<(), PasswordManagerError> {
    let service_name = format!("HeikkinenPasswordManager-{}", profile_id);
    let username = "default_user_for_vek";

    debug!("Attempting to delete VEK for service: {}", service_name);

    let keyring_entry = keyring_provider_ctor(&service_name, username)
        .map_err(|e| {
            error!("Failed to create keyring entry for service {}: {}", service_name, e);
            PasswordManagerError::KeyringError(format!("Keyring init failed: {}", e))
        })?;

    keyring_entry.delete_password()
        .map_err(|e| {
            error!("Failed to delete password from keyring for service {}: {}", service_name, e);
            PasswordManagerError::KeyringError(format!("Keyring delete password failed: {}", e))
        })?;

    info!("VEK successfully deleted from OS keyring for profile: {}", profile_id);
    Ok(())
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use crate::crypto::KEY_LEN; // Ensure KEY_LEN is accessible from crypto module

    // --- Mock Keyring Provider for Testing ---
    struct MockKeyringProvider {
        service: String,
        username: String,
        // Using RefCell<HashMap> to allow mutable access to stored data from immutable self (e.g. in tests)
        // Static mut is typically discouraged, but for a global mock store for tests, it's acceptable.
        // It's essential that these tests are run in a single-threaded manner or with proper synchronization.
        // For 'cargo test', tests are run in parallel by default, so a global HashMap would need a Mutex.
        // For simplicity and typical test isolation, we'll make this mock handle its own state locally.
        // A more robust global mock might use `lazy_static!` and `Mutex`.
        // However, since `keyring_provider_ctor` allows a *new* instance for each call,
        // we can simulate local state for each mock instance.
        // For real-world use with `cargo test -- --test-threads=1` or
        // if a *single* global state is required for a series of tests, `Mutex` would be vital.
        stored_data: RefCell<HashMap<(String, String), String>>,
    }

    impl KeyringProvider for MockKeyringProvider {
        fn new(service: &str, username: &str) -> Result<Self, keyring::Error> {
            // In a real mock, you'd usually pass in the shared state (e.g., Arc<Mutex<HashMap>>)
            // Here, for simplicity, we'll just initialize an empty map for each new mock instance.
            // This means each test requiring a `MockKeyringProvider` gets a fresh, isolated mock.
            // If you needed to simulate persistent storage across calls within one test *scenario*,
            // you'd need to pass a shared RefCell/Mutex, e.g., via a closure that captures it.
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
                .ok_or_else(|| keyring::Error::NoEntry) // Simulate NoEntry error
        }

        fn delete_password(&self) -> Result<(), keyring::Error> {
            debug!("Mock Keyring: Deleting password for ({}, {})", self.service, self.username);
            let mut data = self.stored_data.borrow_mut();
            if data.remove(&(self.service.clone(), self.username.clone())).is_some() {
                Ok(())
            } else {
                Err(keyring::Error::NoEntry) // Simulate NoEntry error if nothing to delete
            }
        }
    }

    // --- Keyring Provider Constructor for Mocking ---
    // This allows us to pass a specific mock instance to the functions.
    // The `new` method on the `MockKeyringProvider` will initialize its own internal hashmap.
    fn mock_keyring_ctor_for_test(service: &str, username: &str) -> Result<MockKeyringProvider, keyring::Error> {
        MockKeyringProvider::new(service, username)
    }

    // --- Tests using the Mock Keyring Provider ---

    #[test]
    fn test_store_and_retrieve_vek_with_mock_keyring() {
        let profile_id = "test_profile_mock";
        let original_vek = EncryptionKey(vec![0x01; KEY_LEN]); // Create a dummy VEK

        // Store the VEK using the mock provider
        let result = store_vek_os_bound(profile_id, &original_vek, mock_keyring_ctor_for_test);
        assert!(result.is_ok(), "Storing VEK with mock keyring failed: {:?}", result.unwrap_err());

        // Retrieve the VEK using the mock provider
        let retrieved_vek_result = retrieve_vek_os_bound(profile_id, mock_keyring_ctor_for_test);
        assert!(retrieved_vek_result.is_ok(), "Retrieving VEK with mock keyring failed: {:?}", retrieved_vek_result.unwrap_err());
        let retrieved_vek = retrieved_vek_result.unwrap();

        // Verify that the retrieved VEK matches the original
        assert_eq!(original_vek, retrieved_vek, "Retrieved VEK does not match original VEK");
    }

    #[test]
    fn test_retrieve_non_existent_vek_with_mock_keyring() {
        let profile_id = "non_existent_profile_mock";

        // Attempt to retrieve a VEK that hasn't been stored
        let retrieved_vek_result = retrieve_vek_os_bound(profile_id, mock_keyring_ctor_for_test);
        assert!(retrieved_vek_result.is_err(), "Retrieving non-existent VEK should fail");

        // Check if the error is a KeyringError
        if let Err(PasswordManagerError::KeyringError(msg)) = retrieved_vek_result {
            assert!(msg.contains("No entry found"), "Error message should indicate no entry: {}", msg);
        } else {
            panic!("Expected KeyringError, but got {:?}", retrieved_vek_result);
        }
    }

    #[test]
    fn test_store_and_delete_vek_with_mock_keyring() {
        let profile_id = "delete_test_profile_mock";
        let original_vek = EncryptionKey(vec![0x02; KEY_LEN]); // Another dummy VEK

        // Store the VEK
        let store_result = store_vek_os_bound(profile_id, &original_vek, mock_keyring_ctor_for_test);
        assert!(store_result.is_ok(), "Storing VEK for delete test failed: {:?}", store_result.unwrap_err());

        // Delete the VEK
        let delete_result = delete_vek_os_bound(profile_id, mock_keyring_ctor_for_test);
        assert!(delete_result.is_ok(), "Deleting VEK with mock keyring failed: {:?}", delete_result.unwrap_err());

        // Attempt to retrieve it again; it should fail
        let retrieved_vek_result = retrieve_vek_os_bound(profile_id, mock_keyring_ctor_for_test);
        assert!(retrieved_vek_result.is_err(), "Retrieving deleted VEK should fail");
        if let Err(PasswordManagerError::KeyringError(msg)) = retrieved_vek_result {
            assert!(msg.contains("No entry found"), "Error message should indicate no entry after deletion: {}", msg);
        } else {
            panic!("Expected KeyringError after deletion, but got {:?}", retrieved_vek_result);
        }
    }

    #[test]
    fn test_retrieve_with_invalid_base64_data() {
        let profile_id = "invalid_base64_profile_mock";
        let service_name = format!("HeikkinenPasswordManager-{}", profile_id);
        let username = "default_user_for_vek";

        // Manually create a mock that returns invalid base64
        struct BadBase64Mock;
        impl KeyringProvider for BadBase64Mock {
            fn new(_service: &str, _username: &str) -> Result<Self, keyring::Error> { Ok(BadBase64Mock) }
            fn set_password(&self, _password: &str) -> Result<(), keyring::Error> { Ok(()) }
            fn get_password(&self) -> Result<String, keyring::Error> {
                Ok("invalid-base64-string!".to_string())
            }
            fn delete_password(&self) -> Result<(), keyring::Error> { Ok(()) }
        }

        let result = retrieve_vek_os_bound(profile_id, |s, u| Ok(BadBase64Mock::new(s, u).unwrap()));
        assert!(result.is_err());
        if let Err(PasswordManagerError::DataCorruption(msg)) = result {
            assert!(msg.contains("Base64 decoding failed"), "Expected Base64 decoding error, got: {}", msg);
        } else {
            panic!("Expected DataCorruption error, got {:?}", result);
        }
    }
}