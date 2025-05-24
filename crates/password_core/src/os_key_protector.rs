// crates/password_core/src/os_key_protector.rs

use keyring::Entry; // Keep this
use crate::error::PasswordManagerError;
use crate::crypto::EncryptionKey;

// Define a constant for our application's service name.
const KEYRING_SERVICE_NAME: &str = "HeikkinenPasswordManager";

/// Trait to abstract keyring operations for testability.
pub trait KeyringProvider {
    fn new(service: &str, username: &str) -> Result<Self, keyring::Error> where Self: Sized;
    fn set_password(&self, password: &[u8]) -> Result<(), keyring::Error>;
    fn get_password(&self) -> Result<Vec<u8>, keyring::Error>;
    fn delete_password(&self) -> Result<(), keyring::Error>; // Add delete for cleanup
}

// Implement KeyringProvider for the actual keyring::Entry
impl KeyringProvider for Entry {
    fn new(service: &str, username: &str) -> Result<Self, keyring::Error> {
        Entry::new(service, username)
    }

    fn set_password(&self, password: &[u8]) -> Result<(), keyring::Error> {
        self.set_password(password)
    }

    fn get_password(&self) -> Result<Vec<u8>, keyring::Error> {
        self.get_password()
    }

    fn delete_password(&self) -> Result<(), keyring::Error> {
        self.delete_password()
    }
}


// pub fn store_vek_os_bound(profile_id: &str, vek: &EncryptionKey) -> Result<(), PasswordManagerError> {
//     // keyring v3 Entry::new takes service and username
//     let entry = Entry::new(KEYRING_SERVICE_NAME, profile_id)
//         .map_err(|e| PasswordManagerError::KeyringError(format!("Failed to create keyring entry: {}", e)))?;

//     // Convert EncryptionKey (which is a newtype over PasswordBytes) to &[u8]
//     // keyring v3 set_password expects Vec<u8>
//     entry.set_password(&vek.expose_secret().to_vec()) // Use expose_secret().to_vec() for Vec<u8>
//         .map_err(|e| PasswordManagerError::KeyringError(format!("Failed to set password in keyring: {}", e)))?;

//     Ok(())
// }

/// Stores the Vault Encryption Key (VEK) securely using the provided keyring provider.
/// The VEK is associated with a specific user profile ID.
pub fn store_vek_os_bound(
        profile_id: &str,
        vek: &EncryptionKey,
        keyring_provider_ctor: 
            impl FnOnce(&str, &str) -> Result<impl KeyringProvider, keyring::Error> // Constructor for the provider
    ) -> Result<(), PasswordManagerError> {

    let entry = keyring_provider_ctor(KEYRING_SERVICE_NAME, profile_id)
        .map_err(|e| PasswordManagerError::KeyringError(format!("Failed to create keyring entry: {}", e)))?;

    entry.set_password(vek.expose_secret().as_slice()) // Use as_slice() on &[u8] for clarity
        .map_err(|e| PasswordManagerError::KeyringError(format!("Failed to set password in keyring: {}", e)))?;

    Ok(())
}

/// Retrieves the Vault Encryption Key (VEK) from the provided keyring provider
/// for a given user profile ID.
pub fn retrieve_vek_os_bound(
        profile_id: &str,
        keyring_provider_ctor: 
            impl FnOnce(&str, &str) -> Result<impl KeyringProvider, keyring::Error> // Constructor for the provider
    ) -> Result<EncryptionKey, PasswordManagerError> {

    let entry = keyring_provider_ctor(KEYRING_SERVICE_NAME, profile_id)
        .map_err(|e| PasswordManagerError::KeyringError(format!("Failed to create keyring entry: {}", e)))?;

    let vek_bytes = entry.get_password()
        .map_err(|e| PasswordManagerError::KeyringError(format!("Failed to get password from keyring: {}", e)))?;

    // EncryptionKey::new(vek_bytes)
    //     .map_err(|_| PasswordManagerError::KeyDerivationError("Invalid VEK length retrieved from keyring".into()))
    Ok(PasswordBytes(vek_bytes))
}

/// Deletes the Vault Encryption Key (VEK) from the provided keyring provider
/// for a given user profile ID.
pub fn delete_vek_os_bound(
        profile_id: &str,
        keyring_provider_ctor: 
            impl FnOnce(&str, &str) -> Result<impl KeyringProvider, keyring::Error> // Constructor for the provider
    ) -> Result<(), PasswordManagerError> {

    let entry = keyring_provider_ctor(KEYRING_SERVICE_NAME, profile_id)
        .map_err(|e| PasswordManagerError::KeyringError(format!("Failed to create keyring entry: {}", e)))?;

    entry.delete_password()
        .map_err(|e| PasswordManagerError::KeyringError(format!("Failed to delete password from keyring: {}", e)))?;

    Ok(())
}




/*



    TEST



*/

// crates/password_core/src/os_key_protector.rs

// ... (all code from above) ...

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use crate::crypto::{derive_random_encryption_key, KEY_LEN}; // Assuming derive_random_encryption_key exists

    // In-memory store for the mock keyring. Use Arc<Mutex> for shared mutable state across mock instances.
    static MOCK_KEYRING_STORE: once_cell::sync::Lazy<Arc<Mutex<HashMap<(String, String), Vec<u8>>>>> =
        once_cell::sync::Lazy::new(|| Arc::new(Mutex::new(HashMap::new())));

    /// A mock implementation of KeyringProvider for testing.
    struct MockKeyringEntry {
        service: String,
        username: String,
        store: Arc<Mutex<HashMap<(String, String), Vec<u8>>>>,
    }

    impl KeyringProvider for MockKeyringEntry {
        fn new(service: &str, username: &str) -> Result<Self, keyring::Error> {
            Ok(MockKeyringEntry {
                service: service.to_string(),
                username: username.to_string(),
                store: MOCK_KEYRING_STORE.clone(),
            })
        }

        fn set_password(&self, password: &[u8]) -> Result<(), keyring::Error> {
            let mut store = self.store.lock().unwrap();
            store.insert((self.service.clone(), self.username.clone()), password.to_vec());
            Ok(())
        }

        fn get_password(&self) -> Result<Vec<u8>, keyring::Error> {
            let store = self.store.lock().unwrap();
            store.get(&(self.service.clone(), self.username.clone()))
                .cloned() // Clone the Vec<u8> to return ownership
                .ok_or_else(|| keyring::Error::NoEntry) // Custom error for not found
        }

        fn delete_password(&self) -> Result<(), keyring::Error> {
            let mut store = self.store.lock().unwrap();
            store.remove(&(self.service.clone(), self.username.clone()));
            Ok(())
        }
    }

    // Helper for creating a mock provider constructor
    fn mock_keyring_ctor(service: &str, username: &str) -> Result<MockKeyringEntry, keyring::Error> {
        MockKeyringEntry::new(service, username)
    }

    // --- Test Cases ---

    #[test]
    fn test_store_and_retrieve_vek() {
        let profile_id = "test_user_1";
        let vek = derive_random_encryption_key().unwrap(); // Use your crypto module to create a test VEK

        // Store the VEK using the mock provider
        let result = store_vek_os_bound(profile_id, &vek, mock_keyring_ctor);
        assert!(result.is_ok(), "Failed to store VEK: {:?}", result.err());

        // Retrieve the VEK using the mock provider
        let retrieved_vek = retrieve_vek_os_bound(profile_id, mock_keyring_ctor).unwrap();

        // Assert that the retrieved VEK matches the original
        assert_eq!(vek.expose_secret(), retrieved_vek.expose_secret());

        // Clean up (optional for mock, but good practice if it were real)
        delete_vek_os_bound(profile_id, mock_keyring_ctor).unwrap();
    }

    #[test]
    fn test_retrieve_non_existent_vek() {
        let profile_id = "non_existent_user";
        let result = retrieve_vek_os_bound(profile_id, mock_keyring_ctor);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), PasswordManagerError::KeyringError(_)));
    }

    #[test]
    fn test_delete_vek() {
        let profile_id = "test_user_for_delete";
        let vek = derive_random_encryption_key().unwrap();

        store_vek_os_bound(profile_id, &vek, mock_keyring_ctor).unwrap();
        let retrieved_vek = retrieve_vek_os_bound(profile_id, mock_keyring_ctor).unwrap();
        assert_eq!(vek.expose_secret(), retrieved_vek.expose_secret());

        delete_vek_os_bound(profile_id, mock_keyring_ctor).unwrap();

        // Should now fail to retrieve
        let result = retrieve_vek_os_bound(profile_id, mock_keyring_ctor);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), PasswordManagerError::KeyringError(_)));
    }

    // Add more tests for error cases, different profile IDs, etc.
}