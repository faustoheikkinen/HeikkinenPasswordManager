// crates/password_core/src/crypto.rs

use argon2::{
    password_hash::{rand_core::OsRng, rand_core::RngCore, SaltString},
    Argon2
};
use chacha20poly1305::{
    Key, Nonce, ChaCha20Poly1305, aead::{Aead, KeyInit}
};
use crate::error::PasswordManagerError; // Custom error types

// Constants for Argon2 (can be tuned, but good defaults for a start)
pub const SALT_LEN: usize = 16; // Length of the salt for Argon2 (recommended 16 bytes)
pub const NONCE_LEN: usize = 12; // Length of the nonce/IV for ChaCha20Poly1305 (fixed at 12 bytes)
pub const KEY_LEN: usize = 32; // Length of the derived key for ChaCha20Poly1305 (fixed at 32 bytes for Key type)

// Type alias for the encryption key from chacha20poly1305
pub type EncryptionKey = Key;

/// Generates a cryptographically secure random byte array of a specified length.
/// This is used for generating salts for key derivation and nonces for encryption.
pub fn generate_random_bytes(len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    OsRng.fill_bytes(&mut bytes); // Fill the buffer with cryptographically secure random bytes
    bytes
}

/// Derives a strong encryption key from a master password and a salt using Argon2id.
///
/// Returns the derived 32-byte key and the salt used, or a `PasswordManagerError` if derivation fails.
pub fn derive_key_from_password(password: &[u8], salt: Option<&[u8]>) -> Result<(EncryptionKey, Vec<u8>), PasswordManagerError> {
    // Validate master password: It cannot be empty
    if password.is_empty() {
        return Err(PasswordManagerError::InvalidInput("Master password cannot be empty.".to_string()));
    }

    let actual_salt_bytes = match salt {
        Some(s) => {
            // Validate provided salt length
            if s.len() != SALT_LEN {
                return Err(PasswordManagerError::Other(format!("Provided salt must be exactly {} bytes long.", SALT_LEN)));
            }
            s.to_vec()
        },
        None => {
            let generated_salt = generate_random_bytes(SALT_LEN);
            // Defensive check for generated salt (should not be empty if SALT_LEN > 0)
            if generated_salt.is_empty() {
                return Err(PasswordManagerError::InvalidInput("Generated salt cannot be empty (internal error).".to_string()));
            }
            generated_salt
        },
    };

    // This `SaltString::encode_b64` can return an error if `actual_salt_bytes`
    // contains invalid characters, though this is highly unlikely for random bytes.
    let _salt_string = SaltString::encode_b64(&actual_salt_bytes)
        .map_err(|e| PasswordManagerError::Argon2PasswordHashError(e))?;


    // Argon2id parameters:
    // m_cost (memory cost): 65536 (2^16 KB)
    // t_cost (time cost): 3 (iterations)
    // p_cost (parallelism): 1
    // Some(KEY_LEN) sets the output key length to 32 bytes.
    let params = argon2::Params::new(65536, 3, 1, Some(KEY_LEN))
        .map_err(|e| PasswordManagerError::Argon2CalculationError(e))?; // Map argon2::Error to Argon2CalculationError

    let argon2_raw = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::default(), params);

    let mut derived_key_bytes = [0u8; KEY_LEN]; // Fixed-size array for the output key
    argon2_raw.hash_password_into(password, &actual_salt_bytes, &mut derived_key_bytes)
        .map_err(|e| PasswordManagerError::Argon2CalculationError(e))?; // Map argon2::Error to Argon2CalculationError

    let key = EncryptionKey::from(derived_key_bytes); // Direct conversion from [u8; 32] to Key

    Ok((key, actual_salt_bytes))
}

/// Encrypts plaintext data using ChaCha20-Poly1305.
/// Returns the ciphertext and the nonce used for encryption.
pub fn encrypt(key: &EncryptionKey, plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), PasswordManagerError> {
    let cipher = ChaCha20Poly1305::new(key);
    let nonce_bytes = generate_random_bytes(NONCE_LEN);
    let nonce = Nonce::from_slice(&nonce_bytes); // Convert Vec<u8> to Fixed-size Nonce

    let ciphertext = cipher.encrypt(nonce, plaintext)
        .map_err(|e| PasswordManagerError::EncryptionError(e))?; // Map aead::Error to EncryptionError

    Ok((ciphertext, nonce_bytes))
}

/// Decrypts ciphertext data using ChaCha20-Poly1305.
/// Returns the original plaintext.
pub fn decrypt(key: &EncryptionKey, ciphertext: &[u8], nonce_bytes: &[u8]) -> Result<Vec<u8>, PasswordManagerError> {
    let cipher = ChaCha20Poly1305::new(key);

    // Ensure the nonce is the correct length before converting
    if nonce_bytes.len() != NONCE_LEN {
        return Err(PasswordManagerError::Other(format!("Invalid nonce length: expected {}, got {}", NONCE_LEN, nonce_bytes.len())));
    }
    let nonce = Nonce::from_slice(nonce_bytes); // Convert slice to Fixed-size Nonce

    let plaintext = cipher.decrypt(nonce, ciphertext)
        .map_err(|_e| PasswordManagerError::DecryptionFailed)?; // Map decryption failure to DecryptionFailed

    Ok(plaintext)
}