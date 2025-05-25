// crates/password_core/src/crypto.rs

//! This module provides all cryptographic primitives for the password manager.
//! It handles key derivation using Argon2id, symmetric encryption/decryption
//! using ChaCha20Poly1305, and Base64 encoding/decoding for secure data representation.

use argon2::{
    password_hash::{rand_core::OsRng, rand_core::RngCore},
    Argon2
};
use chacha20poly1305::{
    Key, Nonce, ChaCha20Poly1305, aead::{Aead, KeyInit}
};
use crate::error::PasswordManagerError;
use crate::data_types::PasswordBytes;
use base64::{engine::general_purpose, Engine as _};

/// The recommended length for the salt used in Argon2 key derivation (16 bytes).
pub const SALT_LEN: usize = 16;
/// The fixed length of the nonce (or IV) used in ChaCha20Poly1305 encryption (12 bytes).
pub const NONCE_LEN: usize = 12;
/// The fixed length of the derived encryption key (32 bytes), suitable for ChaCha20Poly1305.
pub const KEY_LEN: usize = 32;

/// A type alias for the encryption key, ensuring it's handled securely using `PasswordBytes`.
pub type EncryptionKey = PasswordBytes;

/// Generates a cryptographically secure random byte array of a specified length.
///
/// This is crucial for generating unique salts for key derivation and nonces for encryption,
/// enhancing the security of the cryptographic operations.
///
/// # Arguments
///
/// * `len` - The desired length of the random byte array.
///
/// # Returns
///
/// A `Vec<u8>` containing cryptographically secure random bytes.
pub fn generate_random_bytes(len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

/// Derives a cryptographically secure random encryption key of KEY_LEN bytes.
///
/// This is specifically for generating a new, truly random VEK when a user
/// first sets up their master password and chooses to store the VEK via OS-binding.
///
/// # Returns
///
/// A `Result` containing:
/// * `Ok(EncryptionKey)` - A new, randomly generated `EncryptionKey`.
/// * `Err(PasswordManagerError)` - If key generation fails (e.g., due to an internal error
///                                 in `generate_random_bytes` not producing the correct length).
pub fn derive_random_encryption_key() -> Result<EncryptionKey, PasswordManagerError> {
    let key_bytes = generate_random_bytes(KEY_LEN);
    if key_bytes.len() != KEY_LEN {
        return Err(PasswordManagerError::KeyDerivationError(
            format!("Generated random key has incorrect length: expected {}, got {}", KEY_LEN, key_bytes.len())
        ));
    }
    // FIX: Use PasswordBytes constructor directly
    Ok(PasswordBytes(key_bytes))
}




/// Derives a strong encryption key from a master password using Argon2id.
///
/// This function uses Argon2id, a memory-hard key derivation function,
/// to transform a user's master password into a robust encryption key.
/// If `salt` is `None`, a new random salt will be generated.
///
/// # Arguments
///
/// * `password` - The master password as a byte slice. Cannot be empty.
/// * `salt` - An optional byte slice to use as the salt. If `None`, a new `SALT_LEN`
///            random salt is generated. If `Some`, its length must match `SALT_LEN`.
///
/// # Returns
///
/// A `Result` containing:
/// * `Ok((EncryptionKey, Vec<u8>))` - The derived 32-byte encryption key (wrapped in `PasswordBytes`)
///                                    and the salt used for derivation.
/// * `Err(PasswordManagerError)` - If the password is empty, salt length is incorrect,
///                                 or Argon2 derivation fails.
pub fn derive_key_from_password(password: &[u8], salt: Option<&[u8]>) -> Result<(EncryptionKey, Vec<u8>), PasswordManagerError> {
    if password.is_empty() {
        return Err(PasswordManagerError::InvalidInput("Master password cannot be empty.".to_string()));
    }

    let actual_salt_bytes = match salt {
        Some(s) => {
            if s.len() != SALT_LEN {
                return Err(PasswordManagerError::InvalidInput(format!("Provided salt must be exactly {} bytes long.", SALT_LEN)));
            }
            s.to_vec()
        },
        None => {
            let generated_salt = generate_random_bytes(SALT_LEN);
            if generated_salt.is_empty() {
                return Err(PasswordManagerError::InvalidInput("Generated salt cannot be empty (internal error).".to_string()));
            }
            generated_salt
        },
    };

    let params = argon2::Params::new(65536, 3, 1, Some(KEY_LEN))
        .map_err(|e| PasswordManagerError::Argon2CalculationError(e))?;

    let argon2_raw = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::default(), params);

    let mut derived_key_bytes = [0u8; KEY_LEN];
    argon2_raw.hash_password_into(password, &actual_salt_bytes, &mut derived_key_bytes)
        .map_err(|e| PasswordManagerError::Argon2CalculationError(e))?;

    let key = PasswordBytes(derived_key_bytes.to_vec());

    Ok((key, actual_salt_bytes))
}

/// Encrypts plaintext data using the ChaCha20-Poly1305 authenticated encryption algorithm.
///
/// This function generates a new random nonce for each encryption operation, ensuring
/// the security properties of the algorithm.
///
/// # Arguments
///
/// * `key` - The `EncryptionKey` used for encryption.
/// * `plaintext` - The data to be encrypted as a byte slice.
///
/// # Returns
///
/// A `Result` containing:
/// * `Ok((Vec<u8>, Vec<u8>))` - The resulting ciphertext and the nonce used for encryption.
/// * `Err(PasswordManagerError)` - If an encryption error occurs.
pub fn encrypt(key: &EncryptionKey, plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), PasswordManagerError> {
    let chacha_key = Key::from_slice(&key.0);
    let cipher = ChaCha20Poly1305::new(chacha_key);

    let nonce_bytes = generate_random_bytes(NONCE_LEN);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, plaintext)
    .map_err(|e| PasswordManagerError::EncryptionError(format!("{:?}", e)))?;

    Ok((ciphertext, nonce_bytes))
}

/// Decrypts ciphertext data using the ChaCha20-Poly1305 authenticated encryption algorithm.
///
/// This function verifies the integrity and authenticity of the ciphertext during decryption.
///
/// # Arguments
///
/// * `key` - The `EncryptionKey` used for decryption.
/// * `ciphertext` - The encrypted data as a byte slice.
/// * `nonce_bytes` - The nonce that was used during encryption, as a byte slice.
///                   Must be `NONCE_LEN` bytes long.
///
/// # Returns
///
/// A `Result` containing:
/// * `Ok(Vec<u8>)` - The original plaintext data.
/// * `Err(PasswordManagerError)` - If the nonce length is invalid, the key is incorrect,
///                                 the data has been tampered with, or decryption fails.
pub fn decrypt(key: &EncryptionKey, ciphertext: &[u8], nonce_bytes: &[u8]) -> Result<Vec<u8>, PasswordManagerError> {
    let chacha_key = Key::from_slice(&key.0);
    let cipher = ChaCha20Poly1305::new(chacha_key);

    if nonce_bytes.len() != NONCE_LEN {
        return Err(PasswordManagerError::InvalidInput(format!("Invalid nonce length: expected {}, got {}", NONCE_LEN, nonce_bytes.len())));
    }
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher.decrypt(nonce, ciphertext)
        .map_err(|_e| PasswordManagerError::DecryptionFailed)?;

    Ok(plaintext)
}

/// Encodes a byte slice into a standard Base64 string.
///
/// This is typically used for converting raw binary data (like salts or nonces)
/// into a text-based format suitable for storage or transmission.
///
/// # Arguments
///
/// * `input` - The data to encode, which can be any type that can be referenced as a byte slice.
///
/// # Returns
///
/// A `String` containing the Base64 encoded representation of the input.
pub fn encode_base64<T: AsRef<[u8]>>(input: T) -> String {
    general_purpose::STANDARD.encode(input)
}

/// Decodes a Base64 string into a byte vector.
///
/// This is the inverse of `encode_base64`, converting a Base64 string back into its
/// original binary data.
///
/// # Arguments
///
/// * `input` - The Base64 encoded string.
///
/// # Returns
///
/// A `Result` containing:
/// * `Ok(Vec<u8>)` - The decoded byte vector.
/// * `Err(PasswordManagerError)` - If the input string is not valid Base64.
pub fn decode_base64<T: AsRef<str>>(input: T) -> Result<Vec<u8>, PasswordManagerError> {
    general_purpose::STANDARD.decode(input.as_ref())
        .map_err(PasswordManagerError::Base64DecodeError)
}

/// Unit tests for the `crypto` module.
///
/// These tests verify the correctness and security properties of the
/// cryptographic functions, including key derivation, encryption/decryption cycles,
/// and error handling for invalid inputs or tampered data.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{generate_random_bytes, derive_key_from_password, encrypt, decrypt};
    use crate::error::PasswordManagerError;

    #[test]
    fn test_generate_random_bytes() {
        let len = 32;
        let bytes = generate_random_bytes(len);
        assert_eq!(bytes.len(), len);
        assert!(!bytes.iter().all(|&b| b == 0), "Generated bytes should not be all zeros");

        let len_small = 5;
        let bytes_small = generate_random_bytes(len_small);
        assert_eq!(bytes_small.len(), len_small);
    }

    #[test]
    fn test_derive_key_from_password_new_salt() {
        let password = b"my_master_password";
        let (key1, salt1) = derive_key_from_password(password, None).unwrap();
        assert_eq!(key1.0.len(), KEY_LEN);
        assert_eq!(salt1.len(), SALT_LEN);

        let (key2, salt2) = derive_key_from_password(password, None).unwrap();
        assert_ne!(salt1, salt2, "Different salts should be generated when None is provided");
        assert_ne!(key1.0, key2.0, "Different keys should be derived with different salts");
    }

    #[test]
    fn test_derive_key_from_password_fixed_salt() {
        let password = b"my_master_password";
        let fixed_salt = generate_random_bytes(SALT_LEN);

        let (key1, _) = derive_key_from_password(password, Some(&fixed_salt)).unwrap();
        let (key2, _) = derive_key_from_password(password, Some(&fixed_salt)).unwrap();

        assert_eq!(key1.0, key2.0, "Same key should be derived with the same password and fixed salt");
    }

    #[test]
    fn test_derive_key_from_password_empty_password_error() {
        let password = b"";
        let result = derive_key_from_password(password, None);
        assert!(result.is_err(), "Empty password should result in an error");
        match result.unwrap_err() {
            PasswordManagerError::InvalidInput(msg) => assert!(msg.contains("Master password cannot be empty.")),
            _ => panic!("Expected InvalidInput error for empty password"),
        }
    }

    #[test]
    fn test_derive_key_from_password_invalid_salt_len() {
        let password = b"test";
        let invalid_salt = vec![1, 2, 3];
        let result = derive_key_from_password(password, Some(&invalid_salt));
        assert!(result.is_err());
        match result.unwrap_err() {
            PasswordManagerError::InvalidInput(msg) => assert!(msg.contains("Provided salt must be exactly")),
            _ => panic!("Expected InvalidInput error for invalid salt length"),
        }
    }

    #[test]
    fn test_encrypt_decrypt_cycle() {
        let password = b"strong_master_password";
        let (key, _salt) = derive_key_from_password(password, None).unwrap();

        let plaintext = b"This is a secret message that needs to be protected.";
        let (ciphertext, nonce) = encrypt(&key, plaintext).unwrap();

        assert_ne!(plaintext, ciphertext.as_slice(), "Ciphertext should not be equal to plaintext");
        assert_eq!(nonce.len(), NONCE_LEN, "Nonce should have correct length");

        let decrypted_text = decrypt(&key, &ciphertext, &nonce).unwrap();
        assert_eq!(plaintext.to_vec(), decrypted_text, "Decrypted text should match original plaintext");

        let empty_plaintext = b"";
        let (empty_ciphertext, empty_nonce) = encrypt(&key, empty_plaintext).unwrap();
        assert!(empty_ciphertext.len() > 0, "Empty plaintext should still produce non-empty ciphertext (due to tag)");
        assert_eq!(empty_nonce.len(), NONCE_LEN, "Nonce for empty plaintext should have correct length");
        let decrypted_empty_text = decrypt(&key, &empty_ciphertext, &empty_nonce).unwrap();
        assert_eq!(empty_plaintext.to_vec(), decrypted_empty_text, "Decrypted empty text should match original empty plaintext");
    }

    #[test]
    fn test_decrypt_with_incorrect_key() {
        let correct_password = b"correct_password";
        let wrong_password = b"wrong_password";

        let (correct_key, salt) = derive_key_from_password(correct_password, None).unwrap();
        let (wrong_key, _) = derive_key_from_password(wrong_password, Some(&salt)).unwrap();

        let plaintext = b"Sensitive data.";
        let (ciphertext, nonce) = encrypt(&correct_key, plaintext).unwrap();

        let result = decrypt(&wrong_key, &ciphertext, &nonce);
        assert!(result.is_err(), "Decryption should fail with incorrect key");
        assert_eq!(result.unwrap_err(), PasswordManagerError::DecryptionFailed);
    }

    #[test]
    fn test_decrypt_with_incorrect_nonce() {
        let password = b"password123";
        let (key, _) = derive_key_from_password(password, None).unwrap();

        let plaintext = b"Another secret.";
        let (ciphertext, _correct_nonce) = encrypt(&key, plaintext).unwrap();

        let wrong_nonce = generate_random_bytes(NONCE_LEN);

        let result = decrypt(&key, &ciphertext, &wrong_nonce);
        assert!(result.is_err(), "Decryption should fail with incorrect nonce");
        assert_eq!(result.unwrap_err(), PasswordManagerError::DecryptionFailed);
    }

    #[test]
    fn test_decrypt_with_tampered_ciphertext() {
        let password = b"password_for_tampering";
        let (key, _) = derive_key_from_password(password, None).unwrap();

        let plaintext = b"Original message.";
        let (mut ciphertext, nonce) = encrypt(&key, plaintext).unwrap();

        if !ciphertext.is_empty() {
            ciphertext[0] = ciphertext[0].wrapping_add(1);
        } else {
            return;
        }

        let result = decrypt(&key, &ciphertext, &nonce);
        assert!(result.is_err(), "Decryption should fail with tampered ciphertext");
        assert_eq!(result.unwrap_err(), PasswordManagerError::DecryptionFailed);
    }

    #[test]
    fn test_decrypt_with_invalid_nonce_length() {
        let password = b"test_pass";
        let (key, _) = derive_key_from_password(password, None).unwrap();
        let plaintext = b"some data";
        let (ciphertext, _nonce) = encrypt(&key, plaintext).unwrap();

        let short_nonce = vec![1, 2, 3];
        let result = decrypt(&key, &ciphertext, &short_nonce);
        assert!(result.is_err());
        match result.unwrap_err() {
            PasswordManagerError::InvalidInput(msg) => assert!(msg.contains("Invalid nonce length")),
            _ => panic!("Expected InvalidInput error for invalid nonce length"),
        }

        let long_nonce = vec![1; NONCE_LEN + 1];
        let result = decrypt(&key, &ciphertext, &long_nonce);
        assert!(result.is_err());
        match result.unwrap_err() {
            PasswordManagerError::InvalidInput(msg) => assert!(msg.contains("Invalid nonce length")),
            _ => panic!("Expected InvalidInput error for invalid nonce length"),
        }
    }

    #[test]
    fn test_base64_encoding_decoding_cycle() {
        let original_bytes = vec![1, 2, 3, 4, 5, 255, 0, 128];
        let encoded_string = encode_base64(&original_bytes);
        let decoded_bytes = decode_base64(&encoded_string).unwrap();
        assert_eq!(original_bytes, decoded_bytes);

        let empty_bytes: Vec<u8> = Vec::new();
        let empty_encoded = encode_base64(&empty_bytes);
        assert_eq!(empty_encoded, "");
        let empty_decoded = decode_base64(&empty_encoded).unwrap();
        assert_eq!(empty_bytes, empty_decoded);
    }

    #[test]
    fn test_base64_decoding_invalid_input() {
        let invalid_base64 = "invalid-base64!";
        let result = decode_base64(invalid_base64);
        assert!(result.is_err());
        match result.unwrap_err() {
            PasswordManagerError::Base64DecodeError(_) => assert!(true),
            _ => panic!("Expected Base64DecodeError for invalid input"),
        }
    }
}