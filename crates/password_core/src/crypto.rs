// crates/password_core/src/crypto.rs

use argon2::{
    password_hash::{rand_core::OsRng, rand_core::RngCore, SaltString},
    Argon2
};
use chacha20poly1305::{
    Key, Nonce, ChaCha20Poly1305, aead::{Aead, KeyInit}
};
use crate::error::PasswordManagerError; // Custom error types
use crate::data_types::PasswordBytes; // Import PasswordBytes for EncryptionKey
use base64::{engine::general_purpose, Engine as _}; // For base64 encoding/decoding

// Constants for Argon2 (can be tuned, but good defaults for a start)
pub const SALT_LEN: usize = 16; // Length of the salt for Argon2 (recommended 16 bytes)
pub const NONCE_LEN: usize = 12; // Length of the nonce/IV for ChaCha20Poly1305 (fixed at 12 bytes)
pub const KEY_LEN: usize = 32; // Length of the derived key for ChaCha20Poly1305 (fixed at 32 bytes for Key type)

// Type alias for the encryption key, now using PasswordBytes for secure handling
pub type EncryptionKey = PasswordBytes;

/// Generates a cryptographically secure random byte array of a specified length.
/// This is used for generating salts for key derivation and nonces for encryption.
pub fn generate_random_bytes(len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    OsRng.fill_bytes(&mut bytes); // Fill the buffer with cryptographically secure random bytes
    bytes
}

/// Derives a strong encryption key from a master password and a salt using Argon2id.
///
/// Returns the derived 32-byte key (as PasswordBytes) and the salt used,
/// or a `PasswordManagerError` if derivation fails.
pub fn derive_key_from_password(password: &[u8], salt: Option<&[u8]>) -> Result<(EncryptionKey, Vec<u8>), PasswordManagerError> {
    // Validate master password: It cannot be empty
    if password.is_empty() {
        return Err(PasswordManagerError::InvalidInput("Master password cannot be empty.".to_string()));
    }

    let actual_salt_bytes = match salt {
        Some(s) => {
            // Validate provided salt length
            if s.len() != SALT_LEN {
                return Err(PasswordManagerError::InvalidInput(format!("Provided salt must be exactly {} bytes long.", SALT_LEN)));
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

    // Wrap the derived key bytes in PasswordBytes for secure handling
    let key = EncryptionKey(derived_key_bytes.to_vec());

    Ok((key, actual_salt_bytes))
}

/// Encrypts plaintext data using ChaCha20-Poly1305.
///
/// Returns the ciphertext and the nonce used for encryption.
pub fn encrypt(key: &EncryptionKey, plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), PasswordManagerError> {
    // Convert PasswordBytes to chacha20poly1305::Key for encryption
    let chacha_key = Key::from_slice(&key.0);
    let cipher = ChaCha20Poly1305::new(chacha_key);

    let nonce_bytes = generate_random_bytes(NONCE_LEN);
    let nonce = Nonce::from_slice(&nonce_bytes); // Convert Vec<u8> to Fixed-size Nonce

    let ciphertext = cipher.encrypt(nonce, plaintext)
        .map_err(|e| PasswordManagerError::EncryptionError(e))?; // Map aead::Error to EncryptionError

    Ok((ciphertext, nonce_bytes))
}

/// Decrypts ciphertext data using ChaCha20-Poly1305.
///
/// Returns the original plaintext.
pub fn decrypt(key: &EncryptionKey, ciphertext: &[u8], nonce_bytes: &[u8]) -> Result<Vec<u8>, PasswordManagerError> {
    // Convert PasswordBytes to chacha20poly1305::Key for decryption
    let chacha_key = Key::from_slice(&key.0);
    let cipher = ChaCha20Poly1305::new(chacha_key);

    // Ensure the nonce is the correct length before converting
    if nonce_bytes.len() != NONCE_LEN {
        return Err(PasswordManagerError::InvalidInput(format!("Invalid nonce length: expected {}, got {}", NONCE_LEN, nonce_bytes.len())));
    }
    let nonce = Nonce::from_slice(nonce_bytes); // Convert slice to Fixed-size Nonce

    let plaintext = cipher.decrypt(nonce, ciphertext)
        .map_err(|_e| PasswordManagerError::DecryptionFailed)?; // Map decryption failure to DecryptionFailed

    Ok(plaintext)
}

/// Encodes a byte slice into a standard Base64 string.
pub fn encode_base64<T: AsRef<[u8]>>(input: T) -> String {
    general_purpose::STANDARD.encode(input)
}

/// Decodes a Base64 string into a byte vector.
pub fn decode_base64<T: AsRef<str>>(input: T) -> Result<Vec<u8>, PasswordManagerError> {
    general_purpose::STANDARD.decode(input.as_ref())
        .map_err(PasswordManagerError::Base64DecodeError)
}

#[cfg(test)]
mod tests {
    use super::*; // Now super includes the re-exported items
    use crate::crypto::{generate_random_bytes, derive_key_from_password, encrypt, decrypt}; // Individual functions still needed
    use crate::error::PasswordManagerError; // Explicitly bring into scope for error matching

    #[test]
    fn test_generate_random_bytes() {
        let len = 32;
        let bytes = generate_random_bytes(len);
        assert_eq!(bytes.len(), len);
        // It's highly unlikely that all bytes are zero for a cryptographically secure RNG
        assert!(!bytes.iter().all(|&b| b == 0), "Generated bytes should not be all zeros");

        let len_small = 5;
        let bytes_small = generate_random_bytes(len_small);
        assert_eq!(bytes_small.len(), len_small);
    }

    #[test]
    fn test_derive_key_from_password_new_salt() {
        let password = b"my_master_password";
        let (key1, salt1) = derive_key_from_password(password, None).unwrap();
        assert_eq!(key1.0.len(), KEY_LEN); // Access inner Vec<u8>
        assert_eq!(salt1.len(), SALT_LEN);

        let (key2, salt2) = derive_key_from_password(password, None).unwrap();
        // With `None` for salt, a new random salt should be generated each time
        assert_ne!(salt1, salt2, "Different salts should be generated when None is provided");
        assert_ne!(key1.0, key2.0, "Different keys should be derived with different salts"); // Compare inner Vec<u8>
    }

    #[test]
    fn test_derive_key_from_password_fixed_salt() {
        let password = b"my_master_password";
        let fixed_salt = generate_random_bytes(SALT_LEN);

        let (key1, _) = derive_key_from_password(password, Some(&fixed_salt)).unwrap();
        let (key2, _) = derive_key_from_password(password, Some(&fixed_salt)).unwrap();

        // With a fixed salt, the same key should be derived
        assert_eq!(key1.0, key2.0, "Same key should be derived with the same password and fixed salt"); // Compare inner Vec<u8>
    }

    #[test]
    fn test_derive_key_from_password_empty_password_error() {
        let password = b"";
        let result = derive_key_from_password(password, None); // Use None to ensure new salt generation path
        assert!(result.is_err(), "Empty password should result in an error");
        match result.unwrap_err() {
            PasswordManagerError::InvalidInput(msg) => assert!(msg.contains("Master password cannot be empty.")),
            _ => panic!("Expected InvalidInput error for empty password"),
        }
    }

    #[test]
    fn test_derive_key_from_password_invalid_salt_len() {
        let password = b"test";
        let invalid_salt = vec![1, 2, 3]; // Incorrect length
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
        let (key, salt) = derive_key_from_password(password, None).unwrap();

        let plaintext = b"This is a secret message that needs to be protected.";
        let (ciphertext, nonce) = encrypt(&key, plaintext).unwrap();

        assert_ne!(plaintext, ciphertext.as_slice(), "Ciphertext should not be equal to plaintext");
        assert_eq!(nonce.len(), NONCE_LEN, "Nonce should have correct length");

        let decrypted_text = decrypt(&key, &ciphertext, &nonce).unwrap();
        assert_eq!(plaintext.to_vec(), decrypted_text, "Decrypted text should match original plaintext");

        // Test with empty plaintext
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
        let (wrong_key, _) = derive_key_from_password(wrong_password, Some(&salt)).unwrap(); // Use same salt to ensure key difference

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

        let wrong_nonce = generate_random_bytes(NONCE_LEN); // A randomly generated, incorrect nonce

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

        // Tamper with the ciphertext (e.g., flip a bit)
        if !ciphertext.is_empty() {
            ciphertext[0] = ciphertext[0].wrapping_add(1); // Introduce a change
        } else {
            // If ciphertext is empty, we can't tamper this way, might need to adjust test
            // (e.g., ensure plaintext is always non-empty for this specific test case)
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

        let short_nonce = vec![1, 2, 3]; // Too short
        let result = decrypt(&key, &ciphertext, &short_nonce);
        assert!(result.is_err());
        match result.unwrap_err() {
            PasswordManagerError::InvalidInput(msg) => assert!(msg.contains("Invalid nonce length")),
            _ => panic!("Expected InvalidInput error for invalid nonce length"),
        }

        let long_nonce = vec![1; NONCE_LEN + 1]; // Too long
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

        // Test with empty bytes
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
            PasswordManagerError::Base64DecodeError(_) => assert!(true), // Just check the error type
            _ => panic!("Expected Base64DecodeError for invalid input"),
        }
    }
}