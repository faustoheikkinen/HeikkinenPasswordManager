// crates/password_core/src/error_tests.rs

//! Unit tests specifically for the error handling mechanisms defined in `password_core::error`.
//!
//! These tests ensure that:
//! - All `PasswordManagerError` variants display user-friendly messages correctly.
//! - Functions within `password_core::crypto` correctly return `PasswordManagerError`
//!   variants under various failure conditions (e.g., invalid input, incorrect keys, data tampering).
//! - The `From` trait implementations for converting external error types into
//!   `PasswordManagerError` work as expected.

use password_core::crypto::{
    derive_key_from_password, encrypt, decrypt, generate_random_bytes, SALT_LEN, NONCE_LEN, KEY_LEN, EncryptionKey
};
use password_core::error::PasswordManagerError;
use argon2::password_hash::Error as Argon2PasswordHashError; // Alias for clarity
use argon2::Error as Argon2Error; // Alias for clarity
use chacha20poly1305::aead::Error as AeadCryptoError; // Alias for clarity
use base64::DecodeError; // For testing Base64DecodeError directly
use uuid::Error as UuidError; // For testing UuidParseError directly

/// Tests the `Display` implementation for all `PasswordManagerError` variants.
///
/// This ensures that the user-facing error messages are correctly formatted and informative.
#[test]
fn test_password_manager_error_display() {
    assert_eq!(
        format!("{}", PasswordManagerError::EncryptionError(AeadCryptoError)),
        "Encryption/Decryption failed: AeadError"
    );
    assert_eq!(
        format!("{}", PasswordManagerError::Argon2CalculationError(Argon2Error::MemoryExceeded)),
        "Key derivation failed (Argon2 calculation): memory exceeded"
    );
    assert_eq!(
        format!("{}", PasswordManagerError::Argon2PasswordHashError(Argon2PasswordHashError::Unsupported)),
        "Key derivation failed (PasswordHash processing): unsupported"
    );
    assert_eq!(
        format!("{}", PasswordManagerError::IoError(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "Access denied"))),
        "I/O error: Access denied"
    );
    assert_eq!(
        format!("{}", PasswordManagerError::DecryptionFailed),
        "Invalid master password or corrupted vault"
    );
    assert_eq!(
        format!("{}", PasswordManagerError::InvalidVaultData("Corrupted JSON data".to_string())),
        "Vault data is invalid or corrupted: Corrupted JSON data"
    );
    assert_eq!(
        format!("{}", PasswordManagerError::Base64DecodeError(DecodeError::InvalidByte(0, b'!'))),
        "Base64 decoding failed: Invalid byte 0"
    );
    assert_eq!(
        format!("{}", PasswordManagerError::UuidParseError(UuidError::InvalidLength(10))),
        "UUID parsing failed: invalid length 10"
    );
    assert_eq!(
        format!("{}", PasswordManagerError::InvalidInput("User provided empty value".to_string())),
        "Invalid input: User provided empty value"
    );
    assert_eq!(
        format!("{}", PasswordManagerError::Other("A custom error message".to_string())),
        "Other error: A custom error message"
    );
}

/// Tests that `derive_key_from_password` returns an `InvalidInput` error
/// when an empty master password is provided.
#[test]
fn test_derive_key_from_password_empty_password_returns_invalid_input() {
    let password = b""; // Empty password
    let salt = generate_random_bytes(SALT_LEN);
    let result = derive_key_from_password(password, Some(&salt));

    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err(),
        PasswordManagerError::InvalidInput("Master password cannot be empty.".to_string())
    );
}

/// Tests that `derive_key_from_password` returns an `Other` error
/// when a salt of incorrect length is provided.
#[test]
fn test_derive_key_from_password_invalid_salt_len_returns_other_error() {
    let password = b"valid_password";
    let invalid_salt = vec![1, 2, 3]; // Incorrect length (e.g., 3 bytes, not SALT_LEN)
    let result = derive_key_from_password(password, Some(&invalid_salt));

    assert!(result.is_err());
    match result.unwrap_err() {
        PasswordManagerError::Other(msg) => assert!(msg.contains(&format!("Provided salt must be exactly {} bytes long.", SALT_LEN))),
        e => panic!("Expected Other error for invalid salt length, got {:?}", e),
    }
}

/// Tests that the `encrypt` function generally succeeds with valid inputs.
///
/// Note: Directly forcing an `EncryptionError` from `chacha20poly1305` is difficult
/// with valid key/nonce/data. This test primarily ensures that the error
/// conversion path exists if such a rare failure were to occur.
#[test]
fn test_encrypt_returns_encryption_error_on_failure() {
    let key = EncryptionKey::from_slice(&generate_random_bytes(KEY_LEN));
    let plaintext = b"some data";
    let result = encrypt(&key, plaintext);
    assert!(result.is_ok(), "Encryption should succeed with valid inputs.");
}

/// Tests that `decrypt` returns `DecryptionFailed` when an incorrect encryption key is used.
#[test]
fn test_decrypt_with_incorrect_key_returns_decryption_failed() {
    let correct_password = b"correct_password";
    let wrong_password = b"wrong_password";

    let (correct_key, salt) = derive_key_from_password(correct_password, None).unwrap();
    // Use the same salt to isolate the key difference to the password
    let (wrong_key, _) = derive_key_from_password(wrong_password.as_bytes(), Some(&salt)).unwrap();

    let plaintext = b"Sensitive data.";
    let (ciphertext, nonce) = encrypt(&correct_key, plaintext).unwrap();

    let result = decrypt(&wrong_key, &ciphertext, &nonce);
    assert!(result.is_err(), "Decryption should fail with incorrect key");
    assert_eq!(result.unwrap_err(), PasswordManagerError::DecryptionFailed);
}

/// Tests that `decrypt` returns `DecryptionFailed` when an incorrect nonce is used.
#[test]
fn test_decrypt_with_incorrect_nonce_returns_decryption_failed() {
    let password = b"password123";
    let (key, _) = derive_key_from_password(password, None).unwrap();

    let plaintext = b"Another secret.";
    let (ciphertext, _correct_nonce) = encrypt(&key, plaintext).unwrap();

    let wrong_nonce = generate_random_bytes(NONCE_LEN); // A randomly generated, incorrect nonce

    let result = decrypt(&key, &ciphertext, &wrong_nonce);
    assert!(result.is_err(), "Decryption should fail with incorrect nonce");
    assert_eq!(result.unwrap_err(), PasswordManagerError::DecryptionFailed);
}

/// Tests that `decrypt` returns `DecryptionFailed` when the ciphertext has been tampered with.
#[test]
fn test_decrypt_with_tampered_ciphertext_returns_decryption_failed() {
    let password = b"password_for_tampering";
    let (key, _) = derive_key_from_password(password, None).unwrap();

    let plaintext = b"Original message.";
    let (mut ciphertext, nonce) = encrypt(&key, plaintext).unwrap();

    // Tamper with the ciphertext (e.g., flip a bit)
    if !ciphertext.is_empty() {
        ciphertext[0] = ciphertext[0].wrapping_add(1); // Introduce a change
    } else {
        // This test is designed for non-empty plaintext to ensure tampering is possible.
        return;
    }

    let result = decrypt(&key, &ciphertext, &nonce);
    assert!(result.is_err(), "Decryption should fail with tampered ciphertext");
    assert_eq!(result.unwrap_err(), PasswordManagerError::DecryptionFailed);
}

/// Tests that `decrypt` returns an `Other` error when an invalid nonce length is provided.
#[test]
fn test_decrypt_with_invalid_nonce_length_returns_other_error() {
    let password = b"test_pass";
    let (key, _) = derive_key_from_password(password, None).unwrap();
    let plaintext = b"some data";
    let (ciphertext, _nonce) = encrypt(&key, plaintext).unwrap();

    let short_nonce = vec![1, 2, 3]; // Too short
    let result = decrypt(&key, &ciphertext, &short_nonce);
    assert!(result.is_err());
    match result.unwrap_err() {
        PasswordManagerError::Other(msg) => assert!(msg.contains("Invalid nonce length")),
        e => panic!("Expected Other error for invalid nonce length, got {:?}", e),
    }

    let long_nonce = vec![1; NONCE_LEN + 1]; // Too long
    let result = decrypt(&key, &ciphertext, &long_nonce);
    assert!(result.is_err());
    match result.unwrap_err() {
        PasswordManagerError::Other(msg) => assert!(msg.contains("Invalid nonce length")),
        e => panic!("Expected Other error for invalid nonce length, got {:?}", e),
    }
}

/// Tests the `From` implementation for `std::io::Error`, ensuring correct conversion.
#[test]
fn test_from_io_error() {
    let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "File not found");
    let pm_err: PasswordManagerError = io_err.into();
    assert_eq!(pm_err, PasswordManagerError::IoError(std::io::Error::new(std::io::ErrorKind::NotFound, "File not found")));
}

/// Tests the `From` implementation for `base64::DecodeError`, ensuring correct conversion.
#[test]
fn test_from_base64_decode_error() {
    let decode_err = base64::DecodeError::InvalidLength;
    let pm_err: PasswordManagerError = decode_err.into();
    assert_eq!(pm_err, PasswordManagerError::Base64DecodeError(base64::DecodeError::InvalidLength));
}

/// Tests the `From` implementation for `uuid::Error`, ensuring correct conversion.
#[test]
fn test_from_uuid_parse_error() {
    let uuid_err = uuid::Error::InvalidLength(5);
    let pm_err: PasswordManagerError = uuid_err.into();
    assert_eq!(pm_err, PasswordManagerError::UuidParseError(uuid::Error::InvalidLength(5)));
}

/// Tests the `From` implementation for `serde_json::Error`, ensuring it maps to `InvalidVaultData`.
#[test]
fn test_from_serde_json_error() {
    // Attempt to parse invalid JSON to get a serde_json::Error
    let json_str = "{invalid json}";
    let serde_err = serde_json::from_str::<serde_json::Value>(json_str).unwrap_err();
    let pm_err: PasswordManagerError = serde_err.into();

    // Verify that the error variant is correct and contains the expected message.
    assert!(matches!(pm_err, PasswordManagerError::InvalidVaultData(msg) if msg.contains("JSON serialization/deserialization error")));
}

/// Tests the `From` implementations for `String` and `&str`, ensuring they map to `Other`.
#[test]
fn test_from_string_and_str() {
    let string_err: PasswordManagerError = "An error from string".to_string().into();
    assert_eq!(string_err, PasswordManagerError::Other("An error from string".to_string()));

    let str_err: PasswordManagerError = "An error from &str".into();
    assert_eq!(str_err, PasswordManagerError::Other("An error from &str".to_string()));
}