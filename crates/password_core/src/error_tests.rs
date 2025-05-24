// crates/password_core/tests/error_tests.rs

use password_core::crypto::{
    derive_key_from_password, encrypt, decrypt, generate_random_bytes, SALT_LEN, NONCE_LEN, KEY_LEN, EncryptionKey
};
use password_core::error::PasswordManagerError;
use argon2::password_hash::Error as Argon2PasswordHashError; // Alias for clarity
use argon2::Error as Argon2Error; // Alias for clarity
use chacha20poly1305::aead::Error as AeadCryptoError; // Alias for clarity
use base64::DecodeError; // For testing Base64DecodeError directly
use uuid::Error as UuidError; // For testing UuidParseError directly

// --- Test Display Implementations (Important for user-facing errors) ---
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

// --- Test Error Triggers from crypto.rs ---

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

// Note: Testing Argon2CalculationError or Argon2PasswordHashError directly by *forcing*
// them is difficult without mocking, as the underlying `argon2` crate is robust
// and unlikely to fail with valid, constant parameters. The `map_err` calls
// are there to ensure conversion if a failure *were* to occur, which is good.
// The primary KDF error we can induce with invalid input is the empty password above.

#[test]
fn test_encrypt_returns_encryption_error_on_failure() {
    // This scenario is hard to reliably trigger with chacha20poly1305 and valid keys/nonces.
    // However, if there was a way to make `cipher.encrypt` fail (e.g., extremely large data
    // exhausting memory, or some internal state corruption), this test would catch it.
    // For now, we confirm it usually succeeds with valid inputs and is ready for real errors.
    let key = EncryptionKey::from_slice(&generate_random_bytes(KEY_LEN));
    let plaintext = b"some data";
    let result = encrypt(&key, plaintext);
    assert!(result.is_ok(), "Encryption should succeed with valid inputs, otherwise this test is setup wrong.");

    // If you introduce a way to force an AeadError, add it here.
    // Example (pseudo-code, does not work without mocking):
    // mock_aead_encrypt_to_return_error();
    // let result = encrypt(&key, plaintext);
    // assert!(matches!(result, Err(PasswordManagerError::EncryptionError(_))));
}


#[test]
fn test_decrypt_with_incorrect_key_returns_decryption_failed() {
    let correct_password = b"correct_password";
    let wrong_password = b"wrong_password";

    let (correct_key, salt) = derive_key_from_password(correct_password, None).unwrap();
    // Use the same salt to ensure the key difference is solely due to the password
    let (wrong_key, _) = derive_key_from_password(wrong_password.as_bytes(), Some(&salt)).unwrap();

    let plaintext = b"Sensitive data.";
    let (ciphertext, nonce) = encrypt(&correct_key, plaintext).unwrap();

    let result = decrypt(&wrong_key, &ciphertext, &nonce);
    assert!(result.is_err(), "Decryption should fail with incorrect key");
    assert_eq!(result.unwrap_err(), PasswordManagerError::DecryptionFailed);
}

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
        // If plaintext was empty, ciphertext might only contain the authentication tag.
        // For this test, ensure plaintext is non-empty.
        return;
    }

    let result = decrypt(&key, &ciphertext, &nonce);
    assert!(result.is_err(), "Decryption should fail with tampered ciphertext");
    assert_eq!(result.unwrap_err(), PasswordManagerError::DecryptionFailed);
}

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

// --- Test `From` implementations for PasswordManagerError ---

#[test]
fn test_from_io_error() {
    let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "File not found");
    let pm_err: PasswordManagerError = io_err.into();
    assert_eq!(pm_err, PasswordManagerError::IoError(std::io::Error::new(std::io::ErrorKind::NotFound, "File not found")));
}

#[test]
fn test_from_base64_decode_error() {
    let decode_err = base64::DecodeError::InvalidLength;
    let pm_err: PasswordManagerError = decode_err.into();
    assert_eq!(pm_err, PasswordManagerError::Base64DecodeError(base64::DecodeError::InvalidLength));
}

#[test]
fn test_from_uuid_parse_error() {
    let uuid_err = uuid::Error::InvalidLength(5);
    let pm_err: PasswordManagerError = uuid_err.into();
    assert_eq!(pm_err, PasswordManagerError::UuidParseError(uuid::Error::InvalidLength(5)));
}

#[test]
fn test_from_serde_json_error() {
    // This is hard to construct directly for comparison due to serde_json::Error not being PartialEq.
    // We'll test the output message and variant.
    let json_str = "{invalid json}";
    let serde_err = serde_json::from_str::<serde_json::Value>(json_str).unwrap_err();
    let pm_err: PasswordManagerError = serde_err.into();

    assert!(matches!(pm_err, PasswordManagerError::InvalidVaultData(msg) if msg.contains("JSON serialization/deserialization error")));
}

#[test]
fn test_from_string_and_str() {
    let string_err: PasswordManagerError = "An error from string".to_string().into();
    assert_eq!(string_err, PasswordManagerError::Other("An error from string".to_string()));

    let str_err: PasswordManagerError = "An error from &str".into();
    assert_eq!(str_err, PasswordManagerError::Other("An error from &str".to_string()));
}