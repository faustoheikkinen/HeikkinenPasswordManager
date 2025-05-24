// crates/password_core/src/error.rs

//! Defines custom error types for the `password_core` crate.
//!
//! This module centralizes error handling, providing a comprehensive set of
//! specific error variants that can occur during cryptographic operations,
//! vault management, and data processing. It leverages the `thiserror` crate
//! for simplified error declaration and display formatting, and includes
//! `From` implementations for easy conversion from underlying library errors.

use thiserror::Error;
use argon2::Error as ArgonLibError;
use argon2::password_hash::Error as ArgonPasswordHashError;
use chacha20poly1305::Error as AeadError;
use std::io;
use base64::DecodeError;
use uuid::Error as UuidError;

/// Custom Error Type for the Password Manager Core.
///
/// This enum encapsulates all possible errors that can occur within the `password_core`
/// crate, from cryptographic failures to I/O issues and data corruption.
#[derive(Debug, Error)]
pub enum PasswordManagerError {
    /// An error occurred during encryption or decryption using an Authenticated Encryption with Associated Data (AEAD) algorithm.
    #[error("Encryption/Decryption failed: {0}")]
    EncryptionError(AeadError),
    /// An error occurred during the Argon2 key derivation calculation itself.
    #[error("Key derivation failed (Argon2 calculation): {0}")]
    Argon2CalculationError(ArgonLibError),
    /// An error related to processing password hash components (e.g., salt string parsing) during key derivation.
    #[error("Key derivation failed (PasswordHash processing): {0}")]
    Argon2PasswordHashError(ArgonPasswordHashError),
    /// An input/output error occurred, typically when reading from or writing to files.
    #[error("I/O error: {0}")]
    IoError(#[from] io::Error),
    /// Decryption failed, usually indicating an incorrect master password or corrupted ciphertext.
    #[error("Invalid master password or corrupted vault")]
    DecryptionFailed,
    /// The vault data is in an invalid or corrupted format, preventing parsing or proper interpretation.
    #[error("Vault data is invalid or corrupted: {0}")]
    InvalidVaultData(String),
    /// An error occurred during Base64 decoding of data.
    #[error("Base64 decoding failed: {0}")]
    Base64DecodeError(#[from] DecodeError),
    /// An error occurred when parsing or validating a UUID.
    #[error("UUID parsing failed: {0}")]
    UuidParseError(#[from] UuidError),
    /// An invalid input was provided to a function, typically due to failed validation checks.
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    /// A catch-all error for other unexpected issues not covered by specific variants.
    #[error("Other error: {0}")]
    Other(String),
}

/// Implements `PartialEq` for `PasswordManagerError` to allow comparison of error types.
///
/// Note: For errors wrapping external library errors (`AeadError`, `ArgonLibError`, etc.),
/// comparison is based on their string representation or internal kind (for `IoError`).
/// This is a common approach when the underlying error types don't implement `PartialEq` themselves,
/// or when only the general type of error matters for testing or control flow.
impl PartialEq for PasswordManagerError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (PasswordManagerError::EncryptionError(e1), PasswordManagerError::EncryptionError(e2)) => e1.to_string() == e2.to_string(),
            (PasswordManagerError::Argon2CalculationError(e1), PasswordManagerError::Argon2CalculationError(e2)) => e1.to_string() == e2.to_string(),
            (PasswordManagerError::Argon2PasswordHashError(e1), PasswordManagerError::Argon2PasswordHashError(e2)) => e1.to_string() == e2.to_string(),
            (PasswordManagerError::IoError(e1), PasswordManagerError::IoError(e2)) => e1.kind() == e2.kind(),
            (PasswordManagerError::DecryptionFailed, PasswordManagerError::DecryptionFailed) => true,
            (PasswordManagerError::InvalidVaultData(s1), PasswordManagerError::InvalidVaultData(s2)) => s1 == s2,
            (PasswordManagerError::Base64DecodeError(e1), PasswordManagerError::Base64DecodeError(e2)) => e1.to_string() == e2.to_string(),
            (PasswordManagerError::UuidParseError(e1), PasswordManagerError::UuidParseError(e2)) => e1.to_string() == e2.to_string(),
            (PasswordManagerError::InvalidInput(s1), PasswordManagerError::InvalidInput(s2)) => s1 == s2,
            (PasswordManagerError::Other(s1), PasswordManagerError::Other(s2)) => s1 == s2,
            _ => false,
        }
    }
}
/// Implements `Eq` for `PasswordManagerError`, signifying that `PartialEq` implies a total equivalence relation.
impl Eq for PasswordManagerError {}

/// Implements conversion from `chacha20poly1305::Error` to `PasswordManagerError::EncryptionError`.
impl From<AeadError> for PasswordManagerError {
    fn from(err: AeadError) -> Self {
        PasswordManagerError::EncryptionError(err)
    }
}

/// Implements conversion from `argon2::Error` to `PasswordManagerError::Argon2CalculationError`.
impl From<ArgonLibError> for PasswordManagerError {
    fn from(err: ArgonLibError) -> Self {
        PasswordManagerError::Argon2CalculationError(err)
    }
}

/// Implements conversion from `argon2::password_hash::Error` to `PasswordManagerError::Argon2PasswordHashError`.
impl From<ArgonPasswordHashError> for PasswordManagerError {
    fn from(err: ArgonPasswordHashError) -> Self {
        PasswordManagerError::Argon2PasswordHashError(err)
    }
}

/// Implements conversion from `String` to `PasswordManagerError::Other`.
impl From<String> for PasswordManagerError {
    fn from(s: String) -> Self {
        PasswordManagerError::Other(s)
    }
}

/// Implements conversion from `&str` to `PasswordManagerError::Other`.
impl From<&str> for PasswordManagerError {
    fn from(s: &str) -> Self {
        PasswordManagerError::Other(s.to_string())
    }
}

/// Implements conversion from `serde_json::Error` to `PasswordManagerError::InvalidVaultData`.
impl From<serde_json::Error> for PasswordManagerError {
    fn from(err: serde_json::Error) -> Self {
        PasswordManagerError::InvalidVaultData(format!("JSON serialization/deserialization error: {}", err))
    }
}