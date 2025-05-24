// crates/password_core/src/error.rs

use thiserror::Error;
use argon2::Error as ArgonLibError; // For errors directly from argon2 calculations
use argon2::password_hash::Error as ArgonPasswordHashError; // For errors from password_hash utilities like SaltString
use chacha20poly1305::Error as AeadError;
use std::io;
use base64::DecodeError;
use uuid::Error as UuidError;

// Custom Error Type for the Password Manager Core
#[derive(Debug, Error)]
pub enum PasswordManagerError {
    #[error("Encryption/Decryption failed: {0}")]
    EncryptionError(AeadError),
    #[error("Key derivation failed (Argon2 calculation): {0}")]
    Argon2CalculationError(ArgonLibError), // For errors directly from argon2
    #[error("Key derivation failed (PasswordHash processing): {0}")]
    Argon2PasswordHashError(ArgonPasswordHashError), // For errors from password_hash types
    #[error("I/O error: {0}")]
    IoError(#[from] io::Error),
    #[error("Invalid master password or corrupted vault")]
    DecryptionFailed,
    #[error("Vault data is invalid or corrupted: {0}")]
    InvalidVaultData(String),
    #[error("Base64 decoding failed: {0}")]
    Base64DecodeError(#[from] DecodeError),
    #[error("UUID parsing failed: {0}")]
    UuidParseError(#[from] UuidError),
    #[error("Invalid input: {0}")] // New variant for validation errors
    InvalidInput(String),
    #[error("Other error: {0}")]
    Other(String),
}

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
            (PasswordManagerError::InvalidInput(s1), PasswordManagerError::InvalidInput(s2)) => s1 == s2, // Compare messages
            (PasswordManagerError::Other(s1), PasswordManagerError::Other(s2)) => s1 == s2,
            _ => false,
        }
    }
}
impl Eq for PasswordManagerError {}

impl From<AeadError> for PasswordManagerError {
    fn from(err: AeadError) -> Self {
        PasswordManagerError::EncryptionError(err)
    }
}

impl From<ArgonLibError> for PasswordManagerError {
    fn from(err: ArgonLibError) -> Self {
        PasswordManagerError::Argon2CalculationError(err)
    }
}

impl From<ArgonPasswordHashError> for PasswordManagerError {
    fn from(err: ArgonPasswordHashError) -> Self {
        PasswordManagerError::Argon2PasswordHashError(err)
    }
}

impl From<String> for PasswordManagerError {
    fn from(s: String) -> Self {
        PasswordManagerError::Other(s)
    }
}

impl From<&str> for PasswordManagerError {
    fn from(s: &str) -> Self {
        PasswordManagerError::Other(s.to_string())
    }
}

impl From<serde_json::Error> for PasswordManagerError {
    fn from(err: serde_json::Error) -> Self {
        PasswordManagerError::InvalidVaultData(format!("JSON serialization/deserialization error: {}", err))
    }
}