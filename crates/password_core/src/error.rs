// crates/password_core/src/error.rs

use std::io;
use thiserror::Error;
use std::string::FromUtf8Error;
use argon2::Error as ArgonLibError;
use argon2::password_hash::Error as ArgonPasswordHashError;
// Corrected import: Use chacha20poly1305::Error as AeadLibError
use chacha20poly1305::Error as AeadLibError; // Corrected import
use base64::DecodeError;
use bincode::Error as BincodeError;
use serde_json::Error as SerdeJsonError;


#[derive(Debug, Error)]
pub enum PasswordManagerError {
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    #[error("Key derivation error: {0}")]
    KeyDerivationError(String),
    #[error("Argon2 calculation error: {0}")]
    Argon2CalculationError(#[from] ArgonLibError),
    #[error("Password hashing error: {0}")]
    PasswordHashingError(#[from] ArgonPasswordHashError),

    #[error("Encryption error: {0}")]
    EncryptionError(String), // Takes a String now

    #[error("Decryption failed. The key might be incorrect, or the data has been tampered with.")]
    DecryptionFailed,
    #[error("Base64 decode error: {0}")]
    Base64DecodeError(#[from] DecodeError),
    #[error("UTF-8 conversion error: {0}")]
    Utf8Error(#[from] FromUtf8Error),
    #[error("Keyring operation failed: {0}")]
    KeyringError(String),
    #[error("Data corruption: {0}")]
    DataCorruption(String),

    #[error("Bincode serialization/deserialization error: {0}")]
    Bincode(#[from] BincodeError),

    #[error("IO error: {0}")]
    IoError(#[from] io::Error),
    #[error("JSON serialization/deserialization error: {0}")]
    JsonError(#[from] SerdeJsonError),

    #[error("Invalid vault data: {0}")]
    InvalidVaultData(String),
    #[error("Other error: {0}")]
    Other(String),
}

// Manual `From` implementation for `chacha20poly1305::Error` to convert it to a `String`
impl From<AeadLibError> for PasswordManagerError {
    fn from(err: AeadLibError) -> Self {
        // Since chacha20poly1305::Error is a unit struct and doesn't have a useful .to_string()
        // we can just provide a generic message or use Debug format.
        PasswordManagerError::EncryptionError(format!("AEAD encryption/decryption failed: {:?}", err))
    }
}


// Manual PartialEq implementation for PasswordManagerError
impl PartialEq for PasswordManagerError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::InvalidInput(s1), Self::InvalidInput(s2)) => s1 == s2,
            (Self::KeyDerivationError(s1), Self::KeyDerivationError(s2)) => s1 == s2,
            (Self::Argon2CalculationError(e1), Self::Argon2CalculationError(e2)) => e1.to_string() == e2.to_string(),
            (Self::PasswordHashingError(e1), Self::PasswordHashingError(e2)) => e1.to_string() == e2.to_string(),
            (Self::EncryptionError(s1), Self::EncryptionError(s2)) => s1 == s2,
            (Self::DecryptionFailed, Self::DecryptionFailed) => true,
            (Self::Base64DecodeError(e1), Self::Base64DecodeError(e2)) => e1.to_string() == e2.to_string(),
            (Self::Utf8Error(e1), Self::Utf8Error(e2)) => e1.to_string() == e2.to_string(),
            (Self::KeyringError(s1), Self::KeyringError(s2)) => s1 == s2,
            (Self::DataCorruption(s1), Self::DataCorruption(s2)) => s1 == s2,
            (Self::IoError(e1), Self::IoError(e2)) => e1.kind() == e2.kind() && e1.to_string() == e2.to_string(),
            (Self::Bincode(e1), Self::Bincode(e2)) => e1.to_string() == e2.to_string(),
            (Self::JsonError(e1), Self::JsonError(e2)) => e1.to_string() == e2.to_string(),
            (Self::InvalidVaultData(s1), Self::InvalidVaultData(s2)) => s1 == s2,
            (Self::Other(s1), Self::Other(s2)) => s1 == s2,
            _ => false, // Different variants are not equal
        }
    }
}

impl Eq for PasswordManagerError {}

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