use thiserror::Error;
use std::string::FromUtf8Error;
use argon2::Error as ArgonLibError;
use argon2::password_hash::Error as ArgonPasswordHashError;
use chacha20poly1305::Error as AeadError;
use base64::DecodeError;

#[derive(Debug, Error)]
pub enum PasswordManagerError {
    #[error("Encryption error: {0}")]
    EncryptionError(AeadError),
    #[error("Decryption failed. The key might be incorrect, or the data has been tampered with.")]
    DecryptionFailed,
    #[error("Argon2 calculation error: {0}")]
    Argon2CalculationError(ArgonLibError),
    #[error("Password hashing error: {0}")]
    PasswordHashingError(ArgonPasswordHashError),
    #[error("JSON serialization/deserialization error: {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("Base64 decoding error: {0}")]
    Base64DecodeError(#[from] DecodeError),
    #[error("UTF-8 conversion error: {0}")]
    Utf8Error(#[from] FromUtf8Error),
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Key derivation failed: {0}")]
    KeyDerivationError(String),
    #[error("Keyring operation failed: {0}")]
    KeyringError(String),
    #[error("Data corruption detected: {0}")]
    DataCorruption(String),
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    #[error("Invalid vault data: {0}")]
    InvalidVaultData(String),
    #[error("Other error: {0}")]
    Other(String),
}

impl PartialEq for PasswordManagerError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (PasswordManagerError::EncryptionError(e1), PasswordManagerError::EncryptionError(e2)) => e1.to_string() == e2.to_string(),
            (PasswordManagerError::DecryptionFailed, PasswordManagerError::DecryptionFailed) => true,
            (PasswordManagerError::Argon2CalculationError(e1), PasswordManagerError::Argon2CalculationError(e2)) => e1.to_string() == e2.to_string(),
            (PasswordManagerError::PasswordHashingError(e1), PasswordManagerError::PasswordHashingError(e2)) => e1.to_string() == e2.to_string(),
            (PasswordManagerError::JsonError(e1), PasswordManagerError::JsonError(e2)) => e1.to_string() == e2.to_string(),
            (PasswordManagerError::Base64DecodeError(e1), PasswordManagerError::Base64DecodeError(e2)) => e1.to_string() == e2.to_string(),
            (PasswordManagerError::Utf8Error(e1), PasswordManagerError::Utf8Error(e2)) => e1.to_string() == e2.to_string(),
            (PasswordManagerError::IoError(e1), PasswordManagerError::IoError(e2)) => e1.kind() == e2.kind() && e1.to_string() == e2.to_string(),
            (PasswordManagerError::KeyDerivationError(s1), PasswordManagerError::KeyDerivationError(s2)) => s1 == s2,
            (PasswordManagerError::KeyringError(s1), PasswordManagerError::KeyringError(s2)) => s1 == s2,
            (PasswordManagerError::DataCorruption(s1), PasswordManagerError::DataCorruption(s2)) => s1 == s2,
            (PasswordManagerError::InvalidInput(s1), PasswordManagerError::InvalidInput(s2)) => s1 == s2,
            (PasswordManagerError::InvalidVaultData(s1), PasswordManagerError::InvalidVaultData(s2)) => s1 == s2,
            (PasswordManagerError::Other(s1), PasswordManagerError::Other(s2)) => s1 == s2,
            _ => false,
        }
    }
}

impl Eq for PasswordManagerError {}

// Implement From<AeadError> for PasswordManagerError
impl From<AeadError> for PasswordManagerError {
    fn from(err: AeadError) -> Self {
        PasswordManagerError::EncryptionError(err)
    }
}

// Implement From<ArgonLibError> for PasswordManagerError
impl From<ArgonLibError> for PasswordManagerError {
    fn from(err: ArgonLibError) -> Self {
        PasswordManagerError::Argon2CalculationError(err)
    }
}

// Implement From<ArgonPasswordHashError> for PasswordManagerError
impl From<ArgonPasswordHashError> for PasswordManagerError {
    fn from(err: ArgonPasswordHashError) -> Self {
        PasswordManagerError::PasswordHashingError(err)
    }
}

// Implement From<String> for PasswordManagerError
impl From<String> for PasswordManagerError {
    fn from(s: String) -> Self {
        PasswordManagerError::Other(s)
    }
}

// Implement From<&str> for PasswordManagerError
impl From<&str> for PasswordManagerError {
    fn from(s: &str) -> Self {
        PasswordManagerError::Other(s.to_string())
    }
}