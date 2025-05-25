// crates/password_core/src/bin/interactive_demo.rs

use password_core::crypto::{self, EncryptionKey, KEY_LEN, NONCE_LEN};
use password_core::data_types::EncryptedVault;
use password_core::error::PasswordManagerError;
use password_core::os_key_protector;
use password_core::printer as p; // Alias printer as 'p'

use std::io::{self, Write};
use std::fs;
use std::path::PathBuf;
use tempfile::tempdir;
use serde::{Serialize, Deserialize};
use bincode;
use tokio;
use env_logger;

// --- Minimal Vault Structure for Demo ---
#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct Vault {
    name: String,
}

impl Vault {
    fn new(name: String) -> Self {
        Vault { name }
    }

    fn get_info(&self) -> String {
        format!("Demo Vault: '{}'. (Contains placeholder content)", self.name)
    }
}

// --- High-level Vault Manager Functions for Demo ---

/// Initializes a new vault, generates a VEK, stores it in the OS keyring,
/// and saves an empty encrypted vault to a file.
async fn initialize_new_vault(
    profile_id: &str,
    vault_name: &str,
    vault_file_path: &PathBuf,
) -> Result<(), PasswordManagerError> {
    p::print_header("Initializing New Vault");
    p::print_info("Generating a new Vault Encryption Key (VEK)...");

    p::print_code_call(&format!("crypto::generate_random_bytes(KEY_LEN)"));
    let vek: EncryptionKey = crypto::generate_random_bytes(KEY_LEN).into();
    p::print_code_result(&format!("Generated VEK (length: {} bytes)", KEY_LEN)); // <--- Changed

    p::print_info("Storing VEK in OS Keyring. You may be prompted by your OS.");
    p::print_code_call(&format!("os_key_protector::store_vek_os_bound(\"{}\", &vek)", profile_id));
    os_key_protector::store_vek_os_bound(profile_id, &vek)?;
    p::print_code_result("VEK stored successfully");

    p::print_info("Creating initial empty vault content...");
    let vault = Vault::new(vault_name.to_string());
    p::print_code_call(&format!("bincode::serialize(&Vault::new(\"{}\"))", vault_name));
    let serialized_vault = bincode::serialize(&vault)
        .map_err(PasswordManagerError::Bincode)?;
    p::print_code_result("Vault serialized to bytes");

    p::print_info("Encrypting vault content...");
    p::print_code_call(&format!("crypto::encrypt(&vek, &serialized_vault)"));
    let (ciphertext, nonce) = crypto::encrypt(&vek, &serialized_vault)?;
    p::print_code_result(&format!("Content encrypted, got ciphertext (len: {}) and nonce (len: {})", ciphertext.len(), nonce.len())); // <--- Changed

    let vault_salt = crypto::generate_random_bytes(NONCE_LEN);
    p::print_code_call(&format!("crypto::generate_random_bytes(NONCE_LEN)"));
    p::print_code_result(&format!("Generated vault_salt (len: {})", NONCE_LEN)); // <--- Changed

    let encrypted_vault_data = EncryptedVault {
        salt: vault_salt,
        nonce: nonce,
        encrypted_payload: ciphertext,
        vault_version: 1,
    };
    p::print_code_call(&format!("bincode::serialize(&EncryptedVault {{ ... }})"));
    let final_data = bincode::serialize(&encrypted_vault_data)
        .map_err(PasswordManagerError::Bincode)?;
    p::print_code_result("EncryptedVault struct serialized");

    p::print_info(&format!("Saving encrypted vault to file: {:?}", vault_file_path));
    p::print_code_call(&format!("fs::write({:?}, final_data)", vault_file_path));
    fs::write(vault_file_path, final_data)
        .map_err(PasswordManagerError::IoError)?;
    p::print_code_result("File written successfully");

    p::print_success(&format!("Vault '{}' initialized and saved successfully!", vault_name));
    Ok(())
}

/// Loads an existing encrypted vault from a file, retrieves the VEK from the OS keyring,
/// and decrypts the vault content.
async fn load_existing_vault(
    profile_id: &str,
    vault_file_path: &PathBuf,
) -> Result<Vault, PasswordManagerError> {
    p::print_header("Loading Existing Vault");
    p::print_info("Attempting to retrieve VEK from OS Keyring. You may be prompted by your OS.");
    p::print_code_call(&format!("os_key_protector::retrieve_vek_os_bound(\"{}\")", profile_id));
    let vek = os_key_protector::retrieve_vek_os_bound(profile_id)?;
    p::print_code_result("VEK retrieved successfully");

    p::print_info(&format!("Reading encrypted vault from file: {:?}", vault_file_path));
    p::print_code_call(&format!("fs::read({:?})", vault_file_path));
    let final_data = fs::read(vault_file_path)
        .map_err(PasswordManagerError::IoError)?;
    p::print_code_result(&format!("File read ({} bytes)", final_data.len())); // <--- Changed

    p::print_code_call(&format!("bincode::deserialize(&final_data) as EncryptedVault"));
    let encrypted_vault_data: EncryptedVault = bincode::deserialize(&final_data)
        .map_err(PasswordManagerError::Bincode)?;
    p::print_code_result("EncryptedVault struct deserialized");

    p::print_info("Decrypting vault content...");
    p::print_code_call(&format!("crypto::decrypt(&vek, &encrypted_vault_data.encrypted_payload, &encrypted_vault_data.nonce)"));
    let decrypted_bytes = crypto::decrypt(&vek, &encrypted_vault_data.encrypted_payload, &encrypted_vault_data.nonce)?;
    p::print_code_result(&format!("Content decrypted ({} bytes)", decrypted_bytes.len())); // <--- Changed

    p::print_code_call(&format!("bincode::deserialize(&decrypted_bytes) as Vault"));
    let vault: Vault = bincode::deserialize(&decrypted_bytes)
        .map_err(PasswordManagerError::Bincode)?;
    p::print_code_result("Vault deserialized");

    p::print_success(&format!("Vault '{}' loaded successfully!", vault.name));
    Ok(vault)
}

/// Deletes the VEK from the OS keyring and the vault file.
async fn delete_vault(
    profile_id: &str,
    vault_file_path: &PathBuf,
) -> Result<(), PasswordManagerError> {
    p::print_header("Deleting Vault Data");
    p::print_info("Attempting to delete VEK from OS Keyring. You may be prompted by your OS.");
    p::print_code_call(&format!("os_key_protector::delete_vek_os_bound(\"{}\")", profile_id));
    os_key_protector::delete_vek_os_bound(profile_id)?;
    p::print_success("VEK successfully deleted from OS keyring.");

    if vault_file_path.exists() {
        p::print_info(&format!("Deleting vault file: {:?}", vault_file_path));
        p::print_code_call(&format!("fs::remove_file({:?})", vault_file_path));
        fs::remove_file(vault_file_path)
            .map_err(PasswordManagerError::IoError)?;
        p::print_success(&format!("Vault file deleted: {:?}", vault_file_path));
    } else {
        p::print_dimmed(&format!("Vault file did not exist: {:?}", vault_file_path));
    }

    p::print_success("Vault data removed successfully.");
    Ok(())
}

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .init();

    p::print_header("Heikkinen Password Manager Interactive Demo");
    p::print_info("This demo will interact with your OS keyring.");
    p::print_info("You might see prompts for password, PIN, or biometric authentication.");

    let profile_id = "demo_profile";
    let vault_name = "MyPersonalVault";

    let temp_dir = tempdir().expect("Failed to create temporary directory");
    let vault_file_path = temp_dir.path().join("my_encrypted_vault.bin");

    p::print_info(&format!("\nVault file will be stored temporarily at: {:?}", vault_file_path));

    // --- Scenario 1: Initialize New Vault ---
    p::print_scenario_header("Scenario 1: Initializing a New Vault");
    p::print_info("If this is your first run, the VEK will be generated and stored.");
    let init_result = initialize_new_vault(profile_id, vault_name, &vault_file_path).await;
    match init_result {
        Ok(_) => p::print_success("Scenario 1 completed successfully."),
        Err(e) => {
            p::print_error(&format!("Scenario 1 failed: {}", e));
            p::print_dimmed("This might happen if your OS keyring is not configured or accessible.");
            p::print_dimmed("Please ensure a keyring/secret service is running (e.g., GNOME Keyring, KDE Wallet, Windows Credential Manager, macOS Keychain).");
            p::print_error("Exiting demo.");
            temp_dir.close().expect("Failed to remove temporary directory on error exit.");
            return;
        }
    }

    print!("\n");
    p::print_dimmed("Press Enter to continue to Scenario 2 (Loading Vault)...");
    io::stdout().flush().unwrap();
    let mut _input = String::new();
    io::stdin().read_line(&mut _input).unwrap();

    // --- Scenario 2: Loading Existing Vault ---
    p::print_scenario_header("Scenario 2: Loading Existing Vault");
    p::print_info("The VEK will be retrieved from the OS keyring.");
    let load_result = load_existing_vault(profile_id, &vault_file_path).await;
    match load_result {
        Ok(vault) => {
            p::print_success("Scenario 2 completed successfully.");
            p::print_info(&format!("Loaded Vault Info: {}", vault.get_info()));
        }
        Err(e) => {
            p::print_error(&format!("Scenario 2 failed: {}", e));
            p::print_dimmed("This might happen if the VEK was not correctly stored, or if there's an issue with the vault file.");
            p::print_error("Exiting demo.");
            temp_dir.close().expect("Failed to remove temporary directory on error exit.");
            return;
        }
    }

    print!("\n");
    p::print_dimmed("Press Enter to continue to Scenario 3 (Deleting Vault Data)...");
    io::stdout().flush().unwrap();
    let mut _input = String::new();
    io::stdin().read_line(&mut _input).unwrap();

    // --- Scenario 3: Delete Vault Data ---
    p::print_scenario_header("Scenario 3: Deleting Vault Data");
    p::print_info("The VEK will be removed from your OS keyring and the vault file will be deleted.");
    let delete_result = delete_vault(profile_id, &vault_file_path).await;
    match delete_result {
        Ok(_) => p::print_success("Scenario 3 completed successfully. All demo data removed."),
        Err(e) => p::print_error(&format!("Scenario 3 failed: {}", e)),
    }

    p::print_header("Demo Complete");

    temp_dir.close().expect("Failed to remove temporary directory");
    p::print_dimmed("Temporary vault directory cleaned up.");
}