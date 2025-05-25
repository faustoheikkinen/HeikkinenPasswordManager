// crates/password_cli/src/main.rs

use std::io::{self, Write};

// Import necessary items from password_core
use password_core::{
    crypto::{derive_key_from_password, encrypt, decrypt},
    data_types::{EncryptedVault, PasswordEntry, Note}, // Note import should now work
    settings_manager::{AppUserProfile, SettingsManager},
    PasswordManagerError,
};

// use rpassword::read_password;
use scanpw::scanpw;
use serde_json::{self, Value};
use zeroize::Zeroize;
use termcolor::{Color, ColorChoice, ColorSpec, StandardStream, WriteColor};


// Helper function for colored output - now with an optional 'dimmed' parameter
fn pc(writer: &mut StandardStream, text: &str, color: Color, bold: bool, intense: bool, dimmed: bool) -> io::Result<()> {
    let mut color_spec = ColorSpec::new();
    color_spec.set_fg(Some(color)).set_bold(bold).set_intense(intense);
    if dimmed {
        color_spec.set_dimmed(true);
    }
    writer.set_color(&color_spec)?;
    write!(writer, "{}", text)?;
    writer.reset()?;
    writer.flush()
}

// Helper function to get password input
fn get_password_input(_prompt: &str) -> io::Result<String> {
    io::stdout().flush()?;
    //let input = read_password().unwrap_or_default();
    let input = scanpw!("Enter password: ");
    Ok(input.trim().to_string())
}

// Function to print the parsed vault contents (notes and passwords)
fn print_vault_contents(
    stdout: &mut StandardStream,
    profile_name: &str,
    vault_data: &[u8],
) -> Result<(), PasswordManagerError> {
    pc(stdout, &format!("\n--- Contents for {}'s Vault ---", profile_name), Color::Blue, false, false, false)?;
    pc(stdout, "\nInvoking app logic: serde_json::from_slice(...) to parse vault.", Color::White, false, false, true)?; // Added \n

    let json_value: Value = serde_json::from_slice(vault_data)
        .map_err(|e| PasswordManagerError::InvalidVaultData(format!("Failed to parse vault JSON: {}", e)))?;

    if let Some(notes_array) = json_value["notes"].as_array() {
        pc(stdout, "\nNotes:", Color::Green, true, false, false)?;
        if notes_array.is_empty() {
            pc(stdout, "  No notes found.", Color::White, false, false, false)?;
        } else {
            for (i, note_val) in notes_array.iter().enumerate() {
                let note: Note = serde_json::from_value(note_val.clone())
                    .map_err(|e| PasswordManagerError::InvalidVaultData(format!("Failed to deserialize note entry: {}", e)))?;
                pc(stdout, &format!("  Note {}: ID: {}, Content: \"{}\"", i + 1, note.id, note.content), Color::White, false, false, false)?;
            }
        }
    } else {
        pc(stdout, "\nNo 'notes' section found in vault.", Color::Yellow, false, false, false)?;
    }

    if let Some(pass_entries_array) = json_value["password_entries"].as_array() {
        pc(stdout, "\nPassword Entries:", Color::Green, true, false, false)?;
        if pass_entries_array.is_empty() {
            pc(stdout, "  No password entries found.", Color::White, false, false, false)?;
        } else {
            for (i, entry_val) in pass_entries_array.iter().enumerate() {
                let entry: PasswordEntry = serde_json::from_value(entry_val.clone())
                    .map_err(|e| PasswordManagerError::InvalidVaultData(format!("Failed to deserialize password entry: {}", e)))?;

                let password_display = if !entry.password_versions.is_empty() {
                    "[****** (password encrypted)]"
                } else {
                    "[No password stored]"
                };
                pc(stdout, &format!("  Entry {}: Name: \"{}\", Username: {:?}, URL: {:?}, Type: {:?}, Password: {}",
                    i + 1, entry.name, entry.username, entry.url, entry.credential_type, password_display), Color::White, false, false, false)?;
                if let Some(notes) = entry.notes {
                    pc(stdout, &format!("    Notes: \"{}\"", notes), Color::White, false, false, false)?;
                }
            }
        }
    } else {
        pc(stdout, "\nNo 'password_entries' section found in vault.", Color::Yellow, false, false, false)?;
    }
    pc(stdout, "--- End Contents for Vault ---", Color::Blue, false, false, false)?;
    Ok(())
}


// Function to handle a single user's login and vault interaction
fn handle_user_login(
    stdout: &mut StandardStream,
    profile: &AppUserProfile,
    _settings_manager: &SettingsManager,
    is_first_login_simulation: bool,
) -> Result<(), PasswordManagerError> {
    pc(stdout, &format!("\n--- Simulating login for user: {} ({}) ---", profile.name, profile.id), Color::Cyan, true, false, false)?;

    let mut master_password_vec: Vec<u8>;
    let mut vault_data: Vec<u8>;

    pc(stdout, "\nInvoking app logic: std::path::PathBuf::exists()", Color::White, false, false, true)?; // Added \n
    let vault_exists = profile.vault_path.exists();

    if is_first_login_simulation {
        pc(stdout, &format!("\nEnter Master Password for {}: ", profile.name), Color::Green, false, true, false)?;
        pc(stdout, "\nInvoking app logic: rpassword::read_password()", Color::White, false, false, true)?; // Added \n
        master_password_vec = get_password_input("")?.into_bytes();
        if master_password_vec.is_empty() {
            return Err(PasswordManagerError::InvalidInput(format!("Master password for {} cannot be empty.", profile.name)));
        }

        if vault_exists {
            pc(stdout, &format!("Vault file found at {:?}. Attempting to decrypt...", profile.vault_path), Color::Yellow, false, false, false)?;
            pc(stdout, "\nInvoking app logic: std::fs::read_to_string()", Color::White, false, false, true)?; // Added \n
            let encrypted_vault_json = std::fs::read_to_string(&profile.vault_path)?;
            pc(stdout, "\nInvoking app logic: serde_json::from_str()", Color::White, false, false, true)?; // Added \n
            let encrypted_vault: EncryptedVault = serde_json::from_str(&encrypted_vault_json)?;

            pc(stdout, "\nInvoking password_core::crypto::derive_key_from_password(...)", Color::White, false, false, true)?; // Added \n
            let (master_key, _) = derive_key_from_password(&master_password_vec, Some(&encrypted_vault.salt))?;

            pc(stdout, "\nInvoking password_core::crypto::decrypt(...)", Color::White, false, false, true)?; // Added \n
            match decrypt(&master_key, &encrypted_vault.encrypted_payload, &encrypted_vault.nonce) {
                Ok(decrypted_payload) => {
                    vault_data = decrypted_payload;
                    pc(stdout, "Vault decrypted successfully!", Color::Green, true, false, false)?;
                }
                Err(e) => {
                    master_password_vec.zeroize();
                    pc(stdout, &format!("Decryption failed for {}: {}", profile.name, e), Color::Red, true, false, false)?;
                    return Err(e);
                }
            }
        } else {
            pc(stdout, &format!("No vault file found at {:?}. Creating a new one for {}...", profile.vault_path, profile.name), Color::Yellow, false, false, false)?;
            pc(stdout, "\nInvoking password_core::crypto::derive_key_from_password(...)", Color::White, false, false, true)?; // Added \n
            let (master_key, new_salt) = derive_key_from_password(&master_password_vec, None)?;

            let initial_plaintext_vault_content = r#"{ "notes": [ { "id": "welcome", "content": "Welcome to the Heikkinen Password Manager" } ], "password_entries": [] }"#.as_bytes().to_vec();

            pc(stdout, "\nInvoking password_core::crypto::encrypt(...)", Color::White, false, false, true)?; // Added \n
            let (encrypted_payload, nonce) = encrypt(&master_key, &initial_plaintext_vault_content)?;

            let new_vault = EncryptedVault {
                salt: new_salt,
                encrypted_payload,
                nonce,
                vault_version: 1,
            };

            pc(stdout, "\nInvoking app logic: serde_json::to_string_pretty(...)", Color::White, false, false, true)?; // Added \n
            let json_data = serde_json::to_string_pretty(&new_vault)?;
            pc(stdout, "\nInvoking app logic: std::path::PathBuf::parent(), std::fs::create_dir_all(), std::fs::write()", Color::White, false, false, true)?; // Added \n
            let parent_dir = profile.vault_path.parent().ok_or(PasswordManagerError::Other(format!("Could not determine parent directory for {}'s vault.", profile.name)))?;
            std::fs::create_dir_all(parent_dir)?;
            std::fs::write(&profile.vault_path, json_data)?;
            pc(stdout, &format!("New vault created and encrypted at {:?}", profile.vault_path), Color::Green, true, false, false)?;
            vault_data = initial_plaintext_vault_content;
        }
    } else {
        pc(stdout, &format!("\nSimulating second login for {}. Enter Master Password (again): ", profile.name), Color::Green, false, true, false)?;
        pc(stdout, "\nInvoking app logic: rpassword::read_password()", Color::White, false, false, true)?; // Added \n
        master_password_vec = get_password_input("")?.into_bytes();
        if master_password_vec.is_empty() {
            pc(stdout, &format!("Skipping second login test for {} (password was empty).", profile.name), Color::Yellow, false, false, false)?;
            return Ok(());
        }

        if !vault_exists {
             pc(stdout, &format!("ERROR: Vault for {} unexpectedly not found on second login simulation!", profile.name), Color::Red, true, false, false)?;
             return Err(PasswordManagerError::Other("Vault missing for second login.".to_string()));
        }

        pc(stdout, "\nInvoking app logic: std::fs::read_to_string()", Color::White, false, false, true)?; // Added \n
        let encrypted_vault_json = std::fs::read_to_string(&profile.vault_path)?;
        pc(stdout, "\nInvoking app logic: serde_json::from_str()", Color::White, false, false, true)?; // Added \n
        let encrypted_vault: EncryptedVault = serde_json::from_str(&encrypted_vault_json)?;

        pc(stdout, "\nInvoking password_core::crypto::derive_key_from_password(...)", Color::White, false, false, true)?; // Added \n
        let (master_key, _) = derive_key_from_password(&master_password_vec, Some(&encrypted_vault.salt))?;

        pc(stdout, "\nInvoking password_core::crypto::decrypt(...)", Color::White, false, false, true)?; // Added \n
        match decrypt(&master_key, &encrypted_vault.encrypted_payload, &encrypted_vault.nonce) {
            Ok(decrypted_payload) => {
                vault_data = decrypted_payload;
                pc(stdout, &format!("Vault re-opened and decrypted successfully for {}!", profile.name), Color::Green, true, false, false)?;
            }
            Err(e) => {
                master_password_vec.zeroize();
                pc(stdout, &format!("Failed to re-open vault for {}: {}", profile.name, e), Color::Red, true, false, false)?;
                return Err(e);
            }
        }
    }

    print_vault_contents(stdout, &profile.name, &vault_data)?;

    if profile.id == "manager" {
        pc(stdout, &format!("\nAs {}, you are indeed the Manager. You can create and manage profiles!", profile.name), Color::Magenta, true, false, false)?;
    }

    pc(stdout, "\n--- Quick Verification of Welcome Note ---", Color::Blue, false, false, false)?;
    pc(stdout, "\nInvoking app logic: serde_json::from_slice() and direct content comparison.", Color::White, false, false, true)?; // Added \n
    match serde_json::from_slice::<Value>(&vault_data) {
        Ok(json_value) => {
            if let Some(notes_array) = json_value["notes"].as_array() {
                if let Some(first_note) = notes_array.get(0) {
                    if let Some(note_content) = first_note["content"].as_str() {
                        pc(stdout, &format!("Extracted note content: \"{}\"", note_content), Color::Blue, false, false, false)?;
                        let expected_note_content = "Welcome to the Heikkinen Password Manager";
                        if note_content == expected_note_content {
                            pc(stdout, "\nNote content MATCHES expected value!", Color::Green, true, false, false)?;
                        } else {
                            pc(stdout, "\nNote content DOES NOT MATCH expected value!", Color::Red, true, false, false)?;
                        }
                    } else {
                        pc(stdout, "\n'content' field not found in the first note.", Color::Yellow, false, false, false)?;
                    }
                } else {
                    pc(stdout, "\nNo notes found in the 'notes' array.", Color::Yellow, false, false, false)?;
                }
            } else {
                pc(stdout, "\n'notes' array not found in the vault JSON.", Color::Red, false, false, false)?;
            }
        }
        Err(e) => {
            pc(stdout, &format!("\nError parsing vault content as JSON for {}: {}", profile.name, e), Color::Red, true, false, false)?;
        }
    }
    pc(stdout, "--- End Quick Verification ---", Color::Blue, false, false, false)?;


    master_password_vec.zeroize();
    vault_data.zeroize();

    Ok(())
}


fn main() -> Result<(), PasswordManagerError> {
    env_logger::init();
    let mut stdout = StandardStream::stdout(ColorChoice::Auto);

    pc(&mut stdout, "--- Initializing User Profiles ---", Color::Cyan, true, false, false)?;
    let is_portable = false;
    pc(&mut stdout, "\nInvoking settings_manager::SettingsManager::new(...)", Color::White, false, false, true)?; // Added \n
    let mut settings_manager = SettingsManager::new(is_portable)?;

    let mut settings_config = settings_manager.config.clone();

    pc(&mut stdout, "\nInitial settings (pretty-printed):", Color::Green, false, false, false)?;
    pc(&mut stdout, "\nInvoking app logic: serde_json::to_string_pretty(...)", Color::White, false, false, true)?; // Added \n
    println!("{}", serde_json::to_string_pretty(&settings_config)?);

    let profiles_to_ensure = vec![
        ("jesus", "Jesus", false),
        ("fausto", "Fausto", false),
        ("manager", "Manager", true),
        ("god", "God", false),
    ];

    for (profile_id, display_name, is_admin) in profiles_to_ensure.clone() {
        pc(&mut stdout, "\nInvoking app logic: SettingsManager::get_default_data_dir()", Color::White, false, false, true)?; // Added \n
        let vault_filename = format!("{}_vault.enc", profile_id);
        let user_vault_path = SettingsManager::get_default_data_dir()?.join(vault_filename);

        pc(&mut stdout, "\nInvoking app logic: settings_config.get_profile_by_id()", Color::White, false, false, true)?; // Added \n
        if settings_config.get_profile_by_id(profile_id).is_none() {
            pc(&mut stdout, &format!("\nCreating new profile '{}' for {} with vault path: {:?}", profile_id, display_name, user_vault_path), Color::Yellow, false, false, false)?;
            pc(&mut stdout, "\nInvoking password_core::settings_manager::AppUserProfile::new(...)", Color::White, false, false, true)?; // Added \n
            let new_profile = AppUserProfile::new(
                profile_id.to_string(),
                display_name.to_string(),
                user_vault_path.clone(),
                is_admin,
            );
            pc(&mut stdout, "\nInvoking app logic: settings_config.add_or_update_profile()", Color::White, false, false, true)?; // Added \n
            settings_config.add_or_update_profile(new_profile);
        } else {
            pc(&mut stdout, &format!("\nProfile '{}' for {} already exists. Using its vault path.", profile_id, display_name), Color::Blue, false, false, false)?;
        }
    }

    settings_manager.config = settings_config.clone();
    pc(&mut stdout, "\nInvoking settings_manager::SettingsManager::save()", Color::White, false, false, true)?; // Added \n
    settings_manager.save()?;
    pc(&mut stdout, "\nUpdated settings after profile creation (pretty-printed):", Color::Green, false, false, false)?;
    pc(&mut stdout, "\nInvoking app logic: serde_json::to_string_pretty(...)", Color::White, false, false, true)?; // Added \n
    println!("{}", serde_json::to_string_pretty(&settings_manager.config)?);

    pc(&mut stdout, "--- End User Profile Initialization ---\n", Color::Cyan, true, false, false)?;


    pc(&mut stdout, "\n--- Simulating FIRST-TIME Login for All Profiles ---", Color::Yellow, true, true, false)?;
    for (profile_id, _, _) in profiles_to_ensure.iter() {
        pc(&mut stdout, &format!("\nInvoking app logic: settings_manager.config.get_profile_by_id(\"{}\")", profile_id), Color::White, false, false, true)?; // Added \n
        let profile = settings_manager.config.get_profile_by_id(profile_id)
            .ok_or_else(|| PasswordManagerError::Other(format!("Profile '{}' not found after setup.", profile_id)))?;
        handle_user_login(&mut stdout, profile, &settings_manager, true)?;
    }
    pc(&mut stdout, "\n--- Finished FIRST-TIME Login Simulations ---", Color::Yellow, true, true, false)?;


    pc(&mut stdout, "\n\n--- Simulating SECOND-TIME Login for All Profiles ---", Color::Green, true, true, false)?;
    for (profile_id, _, _) in profiles_to_ensure.iter() {
        pc(&mut stdout, &format!("\nInvoking app logic: settings_manager.config.get_profile_by_id(\"{}\")", profile_id), Color::White, false, false, true)?; // Added \n
        let profile = settings_manager.config.get_profile_by_id(profile_id)
            .ok_or_else(|| PasswordManagerError::Other(format!("Profile '{}' not found for second login.", profile_id)))?;
        handle_user_login(&mut stdout, profile, &settings_manager, false)?;
    }
    pc(&mut stdout, "\n--- Finished SECOND-TIME Login Simulations ---", Color::Green, true, true, false)?;


    pc(&mut stdout, "\n\n--- Demonstrating Failed Decryption (Incorrect Key) ---", Color::Cyan, true, false, false)?;
    pc(&mut stdout, "Enter a *different* master password to test failed decryption: ", Color::White, false, false, false)?;
    pc(&mut stdout, "\nInvoking app logic: rpassword::read_password()", Color::White, false, false, true)?; // Added \n
    let wrong_password_input = get_password_input("")?;
    if wrong_password_input.is_empty() {
        pc(&mut stdout, "Skipping incorrect key test (password was empty).", Color::Yellow, false, false, false)?;
    } else {
        pc(&mut stdout, "\nInvoking app logic: settings_manager.config.get_profile_by_id(\"jesus\")", Color::White, false, false, true)?; // Added \n
        let jesus_profile = settings_manager.config.get_profile_by_id("jesus")
            .ok_or_else(|| PasswordManagerError::Other("Jesus profile not found for decryption test.".to_string()))?;
        let vault_path_for_test = &jesus_profile.vault_path;

        pc(&mut stdout, "Deriving key with wrong password...", Color::White, false, false, false)?;
        pc(&mut stdout, "\nInvoking app logic: std::fs::read_to_string()", Color::White, false, false, true)?; // Added \n
        let encrypted_vault_json = std::fs::read_to_string(vault_path_for_test)?;
        pc(&mut stdout, "\nInvoking app logic: serde_json::from_str()", Color::White, false, false, true)?; // Added \n
        let loaded_vault_for_test: EncryptedVault = serde_json::from_str(&encrypted_vault_json)?;

        pc(&mut stdout, "\nInvoking password_core::crypto::derive_key_from_password(...)", Color::White, false, false, true)?; // Added \n
        let (wrong_key, _) = derive_key_from_password(wrong_password_input.as_bytes(), Some(&loaded_vault_for_test.salt))?;
        pc(&mut stdout, "Attempting decryption with incorrect key...", Color::White, false, false, false)?;
        pc(&mut stdout, "\nInvoking password_core::crypto::decrypt(...)", Color::White, false, false, true)?; // Added \n
        let decryption_result = decrypt(&wrong_key, &loaded_vault_for_test.encrypted_payload, &loaded_vault_for_test.nonce);

        if let Err(e) = decryption_result {
            pc(&mut stdout, &format!("\nDecryption FAILED as expected: {}", e), Color::Green, true, false, false)?;
        } else {
            pc(&mut stdout, "\nERROR: Decryption SUCCEEDED with incorrect key! This is a security flaw!", Color::Red, true, false, false)?;
        }
    }

    Ok(())
}