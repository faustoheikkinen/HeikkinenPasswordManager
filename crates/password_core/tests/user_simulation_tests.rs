// crates/password_core/tests/user_simulation_tests.rs

use password_core::crypto::{
    derive_key_from_password, encrypt, decrypt, EncryptionKey
};
use password_core::data_types::{
    PasswordEntry, PasswordBytes, CredentialType, EncryptedVault
};
use password_core::error::PasswordManagerError;

// use serde_json;
use colored::*;

// --- Helper Functions to Simulate Vault Operations ---

/// Simulates starting the app for the first time with a master password.
/// Returns the initial EncryptedVault, the derived EncryptionKey, and the salt.
fn simulate_initial_vault_setup(
    master_password: &str,
) -> Result<(EncryptedVault, EncryptionKey, Vec<u8>), PasswordManagerError> {
    println!("\n{}", "--- Simulating: Initial Vault Setup ---".magenta());
    println!("{}", "Action: User provides a master password.".blue());
    println!("    {}", "Invoking app function: derive_key_from_password(...)".white().dimmed());
    let (key, salt_original) = derive_key_from_password(master_password.as_bytes(), None)?;
    let salt_to_return = salt_original.clone();

    println!("{}", "Action: Generating encryption key and encrypting an empty vault payload.".green());
    println!("    {}", "Invoking app function: encrypt(...) (empty payload)".white().dimmed());
    let (encrypted_payload, nonce) = encrypt(&key, &serde_json::to_vec(&Vec::<PasswordEntry>::new()).unwrap())?;

    let vault = EncryptedVault {
        salt: salt_original,
        encrypted_payload,
        nonce,
        vault_version: 1,
    };
    println!("{}", format!("Result: New encrypted vault created. Vault payload size: {} bytes.", vault.encrypted_payload.len()).green());
    Ok((vault, key, salt_to_return))
}

/// Simulates loading the vault content (decrypting the payload).
/// Returns a vector of PasswordEntry.
fn simulate_load_vault(
    encrypted_vault: &EncryptedVault,
    key: &EncryptionKey,
) -> Result<Vec<PasswordEntry>, PasswordManagerError> {
    println!("{}", "Action: Attempting to load (decrypt) the vault content.".green());
    println!("    {}", "Invoking app function: decrypt(...)".white().dimmed());
    let decrypted_bytes = decrypt(key, &encrypted_vault.encrypted_payload, &encrypted_vault.nonce)?;
    println!("    {}", "Invoking app function: serde_json::from_slice(...)".white().dimmed());
    let entries: Vec<PasswordEntry> = serde_json::from_slice(&decrypted_bytes)
        .map_err(|e| PasswordManagerError::InvalidVaultData(e.to_string()))?;
    println!("{}", format!("Result: Vault decrypted. Found {} entries.", entries.len()).green());
    Ok(entries)
}

/// Simulates saving the vault content (encrypting the vector of PasswordEntry).
/// Returns a new EncryptedVault.
fn simulate_save_vault(
    entries: Vec<PasswordEntry>,
    key: &EncryptionKey,
    salt: &[u8],
) -> Result<EncryptedVault, PasswordManagerError> {
    println!("{}", format!("Action: Encrypting {} entries to save the vault.", entries.len()).green());
    println!("    {}", "Invoking app function: serde_json::to_vec(...)".white().dimmed());
    let serialized_entries = serde_json::to_vec(&entries)
        .map_err(|e| PasswordManagerError::InvalidVaultData(e.to_string()))?;
    println!("    {}", "Invoking app function: encrypt(...) (with entries)".white().dimmed());
    let (encrypted_payload, nonce) = encrypt(key, &serialized_entries)?;

    let new_vault = EncryptedVault {
        salt: salt.to_vec(),
        encrypted_payload,
        nonce,
        vault_version: 1,
    };
    println!("{}", format!("Result: Vault re-encrypted. New payload size: {} bytes.", new_vault.encrypted_payload.len()).green());
    Ok(new_vault)
}

/// Simulates adding a new password entry and updating the vault.
/// Returns the updated EncryptedVault.
#[allow(clippy::too_many_arguments)]
fn simulate_add_password_entry(
    current_vault: &EncryptedVault,
    key: &EncryptionKey,
    salt: &[u8],
    name: String,
    url: Option<String>,
    username: Option<String>,
    password: &str,
    notes: Option<String>,
    credential_type: CredentialType,
) -> Result<EncryptedVault, PasswordManagerError> {
    println!("\n{}", "--- Simulating: Adding a New Password Entry ---".magenta());
    println!("{}", "Action: Loading current vault to add a new entry.".green());
    // Calls simulate_load_vault, which has its own logging for app functions
    let mut entries = simulate_load_vault(current_vault, key)?;

    println!("    {}", "Invoking app function: PasswordEntry::new(...)".white().dimmed());
    let initial_password_bytes = PasswordBytes(password.as_bytes().to_vec());
    let mut new_entry = PasswordEntry::new(name, Some(initial_password_bytes));
    new_entry.url = url.clone();
    new_entry.username = username.clone();
    new_entry.notes = notes.clone();
    new_entry.credential_type = credential_type.clone();

    println!("{}", format!("Details: Adding entry for Name: \"{}\", Username: {}, URL: {}, Notes: {}",
             new_entry.name.yellow(),
             format!("{:?}", new_entry.username).yellow(),
             format!("{:?}", new_entry.url).yellow(),
             format!("{:?}", new_entry.notes).yellow()).yellow());

    entries.push(new_entry);

    println!("{}", "Action: Saving the vault with the new entry.".green());
    // Calls simulate_save_vault, which has its own logging for app functions
    simulate_save_vault(entries, key, salt)
}

/// Simulates searching for entries.
/// Returns a vector of references to matching PasswordEntry objects.
fn simulate_search_entries<'a>(
    entries: &'a [PasswordEntry],
    search_term: &str,
    note_filter: Option<&str>,
) -> Vec<&'a PasswordEntry> {
    println!("\n{}", "--- Simulating: Searching for Entries ---".magenta());
    let search_term_lower = search_term.to_lowercase();
    let note_filter_lower = note_filter.map(|s| s.to_lowercase());


    println!("{}", format!("Action: Searching vault for term \"{}\". Note filter: {}", search_term.yellow(), format!("{:?}", note_filter).yellow()).blue());
    println!("    {}", "Invoking app logic: filtering PasswordEntry fields".white().dimmed());

    let results: Vec<&'a PasswordEntry> = entries.iter().filter(|entry| {
        let name_match        = entry.name.to_lowercase().contains(&search_term_lower);
        // Simplified using is_some_and
        let url_match         = entry.url.as_ref()
                                .is_some_and(|u| u.to_lowercase().contains(&search_term_lower));
        // Simplified using is_some_and
        let username_match    = entry.username.as_ref()
                                .is_some_and(|u| u.to_lowercase().contains(&search_term_lower));
        // Simplified using is_some_and
        let notes_match       = entry.notes.as_ref()
                                .is_some_and(|n| n.to_lowercase().contains(&search_term_lower));

        let main_match        = name_match || url_match || username_match || notes_match;

        if let Some(nf_lower) = &note_filter_lower {
            // Simplified using is_some_and
            entry.notes.as_ref().is_some_and(|n| n.to_lowercase().contains(nf_lower)) && main_match
        } else {
            main_match
        }
    }).collect();

    println!("{}", format!("Result: Found {} matching entries.", results.len()).green());
    for (i, entry) in results.iter().enumerate() {
        println!("  {}", format!("Match {}: Name: \"{}\", Username: {}, URL: {}, Notes: {}",
                 i + 1, entry.name.yellow(), format!("{:?}", entry.username).yellow(), format!("{:?}", entry.url).yellow(), format!("{:?}", entry.notes).yellow()).yellow());
    }
    results
}


// --- User Case Simulation Test ---

#[test]
fn user_case_first_time_setup_and_record_management() -> Result<(), PasswordManagerError> {
    println!("\n{}", "==================================================".bright_blue());
    println!("{}", "Starting User Simulation Test: First Time Setup and Record Management".bright_green());
    println!("{}", "==================================================\n".bright_blue());

    let master_password = "MySuperSecretMasterPassword123!";




    // 1. User starts app and enters master password for the first time
    println!("{}", "Scenario Step 1: User opens the application for the first time.".cyan());
    println!("{}", "Simulating: User provides a master password for initial vault setup.".blue());

    let (mut current_encrypted_vault, key, salt) = simulate_initial_vault_setup(master_password)?;

    println!("{}", "User Action: Vault setup complete.".blue());

    println!("\n{}", "Verification: Attempting to load the vault to ensure it's empty.".cyan());
    let entries_after_init = simulate_load_vault(&current_encrypted_vault, &key)?;
    assert!(entries_after_init.is_empty(), "Vault should be empty initially");
    println!("{}", "Assertion Passed: Vault is empty as expected after initial setup.".bright_green());




    // 2. User creates a record for gmail.com
    println!("\n{}", "Scenario Step 2: User decides to add their first password entry.".cyan());
    current_encrypted_vault = simulate_add_password_entry(
                                                &current_encrypted_vault,
                                                &key,
                                                &salt,
                                                "Gmail Personal".to_string(),
                                                Some("gmail.com".to_string()),
                                                Some("fausto@gmail.com".to_string()),
                                                "password12345",
                                                Some("I love my email.".to_string()),
                                                CredentialType::Website,
    )?;
    println!("{}", "User Action: Gmail Personal entry added.".blue());

    println!("\n{}", "Verification: Loading vault to confirm the new entry was saved.".cyan());

    let entries_after_first = simulate_load_vault(&current_encrypted_vault, &key)?;


    assert_eq!(entries_after_first.len(), 1, "Should have 1 entry after adding Gmail");
    println!("{}", format!("Assertion Passed: Vault now contains {} entry.", entries_after_first.len()).bright_green());
    println!("{}", format!("Entry details: Name: \"{}\", Username: {}, URL: {}",
             entries_after_first[0].name.yellow(), 
             format!("{:?}", 
             entries_after_first[0].username).yellow(), 
             format!("{:?}", 
             entries_after_first[0].url).yellow()).yellow());
    println!("    {}", "Invoking app function: PasswordEntry::get_current_password()".white().dimmed());
    assert_eq!(entries_after_first[0].get_current_password().unwrap().0, b"password12345".to_vec());
    println!("{}", "Assertion Passed: Entry details match expected values.".bright_green());




    // 3. User adds 5 more emails
    println!("\n{}", "Scenario Step 3: User adds five more email-related password entries.".cyan());
    current_encrypted_vault = simulate_add_password_entry(
        &current_encrypted_vault, &key, &salt,
        "Outlook Work".to_string(), 
        Some("outlook.com".to_string()), 
        Some("fausto.work@outlook.com".to_string()),
        "workpass1", 
        Some("Important work stuff.".to_string()), 
        CredentialType::Website,
    )?;
    current_encrypted_vault = simulate_add_password_entry(
        &current_encrypted_vault, &key, &salt,
        "Yahoo Mail".to_string(), 
        Some("yahoo.com".to_string()), 
        Some("fausto.yahoo@yahoo.com".to_string()),
        "yahoopass", 
        None, 
        CredentialType::Website,
    )?;
    current_encrypted_vault = simulate_add_password_entry(
        &current_encrypted_vault, &key, &salt,
        "ProtonMail Personal".to_string(), 
        Some("protonmail.com".to_string()), 
        Some("fausto@protonmail.com".to_string()),
        "protonpass", 
        Some("Secure emails.".to_string()), 
        CredentialType::Website,
    )?;
    current_encrypted_vault = simulate_add_password_entry(
        &current_encrypted_vault, &key, &salt,
        "Another Gmail".to_string(), 
        Some("gmail.com".to_string()), 
        Some("mybackup@gmail.com".to_string()),
        "backupGMail", 
        Some("Backup account.".to_string()), 
        CredentialType::Website,
    )?;
    current_encrypted_vault = simulate_add_password_entry(
        &current_encrypted_vault, &key, &salt,
        "Work Gmail".to_string(), 
        Some("gmail.com".to_string()), 
        Some("work@gmail.com".to_string()),
        "workGMail", 
        Some("Client emails.".to_string()), 
        CredentialType::Website,
    )?;
    println!("{}", "User Action: All 5 additional records added.".blue());
    println!("\n{}", "Verification: Loading vault to confirm total number of entries.".cyan());

    let all_entries = simulate_load_vault(&current_encrypted_vault, &key)?;

    assert_eq!(all_entries.len(), 6, "Should have 6 entries in total");
    println!("{}", "Assertion Passed: Vault now contains {} entries in total.".bright_green());




    // 4. User searches for the first email by typing only "@Gmail"
    println!("\n{}", "Scenario Step 4: User wants to find their Gmail accounts.".cyan());

    let search_results_gmail = simulate_search_entries(&all_entries, "@gmail", None);


    assert!(search_results_gmail.len() > 1, "Should find more than one Gmail entry");
    println!("{}", "Assertion Passed: Multiple entries matching '@gmail' were found.".bright_green());

    println!("\n{}", "Verification: Checking usernames of found Gmail entries.".cyan());

    let found_usernames: Vec<String> = search_results_gmail.iter()
        .filter_map(|e| e.username.clone())
        .collect();

    assert!(found_usernames.contains(&"fausto@gmail.com".to_string()));
    assert!(found_usernames.contains(&"mybackup@gmail.com".to_string()));
    assert!(found_usernames.contains(&"work@gmail.com".to_string()));
    println!("{}", "Assertion Passed: All expected Gmail usernames are in the search results.".bright_green());




    // 5. User types an extra "note" filter to narrow the search
    println!("\n{}", "Scenario Step 5: User realizes they have many Gmail entries and refines the search.".cyan());
    println!("{}", "User Action: Adding a note filter 'I love my email' to the search for '@gmail'.".blue());

    let narrow_results = simulate_search_entries(&all_entries, 
                                                "@gmail", 
                                                Some("I love my email"));

    assert_eq!(narrow_results.len(), 1, "Should narrow down to exactly one record");
    println!("{}", "Assertion Passed: Search successfully narrowed down to exactly one entry.".bright_green());

    let final_record = narrow_results[0];
    println!("{}", format!("Result: The specific entry found is Name: \"{}\", Username: {}, Notes: {}",
             final_record.name.yellow(), format!("{:?}", final_record.username).yellow(), format!("{:?}", final_record.notes).yellow()).yellow());
    assert_eq!(final_record.username, Some("fausto@gmail.com".to_string()));
    assert_eq!(final_record.notes, Some("I love my email.".to_string()));
    println!("{}", "Assertion Passed: The found entry matches the expected 'Gmail Personal' details.".bright_green());





    // 6. User should have the password copied to the clipboard (simulated)
    println!("\n{}", "Scenario Step 6: User clicks to copy the password for the selected entry.".cyan());
    println!("    {}", "Invoking app function: PasswordEntry::get_current_password()".white().dimmed());

    let password_to_copy = final_record.get_current_password().expect("Should have a password to copy");

    // println!("{}", format!("Simulated Result: Password for \"{}\" copied to clipboard. (Value: {})", final_record.name.yellow(), format!("{:?}", password_to_copy.0).yellow()).green());
    println!("{}", format!("Simulated Result: Password for \"{}\" copied to clipboard. (Value: {})", final_record.name.yellow(), String::from_utf8_lossy(&password_to_copy.0)).yellow().green());
    assert_eq!(password_to_copy.0, b"password12345".to_vec());




    // 7. User will paste the content to a file and be happy (simulated by test passing)
    println!("\n{}", "Scenario Step 7: User pastes the password and completes their task.".cyan());
    println!("{}", "User is happy. Test passed!".bright_green());
    println!("\n{}", "==================================================".bright_blue());
    println!("{}", "User Simulation Test Finished Successfully!".bright_green());
    println!("{}", "==================================================\n".bright_blue());

    Ok(())
}