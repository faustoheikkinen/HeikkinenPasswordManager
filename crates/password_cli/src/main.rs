// Add this at the top of main.rs in password_cli
use base64::engine::Engine as _; // Import the trait for the encode method
use base64::engine::general_purpose::STANDARD; // Import the standard engineuse std::io::{self, Write};
use std::io::{self, Write}; // <-- This was the merged line. Now it's properly separated.

// Import the specific items directly from password_core::crypto
use password_core::crypto::{derive_key_from_password, encrypt, decrypt};
// Now you can import the re-exported constants directly from password_core
use password_core::{SALT_LEN, NONCE_LEN};


fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("--- Simple Password Core Demo ---");

    // --- 1. Get Master Password ---
    let master_password = get_password_input("Enter your master password (for demonstration): ")?;
    if master_password.is_empty() {
        println!("Master password cannot be empty. Exiting.");
        return Ok(());
    }

    // --- 2. Derive Key and generate/get Salt ---
    println!("\nDeriving encryption key...");
    // In a real app, salt would be loaded from a vault file if it exists.
    // For this demo, we'll always generate a new salt.
    let (encryption_key, salt_bytes) = derive_key_from_password(master_password.as_bytes(), None)?;
    println!("Key derived successfully. Generated new salt ({} bytes).", salt_bytes.len());
    // In a real app, you would save this salt along with your encrypted data.

    // --- 3. Get Plaintext Data ---
    let plaintext_input = get_input("Enter some data to encrypt: ")?;
    if plaintext_input.is_empty() {
        println!("No data to encrypt. Exiting.");
        return Ok(());
    }
    let plaintext_bytes = plaintext_input.as_bytes();

    // --- 4. Encrypt Data ---
    println!("\nEncrypting data...");
    let (ciphertext, nonce) = encrypt(&encryption_key, plaintext_bytes)?;
    println!("Data encrypted successfully!");
    println!("Ciphertext (Base64): {}", STANDARD.encode(&ciphertext)); // Updated base64 usage
    println!("Nonce (Base64):      {}", STANDARD.encode(&nonce));     // Updated base64 usage

    // --- 5. Decrypt Data ---
    println!("\nAttempting to decrypt data...");
    // For decryption, we use the same key and the nonce that was returned from encryption.
    let decrypted_bytes = decrypt(&encryption_key, &ciphertext, &nonce)?;
    let decrypted_string = String::from_utf8(decrypted_bytes)?;
    println!("Data decrypted successfully!");
    println!("Decrypted text: {}", decrypted_string);

    // --- 6. Demonstrate Failed Decryption (Incorrect Key) ---
    println!("\n--- Demonstrating Failed Decryption ---");
    let wrong_password = get_password_input("Enter a *different* master password to test failed decryption: ")?;
    if wrong_password.is_empty() || wrong_password == master_password {
        println!("Skipping incorrect key test (password was empty or same).");
    } else {
        println!("Deriving key with wrong password...");
        // Use the *original* salt to derive a key from the wrong password
        // This simulates trying to open a vault with the wrong password
        let (wrong_key, _) = derive_key_from_password(wrong_password.as_bytes(), Some(&salt_bytes))?;
        println!("Attempting decryption with incorrect key...");
        let decryption_result = decrypt(&wrong_key, &ciphertext, &nonce);
        if let Err(e) = decryption_result {
            println!("Decryption FAILED as expected: {}", e);
        } else {
            println!("ERROR: Decryption SUCCEEDED with incorrect key! This is a security flaw!");
        }
    }

    Ok(())
}

fn get_input(prompt: &str) -> io::Result<String> {
    print!("{}", prompt);
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}

fn get_password_input(prompt: &str) -> io::Result<String> {
    print!("{}", prompt);
    io::stdout().flush()?;
    let mut input = String::new();
    // Using `rpassword` crate for hidden input would be better for a real app,
    // but for this demo, plain read_line is fine.
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}