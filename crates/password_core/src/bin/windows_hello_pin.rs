// // crates/password_core/src/bin/windows_hello_pin.rs

// use windows::core::{HSTRING, Result as WindowsResult}; // Use HSTRING for message box text
// use windows::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_OK}; // For MessageBoxW
// use windows::Win32::Foundation::HWND; // For window handle

// fn main() -> WindowsResult<()> {
//     println!("--- Windows API Test (MessageBoxW) ---");
//     println!("This will open a simple Windows message box.");

//     unsafe {
//         let title = HSTRING::from("Hello from Rust!");
//         let message = HSTRING::from("Your Rust application is running and can call Windows APIs.");

//         // Call the MessageBoxW API
//         MessageBoxW(
//             Some(HWND::default()), // <--- FIX: Wrap HWND::default() in Some()
//             &message,              // Message text
//             &title,                // Title text
//             MB_OK,                 // Message box type (OK button only)
//         );
//     }

//     println!("\nMessage box displayed. Check your screen!");
//     Ok(())
// }

use windows::core::{Result, HSTRING};
use windows::Security::Credentials::UI::{UserConsentVerificationResult, UserConsentVerifier};

#[tokio::main]
async fn main() -> Result<()> {
    println!("Attempting to verify user consent (Windows Hello)...");

    let message = HSTRING::from("Please verify your identity to continue.");

    let operation = UserConsentVerifier::RequestVerificationAsync(&message)?;

    // Instead of .await or .into_future(), use get() — blocks until complete
    let result = operation.get()?; // This is a synchronous wait

    match result {
        UserConsentVerificationResult::Verified => {
            println!("User successfully verified!");
        }
        UserConsentVerificationResult::Canceled => {
            println!("User canceled the verification.");
        }
        UserConsentVerificationResult::RetriesExhausted => {
            println!("Too many failed attempts. Verification failed.");
        }
        UserConsentVerificationResult::DeviceNotPresent => {
            println!("No Windows Hello device found (e.g., fingerprint reader, camera).");
        }
        UserConsentVerificationResult::NotConfiguredForUser => {
            println!("Windows Hello is not configured for this user.");
        }
        UserConsentVerificationResult::DisabledByPolicy => {
            println!("Windows Hello is disabled by system policy.");
        }
        _ => {
            println!("Unknown or unhandled verification result: {:?}", result);
        }
    }

    Ok(())
}
