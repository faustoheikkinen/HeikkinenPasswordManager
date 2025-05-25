// crates/password_core/src/bin/windows_hello_pin.rs

use windows::core::{HSTRING, Result as WindowsResult}; // Use HSTRING for message box text
use windows::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_OK}; // For MessageBoxW
use windows::Win32::Foundation::HWND; // For window handle

fn main() -> WindowsResult<()> {
    println!("--- Windows API Test (MessageBoxW) ---");
    println!("This will open a simple Windows message box.");

    unsafe {
        let title = HSTRING::from("Hello from Rust!");
        let message = HSTRING::from("Your Rust application is running and can call Windows APIs.");

        // Call the MessageBoxW API
        MessageBoxW(
            Some(HWND::default()), // <--- FIX: Wrap HWND::default() in Some()
            &message,              // Message text
            &title,                // Title text
            MB_OK,                 // Message box type (OK button only)
        );
    }

    println!("\nMessage box displayed. Check your screen!");
    Ok(())
}