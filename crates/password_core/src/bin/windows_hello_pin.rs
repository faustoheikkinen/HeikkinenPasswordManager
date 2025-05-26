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


















// // crates/password_core/src/bin/windows_hello_pin.rs

// // Use raw FFI types from core::ffi and windows_sys
// use core::ffi::{c_void, c_char};
// use windows_sys::Win32::Foundation::{HANDLE, HWND, BOOL, PWSTR, HRESULT}; // BOOL and HRESULT from here
// use windows_sys::Win32::Security::Credentials::{
//     CredFree,
//     CredUIPromptForWindowsCredentialsW,
//     CREDUI_INFOW,
//     // Constants are usually just u32s in windows-sys
//     CREDUI_MAX_USERNAME_LENGTH,
//     CREDUI_MAX_PASSWORD_LENGTH,
//     CREDUIWIN_GENERIC,
//     CREDUIWIN_DO_NOT_PERSIST,
//     // Add other CREDUIWIN_ flags if needed, e.g., CREDUIWIN_CHECKBOX
// };

// // Helper to convert Rust string slices to null-terminated wide (UTF-16) C-style strings
// // This is a common pattern when working with raw Windows APIs.
// fn to_hstring(s: &str) -> Vec<u16> {
//     s.encode_utf16().chain(std::iter::once(0)).collect()
// }

// fn main() -> Result<(), Box<dyn std::error::Error>> { // Use standard Result for simplicity
//     println!("--- Minimal Windows Hello/PIN Authentication Demo (windows-sys) ---");

//     unsafe {
//         let message_text_w = to_hstring("Please enter your PIN.");
//         let caption_text_w = to_hstring("Authentication");

//         let mut ui_info = CREDUI_INFOW {
//             cbSize: std::mem::size_of::<CREDUI_INFOW>() as u32,
//             hwndParent: HWND::default(),
//             pszMessageText: message_text_w.as_ptr(),
//             pszCaptionText: caption_text_w.as_ptr(),
//             hbmBanner: 0, // Default to null handle
//             hbmMessage: 0, // Default to null handle
//             pszBannerText: std::ptr::null(), // Default to null pointer
//         };

//         let mut username_buffer = [0u16; CREDUI_MAX_USERNAME_LENGTH as usize];
//         let mut password_buffer = [0u16; CREDUI_MAX_PASSWORD_LENGTH as usize];

//         let mut auth_package = 0;
//         let mut pdw_flags: u32 = CREDUIWIN_GENERIC | CREDUIWIN_DO_NOT_PERSIST;

//         // Arguments for CredUIPromptForWindowsCredentialsW (windows-sys signature)
//         // puiinfo: *const CREDUI_INFOW
//         // dwAuthError: u32
//         // pulAuthPackage: *mut u32
//         // pszTargetName: PWSTR (can be null for generic)
//         // pszUserName: PWSTR (output buffer for username)
//         // pszPassword: PWSTR (output buffer for password)
//         // fSave: BOOL
//         // pfSave: *mut BOOL (pointer to BOOL for save checkbox state)
//         // pdwFlags: *mut u32

//         let raw_hresult = CredUIPromptForWindowsCredentialsW(
//             &ui_info as *const CREDUI_INFOW, // Pass raw pointer
//             0,                               // dwAuthError
//             &mut auth_package,               // pulAuthPackage
//             std::ptr::null_mut(),            // pszTargetName (null PWSTR)
//             username_buffer.as_mut_ptr(),    // pszUserName (raw *mut u16)
//             password_buffer.as_mut_ptr(),    // pszPassword (raw *mut u16)
//             BOOL::from(false),               // fSave (BOOL from windows_sys)
//             std::ptr::null_mut(),            // pfSave (null *mut BOOL)
//             &mut pdw_flags,                  // pdwFlags
//         );

//         if raw_hresult == 0 { // ERROR_SUCCESS is 0
//             println!("\nAuthentication successful!");
//             let username = String::from_utf16_lossy(&username_buffer[..]);
//             println!("Authenticated User: '{}'", username.trim_end_matches('\0')); // Trim null terminator
//             // Clear sensitive data
//             password_buffer.fill(0);
//         } else {
//             eprintln!("\nAuthentication failed or cancelled. HRESULT: 0x{:X}", raw_hresult);
//             // Common HRESULT for cancellation: 0x800704C7 (ERROR_CANCELLED)
//         }
//     }

//     Ok(())
// }