// crates/password_core/src/printer.rs

use colored::{Colorize, CustomColor};
use once_cell::sync::Lazy; // Import Lazy

// Define custom colors for better readability using Lazy initialization
static DIM_GRAY: Lazy<CustomColor> = Lazy::new(|| CustomColor::new(100, 100, 100));
static BRIGHT_CYAN: Lazy<CustomColor> = Lazy::new(|| CustomColor::new(0, 255, 255));
static LIGHT_GREEN: Lazy<CustomColor> = Lazy::new(|| CustomColor::new(144, 238, 144));
static LIGHT_RED: Lazy<CustomColor> = Lazy::new(|| CustomColor::new(255, 100, 100));

/// Prints a message in bright cyan.
pub fn print_info(message: &str) {
    println!("{}", message.custom_color(*BRIGHT_CYAN)); // Dereference Lazy
}

/// Prints a message in light green.
pub fn print_success(message: &str) {
    println!("{}", message.custom_color(*LIGHT_GREEN)); // Dereference Lazy
}

/// Prints a message in light red.
pub fn print_error(message: &str) {
    eprintln!("{}", message.custom_color(*LIGHT_RED)); // Dereference Lazy
}

/// Prints a dimmed message, typically for less important information.
pub fn print_dimmed(message: &str) {
    println!("{}", message.custom_color(*DIM_GRAY)); // Dereference Lazy
}

/// Prints a section header in bold white.
pub fn print_header(title: &str) {
    println!("{}", format!("\n--- {} ---", title).white().bold());
}

/// Prints a sub-scenario header in bold yellow.
pub fn print_scenario_header(title: &str) {
    println!("{}", format!("\n*** {} ***", title).yellow().bold());
}

/// Prints a simulated code call in dim gray, prefixed with "Calling: ".
pub fn print_code_call(code_snippet: &str) {
    println!("{}", format!("  Calling: {}", code_snippet).custom_color(*DIM_GRAY)); // Dereference Lazy
}

/// Prints a simulated code call result in dim gray, prefixed with "  Result: ".
/// This function now expects the `result_message` to be already formatted.
pub fn print_code_result(result_message: &str) {
    println!("{}", format!("  Result: {}", result_message).custom_color(*DIM_GRAY)); // Dereference Lazy
}