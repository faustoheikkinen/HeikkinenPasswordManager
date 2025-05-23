import os
import sys

def create_file(path, content):
    """Helper to create a file with given content.
    Handles creation of parent directories if they don't exist.
    """
    dir_name = os.path.dirname(path)
    if dir_name: # Only create directory if path specifies a directory
        os.makedirs(dir_name, exist_ok=True)
    with open(path, 'w') as f:
        f.write(content)
    print(f"  Created: {path}")

def setup_project_in_current_dir():
    print("Setting up password-manager project in the current directory.")

    print("Initializing Git repository...")
    # Check if .git already exists to avoid re-initializing
    if not os.path.exists(".git"):
        os.system("git init")
    else:
        print("  .git directory already exists. Skipping git init.")


    create_file(".tools-version", "rust latest\n")

    create_file(".env.example", """# Example environment variables
# Set this to your master password for automated CLI access (use with caution!)
# Uncomment and set:
# PASSWORD_MANAGER_MASTER_KEY="YourSecureMasterPassword"
""")

    create_file(".gitignore", """# Rust
/target/
/Cargo.lock

# OS-specific files
.DS_Store
Thumbs.db

# IDE-specific files
.idea/
.vscode/

# Sensitive files (local config, temporary vault)
.secret/
*.vault
*.db

# Environment variables
.env
""")

    create_file("Cargo.toml", """[workspace]
members = [
    "crates/password_core",
    "crates/password_storage",
    "crates/password_api",
    ".", # This includes the top-level directory for the binary
]

[package]
name = "password_cli" # Default binary name
version = "0.1.0"
edition = "2021"
publish = false

[dependencies]
# Dependencies for the main CLI application (will be filled later)
password_api = { path = "crates/password_api" }
""")

    print("Creating src directory and main.rs...")
    create_file("src/main.rs", """fn main() {
    println!("Hello from password_cli! This will be our main entry point.");
}
""")

    print("Creating crates directory...")
    # os.makedirs("crates", exist_ok=True) # Redundant due to create_file handling

    # password_core
    create_file("crates/password_core/Cargo.toml", """[package]
name = "password_core"
version = "0.1.0"
edition = "2021"

[dependencies]
# For secure handling of sensitive data in memory
secrecy = "0.8"
zeroize = { version = "1.6", features = ["derive"] }

# For cryptographic operations (AES-GCM, Argon2id)
aes-gcm = { version = "0.10", features = ["aes"] }
argon2 = "0.5"

# For secure random number generation
rand = "0.8"
rand_core = { version = "0.6", features = ["std"] }

# For UUID generation
uuid = { version = "1.8", features = ["v4", "serde"] }

# For date/time handling
chrono = { version = "0.4", features = ["serde"] }

# For robust error handling
thiserror = "1.0"

# For serialization/deserialization
serde = { version = "1.0", features = ["derive"] }
""")
    create_file("crates/password_core/src/lib.rs", "") # Empty file

    # password_storage
    create_file("crates/password_storage/Cargo.toml", """[package]
name = "password_storage"
version = "0.1.0"
edition = "2021"

[dependencies]
password_core = { path = "../password_core" }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
thiserror = "1.0"
anyhow = "1.0"
""")
    create_file("crates/password_storage/src/lib.rs", "") # Empty file

    # password_api
    create_file("crates/password_api/Cargo.toml", """[package]
name = "password_api"
version = "0.1.0"
edition = "2021"

[dependencies]
password_core = { path = "../password_core" }
password_storage = { path = "../password_storage" }
rpassword = "7.0"
clipboard = "0.5"
comfy-table = "7.0"
thiserror = "1.0"
anyhow = "1.0"
clap = { version = "4.5", features = ["derive"] }
once_cell = "1.19"
directories = "5.0"
uuid = { version = "1.8", features = ["v4", "serde"] }
dotenv = "0.15"
inquire = "0.6"
""")
    create_file("crates/password_api/src/lib.rs", "") # Empty file

    print("Creating config directory and default_config.toml...")
    create_file("config/default_config.toml", """# Default configuration settings for the password manager

# Path to the encrypted vault file (relative to .secret folder)
vault_file_name = "vault.encrypted"

# Default password generation options
default_password_length = 16
default_password_include_letters = true
default_password_include_numbers = true
default_password_include_symbols = true
default_password_custom_symbols = "!@#$%%^&*()"
""")

    print("Creating .secret directory placeholder...")
    create_file(".secret/README.md", """# This directory is for user-specific sensitive data (e.g., vault file location, encrypted configs)
# It should be excluded from version control.
""")

    print("\nProject structure created successfully in the current directory!")
    print("\nTo get started:")
    print("1. Run 'cargo build' to compile the workspace.")
    print("2. The CLI application is in 'src/main.rs'.")

if __name__ == "__main__":
    setup_project_in_current_dir()
    input("\nPress Enter to exit...")