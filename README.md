# Heikkinen Password Manager

Tired of insecure password management? **Heikkinen Password Manager** offers a robust and highly secure solution, crafted entirely in **Rust**. This project prioritizes **security and reliability**, implementing state-of-the-art cryptographic practices to safeguard your sensitive data.

At its core, Heikkinen Password Manager leverages cutting-edge techniques like **Argon2id** for secure password-based key derivation and **ChaCha20Poly1305** for robust, authenticated data encryption. This ensures your credentials are protected against modern threats and brute-force attacks, even when public cryptographic parameters are known.

Built with a **modular, crate-based architecture**, the project is designed for extensibility, testability, and long-term reliability. It comprises key components such as `password_core` for cryptographic primitives, `password_cli` for a powerful command-line interface, and upcoming `password_storage` for secure persistence, with future plans for a `password_api` to enable broader integration. Heikkinen Password Manager is evolving into a comprehensive and trustworthy solution for all your credential management needs.

---

## Table of Contents

1.  [Features](#features)
2.  [Architecture](#architecture)
3.  [Security Deep Dive](#security-deep-dive)
    * [Master Password & Key Derivation](#master-password--key-derivation)
    * [Encryption & Authentication](#encryption--authentication)
    * [Why Public Parameters Aren't a Flaw](#why-public-parameters-arent-a-flaw)
    * [Threat Model](#threat-model)
4.  [Getting Started](#getting-started)
    * [Prerequisites](#prerequisites)
    * [Building the Project](#building-the-project)
    * [Running Tests](#running-tests)
5.  [Usage (CLI)](#usage-cli)
6.  [Project Structure](#project-structure)
7.  [Future Plans / Roadmap](#future-plans--roadmap)
8.  [Contributing](#contributing)
9.  [License](#license)

---

## 1. Features

Heikkinen Password Manager aims to provide a full-fledged, secure password management experience. Key features include:

* **Robust Cryptography:** Utilizes industry-standard algorithms like **Argon2id** for key derivation and **ChaCha20Poly1305** for authenticated encryption, ensuring high-grade security.
* **Modular Design:** Built as a Rust workspace with distinct crates for core logic, CLI, storage, and API, promoting maintainability and extensibility.
* **Cross-Platform Compatibility:** As a Rust application, it is designed to compile and run on various operating systems.
* **Command-Line Interface (CLI):** A powerful text-based interface for managing passwords and vaults (currently basic, but expanding).
* **Secure Storage (Upcoming):** Persistent, encrypted storage of your password vaults on disk.
* **Extensible API (Planned):** A programmatic interface to allow integration with other applications or future UI developments.
* **Comprehensive Testing:** Dedicated unit and integration tests to ensure cryptographic correctness and application reliability.

## 2. Architecture

The Heikkinen Password Manager is structured as a Rust workspace, composed of several crates (individual Rust packages) that handle distinct responsibilities. This modular approach enhances maintainability, testability, and allows for independent development and potential reuse of components.

* **`password_core`**:
    * **Role:** The foundational cryptographic library. It contains the core logic for key derivation, encryption, decryption, and vault representation. This crate is designed to be highly secure and rigorously tested, with no external dependencies on file I/O or user interaction.
    * **Key Components:** `EncryptedVault` struct, `MasterKey` management, `crypto.rs` for Argon2id and ChaCha20Poly1305 operations.

* **`password_cli`**:
    * **Role:** The command-line interface application. This binary crate utilizes `password_core` to perform cryptographic operations based on user commands. It handles user input and output.
    * **Current State:** A basic setup capable of interacting with `password_core` (e.g., demonstrating key derivation and encryption principles).

* **`password_storage` (Upcoming)**:
    * **Role:** Will handle the secure reading from and writing to disk of the encrypted vault. It will manage the file format and interaction with the file system.
    * **Dependencies:** Will rely on `password_core` for encryption/decryption of the vault data itself.

* **`password_api` (Planned)**:
    * **Role:** A future crate designed to provide a programmatic interface (e.g., a REST API or gRPC service) to interact with the password manager, enabling integration with desktop UIs, web interfaces, or other applications.
    * **Dependencies:** Will build upon `password_core` and `password_storage`.

---

## 3. Security Deep Dive

The security of your sensitive data is the paramount concern for Heikkinen Password Manager. Our design adheres to modern cryptographic best practices.

### Master Password & Key Derivation

Your master password is the sole secret you need to remember. It is never stored directly. Instead, it's used in conjunction with a robust Key Derivation Function (KDF):

* **Argon2id (KDF):** This is the industry-recommended algorithm for deriving cryptographic keys from passwords. Argon2id is specifically designed to be resistant to various attacks, including brute-force, dictionary, side-channel, and GPU-based attacks.
* **Unique Salt:** When your vault is created, a unique, cryptographically random salt is generated. This salt is *not a secret* and is stored unencrypted within the vault file. Its purpose is to ensure that even if two users choose the exact same master password, their derived encryption keys will be entirely different, defeating rainbow tables and pre-computation attacks.
* **Computational Cost:** Argon2id is configured to be intentionally slow and memory-intensive. This "slowness" is a critical security feature, making it computationally infeasible for an attacker to rapidly guess master passwords, even if they possess the encrypted vault file and all public parameters.

### Encryption & Authentication

Once the robust encryption key is derived, it's used to protect your vault data:

* **ChaCha20Poly1305 (Authenticated Encryption):** This is a modern, fast, and secure authenticated encryption with associated data (AEAD) cipher. It encrypts your vault's contents while simultaneously providing an authentication tag to ensure data integrity and authenticity.
* **Nonce (Number Used Once):** For each encryption operation, a unique nonce is generated. Like the salt, the nonce is *not a secret* and is stored unencrypted alongside the ciphertext in the vault file. Its purpose is to ensure that encrypting the exact same data multiple times with the same key results in different ciphertexts, preventing pattern recognition and replay attacks.
* **Single Layer of Encryption:** The entire vault content is encrypted as a single blob using the derived key and the nonce. There are no nested layers of encryption; the public parameters (salt, nonce, KDF settings) reside outside this encrypted blob.

### Why Public Parameters Aren't a Flaw

It's natural to wonder if storing the salt, nonce, and KDF parameters unencrypted within the vault file poses a risk. This design is standard and secure for the following reasons:

* **Not Secrets:** These parameters are not intended to be secrets themselves. Their role is to provide essential, non-confidential inputs to the key derivation and encryption processes.
* **Master Password is the Sole Secret:** The entire security model hinges on the secrecy and strength of your master password.
* **Computational Barrier:** As thoroughly discussed (refer to **TIME-POINT: 2025-05-23_16:11_EncryptionProcessClarification**), even with full knowledge of the salt, nonce, and KDF parameters, an attacker *cannot* use a generic rainbow table. They are forced into a targeted brute-force attack on your master password. Argon2id's design makes this process astronomically time-consuming and resource-intensive, rendering it practically impossible to break a strong master password within any realistic timeframe.

### Threat Model

Heikkinen Password Manager is designed to protect against:

* **Offline Brute-Force/Dictionary Attacks:** Even if an attacker steals your encrypted vault file.
* **Rainbow Table Attacks:** Due to the unique salt.
* **Data Tampering:** The authentication tag (Poly1305) ensures that any modification to the encrypted data is detected.
* **Information Leakage from Repeated Data:** The nonce prevents patterns from revealing information.

It does **not** protect against:

* **Keyloggers:** If your master password is captured as you type it.
* **Malware:** If your system is compromised, allowing an attacker to read your vault in its decrypted state after you unlock it.
* **Weak Master Passwords:** The strength of the encryption heavily relies on the strength of your chosen master password.

---

## 4. Getting Started

To build and run the Heikkinen Password Manager, you'll need to have Rust installed.

### Prerequisites

* **Rust:** Install Rust via `rustup` by following the instructions on [rust-lang.org](https://www.rust-lang.org/tools/install).

### Building the Project

Navigate to the root directory of the project (where `Cargo.toml` for the workspace is located) and run:

    cargo build --release

The `--release` flag optimizes the binaries for performance, which is important for cryptographic operations.

### Running Tests

To ensure everything is functioning correctly, you can run the test suite:

    cargo test

This will run all unit and integration tests across all crates in the workspace.

---

## 5. Usage (CLI)

The `password_cli` crate provides the command-line interface. Once built, you can run it from the target directory.

*(Note: Specific commands for creating vaults, adding passwords, etc., will be detailed here as the `password_cli` functionality is expanded.)*

**Basic Example (Conceptual):**

    # To be implemented:
    # cargo run --bin password_cli -- create-vault my_first_vault
    # cargo run --bin password_cli -- add-password my_first_vault --name "GitHub" --username "myuser"
    # cargo run --bin password_cli -- get-password my_first_vault --name "GitHub"

---

## 6. Project Structure

The repository is a Rust workspace with the following key crates:

    heikkinen-password-manager/
    ├── Cargo.toml          # Workspace manifest
    ├── password_core/      # Core cryptographic library
    │   └── src/
    │       ├── lib.rs
    │       ├── crypto.rs   # Cryptographic functions
    │       └── vault.rs    # Vault data structures
    ├── password_cli/       # Command-line interface application
    │   └── src/
    │       └── main.rs
    ├── tests/              # Integration tests for the workspace (optional, or specific crate tests)
    └── README.md           # This file

---

## 7. Future Plans / Roadmap

The Heikkinen Password Manager is actively being developed. Key upcoming features include:

* **Secure Persistent Storage:** Implementation of `password_storage` to handle encrypted vault files on disk.
* **Expanded CLI Commands:** Full set of commands for vault management (create, open, add, get, update, delete credentials).
* **Configuration Management:** Handling settings and preferences.
* **API Development:** Creation of `password_api` for programmatic access.
* **Cross-Platform UI (Long-term):** Potential development of a graphical user interface.

---

## 8. Contributing

Contributions are welcome! If you'd like to contribute, please feel free to open issues or submit pull requests.

---

## 9. License

This project is licensed under the [MIT License](LICENSE.md).