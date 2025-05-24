# Password Manager Storage, Multi-User, and Authentication Requirements

This document outlines the core requirements for managing vault files, user profiles, and authentication methods. It focuses on balancing security, flexibility, and user convenience across different operating modes.

---

## 1. Vault File Management & Protection

The central vault file (`.vault` extension) must be robustly managed to prevent data loss and ensure integrity.

* **1.1 Data Encryption:** The entire vault file must be encrypted using strong, industry-standard **symmetric encryption** (e.g., AES-256). The encryption key will be derived from the user's **Master Password** via a **Key Derivation Function (KDF)** like PBKDF2 or Argon2.
* **1.2 Backup on Open:** Before opening any vault file, a temporary backup copy of the existing vault must be created. This copy will be stored in a designated secure location (e.g., a subfolder within the user's application data directory or a temporary system location). This backup serves as a rollback point in case of corruption during the open operation.
* **1.3 Transactional Save with Backup Rotation:**
    * When saving changes to a vault file, the app will first write the changes to a temporary new file.
    * Upon a successful write, the previous backup of the vault is discarded, the original vault file is replaced by the newly saved temporary file, and a fresh backup is created from this new primary vault file.
    * If any error occurs during the save process, the temporary file will be discarded, and the original vault file (potentially restored from its pre-save backup) will be preserved.
* **1.4 Checksum Verification:** A **checksum** (e.g., SHA256 hash) of the vault file's content must be calculated and stored (either within the vault file itself or alongside it). This checksum must be verified every time the vault is opened and after every successful save operation to detect any tampering or corruption.
* **1.5 Accidental Deletion/Re-creation Prevention (In-App):** The application's user interface (UI) must prevent the direct deletion of an active vault file without explicit user confirmation and robust safeguards. It must also prevent the accidental re-creation of a new vault over an existing one without clear warnings and confirmation.
* **1.6 User-Configurable Vault File Location:** Users must have the ability to change the storage location of their vault file to any accessible directory on their local system. This includes locations within cloud synchronization folders (e.g., Dropbox, OneDrive, Google Drive). The chosen path must be stored in the user's preferences.

---

## 2. User Profiles & Multi-User Support

The application must support multiple distinct users, even when running under a single operating system (OS) login.

* **2.1 App User Profiles:** The application will manage "App User Profiles," each representing a distinct user of the password manager. Each profile will include:
    * A **unique identifier** (UUID/GUID).
    * A user-friendly **name** (e.g., "John's Vault," "Marketing Team").
    * Its own **vault file path**.
    * Its own **encrypted Master Password** (specifically, its Vault Encryption Key or VEK).
    * Its own **last access timestamp**.
    * A flag indicating if it's an **"admin" profile**.
* **2.2 Manager/Admin Profile Role (Exclusive Management):**
    * One or more App User Profiles can be designated as "admin" profiles.
    * When an admin user logs into *their own profile*, their **Master Password** will not only unlock their vault but also grant them **exclusive access** to a "Manage Profiles" UI section.
    * **Only users logged into an admin profile** will be able to perform the following actions:
        * **Create new App User Profiles** (setting their name and initial vault file path).
        * **Rename existing App User Profiles**.
        * **Delete existing App User Profiles** (with strong warnings).
        * **Reset the Master Password storage** for an App User Profile (forcing that user to re-enter their Master Password on next access).
    * Admin users can only access *their own* vault; they cannot directly access or unlock other users' vaults.
* **2.3 Profile Selection at App Launch:**
    * When the application is launched (after being fully closed):
        * If an "admin" profile exists and has not yet explicitly unlocked the profile list, the app will first prompt for the **Manager's Master Password** (for the designated admin profile). This step must be completed to make the list of App User Profiles visible and selectable.
        * Once the profile list is unlocked (either by manager login or if no manager is configured), the app will display a list of all available App User Profiles.
        * Users (including the manager) will then select their desired profile from this list.

---

## 3. Master Password & Authentication

Authentication mechanisms must provide robust security for Master Passwords while offering convenience features.

* **3.1 Master Password Never Stored in Plaintext:** The user's Master Password will never be stored in plain text anywhere (neither in config files nor environment variables).
* **3.2 Vault Encryption Key (VEK) Derivation:** The user's entered Master Password will be used with a strong **Key Derivation Function (KDF)** and a unique salt/iterations to derive the **Vault Encryption Key (VEK)**. This VEK is what directly encrypts and decrypts the vault file.
* **3.3 OS-Bound Encryption for VEK Storage:**
    * Users will have the *option* to securely store their VEK (not their Master Password itself) on the local computer.
    * This storage will leverage **OS-provided secure mechanisms** (e.g., Windows Data Protection API (DPAPI), macOS Keychain Services, Linux Secret Service API/Keyring).
    * Crucially, when storing the VEK, a **unique identifier for the specific App User Profile** will be integrated into the encryption context or metadata provided to the OS API. This ensures that the stored VEK can only be retrieved for that specific App User Profile, even when multiple profiles exist under a single shared OS login.
* **3.4 Automatic Vault Unlock at Launch (If VEK Stored):**
    * If a user has opted to store their VEK (via OS-bound encryption), and the OS-level decryption of the `encrypted_master_key_blob` is successful upon selecting their profile at app launch, their vault will be **automatically unlocked** without requiring manual Master Password entry.
    * This provides a seamless "auto-login" experience for the user.
* **3.5 Re-authentication After Auto-Lock:**
    * The application must include an **auto-lock feature** (with a configurable timeout) that clears sensitive keys from memory and locks the vault after a period of inactivity.
    * To unlock the vault after an auto-lock, the user **MUST re-authenticate**.
    * **Preferred Re-authentication Methods (for convenience):**
        * **OS-level PIN:** (e.g., Windows Hello PIN). If available and configured by the user, this allows quick re-authentication.
        * **Biometrics:** (e.g., Touch ID/Face ID on macOS, or integrated biometric hardware on Windows/Linux).
    * **Fallback Re-authentication:** If OS-level PIN/biometrics are not available, not configured, or if the user wishes to bypass them, the app must **always provide an option to manually enter the Master Password** for the active profile to unlock the vault.
* **3.6 Master Password Reset/Recovery:** If the stored encrypted VEK becomes invalid (e.g., OS change, corruption, admin reset), the application must prompt the user to re-enter their Master Password. This re-entry will then be used to derive a new VEK and securely store it again via the OS-bound method.
* **3.7 No Password Re-entry During Active Session:** Once a user's vault is open and active, they should be able to interact with it (view, edit, add entries) without needing to re-enter their Master Password until the app is closed, logs out, or auto-locks.

---

## 4. Configuration File & Logging

User preferences and system-specific data will be stored securely.

* **4.1 Configuration File Location:**
    * **Installed Mode:** The central configuration file (`config.json` or similar), containing all App User Profiles and general app settings, will be stored in the **standard OS-specific application data directory** (e.g., `%APPDATA%` on Windows, `~/Library/Application Support` on macOS, `~/.config` on Linux). This ensures per-OS-user isolation for the application's configuration.
    * **Portable Mode:** If the application executable and its configuration file are detected in the *same directory* (indicating portable use), the configuration file will reside alongside the executable.
* **4.2 Portable Mode Detection:** The application must detect if it's running in portable mode (e.g., by checking if its config file is in the executable's directory).
    * **Portable Mode Behavior:** In portable mode, the option to "store encrypted Master Password" via OS-bound methods will be disabled, and the app will **always require manual Master Password entry** for vault access.
* **4.3 Last Access Logging:** The configuration file will store a timestamp of the last successful vault access for each App User Profile. This information will be displayed in the UI to the user for auditing purposes.