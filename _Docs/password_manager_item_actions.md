# Password Manager Item Actions Progress Tracker

This document outlines the core functionalities for your password manager, focusing on the management of password entries, notes, and user profiles. It also tracks their implementation status and the crates primarily involved.

---

## Core Vault Operations

1.  ### Load Vault
    * **Description:** Decrypts and loads the `EncryptedVault` content into usable in-memory structures (e.g., `Vec<PasswordEntry>`, `Vec<Note>`).
    * **Status:** Implemented (core `decrypt` in `password_core`, simulated in `password_cli`).
    * **Crates Involved:** `password_core`, `password_storage` (needs specific load implementation).

2.  ### Save Vault
    * **Description:** Serializes and encrypts the in-memory vault content, then persists it to storage.
    * **Status:** Implemented (core `encrypt` in `password_core`, simulated in `password_cli`).
    * **Crates Involved:** `password_core`, `password_storage` (needs specific save implementation).

---

## Password Entry Management

3.  ### Add Password Entry
    * **Description:** Creates a new `PasswordEntry` and adds it to the vault's collection.
    * **Status:** Implemented (simulated in `password_cli` and `user_simulation_tests`).
    * **Crates Involved:** `password_core` (for `PasswordEntry` creation), `password_api` (should expose this high-level action).

4.  ### Edit Password Entry
    * **Description:** Modifies existing fields of a `PasswordEntry` (e.g., name, URL, username, notes, credential type) identified by a unique ID.
    * **Status:** To Do.
    * **Crates Involved:** `password_core`, `password_api`.

5.  ### Update Password
    * **Description:** Adds a new password version to an existing `PasswordEntry`, making it the current password while retaining previous versions for history.
    * **Status:** To Do.
    * **Crates Involved:** `password_core`, `password_api`.

6.  ### Delete Password Entry
    * **Description:** Removes a specific `PasswordEntry` from the vault using its unique ID.
    * **Status:** To Do.
    * **Crates Involved:** `password_core`, `password_api`.

7.  ### Retrieve Password
    * **Description:** Retrieves and decrypts the *current* password for a given `PasswordEntry` (often for copying to clipboard).
    * **Status:** Implemented (`PasswordEntry::get_current_password` in `password_core`, simulated in `user_simulation_tests`).
    * **Crates Involved:** `password_core`, `password_api` (should expose this for interaction).

8.  ### Search Password Entries
    * **Description:** Finds and returns `PasswordEntry` instances based on keywords or specific criteria across various fields (e.g., name, URL, username, notes).
    * **Status:** Implemented (simulated in `user_simulation_tests`).
    * **Crates Involved:** `password_core` (data filtering logic), `password_api` (should expose this high-level action).

---

## Note Management

9.  ### Add Note
    * **Description:** Creates a new `Note` and adds it to the vault's collection.
    * **Status:** To Do.
    * **Crates Involved:** `password_core`, `password_api`.

10. ### Edit Note
    * **Description:** Modifies the content of an existing `Note` identified by its unique ID.
    * **Status:** To Do.
    * **Crates Involved:** `password_core`, `password_api`.

11. ### Delete Note
    * **Description:** Removes a specific `Note` from the vault using its unique ID.
    * **Status:** To Do.
    * **Crates Involved:** `password_core`, `password_api`.

12. ### Search Notes
    * **Description:** Finds and returns `Note` instances based on keywords in their content.
    * **Status:** To Do.
    * **Crates Involved:** `password_core`, `password_api`.

---

## User/Profile Management

13. ### Create User Profile
    * **Description:** Establishes a new user profile, prompting for a master password and initializing an empty, encrypted vault for them.
    * **Status:** Implemented (in `password_cli` using `SettingsManager` and core crypto functions).
    * **Crates Involved:** `password_core` (for `SettingsManager` and crypto), `password_api` (could encapsulate this process).

14. ### Login/Open Vault
    * **Description:** Authenticates a user with their master password and decrypts their vault content for access.
    * **Status:** Implemented (in `password_cli` for simulation).
    * **Crates Involved:** `password_core`, `password_storage`, `password_api` (should encapsulate this action).

15. ### Change Master Password
    * **Description:** Allows a user to change their master password, which involves deriving a new key and re-encrypting the entire vault with the new key.
    * **Status:** To Do.
    * **Crates Involved:** `password_core`, `password_api`, `password_storage`.