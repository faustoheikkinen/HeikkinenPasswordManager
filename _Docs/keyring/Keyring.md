Heikkinen Password Manager: OS-Bound Vault Encryption Key (VEK) Storage
This document details the implementation of the OS-bound VEK storage feature within the Heikkinen Password Manager, focusing on how it leverages operating system's secure keyring services to enhance master password security and user convenience.

1. Implemented Requirements Analysis
Let's review the requirements you provided and assess how the current implementation addresses them:

3.1 Master Password Never Stored in Plaintext
Assessment: FULLY MET

The user's Master Password is never stored by the application, neither in plaintext nor in any encrypted form. It is solely used as an input to a Key Derivation Function (KDF) to derive the Vault Encryption Key (VEK). The VEK itself is then either kept in memory for the session or stored securely via OS-binding, but the Master Password is discarded immediately after key derivation.

3.2 Vault Encryption Key (VEK) Derivation
Assessment: FULLY MET

The application uses argon2id (via the argon2 crate) as its robust Key Derivation Function. The derive_key_from_password function in crates/password_core/src/crypto.rs handles this, ensuring that the VEK is derived using a strong, unique salt and appropriate computational parameters. This VEK is the direct key for encrypting and decrypting the vault file.

Additionally, for the OS-bound storage option, the derive_random_encryption_key function in crypto.rs is used to generate a new, cryptographically random VEK if the user opts for OS-binding without providing a master password. This newly generated VEK is then securely stored via the OS keyring.

3.3 OS-Bound Encryption for VEK Storage
Assessment: FULLY MET

This is the core feature we've implemented.

Users will have the option to securely store their VEK (not their Master Password itself) on the local computer.
The os_key_protector module provides the functions (store_vek_os_bound, retrieve_vek_os_bound, delete_vek_os_bound) that allow the application to securely store, retrieve, or delete the VEK. The user's choice to use this feature (e.g., "Remember Me" or "Login without Master Password") is handled at the application logic layer (like in interactive_demo.rs).
This storage will leverage OS-provided secure mechanisms (e.g., Windows Data Protection API (DPAPI), macOS Keychain Services, Linux Secret Service API/Keyring).
The keyring crate is used, which acts as a cross-platform abstraction layer for these OS-specific secure storage mechanisms. By utilizing keyring::Entry, the application automatically benefits from the underlying OS's security features, including potential user authentication prompts (PIN, biometrics) before access.
Crucially, when storing the VEK, a unique identifier for the specific App User Profile will be integrated into the encryption context or metadata provided to the OS API. This ensures that the stored VEK can only be retrieved for that specific App User Profile, even when multiple profiles exist under a single shared OS login.
The profile_id parameter is incorporated directly into the service_name used by keyring::Entry. The service name is formatted as HeikkinenPasswordManager-{profile_id}. This makes the keyring entry unique to a specific profile, fulfilling the requirement that a VEK can only be retrieved for its corresponding app user profile. The username for the keyring entry is fixed as default_user_for_vek to simplify management, as the profile_id already provides the necessary granularity.
2. Key Components and Data Types
The implementation relies on the following key components:

KeyringProvider Trait: Defined in os_key_protector.rs, this trait abstracts the keyring operations (new, set_password, get_password, delete_credential), allowing for easy mocking in tests.
keyring::Entry Implementation: The KeyringProvider trait is implemented for keyring::Entry, providing the concrete logic for interacting with the OS keyring.
store_vek_os_bound (in os_key_protector.rs): Function to securely store the VEK in the OS keyring.
retrieve_vek_os_bound (in os_key_protector.rs): Function to securely retrieve the VEK from the OS keyring.
delete_vek_os_bound (in os_key_protector.rs): Function to remove the VEK from the OS keyring.
EncryptionKey (in crypto.rs and data_types.rs): A type alias for PasswordBytes (which is struct PasswordBytes(pub Vec<u8>);). This represents the derived Vault Encryption Key.
PasswordBytes (in data_types.rs): A newtype wrapper struct PasswordBytes(pub Vec<u8>); used to encapsulate sensitive byte arrays, preventing accidental misuse and enhancing type safety.
3. Keyring Data Model (ERD)
The following Entity-Relationship Diagram illustrates the conceptual data model for how the VEK is stored in the OS keyring.


erDiagram
    KeyringEntry {
        string service_name PK "HeikkinenPasswordManager-{profile_id}"
        string username PK "Fixed: default_user_for_vek"
        string vek_base64 "Base64 encoded Vault Encryption Key"
    }
    AppUserConceptualProfile {
        string profile_id PK "Used to form service_name"
    }

    AppUserConceptualProfile ||--o{ KeyringEntry : "1:N VEK stored for"
    %% This relationship shows that a profile corresponds to a keyring entry
    %% where the profile_id is part of the service_name.


  Explanation:

KeyringEntry: Represents a single entry in the OS's secure keyring.
service_name (Primary Key): This is a composite string formed by concatenating a fixed prefix (HeikkinenPasswordManager-) with the unique profile_id of the application user. This ensures unique identification for each user's VEK.
username (Primary Key): A fixed string (default_user_for_vek) is used. While keyring entries often use a username, in this context, the profile_id within the service name provides the primary user-specific differentiation.
vek_base64: The actual Vault Encryption Key, stored in a Base64 encoded format.
AppUserConceptualProfile: Represents the application's internal user profile, which influences the naming of the keyring entry. It's a conceptual entity here, as the OS keyring doesn't directly manage "app user profiles" but rather "credentials" associated with "services" and "usernames".
profile_id: The unique identifier for the application's user profile (e.g., from a configuration file or login).
The 1:N relationship signifies that one conceptual App User Profile maps to one (or potentially many, though currently one) KeyringEntry where its profile_id is embedded in the service_name.

4. Operational Flow Diagrams
These sequence diagrams illustrate the interaction between the application code, the os_key_protector module, the keyring::Entry abstraction, and the underlying OS Keyring Service for the three main operations: storing, retrieving, and deleting the VEK.

4.1 Storing the VEK

sequenceDiagram
    participant App as Application Code
    participant OSKP as os_key_protector.rs
    participant KR as keyring::Entry
    participant OS as OS Keyring Service

    App->>OSKP: store_vek_os_bound(profile_id, vek)
    OSKP->>KR: Entry::new(service_name, username)
    KR->>OS: Request Keyring Handle
    OS-->>KR: Keyring Handle
    KR-->>OSKP: Keyring Entry Instance
    OSKP->>OSKP: Base64 Encode VEK (vek.0)
    OSKP->>KR: set_password(base66_vek)
    KR->>OS: Store Credential (VEK)
    Note right of OS: OS may prompt user for authentication (PIN, biometrics)
    OS-->>KR: Storage Result
    KR-->>OSKP: Success/Error
    OSKP-->>App: Result<(), PasswordManagerError>

4.2 Retrieving the VEK 

sequenceDiagram
    participant App as Application Code
    participant OSKP as os_key_protector.rs
    participant KR as keyring::Entry
    participant OS as OS Keyring Service

    App->>OSKP: retrieve_vek_os_bound(profile_id)
    OSKP->>KR: Entry::new(service_name, username)
    KR->>OS: Request Keyring Handle
    OS-->>KR: Keyring Handle
    KR-->>OSKP: Keyring Entry Instance
    OSKP->>KR: get_password()
    KR->>OS: Retrieve Credential (VEK)
    Note right of OS: OS may prompt user for authentication (PIN, biometrics)
    OS-->>KR: Retrieved Credential
    KR-->>OSKP: Base64 Encoded VEK
    OSKP->>OSKP: Base64 Decode VEK
    OSKP->>OSKP: Validate VEK Length
    OSKP-->>App: Result<EncryptionKey, PasswordManagerError>

4.3 Deleting the VEK

sequenceDiagram
    participant App as Application Code
    participant OSKP as os_key_protector.rs
    participant KR as keyring::Entry
    participant OS as OS Keyring Service

    App->>OSKP: delete_vek_os_bound(profile_id)
    OSKP->>KR: Entry::new(service_name, username)
    KR->>OS: Request Keyring Handle
    OS-->>KR: Keyring Handle
    KR-->>OSKP: Keyring Entry Instance
    OSKP->>KR: delete_credential()
    KR->>OS: Delete Credential (VEK)
    OS-->>KR: Deletion Result
    KR-->>OSKP: Success/Error
    OSKP-->>App: Result<(), PasswordManagerError>

    