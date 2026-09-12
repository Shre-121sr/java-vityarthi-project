SecureVault

A command-line file encryption tool written in Java, built for the "Programming in Java" evaluated project. SecureVault demonstrates practical use of core Java cryptography APIs to solve a real cybersecurity problem: protecting file confidentiality and integrity at rest.

Features
AES-256-GCM encryption — authenticated encryption that protects both confidentiality and integrity in a single step (no separate MAC/HMAC needed).
Password-based key derivation using PBKDF2WithHmacSHA256 (100,000 iterations), so the AES key is never derived from the password directly.
Per-file random salt and IV — every encryption run uses a fresh salt and IV, so encrypting the same file twice with the same password produces different ciphertext.
Tamper detection — because GCM is an authenticated cipher mode, decrypting with the wrong password or a modified file fails cleanly instead of silently producing garbage.
Standalone SHA-256 hashing utility for independently verifying file integrity.
Zero external dependencies — uses only the standard JDK (javax.crypto, java.security).
Project structure
SecureVault/
├── README.md
└── src/
    └── com/securevault/
        ├── Main.java        # CLI entry point and menu
        ├── CryptoUtil.java  # AES-256-GCM encryption/decryption + key derivation
        └── HashUtil.java    # SHA-256 file hashing
How it works
When you encrypt a file, SecureVault generates a random 16-byte salt and 12-byte IV.
Your password plus the salt are run through PBKDF2 (100,000 iterations) to derive a 256-bit AES key. The raw password is never stored or used directly as a key.
The file is encrypted with AES/GCM/NoPadding using that key and IV. GCM appends a 128-bit authentication tag to the ciphertext.
The output file (<filename>.vault) stores [salt][iv][ciphertext+tag] — everything needed to decrypt, except the password, which only you know.
On decryption, SecureVault re-derives the key from the password and the stored salt, then decrypts. If the password is wrong or the file was altered, the GCM authentication check fails and decryption is rejected — this is what gives the tool its integrity guarantee.
Build
bash
cd SecureVault
mkdir -p out
javac -d out src/com/securevault/*.java
Run
bash
java -cp out com.securevault.Main

Then follow the on-screen menu to encrypt, decrypt, or hash a file.

Security notes (useful for the project report)
AES-256-GCM was chosen over AES-CBC because it provides authenticated encryption — integrity and confidentiality in one primitive — and avoids padding-oracle-style vulnerabilities associated with CBC + PKCS5Padding.
PBKDF2 with a high iteration count slows brute-force password guessing compared to hashing the password once.
A random salt per file defeats precomputed rainbow-table attacks and ensures identical files/passwords never produce identical ciphertext.
Limitation to note in the report: the key is derived fresh from the password every run and never persisted, which is good for security but means a lost password makes the file unrecoverable — there is no backdoor or key escrow.
Possible extensions
Add a GUI (JavaFX/Swing) file picker instead of typing paths.
Support directory (folder) encryption by zipping first.
Add a password strength meter before allowing encryption.
