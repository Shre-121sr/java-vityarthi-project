package com.securevault;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.SecureRandom;

/**
 * Handles password-based AES-256-GCM encryption and decryption of files.
 *
 * File format produced by encryptFile():
 *   [16 bytes salt] [12 bytes IV] [ciphertext + 16-byte GCM auth tag]
 *
 * GCM mode is authenticated encryption: it detects both a wrong password
 * and any tampering with the encrypted file, so no separate integrity
 * check is required on the ciphertext itself.
 */
public class CryptoUtil {

    private static final int SALT_LENGTH = 16;        // bytes
    private static final int IV_LENGTH = 12;           // bytes, recommended for GCM
    private static final int GCM_TAG_LENGTH_BITS = 128;
    private static final int KEY_LENGTH_BITS = 256;
    private static final int PBKDF2_ITERATIONS = 100_000;
    private static final String CIPHER_ALGO = "AES/GCM/NoPadding";
    private static final String KEY_DERIVATION_ALGO = "PBKDF2WithHmacSHA256";

    /**
     * Derives a 256-bit AES key from a password and salt using PBKDF2.
     * The password is never used directly as an encryption key.
     */
    private static SecretKeySpec deriveKey(char[] password, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password, salt, PBKDF2_ITERATIONS, KEY_LENGTH_BITS);
        SecretKeyFactory factory = SecretKeyFactory.getInstance(KEY_DERIVATION_ALGO);
        byte[] keyBytes = factory.generateSecret(spec).getEncoded();
        spec.clearPassword();
        return new SecretKeySpec(keyBytes, "AES");
    }

    /**
     * Encrypts inputFile and writes [salt | iv | ciphertext+tag] to outputFile.
     */
    public static void encryptFile(File inputFile, File outputFile, char[] password) throws Exception {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[SALT_LENGTH];
        byte[] iv = new byte[IV_LENGTH];
        random.nextBytes(salt);
        random.nextBytes(iv);

        SecretKeySpec key = deriveKey(password, salt);
        Cipher cipher = Cipher.getInstance(CIPHER_ALGO);
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv));

        try (InputStream in = new FileInputStream(inputFile);
             OutputStream out = new FileOutputStream(outputFile)) {

            out.write(salt);
            out.write(iv);

            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = in.read(buffer)) != -1) {
                byte[] chunk = cipher.update(buffer, 0, bytesRead);
                if (chunk != null) out.write(chunk);
            }
            byte[] finalBlock = cipher.doFinal();
            if (finalBlock != null) out.write(finalBlock);
        }
    }

    /**
     * Reads [salt | iv | ciphertext+tag] from inputFile, decrypts, writes
     * plaintext to outputFile. Throws javax.crypto.AEADBadTagException if
     * the password is wrong or the file has been tampered with.
     */
    public static void decryptFile(File inputFile, File outputFile, char[] password) throws Exception {
        try (InputStream in = new FileInputStream(inputFile);
             OutputStream out = new FileOutputStream(outputFile)) {

            byte[] salt = new byte[SALT_LENGTH];
            byte[] iv = new byte[IV_LENGTH];
            readFully(in, salt);
            readFully(in, iv);

            SecretKeySpec key = deriveKey(password, salt);
            Cipher cipher = Cipher.getInstance(CIPHER_ALGO);
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv));

            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = in.read(buffer)) != -1) {
                byte[] chunk = cipher.update(buffer, 0, bytesRead);
                if (chunk != null) out.write(chunk);
            }
            // doFinal() verifies the GCM auth tag — throws AEADBadTagException
            // if the password is wrong or the file has been modified.
            byte[] finalBlock = cipher.doFinal();
            if (finalBlock != null) out.write(finalBlock);
        }
    }

    private static void readFully(InputStream in, byte[] buffer) throws IOException {
        int offset = 0;
        while (offset < buffer.length) {
            int read = in.read(buffer, offset, buffer.length - offset);
            if (read == -1) {
                throw new IOException("Unexpected end of file — this may not be a valid SecureVault file.");
            }
            offset += read;
        }
    }
}
