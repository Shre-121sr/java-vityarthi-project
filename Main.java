package com.securevault;

import java.io.Console;
import java.io.File;
import java.util.Scanner;

/**
 * Command-line entry point for SecureVault.
 * Provides a simple menu for encrypting files, decrypting files,
 * and computing SHA-256 hashes.
 */
public class Main {

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("=== SecureVault: AES-256-GCM File Encryption Tool ===");

        while (true) {
            System.out.println("\n1. Encrypt a file");
            System.out.println("2. Decrypt a file");
            System.out.println("3. Compute SHA-256 hash of a file");
            System.out.println("4. Exit");
            System.out.print("Choose an option: ");
            String choice = scanner.nextLine().trim();

            try {
                switch (choice) {
                    case "1": encryptFlow(scanner); break;
                    case "2": decryptFlow(scanner); break;
                    case "3": hashFlow(scanner); break;
                    case "4": System.out.println("Goodbye."); return;
                    default: System.out.println("Invalid option.");
                }
            } catch (Exception e) {
                System.out.println("Error: " + e.getMessage());
            }
        }
    }

    private static void encryptFlow(Scanner scanner) throws Exception {
        System.out.print("Path of file to encrypt: ");
        File input = new File(scanner.nextLine().trim());
        if (!input.exists()) {
            System.out.println("File not found.");
            return;
        }
        File output = new File(input.getPath() + ".vault");
        char[] password = readPassword("Enter password: ", scanner);

        CryptoUtil.encryptFile(input, output, password);
        System.out.println("Encrypted file written to: " + output.getPath());
    }

    private static void decryptFlow(Scanner scanner) throws Exception {
        System.out.print("Path of .vault file to decrypt: ");
        File input = new File(scanner.nextLine().trim());
        if (!input.exists()) {
            System.out.println("File not found.");
            return;
        }
        System.out.print("Path for decrypted output: ");
        File output = new File(scanner.nextLine().trim());
        char[] password = readPassword("Enter password: ", scanner);

        try {
            CryptoUtil.decryptFile(input, output, password);
            System.out.println("Decrypted file written to: " + output.getPath());
        } catch (javax.crypto.AEADBadTagException e) {
            System.out.println("Decryption failed: wrong password or the file has been tampered with.");
        }
    }

    private static void hashFlow(Scanner scanner) throws Exception {
        System.out.print("Path of file to hash: ");
        File file = new File(scanner.nextLine().trim());
        if (!file.exists()) {
            System.out.println("File not found.");
            return;
        }
        System.out.println("SHA-256: " + HashUtil.sha256(file));
    }

    private static char[] readPassword(String prompt, Scanner scanner) {
        Console console = System.console();
        if (console != null) {
            return console.readPassword(prompt);
        }
        // Fallback for IDEs where System.console() returns null
        // (password characters will be visible in this mode).
        System.out.print(prompt);
        return scanner.nextLine().toCharArray();
    }
}
