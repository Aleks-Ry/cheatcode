package com.security.path;

import java.io.IOException;

/**
 * Main class demonstrating secure and insecure path processing implementations.
 */
public class Main {
    private static final String SECURE_STORAGE = "secureStorage";
    
    public static void main(String[] args) {
        // Initialize all processors
        InsecurePathProcessorNoChecks noChecksProcessor = new InsecurePathProcessorNoChecks(SECURE_STORAGE);
        InsecurePathProcessorSimpleStringContainsCheck simpleCheckProcessor = new InsecurePathProcessorSimpleStringContainsCheck(SECURE_STORAGE);
        SecurePathProcessor secureProcessor = new SecurePathProcessor(SECURE_STORAGE);

        // Example paths including traversal attempts
        String[] testPaths = {
            "legit.txt",                    // Valid file in secure storage
            "../../../pwnStorage/secret.txt", // Basic traversal attempt
            "..%2F..%2FpwnStorage%2Fsecret.txt", // URL encoded traversal
            "....//....//pwnStorage//secret.txt", // Double dot traversal
            "..\\..\\pwnStorage\\secret.txt",    // Windows-style traversal
            null                            // Null input
        };

        System.out.println("=== File Reading Security Demonstration ===\n");

        for (String path : testPaths) {
            System.out.println("Testing path: " + (path == null ? "null" : path));
            
            // Test no-checks implementation
            try {
                System.out.println("\nNo-Checks Implementation:");
                String content = noChecksProcessor.readFile(path);
                System.out.println("File content: " + content);
            } catch (IOException e) {
                System.out.println("File reading error: " + e.getMessage());
            } catch (Exception e) {
                System.out.println("No-checks processor error: " + e.getMessage());
            }

            // Test simple string check implementation
            try {
                System.out.println("\nSimple String Check Implementation:");
                String content = simpleCheckProcessor.readFile(path);
                System.out.println("File content: " + content);
            } catch (IllegalArgumentException e) {
                System.out.println("Simple check processor blocked: " + e.getMessage());
            } catch (IOException e) {
                System.out.println("File reading error: " + e.getMessage());
            } catch (Exception e) {
                System.out.println("Simple check processor error: " + e.getMessage());
            }

            // Test secure implementation
            try {
                System.out.println("\nSecure Implementation:");
                String content = secureProcessor.readFile(path);
                System.out.println("File content: " + content);
            } catch (IllegalArgumentException e) {
                System.out.println("Secure processor blocked: " + e.getMessage());
            } catch (IOException e) {
                System.out.println("File reading error: " + e.getMessage());
            } catch (Exception e) {
                System.out.println("Secure processor error: " + e.getMessage());
            }
            
            System.out.println("\n" + "=".repeat(50) + "\n");
        }
    }
} 