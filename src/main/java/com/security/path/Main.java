package com.security.path;

import java.io.IOException;

/**
 * Main class demonstrating secure and insecure path processing implementations.
 */
public class Main {
    private static final String BASE_DIR = "secureStorage/baseDir";
    private static final String RED = "\u001B[31m";
    private static final String RESET = "\u001B[0m";

    public static void main(String[] args) {
        String[] testPaths = {
            "legit.txt",                         // Valid file in secure storage
            "SomeSubFolder/sublegit.txt",         // Valid file in subfolder of secure storage
            "../pwnStorage/secret.txt",    // Basic traversal attempt, 1 level up
            "../../pwnStorage/secret.txt",    // Basic traversal attempt, 2 levels up   
            "....//....//pwnStorage//secret.txt",// Double dot traversal
            "..\\..\\pwnStorage\\secret.txt",   // Windows-style traversal
            null                                 // Null input
        };

        // Create instances of all processors
        PathProcessor[] processors = {
            new VulnerablePathProcessor_Default_NoChecks(BASE_DIR),
            new VulnerablePathProcessor_Default_NoChecks_ImproperPathConcat(BASE_DIR),            
            new VulnerablePathProcessor_Bypassable_StringContainsCheck(BASE_DIR),
            new VulnerablePathProcessor_ImproperAPIUse_MultipartFileGetOriginalName(BASE_DIR),
            new SecurePathProcessor_StringContains_Simple(BASE_DIR),
            new SecurePathProcessor_RegexValidation_Blacklist_Simple(BASE_DIR),
            new SecurePathProcessor_RegexValidation_Blacklist_Extended(BASE_DIR),
            new SecurePathProcessor_RelativePath_Validation(BASE_DIR),
            new SecurePathProcessor_FileAPI_GetName(BASE_DIR),
            new SecurePathProcessor_ESAPI_FileNameValidation(BASE_DIR)
        };

        // Test each processor
        for (PathProcessor processor : processors) {
            System.out.println("\nTesting: " + processor.getClass().getSimpleName());
            System.out.println("=".repeat(50));

            for (String testPath : testPaths) {
                System.out.println("\nTest path: " + testPath);
                
                try {
                    // Test validation
                    //boolean isValid = processor.validateUserInput(testPath);
                    //System.out.println("Validation result: " + isValid);

                    // Test sanitization
                    //String sanitized = processor.sanitizeUserInput(testPath);
                    //System.out.println("Sanitized path: " + sanitized);                    

                    // Only try to read if path is not null
                    if (testPath != null) {
                        try {
                            // Attempt to read (might throw exception)
                            ReadFileResult result = processor.readFile(testPath);
                            if (result.fileReadException != null) {
                                System.out.println("Read operation: Failed - " + result.fileReadException.toString());
                            } else if (result.fileReadResult != null && result.fileReadResult.contains("CONFIDENTIAL")) {
                                System.out.println(RED + "INJECTION SUCCEEDED: " + result.fileReadResult + RESET);
                            } else {
                                System.out.println("Read operation succeeded: " + result.fileReadResult);
                            }
                        } catch (Exception e) {
                            System.out.println("Read operation: Failed - " + e.toString());
                        }
                    }
                } catch (Exception e) {
                    System.out.println("Error: " + e.getMessage());
                }
            }
        }
    }
} 