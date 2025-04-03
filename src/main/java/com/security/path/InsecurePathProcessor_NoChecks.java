package com.security.path;

/**
 * This class contains a vulnerable path processing implementation
 * that performs no validation or sanitization.
 */
public class InsecurePathProcessor_NoChecks extends PathProcessor {
    
    public InsecurePathProcessor_NoChecks(String baseDirectory) {
        super(baseDirectory);
    }

    @Override
    public boolean validateUserInput(String path) {
        // Vulnerable: No validation
        return true;
    }

    @Override
    public String sanitizeUserInput(String path) {
        // Vulnerable: No sanitization
        return path;
    }
} 