package com.security.path;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * This class contains a vulnerable path processing implementation
 * that performs only a simple string contains check.
 */
public class InsecurePathProcessor_StringContains_BypassableCheck extends PathProcessor {
    
    public InsecurePathProcessor_StringContains_BypassableCheck(String baseDirectory) {
        super(baseDirectory);
    }

    /**
     * Vulnerable method that only checks for "../" in the path
     * @param path The path to validate
     * @return false if path contains "../", true otherwise
     */
    @Override
    public boolean validateUserInput(String path) {
        // Vulnerable: Only checks for "../" which can be bypassed
        return path != null && !path.contains("../");
    }

    /**
     * Vulnerable method that returns the input without any sanitization
     * @param path The path to sanitize
     * @return The original path without any sanitization
     */
    @Override
    public String sanitizeUserInput(String path) {
        // Vulnerable: Returns the input with bypassable sanitization
        return path.replace("../", "");
    }
} 