package com.security.path;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.io.File;

/**
 * This class contains a vulnerable path processing implementation
 * that performs no validation or sanitization.
 */
public class InsecurePathProcessor_NoChecks_PathStringConcat extends PathProcessor {
    
    public InsecurePathProcessor_NoChecks_PathStringConcat(String baseDirectory) {
        super(baseDirectory);
    }
    
    /**
     * Vulnerable method that directly concatenates paths without validation
     * @param basePath The base directory path
     * @param userInput User-provided path
     * @return The concatenated path
     */
    @Override
    public Path CalculateTargetPath(String userInput) {
        // Vulnerable: Direct concatenation without validation\
        return Paths.get(this.baseDirectory + File.separator + userInput);
    }    
    

    /**
     * Vulnerable method that always returns true without any validation
     * @param path The path to validate
     * @return Always returns true, performing no actual validation
     */
    @Override
    public boolean validateUserInput(String path) {
        // Vulnerable: No validation
        return true;
    }

    /**
     * Vulnerable method that returns the input without any sanitization
     * @param path The path to sanitize
     * @return The original path without any sanitization
     */
    @Override
    public String sanitizeUserInput(String path) {
        // Vulnerable: No sanitization
        return path;
    }
} 