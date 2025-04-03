package com.security.path;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * This class contains a secure path processing implementation
 * that uses complex regex validation.
 */
public class SecurePathProcessor_RegexValidation_Extended extends PathProcessor {
    
    public SecurePathProcessor_RegexValidation_Extended(String baseDirectory) {
        super(baseDirectory);
    } 
    
    /**
     * Method that validates a path using regex pattern
     * @param path The path to validate
     * @return true if the path is valid, false otherwise
     */
    @Override
    public boolean validateUserInput(String path) {
        if (path == null) {
            return false;
        }
        // Complex regex validation: checks for path traversal patterns
        return !path.matches(".*\\.\\./.*") && 
               !path.matches(".*\\.\\.\\\\.*") &&
               !path.matches(".*/.*/.*/.*") &&
               !path.matches(".*\\\\.*\\\\.*\\\\.*");
    }

    /**
     * Method that sanitizes a path by replacing unsafe characters
     * @param path The path to sanitize
     * @return The sanitized path
     */
    @Override
    public String sanitizeUserInput(String path) {
        if (path == null) {
            return "";
        }
        // Replace path traversal patterns with underscores
        return path.replaceAll("\\.\\./", "_")
                  .replaceAll("\\.\\.\\\\", "_")
                  .replaceAll("/{2,}", "_")
                  .replaceAll("\\\\{2,}", "_");
    }
} 