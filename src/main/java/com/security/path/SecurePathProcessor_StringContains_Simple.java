package com.security.path;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * This class contains a secure path processing implementation
 * that uses simple regex validation.
 */
public class SecurePathProcessor_StringContains_Simple extends PathProcessor {
    
    public SecurePathProcessor_StringContains_Simple(String baseDirectory) {
        super(baseDirectory);
    } 
    
    /**
     * Method that validates a path by checking for dangerous characters
     * @param path The path to validate
     * @return true if the path is valid, false otherwise
     */
    @Override
    public boolean validateUserInput(String path) {
        if (path == null) {
            return false;
        }
        if (path.contains("..") || path.contains("/") 
            || path.contains("\\")) {
            return false;
        }
        return true;
    }

    /**
     * Method that sanitizes a path by removing dangerous characters
     * @param path The path to sanitize
     * @return The sanitized path
     */
    @Override
    public String sanitizeUserInput(String path) {
        if (path == null) {
            return "";
        }
        return path.replace("..", "")
                  .replace("/", "")
                  .replace("\\", "");
    }
} 