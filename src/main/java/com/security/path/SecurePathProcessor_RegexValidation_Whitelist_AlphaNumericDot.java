package com.security.path;

import java.util.regex.Pattern;

/**
 * This class contains a secure path processing implementation
 * that uses whitelist regex validation to only allow alphanumeric characters.
 */
public class SecurePathProcessor_RegexValidation_Whitelist_AlphaNumericDot extends PathProcessor {
    
    // Regex pattern that only allows alphanumeric characters
    private static final String WHITELIST_REGEX_PATTERN = "^[a-zA-Z0-9.]+$";
    
    public SecurePathProcessor_RegexValidation_Whitelist_AlphaNumericDot(String baseDirectory) {
        super(baseDirectory);
    } 
    
    /**
     * Method that validates a path by checking if it contains only alphanumeric characters
     * @param path The path to validate
     * @return true if the path is valid (contains only alphanumeric characters), false otherwise
     */
    @Override
    public boolean validateUserInput(String path) {
        if (path == null) {
            return false;
        }
        return Pattern.compile(WHITELIST_REGEX_PATTERN).matcher(path).matches();
    }

    /**
     * Method that sanitizes a path by removing all non-alphanumeric characters
     * @param path The path to sanitize
     * @return The sanitized path containing only alphanumeric characters
     */
    @Override
    public String sanitizeUserInput(String path) {
        if (path == null) {
            return "";
        }
        return path.replaceAll("[^a-zA-Z0-9.]", "");
    }
} 