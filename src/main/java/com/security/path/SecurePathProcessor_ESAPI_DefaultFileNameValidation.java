package com.security.path;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.errors.ValidationException;
import java.util.Arrays;
import java.util.List;

/**
 * This class contains a secure path processing implementation
 * that uses OWASP ESAPI's file name validation.
 */
public class SecurePathProcessor_ESAPI_DefaultFileNameValidation extends PathProcessor {
    
    private static final List<String> ALLOWED_EXTENSIONS = Arrays.asList(
        "txt", "pdf", "doc", "docx", "xls", "xlsx", "jpg", "jpeg", "png", "gif"
    );
    
    public SecurePathProcessor_ESAPI_DefaultFileNameValidation(String baseDirectory) {
        super(baseDirectory);
    }
    
    /**
     * Method that validates a path using ESAPI's isValidFileName validator
     * @param path The path to validate
     * @return true if the path contains only a valid filename, false otherwise
     */
    @Override
    public boolean validateUserInput(String path) {
        if (path == null) {
            return false;
        }
        // Use ESAPI's isValidFileName validator with allowNull=false
        return ESAPI.validator().isValidFileName("ESAPI FileName Validation", path, false);
    }

    /**
     * Method that sanitizes a path by extracting only the filename component
     * and validating it with ESAPI
     * @param path The path to sanitize
     * @return The sanitized filename if valid, empty string otherwise
     */
    @Override
    public String sanitizeUserInput(String path) {
        if (path == null) {
            return "";
        }
        try {
            return ESAPI.validator().getValidFileName("ESAPI FileName Validation", path, ALLOWED_EXTENSIONS, false);
        } catch (ValidationException e) {
            throw new RuntimeException("Validation failed: " + e.getMessage(), e);
        }
    }
} 