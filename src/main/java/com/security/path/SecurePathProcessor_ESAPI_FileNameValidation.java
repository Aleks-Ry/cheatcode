package com.security.path;

import org.owasp.esapi.ESAPI;

public class SecurePathProcessor_ESAPI_FileNameValidation extends PathProcessor {
    
    public SecurePathProcessor_ESAPI_FileNameValidation(String baseDirectory) {
        super(baseDirectory);
    }

    @Override
    public String sanitizeUserInput(String path) {
        if (path == null) {
            return "";
        }
        
        try {
            // Use ESAPI's getValidFileName with class name as context
            return ESAPI.validator().getValidFileName(this.getClass().getSimpleName(), path, null, false);
        } catch (Exception e) {
            // If validation fails, return empty string
            return "";
        }
    }

    @Override
    public boolean validateUserInput(String path) {
        if (path == null) {
            return false;
        }
        // Use ESAPI's isValidFileName with class name as context
        return ESAPI.validator().isValidFileName(this.getClass().getSimpleName(), path, false);
    }
} 