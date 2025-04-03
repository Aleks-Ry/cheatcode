package com.security.path;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

import javax.management.NotificationFilterSupport;

/**
 * This class contains a secure path processing implementation
 * that uses canonical path comparison for path traversal detection.
 * Based on https://stackoverflow.com/questions/2375903/whats-the-best-way-to-defend-against-a-path-traversal-attack/34658355#34658355
 */
public class SecurePathProcessor_RelativePath_Validation extends PathProcessor {
    
    public SecurePathProcessor_RelativePath_Validation(String baseDirectory) {
        super(baseDirectory);
        this.CanSanitize = false;
    }
    

    /**
     * Method that validates a path using canonical path comparison
     * @param path The path to validate
     * @return true if the path is valid, false otherwise
     */
    @Override
    public boolean validateUserInput(String path) {
        if (path == null) {
            return false;
        }

        File file = new File(path);
        
        // Check if the path is absolute
        if (file.isAbsolute()) {
            return false;
        }
        
        String canonicalPath;
        String absolutePath;
        
        try {
            canonicalPath = file.getCanonicalPath();
            absolutePath = file.getAbsolutePath();
        } catch (IOException e) {
            return false;
        }
        
        // If canonical path doesn't start with absolute path or they're not equal,
        // it might be a traversal attempt
        return canonicalPath.startsWith(absolutePath) || canonicalPath.equals(absolutePath);
    }

    /**
     * Method that sanitizes a path by ensuring it's relative
     * @param path The path to sanitize
     * @return The sanitized path
     */
    @Override
    public String sanitizeUserInput(String path) {
        throw new UnsupportedOperationException("Sanitization is not supported for this processor");
    }
} 