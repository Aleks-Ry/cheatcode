package com.security.path;

import java.io.File;
import java.io.IOException;

/**
 * This class contains a secure path processing implementation
 * that uses canonical path comparison to ensure paths are relative to a base directory.
 * It prevents directory traversal attacks by validating that paths don't escape the base directory.
 */
public class SecurePathProcessor_RelativeToBaseFolder_Validation extends PathProcessor {
    
    public SecurePathProcessor_RelativeToBaseFolder_Validation(String baseDirectory) {
        super(baseDirectory);
        this.CanSanitize = false;
    }

    /**
     * Method that validates a path by ensuring it's relative to the base directory
     * @param path The path to validate
     * @return true if the path is valid (contained within base directory), false otherwise
     */
    @Override
    public boolean validateUserInput(String path) {
        if (path == null) {
            return false;
        }

        try {
            File baseDir = new File(this.baseDirectory);
            File file = new File(baseDir, path);
            
            String destCanonicalPath = baseDir.getCanonicalPath();
            String fileCanonicalPath = file.getCanonicalPath();

            // Check if the file's canonical path starts with the base directory's canonical path
            // If it doesn't, it means the path tries to escape the base directory
            if (!fileCanonicalPath.startsWith(destCanonicalPath + File.separator)) {
                return false;
            }

            return true;
        } catch (IOException e) {
            return false;
        }
    }

    /**
     * Method that sanitizes a path - not supported in this implementation
     * @param path The path to sanitize
     * @return The sanitized path
     */
    @Override
    public String sanitizeUserInput(String path) {
        throw new UnsupportedOperationException("Sanitization is not supported for this processor");
    }
} 