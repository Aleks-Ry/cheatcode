package com.security.path;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.errors.ValidationException;
import java.util.Arrays;
import java.util.List;
import java.io.File;

/**
 * This class contains a secure path processing implementation
 * that uses OWASP ESAPI's directory path validation.
 */
public class Secure_PathProcessor_ESAPI_CombinedDirectoryAndFileNameValidation extends PathProcessor {
    
    // List of allowed file extensions
    private static final List<String> ALLOWED_EXTENSIONS = Arrays.asList("txt", "pdf", "doc", "docx", "xls", "xlsx");
    
    public Secure_PathProcessor_ESAPI_CombinedDirectoryAndFileNameValidation(String baseDirectory) {
        super(baseDirectory);
    }
    
    /**
     * Method that validates a path by splitting it into directory path and filename components
     * and validating each separately using ESAPI validators
     * @param path The path to validate
     * @return true if both the directory path and filename are valid, false otherwise
     */
    @Override
    public boolean validateUserInput(String path) {
        if (path == null) {
            return false;
        }

        // Split the path into directory and filename components
        File file = new File(path);
        String directoryPath = file.getParent();
        String fileName = file.getName();

        // Validate filename
        boolean isFileNameValid = ESAPI.validator().isValidFileName(
            "ESAPI FileName Validation",
            fileName,
            ALLOWED_EXTENSIONS,
            false
        );

        // Only validate directory path if it exists
        boolean isDirectoryValid = true;
        if (directoryPath != null) {
            isDirectoryValid = ESAPI.validator().isValidDirectoryPath(
                "ESAPI DirectoryPath Validation", 
                directoryPath, 
                new File(this.baseDirectory), 
                false
            );
        }

        return isDirectoryValid && isFileNameValid;
    }

    /**
     * Method that sanitizes a path by validating it with ESAPI's directory path validation
     * @param path The path to sanitize
     * @return The sanitized directory path if valid, empty string otherwise
     */
    @Override
    public String sanitizeUserInput(String path) {
        if (path == null) {
            return "";
        }
        try {
            // Split the path into directory and filename components
            File file = new File(path);
            String directoryPath = file.getParent();
            String fileName = file.getName();

            // Get validated filename
            String validatedFileName = ESAPI.validator().getValidFileName(
                "ESAPI FileName Validation",
                fileName,
                ALLOWED_EXTENSIONS,
                false
            );

            // Only validate directory path if it exists
            String validatedDirectory = ".";
            if (directoryPath != null) {
                validatedDirectory = ESAPI.validator().getValidDirectoryPath(
                    "ESAPI DirectoryPath Validation", 
                    directoryPath, 
                    new File(this.baseDirectory), 
                    false
                );
            }

            // Combine the validated components
            return new File(validatedDirectory, validatedFileName).getPath();
        } catch (ValidationException e) {
            throw new RuntimeException("Validation failed: " + e.getMessage(), e);
        }
    }
} 