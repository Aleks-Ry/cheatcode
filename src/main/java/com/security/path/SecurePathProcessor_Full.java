package com.security.path;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.regex.Pattern;

/**
 * This class contains a secure path processing implementation
 * that combines multiple security measures.
 */
public class SecurePathProcessor_Full extends PathProcessor {
    
    private static final Pattern PATH_TRAVERSAL_PATTERN = Pattern.compile("(?i)\\.\\.(/|\\\\|$)");
    private static final Pattern UNSAFE_CHARS_PATTERN = Pattern.compile("[^a-zA-Z0-9/\\\\-_. ]");
    
    public SecurePathProcessor_Full(String baseDirectory) {
        super(baseDirectory);
    }
    
    /**
     * Secure method that safely concatenates paths
     * @param basePath The base directory path
     * @param userInput User-provided path
     * @return The concatenated path
     */
    // @Override
    // public String concatenatePaths(String basePath, String userInput) {
    //     // Secure: Use Path.normalize() to handle path traversal attempts
    //     Path base = Paths.get(basePath).normalize();
    //     Path user = Paths.get(userInput).normalize();
    //     return base.resolve(user).toString();
    // }
    
    /**
     * Secure method that reads file content with proper validation
     * @param userProvidedFileName The file name provided by the user
     * @return The content of the file
     * @throws IOException if file cannot be read
     * @throws IllegalArgumentException if path is invalid
     */
    // @Override
    // public String readFile(String userProvidedFileName) throws IOException {
    //     // Secure: Validate and sanitize before processing
    //     if (!validatePath(userProvidedFileName)) {
    //         throw new IllegalArgumentException("Invalid path detected");
    //     }
    //     String sanitizedPath = sanitizePath(userProvidedFileName);
    //     String filePath = concatenatePaths(baseDirectory, sanitizedPath);
        
    //     // Additional security check to ensure the final path is within base directory
    //     Path finalPath = Paths.get(filePath).normalize();
    //     Path basePath = Paths.get(baseDirectory).normalize();
    //     if (!finalPath.startsWith(basePath)) {
    //         throw new IllegalArgumentException("Path traversal detected");
    //     }
        
    //     return Files.readString(finalPath);
    // }

    /**
     * Secure method that validates a path
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
        
        try {
            String canonicalPath = file.getCanonicalPath();
            String absolutePath = file.getAbsolutePath();
            
            // Check for path traversal
            if (!canonicalPath.startsWith(absolutePath)) {
                return false;
            }
            
            // Additional regex validation
            return path.matches("^[a-zA-Z0-9./]+$");
        } catch (IOException e) {
            return false;
        }
    }

    /**
     * Secure method that sanitizes a path
     * @param path The path to sanitize
     * @return The sanitized path
     */
    @Override
    public String sanitizeUserInput(String path) {
        if (path == null) {
            return "";
        }
        
        try {
            // Get canonical path
            String canonicalPath = new File(path).getCanonicalPath();
            
            // Replace any non-alphanumeric characters with underscores
            return canonicalPath.replaceAll("[^a-zA-Z0-9./]", "_");
        } catch (IOException e) {
            return path;
        }
    }
} 