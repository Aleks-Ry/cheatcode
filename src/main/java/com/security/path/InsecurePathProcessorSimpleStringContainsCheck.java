package com.security.path;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * This class contains a vulnerable path processing implementation
 * that uses a simple string contains check for path traversal detection.
 * This implementation can be easily bypassed.
 */
public class InsecurePathProcessorSimpleStringContainsCheck {
    
    private final String baseDirectory;
    
    public InsecurePathProcessorSimpleStringContainsCheck(String baseDirectory) {
        this.baseDirectory = baseDirectory;
    }
    
    /**
     * Vulnerable method that directly concatenates paths without validation
     * @param basePath The base directory path
     * @param userInput User-provided path
     * @return The concatenated path
     */
    public String concatenatePaths(String basePath, String userInput) {
        // Vulnerable: Direct concatenation without validation
        return basePath + File.separator + userInput;
    }
    
    /**
     * Vulnerable method that uses a simple string contains check
     * @param path The path to check
     * @return true if path contains "../", false otherwise
     */
    public boolean isPathTraversal(String path) {
        // Vulnerable: Simple string check that can be bypassed
        return path != null && path.contains("../");
    }
    
    /**
     * Vulnerable method that uses File.getCanonicalPath() without validation
     * @param path The path to process
     * @return The canonical path
     */
    public String getCanonicalPath(String path) {
        try {
            // Vulnerable: No validation before canonicalization
            return new File(path).getCanonicalPath();
        } catch (Exception e) {
            return path;
        }
    }
    
    /**
     * Vulnerable method that reads file content with simple string check
     * @param userProvidedFileName The file name provided by the user
     * @return The content of the file
     * @throws IOException if file cannot be read
     */
    public String readFile(String userProvidedFileName) throws IOException {
        // Vulnerable: Only uses simple string check
        if (isPathTraversal(userProvidedFileName)) {
            throw new IllegalArgumentException("Path traversal detected");
        }
        String filePath = concatenatePaths(baseDirectory, userProvidedFileName);
        return Files.readString(Paths.get(filePath));
    }
} 