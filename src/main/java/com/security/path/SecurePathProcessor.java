package com.security.path;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.regex.Pattern;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

/**
 * This class contains secure path processing implementations
 * that demonstrate proper path validation and normalization.
 */
public class SecurePathProcessor {
    
    private static final Pattern PATH_TRAVERSAL_PATTERN = 
        Pattern.compile(".*\\.\\.(\\\\|/|%2F|%2f|%5C|%5c).*|.*%2E%2E.*", Pattern.CASE_INSENSITIVE);
    
    private final String baseDirectory;
    
    public SecurePathProcessor(String baseDirectory) {
        if (baseDirectory == null || baseDirectory.trim().isEmpty()) {
            throw new IllegalArgumentException("Base directory cannot be null or empty");
        }
        this.baseDirectory = baseDirectory;
    }
    
    /**
     * Secure method that validates and normalizes paths before concatenation
     * @param basePath The base directory path
     * @param userInput User-provided path
     * @return The normalized and validated path
     * @throws IllegalArgumentException if the path is invalid or contains traversal attempts
     */
    public String concatenatePaths(String basePath, String userInput) {
        // Validate inputs
        if (basePath == null || userInput == null) {
            throw new IllegalArgumentException("Paths cannot be null");
        }
        
        // URL decode the user input to handle encoded traversal attempts
        String decodedInput;
        try {
            decodedInput = URLDecoder.decode(userInput, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid URL encoding in path", e);
        }
        
        // Normalize and validate the base path
        Path normalizedBase = Paths.get(basePath).normalize();
        
        // Validate user input
        if (containsPathTraversal(decodedInput) || containsPathTraversal(userInput)) {
            throw new IllegalArgumentException("Path traversal attempt detected");
        }
        
        // Combine paths safely
        return normalizedBase.resolve(decodedInput).normalize().toString();
    }
    
    /**
     * Secure method that uses Path.get() with proper normalization
     * @param basePath The base directory path
     * @param userInput User-provided path
     * @return The normalized and validated path
     * @throws IllegalArgumentException if the path is invalid or contains traversal attempts
     */
    public Path getPathWithNormalization(String basePath, String userInput) {
        // Validate inputs
        if (basePath == null || userInput == null) {
            throw new IllegalArgumentException("Paths cannot be null");
        }
        
        // URL decode the user input to handle encoded traversal attempts
        String decodedInput;
        try {
            decodedInput = URLDecoder.decode(userInput, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid URL encoding in path", e);
        }
        
        // Normalize and validate the base path
        Path normalizedBase = Paths.get(basePath).normalize();
        
        // Validate user input
        if (containsPathTraversal(decodedInput) || containsPathTraversal(userInput)) {
            throw new IllegalArgumentException("Path traversal attempt detected");
        }
        
        // Combine paths safely
        return normalizedBase.resolve(decodedInput).normalize();
    }
    
    /**
     * Secure method that checks for path traversal using regex
     * @param path The path to check
     * @return true if path contains traversal attempt, false otherwise
     */
    public boolean containsPathTraversal(String path) {
        if (path == null) {
            return false;
        }
        return PATH_TRAVERSAL_PATTERN.matcher(path).matches() || 
               path.contains("../") || path.contains("..\\") || 
               path.contains("%2e%2e") || path.contains("%2E%2E");
    }
    
    /**
     * Secure method that uses File.getCanonicalPath() with validation
     * @param path The path to process
     * @return The canonical path
     * @throws IllegalArgumentException if the path is invalid or contains traversal attempts
     */
    public String getCanonicalPath(String path) {
        if (path == null) {
            throw new IllegalArgumentException("Path cannot be null");
        }
        
        // URL decode the path to handle encoded traversal attempts
        String decodedPath;
        try {
            decodedPath = URLDecoder.decode(path, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid URL encoding in path", e);
        }
        
        // Validate path before canonicalization
        if (containsPathTraversal(decodedPath) || containsPathTraversal(path)) {
            throw new IllegalArgumentException("Path traversal attempt detected");
        }
        
        try {
            File file = new File(decodedPath);
            String canonicalPath = file.getCanonicalPath();
            
            // Additional validation after canonicalization
            if (containsPathTraversal(canonicalPath)) {
                throw new IllegalArgumentException("Path traversal attempt detected after canonicalization");
            }
            
            return canonicalPath;
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid path: " + path, e);
        }
    }
    
    /**
     * Secure method that reads file content with proper path validation
     * @param userProvidedFileName The file name provided by the user
     * @return The content of the file
     * @throws IOException if file cannot be read
     * @throws IllegalArgumentException if the path is invalid or contains traversal attempts
     */
    public String readFile(String userProvidedFileName) throws IOException {
        if (userProvidedFileName == null) {
            throw new IllegalArgumentException("Paths cannot be null");
        }
        
        // URL decode the path to handle encoded traversal attempts
        String decodedFileName;
        try {
            decodedFileName = URLDecoder.decode(userProvidedFileName, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid URL encoding in path", e);
        }
        
        // Check both original and decoded paths for traversal attempts
        if (containsPathTraversal(decodedFileName) || containsPathTraversal(userProvidedFileName)) {
            throw new IllegalArgumentException("Path traversal attempt detected");
        }
        
        // Validate and normalize the path
        String filePath = concatenatePaths(baseDirectory, decodedFileName);
        
        // Get canonical path to ensure we're within the base directory
        File file = new File(filePath);
        String canonicalPath = file.getCanonicalPath();
        File baseDir = new File(baseDirectory).getCanonicalFile();
        
        // Verify that the file is actually within the base directory
        if (!canonicalPath.startsWith(baseDir.getCanonicalPath())) {
            throw new IllegalArgumentException("Access denied: File is outside the allowed directory");
        }
        
        // Read the file only if all security checks pass
        return Files.readString(Paths.get(filePath));
    }
} 