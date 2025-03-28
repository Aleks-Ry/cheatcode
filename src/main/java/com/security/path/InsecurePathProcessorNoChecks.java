package com.security.path;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * This class contains a vulnerable path processing implementation
 * that performs no validation or checks at all.
 * This is the most vulnerable implementation.
 */
public class InsecurePathProcessorNoChecks {
    
    private final String baseDirectory;
    
    public InsecurePathProcessorNoChecks(String baseDirectory) {
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
     * Vulnerable method that reads file content without any validation
     * @param userProvidedFileName The file name provided by the user
     * @return The content of the file
     * @throws IOException if file cannot be read
     */
    public String readFile(String userProvidedFileName) throws IOException {
        // Vulnerable: No validation at all
        String filePath = concatenatePaths(baseDirectory, userProvidedFileName);
        return Files.readString(Paths.get(filePath));
    }
} 