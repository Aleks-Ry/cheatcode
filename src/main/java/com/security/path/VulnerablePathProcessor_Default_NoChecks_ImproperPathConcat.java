package com.security.path;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.io.File;

/**
 * This class contains a vulnerable path processing implementation
 * that performs no validation or sanitization.
 */
public class VulnerablePathProcessor_Default_NoChecks_ImproperPathConcat extends VulnerablePathProcessor_Default_NoChecks {
    
    public VulnerablePathProcessor_Default_NoChecks_ImproperPathConcat(String baseDirectory) {
        super(baseDirectory);
    }
    
    /**
     * Vulnerable method that directly concatenates paths without validation
     * @param basePath The base directory path
     * @param userInput User-provided path
     * @return The concatenated path
     */
    @Override
    protected Path JoinPaths(String basePath, String userInput) {
        // Vulnerable: Direct concatenation without validation
        return Paths.get(basePath + File.separator + userInput);
    }
} 