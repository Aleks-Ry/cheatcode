package com.security.path;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.Path;
import java.io.IOException;

/**
 * Abstract base class for path processing implementations.
 * Defines the contract for path processing operations.
 */
public abstract class PathProcessor {

    protected final String baseDirectory;

    public static boolean CanValidate = true;
    protected boolean CanSanitize = true;

    protected PathProcessor(String baseDirectory) {
        this.baseDirectory = baseDirectory;
    }

    /**
     * Abstract method for concatenating paths
     * 
     * @param basePath  The base directory path
     * @param userInput User-provided path
     * @return The concatenated path
     */
    public ReadFileResult CalculateTargetPath(String userInput) {
        ReadFileResult result = new ReadFileResult();
        result.userProvidedPath = userInput;
        try {

            if (validateUserInput(userInput)) {
                // No Path traversal attack detected
                result.IsPathTraversalAttackDetected = false;
                result.IsPathSanitized = false;
                result.executedSanitizedFilePath = this.JoinPaths(this.baseDirectory, userInput);
            } else {
                // Path traversal attack detected
                result.IsPathTraversalAttackDetected = true;
                if (CanSanitize) {
                    // Sanitize the input
                    String sanitizedInput = sanitizeUserInput(userInput);
                    result.IsPathSanitized = true;
                    result.executedSanitizedFilePath = this.JoinPaths(this.baseDirectory, sanitizedInput);
                } else {
                    // Sanitization is not supported
                    result.IsPathSanitized = false;
                    result.fileReadException = new UnsupportedOperationException(
                            "PathTraversal is detected. Sanitization is not supported for this processor");
                }
            }
        }
        catch (Exception e) {
            result.fileReadException = e;
        }
        return result;
    }

    /**
     * Merge two paths
     * 
     * @param basePath  The base directory path
     * @param userInput User-provided path
     * @return The merged path
     */
    protected Path JoinPaths(String basePath, String userInput) {
        return Paths.get(basePath, userInput);
    }

    /**
     * Abstract method for reading file content
     * 
     * @param userProvidedFileName The file name provided by the user
     * @return The content of the file
     * @throws IOException if file cannot be read
     */
    public ReadFileResult readFile(String userProvidedFileName) {
        ReadFileResult result = CalculateTargetPath(userProvidedFileName);

        if (result.fileReadException != null) {
            return result;
        }

        try {
            result.fileReadResult = Files.readString(result.executedSanitizedFilePath);
        } catch (Exception e) {
            result.fileReadException = e;
        }

        return result;
    }

    /**
     * Abstract method for validating a path
     * 
     * @param userProvidedFileName The path to validate
     * @return true if the path is valid, false otherwise
     */
    public abstract boolean validateUserInput(String userProvidedFileName);

    /**
     * Abstract method for sanitizing a path
     * 
     * @param userProvidedFileName The path to sanitize
     * @return The sanitized path
     */
    public abstract String sanitizeUserInput(String userProvidedFileName);
}