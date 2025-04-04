package com.security.path;

/**
 * Contains constants for path traversal test payloads used in security testing.
 */
public final class PathTraversalTestPayloads {
    private PathTraversalTestPayloads() {
        // Prevent instantiation
    }

    // Single level traversal
    public static final String SINGLE_LEVEL_TRAVERSAL = "../pwnStorage/secret.txt";
    
    // Double level traversal
    public static final String DOUBLE_LEVEL_TRAVERSAL = "../../pwnStorage/secret.txt";
    
    // Double dot traversal with extra dots and slashes
    public static final String DOUBLE_DOT_TRAVERSAL = "....//....//pwnStorage//secret.txt";
    
    // Windows style path traversal
    public static final String WINDOWS_STYLE_TRAVERSAL = "..\\..\\pwnStorage\\secret.txt";
    
    // Null character injection
    public static final String NULL_CHARACTER_INJECTION = "legit.txt\0";
} 