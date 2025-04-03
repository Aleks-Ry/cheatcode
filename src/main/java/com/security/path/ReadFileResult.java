package com.security.path;

import java.nio.file.Path;

public class ReadFileResult {
    public boolean IsPathTraversalAttackDetected = false;
    public boolean IsPathSanitized = false;
    public String userProvidedPath;
    public Path executedSanitizedFilePath;
    public String fileReadResult;
    public Exception fileReadException;
} 