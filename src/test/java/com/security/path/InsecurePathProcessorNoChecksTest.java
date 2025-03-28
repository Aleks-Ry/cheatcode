package com.security.path;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.NoSuchFileException;
import static org.junit.jupiter.api.Assertions.*;

class InsecurePathProcessorNoChecksTest {
    
    private InsecurePathProcessorNoChecks processor;
    private static final String TEST_CONTENT = "Test file content";
    @TempDir
    Path tempDir;
    
    @BeforeEach
    void setUp() throws IOException {
        // Create a test directory structure
        processor = new InsecurePathProcessorNoChecks(tempDir.toString());
        
        // Create a legitimate test file
        Path legitFile = tempDir.resolve("legit.txt");
        Files.writeString(legitFile, TEST_CONTENT);
        
        // Create a "sensitive" file in a subdirectory
        Path sensitiveDir = tempDir.resolve("sensitive");
        Files.createDirectory(sensitiveDir);
        Path sensitiveFile = sensitiveDir.resolve("secret.txt");
        Files.writeString(sensitiveFile, "SENSITIVE DATA");
    }
    
    @Test
    void testConcatenatePaths_VulnerableToTraversal() {
        String basePath = tempDir.toString();
        String maliciousInput = "../../../etc/passwd";
        
        String result = processor.concatenatePaths(basePath, maliciousInput);
        assertTrue(result.contains("../../../etc/passwd"), "Should allow path traversal");
    }
    
    @Test
    void testReadFile_ValidFile() throws IOException {
        String content = processor.readFile("legit.txt");
        assertEquals(TEST_CONTENT, content, "Should read legitimate file content");
    }
    
    @Test
    void testReadFile_VulnerableToTraversal() {
        // Test that the method is vulnerable to path traversal
        assertThrows(IOException.class, () -> {
            processor.readFile("../../../etc/passwd");
        }, "Should attempt to read file outside base directory");
    }
    
    @Test
    void testReadFile_VulnerableToSensitiveAccess() throws IOException {
        // Test that the method allows access to sensitive subdirectories
        String content = processor.readFile("sensitive/secret.txt");
        assertEquals("SENSITIVE DATA", content, "Should allow access to sensitive files");
    }
    
    @Test
    void testReadFile_NullInput() {
        assertThrows(NoSuchFileException.class, () -> {
            processor.readFile(null);
        }, "Should throw NoSuchFileException for null input");
    }
} 