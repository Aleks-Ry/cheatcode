package com.security.path;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.NoSuchFileException;
import static org.junit.jupiter.api.Assertions.*;

class InsecurePathProcessorSimpleStringContainsCheckTest {
    
    private InsecurePathProcessorSimpleStringContainsCheck processor;
    private static final String TEST_CONTENT = "Test file content";
    @TempDir
    Path tempDir;
    
    @BeforeEach
    void setUp() throws IOException {
        // Create a test directory structure
        processor = new InsecurePathProcessorSimpleStringContainsCheck(tempDir.toString());
        
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
    void testIsPathTraversal_CanBeBypassed() {
        // Test various bypass techniques
        assertFalse(processor.isPathTraversal("..%2F..%2Fetc%2Fpasswd"), "Should not detect URL encoded traversal");
        assertFalse(processor.isPathTraversal("....//....//etc/passwd"), "Should not detect double dot traversal");
        assertFalse(processor.isPathTraversal("..\\..\\etc\\passwd"), "Should not detect Windows-style traversal");
        assertFalse(processor.isPathTraversal("..%252F..%252Fetc%252Fpasswd"), "Should not detect double URL encoding");
    }
    
    @Test
    void testGetCanonicalPath_VulnerableToTraversal() throws IOException {
        String maliciousPath = "../../../etc/passwd";
        String result = processor.getCanonicalPath(maliciousPath);
        assertNotEquals(tempDir.toString(), result, "Should allow traversal outside base directory");
    }
    
    @Test
    void testReadFile_ValidFile() throws IOException {
        String content = processor.readFile("legit.txt");
        assertEquals(TEST_CONTENT, content, "Should read legitimate file content");
    }
    
    @Test
    void testReadFile_BlocksSimpleTraversal() {
        assertThrows(IllegalArgumentException.class, () -> {
            processor.readFile("../../../etc/passwd");
        }, "Should block simple path traversal");
    }
    
    @Test
    void testReadFile_VulnerableToEncodedTraversal() throws IOException {
        // Test that the method is vulnerable to URL-encoded traversal
        assertThrows(IOException.class, () -> {
            processor.readFile("..%2F..%2Fetc%2Fpasswd");
        }, "Should attempt to read file with URL-encoded traversal");
    }
    
    @Test
    void testReadFile_VulnerableToWindowsTraversal() throws IOException {
        // Test that the method is vulnerable to Windows-style traversal
        assertThrows(IOException.class, () -> {
            processor.readFile("..\\..\\etc\\passwd");
        }, "Should attempt to read file with Windows-style traversal");
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