package com.security.path;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import static org.junit.jupiter.api.Assertions.*;

class SecurePathProcessorTest {
    
    private SecurePathProcessor processor;
    private static final String TEST_CONTENT = "Test file content";
    @TempDir
    Path tempDir;
    
    @BeforeEach
    void setUp() throws IOException {
        // Create a test directory structure
        processor = new SecurePathProcessor(tempDir.toString());
        
        // Create a legitimate test file
        Path legitFile = tempDir.resolve("legit.txt");
        Files.writeString(legitFile, TEST_CONTENT);
        
        // Create a "sensitive" file in a parent directory
        Path sensitiveDir = tempDir.getParent().resolve("sensitive");
        Files.createDirectories(sensitiveDir);
        Path sensitiveFile = sensitiveDir.resolve("secret.txt");
        Files.writeString(sensitiveFile, "SENSITIVE DATA");
    }
    
    @Test
    void testConstructor_NullBaseDirectory() {
        assertThrows(IllegalArgumentException.class, () -> {
            new SecurePathProcessor(null);
        }, "Should reject null base directory");
    }
    
    @Test
    void testConstructor_EmptyBaseDirectory() {
        assertThrows(IllegalArgumentException.class, () -> {
            new SecurePathProcessor("");
        }, "Should reject empty base directory");
        
        assertThrows(IllegalArgumentException.class, () -> {
            new SecurePathProcessor("   ");
        }, "Should reject whitespace base directory");
    }
    
    @Test
    void testConcatenatePaths_ValidPath() {
        String result = processor.concatenatePaths(tempDir.toString(), "legit.txt");
        assertTrue(result.endsWith("legit.txt"), "Should properly concatenate valid paths");
        assertFalse(result.contains(".."), "Should not contain path traversal elements");
    }
    
    @Test
    void testConcatenatePaths_RejectsTraversal() {
        assertThrows(IllegalArgumentException.class, () -> {
            processor.concatenatePaths(tempDir.toString(), "../../../etc/passwd");
        }, "Should reject basic traversal");
        
        assertThrows(IllegalArgumentException.class, () -> {
            processor.concatenatePaths(tempDir.toString(), "..\\..\\etc\\passwd");
        }, "Should reject Windows-style traversal");
    }
    
    @Test
    void testConcatenatePaths_RejectsNull() {
        assertThrows(IllegalArgumentException.class, () -> {
            processor.concatenatePaths(null, "test.txt");
        }, "Should reject null base path");
        
        assertThrows(IllegalArgumentException.class, () -> {
            processor.concatenatePaths(tempDir.toString(), null);
        }, "Should reject null user input");
    }
    
    @Test
    void testContainsPathTraversal_DetectsVariousAttempts() {
        assertTrue(processor.containsPathTraversal("../test.txt"), "Should detect simple traversal");
        assertTrue(processor.containsPathTraversal("..\\test.txt"), "Should detect Windows-style traversal");
        assertTrue(processor.containsPathTraversal("test/../../../etc/passwd"), "Should detect nested traversal");
        assertTrue(processor.containsPathTraversal("test\\..\\..\\etc\\passwd"), "Should detect nested Windows-style traversal");
        
        assertFalse(processor.containsPathTraversal("legit.txt"), "Should allow legitimate filenames");
        assertFalse(processor.containsPathTraversal("dir/file.txt"), "Should allow subdirectories");
        assertFalse(processor.containsPathTraversal(null), "Should handle null input");
    }
    
    @Test
    void testReadFile_ValidFile() throws IOException {
        String content = processor.readFile("legit.txt");
        assertEquals(TEST_CONTENT, content, "Should read legitimate file content");
    }
    
    @Test
    void testReadFile_BlocksTraversal() {
        assertThrows(IllegalArgumentException.class, () -> {
            processor.readFile("../../../etc/passwd");
        }, "Should block basic traversal attempt");
        
        assertThrows(IllegalArgumentException.class, () -> {
            processor.readFile("..\\..\\etc\\passwd");
        }, "Should block Windows-style traversal");
        
        assertThrows(IllegalArgumentException.class, () -> {
            processor.readFile("../sensitive/secret.txt");
        }, "Should block access to parent directory");
    }
    
    @Test
    void testReadFile_BlocksEncodedTraversal() {
        assertThrows(IllegalArgumentException.class, () -> {
            processor.readFile("..%2F..%2Fetc%2Fpasswd");
        }, "Should block URL encoded traversal");
        
        assertThrows(IllegalArgumentException.class, () -> {
            processor.readFile("....//....//etc/passwd");
        }, "Should block double dot traversal");
    }
    
    @Test
    void testReadFile_NullInput() {
        assertThrows(IllegalArgumentException.class, () -> {
            processor.readFile(null);
        }, "Should reject null input");
    }
    
    @Test
    void testReadFile_NonexistentFile() {
        assertThrows(IOException.class, () -> {
            processor.readFile("nonexistent.txt");
        }, "Should throw IOException for nonexistent files");
    }
} 