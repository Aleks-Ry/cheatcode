package com.security.path;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.io.File;
import java.nio.file.NoSuchFileException;
import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Path Processor Tests")
abstract class BasePathProcessorTest {
    
    protected PathProcessor processor;
    private static final String PURPLE = "\u001B[35m";
    private static final String RESET = "\u001B[0m";
    private static final String PUBLIC_FILE_CONTENT = "Test file content";
    private static final String SUBFOLDER_CONTENT = "Subfolder file content";
    private static final String SECRET_FILE_CONTENT = "Attack succeeded! CONFIDENTIAL DATA disclosed!";
    @TempDir
    protected Path tempDir;
    
    abstract PathProcessor createProcessor(String baseDir);
    abstract String getProcessorName();
    
    @BeforeEach
    void setUp() throws IOException {
        // Create a test directory structure
        processor = createProcessor(tempDir.toString());
        System.out.println("\nTesting " + processor.getClass().getSimpleName() + ":");
        
        // Create a legitimate test file
        Path legitFile = tempDir.resolve("legit.txt");
        Files.writeString(legitFile, PUBLIC_FILE_CONTENT);
        
        // Create a subfolder with a file
        Path subfolder = tempDir.resolve("SomeSubFolder");
        Files.createDirectories(subfolder);
        Path subfolderFile = subfolder.resolve("sublegit.txt");
        Files.writeString(subfolderFile, SUBFOLDER_CONTENT);
        
        // Create a "sensitive" file in a parent directory
        Path sensitiveDir = tempDir.getParent().resolve("pwnStorage");
        Files.createDirectories(sensitiveDir);
        Path sensitiveFile = sensitiveDir.resolve("secret.txt");
        Files.writeString(sensitiveFile, SECRET_FILE_CONTENT);
    }

    @Test
    void LegitCase_NormalFileName_ShouldReadFile() throws IOException {
        ReadFileResult result = processor.readFile("legit.txt");
        assertFalse(result.IsPathTraversalAttackDetected);
        assertFalse(result.IsPathSanitized);
        assertEquals(PUBLIC_FILE_CONTENT, result.fileReadResult);
        assertNull(result.fileReadException);
    }
    
    @Test
    void LegitCase_RelativePath_ShouldReadSubfolderLegitFile() throws IOException {
        ReadFileResult result = processor.readFile("SomeSubFolder" + File.separator + "sublegit.txt");
        assertFalse(result.IsPathTraversalAttackDetected);
        assertFalse(result.IsPathSanitized);
        assertEquals(SUBFOLDER_CONTENT, result.fileReadResult);
        assertNull(result.fileReadException);
    }
    
    @Test
    void AttackCase_SingleLevelTraversal() {
        ReadFileResult result = processor.readFile("../pwnStorage/secret.txt");
        assertNull(result.fileReadResult, PURPLE + "Attack succeeded! Secret file was read! Content: " + result.fileReadResult + RESET);
        assertTrue(result.IsPathTraversalAttackDetected, "Attack was not detected");
        assertEquals(processor.CanSanitize, result.IsPathSanitized);
        assertNotNull(result.fileReadException);        
        assertTrue(result.fileReadException instanceof UnsupportedOperationException || 
                  result.fileReadException instanceof NoSuchFileException,
                  "Expected UnsupportedOperationException or NoSuchFileException, but got: " + 
                  (result.fileReadException != null ? result.fileReadException.getClass().getSimpleName() : "null"));
    }
    
    @Test
    void AttackCase_DoubleLevelTraversal() {
        ReadFileResult result = processor.readFile("../../pwnStorage/secret.txt");
        assertNull(result.fileReadResult, PURPLE + "Attack succeeded! Secret file was read! Content: " + result.fileReadResult + RESET);
        assertTrue(result.IsPathTraversalAttackDetected, "Attack was not detected");
        assertEquals(processor.CanSanitize, result.IsPathSanitized);
        assertNotNull(result.fileReadException);        
        assertTrue(result.fileReadException instanceof UnsupportedOperationException || 
                  result.fileReadException instanceof NoSuchFileException,
                  "Expected UnsupportedOperationException or NoSuchFileException, but got: " + 
                  (result.fileReadException != null ? result.fileReadException.getClass().getSimpleName() : "null"));
    }
    
    @Test
    void AttackCase_DoubleDotTraversal() {
        ReadFileResult result = processor.readFile("....//....//pwnStorage//secret.txt");
        assertNull(result.fileReadResult, PURPLE + "Attack succeeded! Secret file was read! Content: " + result.fileReadResult + RESET);
        assertTrue(result.IsPathTraversalAttackDetected, "Attack was not detected");
        assertEquals(processor.CanSanitize, result.IsPathSanitized);
        assertNotNull(result.fileReadException);
        assertTrue(result.fileReadException instanceof UnsupportedOperationException || 
                  result.fileReadException instanceof NoSuchFileException,
                  "Expected UnsupportedOperationException or NoSuchFileException, but got: " + 
                  (result.fileReadException != null ? result.fileReadException.getClass().getSimpleName() : "null"));
    }
    
    @Test
    void AttackCase_WindowsStylePathTraversal() {
        ReadFileResult result = processor.readFile("..\\..\\pwnStorage\\secret.txt");
        assertNull(result.fileReadResult, PURPLE + "Attack succeeded! Secret file was read! Content: " + result.fileReadResult + RESET);
        assertTrue(result.IsPathTraversalAttackDetected, "Attack was not detected");
        assertEquals(processor.CanSanitize, result.IsPathSanitized);
        assertNotNull(result.fileReadException);
        assertTrue(result.fileReadException instanceof UnsupportedOperationException || 
                  result.fileReadException instanceof NoSuchFileException,
                  "Expected UnsupportedOperationException or NoSuchFileException, but got: " + 
                  (result.fileReadException != null ? result.fileReadException.getClass().getSimpleName() : "null"));
    }
    
    @Test
    void testReadFile_NullInput() {
        ReadFileResult result = processor.readFile(null);
        assertFalse(result.IsPathTraversalAttackDetected);
        assertFalse(result.IsPathSanitized);
        assertNotNull(result.fileReadException);
        assertTrue(result.fileReadException instanceof IllegalArgumentException);
    }
} 