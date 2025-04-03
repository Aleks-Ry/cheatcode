package com.security.path;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.api.io.TempDir;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.io.File;
import java.nio.file.NoSuchFileException;
import java.util.stream.Stream;
import static org.junit.jupiter.api.Assertions.*;

class BasePathProcessorTest {
    
    private PathProcessor processor;
    private static final String PURPLE = "\u001B[35m";
    private static final String RESET = "\u001B[0m";
    private static final String PUBLIC_FILE_CONTENT = "Test file content";
    private static final String SUBFOLDER_CONTENT = "Subfolder file content";
    private static final String SECRET_FILE_CONTENT = "Attack succeeded! CONFIDENTIAL DATA disclosed!";
    @TempDir
    Path tempDir;

    static Stream<Class<? extends PathProcessor>> processorClasses() {
        return Stream.of(
            SecurePathProcessor_FileAPI_GetName.class,
            SecurePathProcessor_RegexValidation_Simple.class,
            SecurePathProcessor_RegexValidation_Extended.class,
            SecurePathProcessor_RelativePath_Validation.class,
            InsecurePathProcessor_FileAPI_MultipartFileGetOriginalName.class,
            InsecurePathProcessor_NoChecks.class,
            InsecurePathProcessor_NoChecks_PathStringConcat.class,
            InsecurePathProcessor_StringContains_BypassableCheck.class
        );
    }
    
    @BeforeEach
    void setUp() throws Exception {
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
    
    @ParameterizedTest
    @MethodSource("processorClasses")
    void testReadFile_LegitimateFile_ShouldReadLegitFile(Class<? extends PathProcessor> processorClass) throws Exception {
        processor = processorClass
            .getConstructor(String.class)
            .newInstance(tempDir.toString());
            
        ReadFileResult result = processor.readFile("legit.txt");
        assertFalse(result.IsPathTraversalAttackDetected);
        assertFalse(result.IsPathSanitized);
        assertEquals(PUBLIC_FILE_CONTENT, result.fileReadResult);
        assertNull(result.fileReadException);
    }
    
    @ParameterizedTest
    @MethodSource("processorClasses")
    void testReadFile_LegitimateSubfolderFile_ShouldReadLegitFile(Class<? extends PathProcessor> processorClass) throws Exception {
        processor = processorClass
            .getConstructor(String.class)
            .newInstance(tempDir.toString());
            
        ReadFileResult result = processor.readFile("SomeSubFolder" + File.separator + "sublegit.txt");
        assertFalse(result.IsPathTraversalAttackDetected);
        assertFalse(result.IsPathSanitized);
        assertEquals(SUBFOLDER_CONTENT, result.fileReadResult);
        assertNull(result.fileReadException);
    }
    
    @ParameterizedTest
    @MethodSource("processorClasses")
    void testReadFile_SingleLevelTraversal_ShouldDetectAttack(Class<? extends PathProcessor> processorClass) throws Exception {
        processor = processorClass
            .getConstructor(String.class)
            .newInstance(tempDir.toString());
            
        ReadFileResult result = processor.readFile("../pwnStorage/secret.txt");
        assertNull(result.fileReadResult, PURPLE + processor.getClass().getSimpleName() + " - Attack succeeded! Secret file was read! Content: " + result.fileReadResult + RESET);
        assertTrue(result.IsPathTraversalAttackDetected, processor.getClass().getSimpleName() + " - Attack was not detected");
        assertEquals(processor.CanSanitize, result.IsPathSanitized);
        assertNotNull(result.fileReadException);        
        assertTrue(result.fileReadException instanceof UnsupportedOperationException || 
                  result.fileReadException instanceof NoSuchFileException,
                  processor.getClass().getSimpleName() + " - Expected UnsupportedOperationException or NoSuchFileException, but got: " + 
                  (result.fileReadException != null ? result.fileReadException.getClass().getSimpleName() : "null"));
    }
    
    @ParameterizedTest
    @MethodSource("processorClasses")
    void testReadFile_DoubleLevelTraversal_ShouldDetectAttack(Class<? extends PathProcessor> processorClass) throws Exception {
        processor = processorClass
            .getConstructor(String.class)
            .newInstance(tempDir.toString());
            
        ReadFileResult result = processor.readFile("../../pwnStorage/secret.txt");
        assertNull(result.fileReadResult, PURPLE + processor.getClass().getSimpleName() + " - Attack succeeded! Secret file was read! Content: " + result.fileReadResult + RESET);
        assertTrue(result.IsPathTraversalAttackDetected, processor.getClass().getSimpleName() + " - Attack was not detected");
        assertEquals(processor.CanSanitize, result.IsPathSanitized);
        assertNotNull(result.fileReadException);        
        assertTrue(result.fileReadException instanceof UnsupportedOperationException || 
                  result.fileReadException instanceof NoSuchFileException,
                  processor.getClass().getSimpleName() + " - Expected UnsupportedOperationException or NoSuchFileException, but got: " + 
                  (result.fileReadException != null ? result.fileReadException.getClass().getSimpleName() : "null"));
    }
    
    @ParameterizedTest
    @MethodSource("processorClasses")
    void testReadFile_DoubleDotTraversal_ShouldDetectAttack(Class<? extends PathProcessor> processorClass) throws Exception {
        processor = processorClass
            .getConstructor(String.class)
            .newInstance(tempDir.toString());
            
        ReadFileResult result = processor.readFile("....//....//pwnStorage//secret.txt");
        assertNull(result.fileReadResult, PURPLE + processor.getClass().getSimpleName() + " - Attack succeeded! Secret file was read! Content: " + result.fileReadResult + RESET);
        assertTrue(result.IsPathTraversalAttackDetected, processor.getClass().getSimpleName() + " - Attack was not detected");
        assertEquals(processor.CanSanitize, result.IsPathSanitized);
        assertNotNull(result.fileReadException);
        assertTrue(result.fileReadException instanceof UnsupportedOperationException || 
                  result.fileReadException instanceof NoSuchFileException,
                  processor.getClass().getSimpleName() + " - Expected UnsupportedOperationException or NoSuchFileException, but got: " + 
                  (result.fileReadException != null ? result.fileReadException.getClass().getSimpleName() : "null"));
    }
    
    @ParameterizedTest
    @MethodSource("processorClasses")
    void testReadFile_WindowsStyleTraversal_ShouldDetectAttack(Class<? extends PathProcessor> processorClass) throws Exception {
        processor = processorClass
            .getConstructor(String.class)
            .newInstance(tempDir.toString());
            
        ReadFileResult result = processor.readFile("..\\..\\pwnStorage\\secret.txt");
        assertNull(result.fileReadResult, PURPLE + processor.getClass().getSimpleName() + " - Attack succeeded! Secret file was read! Content: " + result.fileReadResult + RESET);
        assertTrue(result.IsPathTraversalAttackDetected, processor.getClass().getSimpleName() + " - Attack was not detected");
        assertEquals(processor.CanSanitize, result.IsPathSanitized);
        assertNotNull(result.fileReadException);
        assertTrue(result.fileReadException instanceof UnsupportedOperationException || 
                  result.fileReadException instanceof NoSuchFileException,
                  processor.getClass().getSimpleName() + " - Expected UnsupportedOperationException or NoSuchFileException, but got: " + 
                  (result.fileReadException != null ? result.fileReadException.getClass().getSimpleName() : "null"));
    }
    
    @ParameterizedTest
    @MethodSource("processorClasses")
    void testReadFile_NullInput_ShouldReadNothing(Class<? extends PathProcessor> processorClass) throws Exception {
        processor = processorClass
            .getConstructor(String.class)
            .newInstance(tempDir.toString());
            
        ReadFileResult result = processor.readFile(null);
        assertFalse(result.IsPathTraversalAttackDetected);
        assertFalse(result.IsPathSanitized);
        assertNotNull(result.fileReadException);
        assertTrue(result.fileReadException instanceof IllegalArgumentException);
    }
} 