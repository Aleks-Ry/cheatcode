package com.security.path;

import org.junit.jupiter.api.Test;
import java.io.IOException;
import static org.junit.jupiter.api.Assertions.*;

class SecurePathProcessor_RegexValidation_Whitelist_AlphaNumericDotTest extends BasePathProcessorTest {
    @Override
    PathProcessor createProcessor(String baseDir) {
        return new SecurePathProcessor_RegexValidation_Whitelist_AlphaNumericDot(baseDir);
    }

    @Override
    String getProcessorName() {
        return "Secure Path Processor (Regex Validation Whitelist)";
    }

    @Test
    void LegitCase_AlphanumericFileName_ShouldReadFile() throws IOException {
        ReadFileResult result = processor.readFile("legit123.txt");
        assertFalse(result.IsPathTraversalAttackDetected);
        assertFalse(result.IsPathSanitized);
        assertEquals(PUBLIC_FILE_CONTENT, result.fileReadResult);
        assertNull(result.fileReadException);
    }

    @Test
    void InvalidCase_NonAlphanumericCharacters_ShouldFail() {
        ReadFileResult result = processor.readFile("legit-file.txt");
        assertTrue(result.IsPathTraversalAttackDetected);
        assertTrue(result.IsPathSanitized);
        assertNull(result.fileReadResult);
        assertNotNull(result.fileReadException);
    }

    @Test
    void InvalidCase_SpecialCharacters_ShouldFail() {
        ReadFileResult result = processor.readFile("legit@file.txt");
        assertTrue(result.IsPathTraversalAttackDetected);
        assertTrue(result.IsPathSanitized);
        assertNull(result.fileReadResult);
        assertNotNull(result.fileReadException);
    }

    @Test
    void InvalidCase_Spaces_ShouldFail() {
        ReadFileResult result = processor.readFile("legit file.txt");
        assertTrue(result.IsPathTraversalAttackDetected);
        assertTrue(result.IsPathSanitized);
        assertNull(result.fileReadResult);
        assertNotNull(result.fileReadException);
    }
}