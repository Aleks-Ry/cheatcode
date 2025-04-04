package com.security.path;

import java.nio.file.InvalidPathException;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class SecurePathProcessor_RegexValidation_Blacklist_ExtendedTest extends BasePathProcessorTest {
    @Override
    PathProcessor createProcessor(String baseDir) {
        return new SecurePathProcessor_RegexValidation_Blacklist_Extended(baseDir);
    }

    @Override
    String getProcessorName() {
        return "Secure Path Processor (Regex Validation Extended)";
    }
} 