package com.security.path;

class SecurePathProcessor_RegexValidation_ExtendedTest extends BasePathProcessorTest {
    @Override
    PathProcessor createProcessor(String baseDir) {
        return new SecurePathProcessor_RegexValidation_Extended(baseDir);
    }

    @Override
    String getProcessorName() {
        return "Secure Path Processor (Regex Validation Extended)";
    }
} 