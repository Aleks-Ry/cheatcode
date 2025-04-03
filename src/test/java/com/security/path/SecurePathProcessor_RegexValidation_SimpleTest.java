package com.security.path;

class SecurePathProcessor_RegexValidation_SimpleTest extends BasePathProcessorTest {
    @Override
    PathProcessor createProcessor(String baseDir) {
        return new SecurePathProcessor_RegexValidation_Simple(baseDir);
    }

    @Override
    String getProcessorName() {
        return "Secure Path Processor (Regex Validation Simple)";
    }
} 