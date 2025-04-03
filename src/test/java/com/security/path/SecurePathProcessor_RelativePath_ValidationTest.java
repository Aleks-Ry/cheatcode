package com.security.path;

class SecurePathProcessor_RelativePath_ValidationTest extends BasePathProcessorTest {
    @Override
    PathProcessor createProcessor(String baseDir) {
        return new SecurePathProcessor_RelativePath_Validation(baseDir);
    }

    @Override
    String getProcessorName() {
        return "Secure Path Processor (Relative Path Validation)";
    }
} 