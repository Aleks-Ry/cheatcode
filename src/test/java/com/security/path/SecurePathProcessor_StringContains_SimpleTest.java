package com.security.path;

class SecurePathProcessor_StringContains_SimpleTest extends BasePathProcessorTest {
    @Override
    PathProcessor createProcessor(String baseDir) {
        return new SecurePathProcessor_StringContains_Simple(baseDir);
    }

    @Override
    String getProcessorName() {
        return "Secure Path Processor (String Contains Simple)";
    }
} 