package com.security.path;

class SecurePathProcessor_FileAPI_GetNameTest extends BasePathProcessorTest {
    @Override
    PathProcessor createProcessor(String baseDir) {
        return new SecurePathProcessor_FileAPI_GetName(baseDir);
    }

    @Override
    String getProcessorName() {
        return "Secure Path Processor (FileAPI GetName)";
    }
} 