package com.security.path;

class InsecurePathProcessor_StringContains_BypassableCheckTest extends BasePathProcessorTest {
    @Override
    PathProcessor createProcessor(String baseDir) {
        return new InsecurePathProcessor_StringContains_BypassableCheck(baseDir);
    }

    @Override
    String getProcessorName() {
        return "Insecure Path Processor (String Contains Bypassable)";
    }
} 