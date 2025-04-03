package com.security.path;

class InsecurePathProcessor_NoChecksTest extends BasePathProcessorTest {
    @Override
    PathProcessor createProcessor(String baseDir) {
        return new InsecurePathProcessor_NoChecks(baseDir);
    }

    @Override
    String getProcessorName() {
        return "Insecure Path Processor (No Checks)";
    }
} 