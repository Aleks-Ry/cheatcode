package com.security.path;

class InsecurePathProcessor_NoChecks_PathStringConcatTest extends BasePathProcessorTest {
    @Override
    PathProcessor createProcessor(String baseDir) {
        return new InsecurePathProcessor_NoChecks_PathStringConcat(baseDir);
    }

    @Override
    String getProcessorName() {
        return "Insecure Path Processor (No Checks Path String Concat)";
    }
} 