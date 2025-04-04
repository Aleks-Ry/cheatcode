package com.security.path;

class VulnerablePathProcessor_Default_NoChecksTest extends BasePathProcessorTest {
    @Override
    PathProcessor createProcessor(String baseDir) {
        return new VulnerablePathProcessor_Default_NoChecks(baseDir);
    }

    @Override
    String getProcessorName() {
        return "Vulnerable Path Processor (No Checks)";
    }
} 