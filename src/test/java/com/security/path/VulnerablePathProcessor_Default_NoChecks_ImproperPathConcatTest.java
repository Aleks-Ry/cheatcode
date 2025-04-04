package com.security.path;

class VulnerablePathProcessor_Default_NoChecks_ImproperPathConcatTest extends BasePathProcessorTest {
    @Override
    PathProcessor createProcessor(String baseDir) {
        return new VulnerablePathProcessor_Default_NoChecks_ImproperPathConcat(baseDir);
    }

    @Override
    String getProcessorName() {
        return "Vulnerable Path Processor (No Checks and Improper Path String Concat)";
    }
} 