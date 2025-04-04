package com.security.path;

class VulnerablePathProcessor_Bypassable_StringContainsCheckTest extends BasePathProcessorTest {
    @Override
    PathProcessor createProcessor(String baseDir) {
        return new VulnerablePathProcessor_Bypassable_StringContainsCheck(baseDir);
    }

    @Override
    String getProcessorName() {
        return "Vulnerable Path Processor (Bypassable 'String Contains' Check)";
    }
} 