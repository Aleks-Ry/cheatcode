package com.security.path;

class VulnerablePathProcessor_ImproperAPIUse_MultipartFileGetOriginalNameTest extends BasePathProcessorTest {
    @Override
    PathProcessor createProcessor(String baseDir) {
        return new VulnerablePathProcessor_ImproperAPIUse_MultipartFileGetOriginalName(baseDir);
    }

    @Override
    String getProcessorName() {
        return "Vulnerable Path Processor (FileAPI MultipartFile)";
    }
} 