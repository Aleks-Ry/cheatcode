package com.security.path;

class InsecurePathProcessor_FileAPI_MultipartFileGetOriginalNameTest extends BasePathProcessorTest {
    @Override
    PathProcessor createProcessor(String baseDir) {
        return new InsecurePathProcessor_FileAPI_MultipartFileGetOriginalName(baseDir);
    }

    @Override
    String getProcessorName() {
        return "Insecure Path Processor (FileAPI MultipartFile)";
    }
} 