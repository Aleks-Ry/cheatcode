package com.security.path;

class Secure_PathProcessor_ESAPI_CombinedDirectoryAndFileNameValidationTest extends BasePathProcessorTest {
    @Override
    PathProcessor createProcessor(String baseDir) {
        return new Secure_PathProcessor_ESAPI_CombinedDirectoryAndFileNameValidation(baseDir);
    }

    @Override
    String getProcessorName() {
        return "Malformed Path Processor (ESAPI Directory Path Validation)";
    }
} 