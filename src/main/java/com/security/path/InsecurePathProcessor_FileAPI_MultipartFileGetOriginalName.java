package com.security.path;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.multipart.commons.CommonsMultipartFile;
import org.apache.commons.fileupload.disk.DiskFileItem;
import org.apache.commons.io.IOUtils;

/**
 * This class contains a vulnerable path processing implementation
 * that uses MultipartFile.getOriginalFilename() for path processing.
 * This is vulnerable because getOriginalFilename() returns the original filename
 * from the client without any sanitization, making it susceptible to path traversal attacks.
 */
public class InsecurePathProcessor_FileAPI_MultipartFileGetOriginalName extends PathProcessor {
    
    public InsecurePathProcessor_FileAPI_MultipartFileGetOriginalName(String baseDirectory) {
        super(baseDirectory);
    }

    /**
     * Vulnerable method that validates a path by trusting the original filename
     * @param path The path to validate
     * @return true if the path is not null, false otherwise
     */
    @Override
    public boolean validateUserInput(String path) {
        // Vulnerable: Trusts the original filename without validation
        return path != null;
    }

    /**
     * Vulnerable method that uses the original filename without sanitization
     * @param path The path to sanitize
     * @return The original filename without any sanitization
     */
    @Override
    public String sanitizeUserInput(String path) {
        if (path == null) {
            return "";
        }
        
        try {
            // Create a real MultipartFile using CommonsMultipartFile            
            MultipartFile multipartFile = this.createMockMultipartFile(path);
            return multipartFile.getOriginalFilename();
        } catch (Exception e) {
            return path;
        }
    }

    private MultipartFile createMockMultipartFile(String path) throws Exception {
        DiskFileItem fileItem = new DiskFileItem("file", "text/plain", false, path, 0, null);
        fileItem.getOutputStream().write("fake content".getBytes());
        return new CommonsMultipartFile(fileItem);
    }
} 