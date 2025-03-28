# Path Security Testing Project

This project demonstrates secure and insecure implementations of path processing functions, focusing on path traversal vulnerabilities. It serves as an educational tool to understand common path traversal vulnerabilities and how to prevent them.

## Project Structure

- `src/main/java/com/security/path/`
  - `InsecurePathProcessor.java`: Contains intentionally vulnerable implementations
  - `SecurePathProcessor.java`: Contains secure implementations with proper validation

- `src/test/java/com/security/path/`
  - `InsecurePathProcessorTest.java`: Tests demonstrating vulnerabilities
  - `SecurePathProcessorTest.java`: Tests demonstrating secure implementations

## Features

### Insecure Implementation Examples
- Direct path concatenation without validation
- Path normalization without validation
- Simple string-based path traversal detection
- Unsafe canonical path resolution

### Secure Implementation Examples
- Input validation
- Path normalization
- Comprehensive path traversal detection
- Safe path resolution
- Null checks
- Exception handling

## Running the Tests

To run the tests, use Maven:

```bash
mvn test
```

## Learning Objectives

1. Understanding path traversal vulnerabilities
2. Common bypass techniques for path traversal
3. Best practices for path processing
4. Input validation techniques
5. Path normalization and canonicalization
6. Exception handling in path processing

## Security Considerations

The insecure implementations in this project are intentionally vulnerable and should never be used in production code. They serve only as examples of common mistakes and vulnerabilities.

## Dependencies

- Java 11 or higher
- JUnit 5
- Mockito (for testing)

## License

This project is open source and available under the MIT License. 