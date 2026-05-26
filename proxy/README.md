# ImmuniSOC-Nexus Proxy

A comprehensive security-focused proxy system implementing advanced threat detection, authentication integrity, and regulatory compliance.

## Overview

The ImmuniSOC-Nexus Proxy is a multi-layered security solution designed to protect backend services through advanced authentication mechanisms, threat detection, and regulatory compliance enforcement. The system implements a defense-in-depth approach with multiple security controls working together.

## Architecture Components

### 1. Input Hardening & Classification (The "Brain")

- **Traffic Classification Engine**: Implements sophisticated request classification using data tier validation
- **Input Cleansing**: Uses regex patterns to reject non-alphanumeric characters in X-User contexts
- **Data Tier Validation**: Supports three distinct security tiers:
  - PUBLIC: Standard access level
  - STANDARD: Elevated access level
  - CRITICAL: Highest security access level

### 2. Middleware & Traffic Control (The "Membrane")

- **Security Headers**: Injects essential security headers:
  - X-Frame-Options: DENY
  - X-Content-Type-Options: nosniff
  - HSTS with proper max-age configuration
- **HTTP Verb Whitelisting**: Restricts access to GET/POST methods only
- **Thread-Safe Rate Limiting**: Token bucket algorithm with 100ms per client threshold
- **Error Masking**: Generic status codes with no stack trace exposure

### 3. Authentication Integrity & Shielding

- **SHA-256 HMAC Signatures**: Generates secure signatures for proxy-to-backend communication
- **Shared Secret Mechanism**: HandshakeSecretToken for proxy-backend binding
- **Cryptographic Timestamps**: 30-second validity window to prevent replay attacks
- **Constant-Time Comparison**: Uses MessageDigest.isEqual to prevent timing analysis

### 4. OPA Policy Integration (The "Consultant")

- **Policy Decision Points**: Integrates with Open Policy Agent for dynamic authorization
- **JSON Request/Response**: Proper serialization for Go-to-OPA communication
- **Boolean Decision Logic**: Returns Allow/Deny decisions for middleware integration
- **Low-Latency Communication**: 200ms timeout for optimal performance

### 5. POPIA Regulatory Compliance

- **Precise Data Processing Boundaries**: Defined in Rego policies
- **Purpose Verification**: Supports CUSTOMER_SERVICE, IDENTITY_VERIFICATION, FRAUD_PREVENTION, LEGAL_COMPLIANCE, CONSENTED_MARKETING
- **Default-Deny Policy**: Fail-closed security model
- **Data Minimization**: Automated masking for non-critical segments
- **Compliance Checking**: Validates consent, retention periods, and field access

### 6. Passive Threat Deception & Countermeasures

- **Canary Dataset Flags**: Tripwire strings deployed in system layers
- **Directory Traversal Detection**: Comprehensive query string parameter checks
- **Automated Containment**: HTTP 451 responses upon honeytoken contact
- **Forensic Logging**: Append-only event logging format for analysis
- **Early Threat Blocking**: Positioned before HMAC and OPA checks for efficiency

### 7. System Wiring (The "Nervous System")

Complete request flow:
1. Receive Request
2. Apply Secure Headers
3. Detect Threats (passive threat detection)
4. Authenticate Request (add HMAC signatures)
5. Check Rate Limiter
6. Classify Request (get Tier)
7. POPIA Compliance Check
8. Query OPA (get decision)
9. Route to backend or Block

## Technical Specifications

### Server Configuration
- **Multiplexer**: Go HTTP server with rigid, explicit path mapping
- **Timeouts**: ReadTimeout: 5s, WriteTimeout: 10s for DoS insulation
- **Error Handling**: Generic status codes with masked error details

### Dependencies
- Go 1.21+
- Open Policy Agent (OPA)
- Java Spring Boot (for backend)
- Docker & Docker Compose

## Security Features

### Authentication
- HMAC-SHA256 signatures for proxy-backend communication
- Timestamp validation with 30-second window
- Constant-time signature verification

### Threat Detection
- Directory traversal prevention
- Canary token detection
- Early blocking with HTTP 451 responses
- Comprehensive logging for forensic analysis

### Compliance
- POPIA-compliant data processing
- Purpose verification for data access
- Consent validation
- Retention period enforcement

## Deployment

The system is configured for Docker-based deployment with the following services:
- Proxy service (port 8080)
- Backend service (port 8081)
- OPA service (port 8181)

### Docker Configuration
- Isolated network (nexus-network)
- Proper service dependencies
- JSON-file logging driver for forensic preservation
- Log rotation (10MB max size, 3 files)

## Updates Log

### Initial Implementation
- Core proxy infrastructure
- Basic middleware with security headers
- Classification engine with tier validation
- HTTP verb whitelisting and rate limiting

### Authentication Integrity & Shielding
- Implemented SHA-256 HMAC signature generation
- Established shared secret mechanism for proxy-backend binding
- Configured cryptographic timestamps with 30-second validity window
- Added HMAC verification in Java Spring Boot controllers
- Implemented constant-time comparison to prevent timing attacks

### POPIA Regulatory Compliance
- Created Rego policies for precise data processing boundaries
- Implemented purpose verification rules
- Established default-deny (fail-closed) clauses
- Integrated low-latency HTTP client with 200ms timeout
- Configured OPA payload serialization
- Implemented automated data minimization/masking logic
- Added comprehensive tests for malformed compliance headers

### Passive Threat Deception & Countermeasures
- Deployed canary dataset flags and tripwire strings
- Implemented query string parameter checks for directory traversal detection
- Built automated containment triggers (HTTP 451 return state) upon honeytoken contact
- Configured append-only event logging format for forensic ingestion
- Positioned threat detection early in the pipeline for performance and security

### Logging & Container Configuration
- Updated Docker configurations with proper logging drivers
- Configured JSON-file logging for forensic preservation
- Set up log rotation and management
- Ensured proper positioning of threat detection in middleware chain

## Security Considerations

- All secrets should be loaded from environment variables in production
- Regular rotation of HandshakeSecretToken is recommended
- Monitor forensic logs regularly for threat indicators
- Keep OPA policies updated based on evolving security requirements

## License

This project is part of the ImmuniSOC-Nexus security platform.