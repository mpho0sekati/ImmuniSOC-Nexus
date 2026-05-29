# ImmuniSOC-Nexus: Next-Gen Zero Trust Network Security

## Overview
ImmuniSOC-Nexus is a cutting-edge cybersecurity platform that combines advanced deception techniques, automated response mechanisms, and cryptographic logging to provide comprehensive network security with autonomous healing capabilities.

## Table of Contents
- [Architecture](#architecture)
- [Core Components](#core-components)
- [Setup](#setup)
- [Configuration](#configuration)
- [Security Features](#security-features)
- [Observability](#observability)
- [Development](#development)
- [Updates Timeline](#updates-timeline)

## Architecture
ImmuniSOC-Nexus follows a microservices architecture with the following layers:
- **Proxy Layer**: Neutrophil Proxy Membrane handles incoming requests with security controls
- **Security Services**: Individual Go services for different security functions
- **Policy Engine**: OPA (Open Policy Agent) for centralized authorization
- **Frontend**: React-based dashboard for monitoring and administration
- **Database**: Persistent storage for logs, policies, and configurations
- **Container Orchestration**: Docker Compose for local deployment

### Component Interactions
```
[External Request] -> [Neutrophil Proxy] -> [Backend Service]
                        |                     |
                   [BloodHound] <- [OPA Policy Engine]
                        |                     |
                   [T-Cell] --------> [Monocyte Logger]
                        |                     |
                   [Deception] <-----> [Dashboard]
```

## Core Components

### 1. Neutrophil Proxy Membrane
- **Advanced Threat Detection**: Implements multi-layered security controls including verb whitelisting, secure headers, rate limiting, and classification systems.
- **Deception Integration**: Injects honeytokens and fake credentials to detect attackers.
- **OPA Policy Enforcement**: Uses Open Policy Agent for dynamic access control decisions.
- **POPIA Compliance**: Includes data protection compliance for South African privacy regulations.
- **Egress Protection**: Implements outbound traffic filtering to prevent data exfiltration.

### 2. BloodHound Tracker
- **Network Topology Mapping**: Visualizes network connections and identifies attack paths.
- **Behavioral Analysis**: Tracks normal network behavior to detect anomalies.
- **Honeytrap Detection**: Identifies when attackers interact with deception elements.
- **Lateral Movement Detection**: Identifies attempts to move between systems.

### 3. Deception Generator
- **Honeytoken Creation**: Generates fake credentials, PII, and API keys.
- **Decoy Endpoint Generation**: Creates fake administrative endpoints.
- **Canary Records**: Produces fake database records to detect unauthorized access.

### 4. T-Cell Self-Healing Engine
- **Autonomous Response**: Automatically responds to threats with appropriate containment measures.
- **Containment Levels**: Implements graduated response based on threat severity.
- **Integration**: Works with BloodHound to respond to detected threats.
- **Response Actions**:
  - Enhanced logging activation
  - Temporary IP/user blocking
  - Session termination
  - Token/identity revocation
  - Security alerts

### 5. Monocyte Immutable Logging
- **Cryptographic Append-Only Logs**: Each log entry contains index, timestamp, data, previous hash, and current hash
- **Tamper-Evident Structure**: Hash chaining ensures any tampering is immediately evident
- **POPIA Breach Report Generation**: Automatic detection and reporting of privacy-related incidents
- **Asynchronous File I/O**: Background goroutine handles file writes to avoid blocking append operations
- **Synchronous Shutdown**: Ensures all pending writes complete before termination

### 6. Observability & Dashboard
- **Real-time Metrics**: View current security metrics including active threats, blocked requests, and honeytoken hits
- **Threat Visualization**: Interactive charts showing threat activity over time and threat type distribution
- **Bloodhound Path Tracking**: Visual representation of attack paths detected by the Bloodhound module
- **Containment Timeline**: Chronological view of automated containment actions taken by the T-Cell engine
- **Threat Monitoring**: Detailed view of recent security threats with classifications and details

### 7. Attack Simulation Framework
- **Insider Attack Simulation**: Tests detection of malicious activities by legitimate users
- **Lateral Movement Simulation**: Tests detection of attackers moving between systems
- **Data Exfiltration Simulation**: Tests detection of data extraction attempts
- **Honeytoken Detection Simulation**: Tests effectiveness of deception elements
- **Normal Traffic Simulation**: Establishes baseline behavior for comparison
- **Penetration Test Simulation**: Coordinated simulation combining all attack types

## Setup

### Prerequisites
- Docker and Docker Compose
- Node.js 16+ (for dashboard development)
- Go 1.19+ (for backend development)
- Git

### Local Development Setup

1. Clone the repository:
```bash
git clone https://github.com/mpho0sekati/ImmuniSOC-Nexus.git
cd ImmuniSOC-Nexus/proxy
```

2. Start the services using Docker Compose:
```bash
docker-compose up -d
```

3. For dashboard development, install dependencies and start the development server:
```bash
cd dashboard
npm install
npm start
```

4. For backend development, build and run the Go services:
```bash
cd cmd/proxy
go build -o proxy .
./proxy
```

### Production Deployment
Use the deployment/docker-compose.yml file for production deployments:
```bash
cd deployment
docker-compose -f docker-compose.yml up -d
```

## Configuration

### Environment Variables
The system uses several environment variables for configuration:

#### Proxy Configuration
- `PROXY_PORT`: Port for the proxy service (default: 8080)
- `BACKEND_URL`: URL of the backend service (default: http://localhost:8081)
- `OPA_URL`: URL of the OPA service (default: http://opa:8181)
- `LOG_FILE_PATH`: Path for log files (default: ./logs/security.log)

#### Security Configuration
- `HANDSHAKE_SECRET_TOKEN`: Secret token for internal service authentication
- `SECURITY_ADMIN_TOKEN`: Admin token for security operations
- `JWT_SECRET`: Secret for JWT token signing
- `ENCRYPTION_KEY`: Key for data encryption

#### Dashboard Configuration
- `REACT_APP_API_BASE_URL`: Base URL for API calls (default: http://localhost:8080/api)
- `REACT_APP_REFRESH_INTERVAL`: Refresh interval for dashboard data (default: 30000ms)
- `REACT_APP_RETRY_ATTEMPTS`: Number of retry attempts for API calls (default: 3)
- `REACT_APP_TIMEOUT_MS`: Timeout for API calls (default: 10000ms)

### Centralized Configuration Management
Configuration is managed through:
1. Environment variables for deployment-specific settings
2. application.properties files for Spring Boot services
3. Docker Compose files for container orchestration
4. Go configuration structs for service-specific settings

## Security Features

### Advanced Deception Techniques
- Honeytokens with unique identifiers
- Fake PII and credentials
- Decoy endpoints that appear legitimate
- Canary records for database monitoring

### Automated Response Mechanisms
- Real-time threat detection and response
- Graduated containment based on threat level
- Self-healing capabilities to restore normal operations
- Integration between detection and response systems

### Cryptographic Security
- Hash-chained immutable logs
- Secure token generation
- Encrypted communications
- Cryptographic integrity verification

### Compliance and Privacy
- POPIA compliance for South African privacy regulations
- Secure handling of personal information
- Audit trails for compliance reporting
- Data minimization principles

## Observability

### Dashboard Access
The dashboard is available at `http://localhost:3000` in development mode or the configured host in production.

### Metrics Available
- Active threats count
- Blocked requests count
- Honeytoken hits
- Active sessions
- Revoked tokens
- Total actions executed

### Logging
- Security logs in JSON format
- Immutable logging with cryptographic integrity
- Structured logging for easy parsing
- Log rotation and retention policies

## Development

### Running Tests
Run the full test suite:
```bash
go test ./...
```

Run specific package tests:
```bash
go test ./internal/bloodhound
go test ./internal/tcell
go test ./internal/monocyte
```

### Building
Build the proxy service:
```bash
cd cmd/proxy
go build
```

Build the dashboard:
```bash
cd dashboard
npm run build
```

### Contributing
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

## Updates Timeline

### May 27, 2026 - Observability & Demo Components
- Added basic React Dashboard for real-time monitoring
- Implemented attack simulation scripts (Insider, Lateral, Exfiltration, Honeytoken, Normal)
- Created final pen-test simulation framework
- Enhanced dashboard with metrics cards, charts, and timelines

### May 27, 2026 - Monocyte Immutable Logging Implementation
- Added cryptographic append-only logs with hash chaining
- Implemented tamper-evident structure with integrity verification
- Created POPIA breach report generation capability
- Added asynchronous file I/O with synchronous shutdown
- Developed comprehensive test suite for the logging system

### Earlier Updates
- Implemented T-Cell Self-Healing Engine with autonomous response mechanisms
- Enhanced egress protection with data sanitization and sensitive data pattern matching
- Improved OPA policy enforcement with threat-based blocking
- Added comprehensive test suites for core security components
- Fixed resource leaks and improved error handling throughout the system

## Support

For support, please open an issue in the GitHub repository or contact the development team.
