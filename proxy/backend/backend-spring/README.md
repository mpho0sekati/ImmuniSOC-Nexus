# Backend Services for ImmuniSOC-Nexus

## Overview
This directory contains backend services that integrate with the ImmuniSOC-Nexus security platform.

## Services

### Spring Boot Backend
- Provides backend APIs for the proxy to communicate with
- Implements security measures that complement the proxy's functionality
- Supports multiple tiers of access (critical, standard, public)

## Recent Updates

### May 27, 2026 - Monocyte Immutable Logging Integration
- Added support for logging security events to immutable logs
- Enhanced audit trail capabilities for compliance reporting
- Updated API endpoints to support POPIA breach notifications

### Earlier Updates
- Integrated with T-Cell Self-Healing Engine for autonomous response
- Added egress protection capabilities to prevent data exfiltration
- Enhanced OPA policy enforcement for dynamic access control
- Improved deception element injection for better attacker detection

## Architecture

The backend services work in conjunction with the Neutrophil Proxy to provide a comprehensive security solution. All communication passes through the proxy, which applies security controls before forwarding requests to the appropriate backend service.

## Security Features

- Multi-tier access control (critical, standard, public)
- Integration with deception elements
- Compliance with POPIA regulations
- Cryptographic security measures
- Automated threat response

## Setup

Follow the setup instructions in the main documentation for complete deployment guidance.