# ImmuniSOC-Nexus: Quick Start Guide

This repository contains the ImmuniSOC-Nexus cybersecurity platform. Follow these steps to get the system up and running for a preview.

## Prerequisites
- [Docker](https://www.docker.com/products/docker-desktop)
- [Docker Compose](https://docs.docker.com/compose/install/)

## Quick Setup

1. **Configure Environment Variables**
   Copy the example environment file to `.env`:
   ```bash
   cp .env.example .env
   ```
   *Note: For a quick preview, the default values in `.env.example` will work.*

2. **Start the Platform**
   Run the following command in the root directory:
   ```bash
   docker compose up --build
   ```
   Alternatively, use the helper scripts:
   - Windows (PowerShell): `./start-all.ps1`
   - Windows (CMD): `start-all.cmd`

3. **Access the Dashboard**
   Once all containers are running:
   - **Frontend Dashboard**: [http://localhost:80](http://localhost:80)
   - **Proxy API**: [http://localhost:8080](http://localhost:8080)

## System Architecture

- **Frontend**: React/Tailwind/Vite dashboard serving security telemetry.
- **Proxy (Neutrophil)**: Go-based security gateway with rate limiting, deception, and T-Cell integration.
- **OPA**: Open Policy Agent for dynamic authorization and compliance.
- **Backend**: A mock service demonstrating protected resource access.

## Manual Development Setup

If you prefer to run components manually:

### Proxy (Go)
```bash
cd proxy
go mod download
go run cmd/proxy/main.go
```

### Frontend (React)
```bash
cd frontend
npm install
npm run dev
```

---
*ImmuniSOC-Nexus: Bio-Inspired Network Security*
