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

## Cloud Deployment (Render.com)

To host this for judges to see a live version, we recommend using **Render.com** (Free Tier):

1. **Push to GitHub**: Push your local changes to a new GitHub repository.
2. **Connect to Render**: Log in to Render.com and click **New > Blueprint**.
3. **Select Repository**: Select your GitHub repository.
4. **Deploy**: Render will automatically detect the `render.yaml` file and set up both the Go Backend and the React Frontend.
   - The Go backend will be assigned a URL like `https://immunisoc-proxy.onrender.com`.
   - The React frontend will be assigned a URL like `https://immunisoc-dashboard.onrender.com`.
   - The `render.yaml` automatically wires the `VITE_API_URL` environment variable so the dashboard knows how to talk to the backend.

## Hosting on Hugging Face Spaces

This project is optimized for Hugging Face Spaces using Docker:

1. **Create a New Space**: Go to [Hugging Face Spaces](https://huggingface.co/new-space) and create a new Space.
2. **Select SDK**: Select **Docker** as the SDK.
3. **Upload Files**: Upload all files from this repository.
4. **Rename Dockerfile**: Hugging Face expects the Dockerfile to be named `Dockerfile` in the root.
   - Rename `Dockerfile.hf` to `Dockerfile`.
   - Ensure `hf-nginx.conf` and `entrypoint.sh` are also in the root.
5. **Configuration**: Hugging Face will automatically build and serve the application on port 7860. The `entrypoint.sh` handles starting both the Go security gateway and the React dashboard.

---
*ImmuniSOC-Nexus: Bio-Inspired Network Security*
