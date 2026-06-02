#!/bin/bash

# ImmuniSOC-Nexus Easy Setup Script

echo "🚀 Starting ImmuniSOC-Nexus Setup..."

# Check for Docker
if ! [ -x "$(command -v docker)" ]; then
  echo "❌ Error: Docker is not installed. Please install Docker and try again."
  exit 1
fi

# Create .env from example if it doesn't exist
if [ ! -f .env ]; then
  echo "📄 Creating .env file from .env.example..."
  cp .env.example .env
else
  echo "✅ .env file already exists."
fi

# Build and start the containers
echo "🐳 Building and starting containers..."
docker compose up --build -d

echo ""
echo "✨ ImmuniSOC-Nexus is starting up!"
echo "------------------------------------------------"
echo "🌐 Dashboard:  http://localhost:80"
echo "🛡️  Proxy API:  http://localhost:8080"
echo "------------------------------------------------"
echo "Use 'docker compose logs -f' to view activity."
