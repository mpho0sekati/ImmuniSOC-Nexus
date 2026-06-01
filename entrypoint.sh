#!/bin/sh

# Set required environment variables for the proxy if not provided
export PORT=8080
export HANDSHAKE_SECRET_TOKEN=${HANDSHAKE_SECRET_TOKEN:-"HF_Nexus_Secret_2026"}
export SECURITY_ADMIN_TOKEN=${SECURITY_ADMIN_TOKEN:-"AdminNexus#2026#SecureAccess"}
export LOG_SECRET=${LOG_SECRET:-"HF_Log_Secret_2026"}
export DECEPTION_SECRET=${DECEPTION_SECRET:-"HF_Deception_Secret_2026"}
export BACKEND_URL=${BACKEND_URL:-"http://localhost:8081"} # Mock or internal

# Start Go Backend in background
echo "Starting Go Proxy Backend..."
/app/proxy-main &

# Start Nginx in foreground
echo "Starting Nginx Frontend..."
nginx -g "daemon off;"
