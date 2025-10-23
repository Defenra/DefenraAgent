#!/bin/bash

set -e

echo "====================================="
echo "Defenra Agent Quick Start"
echo "====================================="
echo ""

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo "❌ Error: Go is not installed"
    echo "Please install Go 1.21 or higher"
    echo "Visit: https://golang.org/dl/"
    exit 1
fi

GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
echo "✓ Go version: $GO_VERSION"

# Check if .env exists
if [ ! -f ".env" ]; then
    echo ""
    echo "Creating .env file..."
    echo ""
    read -p "Agent ID: " AGENT_ID
    read -sp "Agent Key: " AGENT_KEY
    echo ""
    read -p "Core URL (default: http://localhost:3000): " CORE_URL
    CORE_URL=${CORE_URL:-http://localhost:3000}
    
    cat > .env << EOF
AGENT_ID=$AGENT_ID
AGENT_KEY=$AGENT_KEY
CORE_URL=$CORE_URL
POLLING_INTERVAL=60
LOG_LEVEL=info
CACHE_SIZE=10000
EOF
    
    echo "✓ .env file created"
else
    echo "✓ .env file exists"
fi

# Download dependencies
echo ""
echo "Downloading dependencies..."
go mod download
echo "✓ Dependencies downloaded"

# Download GeoIP database if not exists
if [ ! -f "GeoLite2-City.mmdb" ]; then
    echo ""
    echo "Downloading GeoIP database..."
    wget -q --show-progress -O GeoLite2-City.mmdb \
        https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb
    echo "✓ GeoIP database downloaded"
else
    echo "✓ GeoIP database exists"
fi

# Build
echo ""
echo "Building Defenra Agent..."
go build -o defenra-agent .
echo "✓ Build complete"

# Export environment variables
echo ""
echo "Loading environment variables..."
export $(cat .env | xargs)
echo "✓ Environment loaded"

# Show info
echo ""
echo "====================================="
echo "Ready to start!"
echo "====================================="
echo ""
echo "Configuration:"
echo "  - Agent ID: $AGENT_ID"
echo "  - Core URL: $CORE_URL"
echo "  - Polling Interval: 60 seconds"
echo ""
echo "Starting Defenra Agent..."
echo ""
echo "Note: You may need sudo to bind to ports 53, 80, 443"
echo ""

# Check if running as root or with CAP_NET_BIND_SERVICE
if [ "$EUID" -ne 0 ]; then
    echo "⚠️  Warning: Not running as root"
    echo "Privileged ports (53, 80, 443) may not be accessible"
    echo ""
    echo "Options:"
    echo "  1. Run with sudo: sudo -E ./defenra-agent"
    echo "  2. Give capabilities: sudo setcap 'cap_net_bind_service=+ep' ./defenra-agent"
    echo "  3. Use alternative ports (requires firewall rules)"
    echo ""
    read -p "Continue anyway? (y/N): " CONTINUE
    if [ "$CONTINUE" != "y" ] && [ "$CONTINUE" != "Y" ]; then
        echo "Exiting..."
        exit 0
    fi
fi

echo ""
echo "Starting agent..."
echo "Press Ctrl+C to stop"
echo ""

./defenra-agent
