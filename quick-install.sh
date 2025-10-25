#!/bin/bash

set -e

# Quick installation script for Defenra Agent
# Usage: curl -sSL https://raw.githubusercontent.com/Defenra/DefenraAgent/main/quick-install.sh | sudo bash

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

INSTALL_DIR="/opt/defenra-agent"
GITHUB_REPO="Defenra/DefenraAgent"
GITHUB_API="https://api.github.com/repos/${GITHUB_REPO}/releases/latest"

print_success() { echo -e "${GREEN}✓${NC} $1"; }
print_error() { echo -e "${RED}✗${NC} $1"; }
print_warning() { echo -e "${YELLOW}⚠${NC} $1"; }
print_info() { echo -e "${BLUE}ℹ${NC} $1"; }

echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}   Defenra Agent Quick Install${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    print_error "This script must be run as root"
    echo "Please use: curl -sSL https://raw.githubusercontent.com/Defenra/DefenraAgent/main/quick-install.sh | sudo bash"
    exit 1
fi

print_success "Running as root"

# Check for required commands
for cmd in wget curl systemctl; do
    if ! command -v $cmd &> /dev/null; then
        print_error "Missing required command: $cmd"
        echo "Please install it first"
        exit 1
    fi
done
print_success "Required commands available"

# Detect platform
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$ARCH" in
    x86_64|amd64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *)
        print_error "Unsupported architecture: $ARCH"
        exit 1
        ;;
esac

case "$OS" in
    linux) OS="linux" ;;
    darwin) OS="darwin" ;;
    *)
        print_error "Unsupported operating system: $OS"
        exit 1
        ;;
esac

PLATFORM="${OS}-${ARCH}"
BINARY_NAME="defenra-agent-${PLATFORM}"

print_success "Detected platform: ${PLATFORM}"

# Get credentials from environment or use defaults
if [ -z "$AGENT_ID" ]; then
    print_warning "AGENT_ID not set in environment"
    print_info "Using placeholder - YOU MUST CONFIGURE BEFORE STARTING"
    AGENT_ID="agent_change_me"
fi

if [ -z "$AGENT_KEY" ]; then
    print_warning "AGENT_KEY not set in environment"
    print_info "Using placeholder - YOU MUST CONFIGURE BEFORE STARTING"
    AGENT_KEY="change_me"
fi

if [ -z "$CORE_URL" ]; then
    CORE_URL="https://core.defenra.com"
fi

print_info "Agent ID: $AGENT_ID"
print_info "Core URL: $CORE_URL"

# Fetch latest release
print_info "Fetching latest release..."
RELEASE_INFO=$(curl -s "$GITHUB_API")
TAG_NAME=$(echo "$RELEASE_INFO" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')

if [ -z "$TAG_NAME" ]; then
    print_error "Could not fetch latest release"
    echo ""
    echo "For full installation with more options, use:"
    echo "  wget https://raw.githubusercontent.com/Defenra/DefenraAgent/main/install.sh"
    echo "  chmod +x install.sh"
    echo "  sudo ./install.sh"
    exit 1
fi

print_success "Latest release: ${TAG_NAME}"

# Download binary
DOWNLOAD_URL="https://github.com/${GITHUB_REPO}/releases/download/${TAG_NAME}/${BINARY_NAME}.tar.gz"
print_info "Downloading binary..."

if ! wget -q --show-progress -O "/tmp/${BINARY_NAME}.tar.gz" "$DOWNLOAD_URL" 2>&1; then
    print_error "Failed to download binary"
    exit 1
fi

print_success "Binary downloaded"

# Extract
print_info "Extracting..."
tar -xzf "/tmp/${BINARY_NAME}.tar.gz" -C /tmp

# Create user
if ! id "defenra" &>/dev/null; then
    print_info "Creating user 'defenra'..."
    useradd -r -s /bin/false -d $INSTALL_DIR -c "Defenra Agent" defenra
fi

# Create directory
print_info "Creating installation directory..."
mkdir -p $INSTALL_DIR
cp "/tmp/${BINARY_NAME}" "$INSTALL_DIR/defenra-agent"
chown -R defenra:defenra $INSTALL_DIR
chmod 755 "$INSTALL_DIR/defenra-agent"

# Note: Capabilities are granted via systemd service (AmbientCapabilities)
print_info "Network capabilities will be granted via systemd service"

# Download GeoIP database
print_info "Downloading GeoIP database..."
if wget -q --show-progress -O "$INSTALL_DIR/GeoLite2-City.mmdb" \
    "https://s3.tebi.io/wzrd/GeoLite2-City.mmdb" 2>&1; then
    chown defenra:defenra "$INSTALL_DIR/GeoLite2-City.mmdb"
    print_success "GeoIP database downloaded"
else
    print_warning "GeoIP download failed, GeoDNS will not work"
fi

# Create systemd service
print_info "Creating systemd service..."
cat > /etc/systemd/system/defenra-agent.service << EOF
[Unit]
Description=Defenra Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=defenra
Group=defenra
WorkingDirectory=$INSTALL_DIR
Environment="AGENT_ID=$AGENT_ID"
Environment="AGENT_KEY=$AGENT_KEY"
Environment="CORE_URL=$CORE_URL"
Environment="POLLING_INTERVAL=60"
Environment="LOG_LEVEL=info"
ExecStart=$INSTALL_DIR/defenra-agent
Restart=always
RestartSec=10

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$INSTALL_DIR

LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

# Enable and start
print_info "Enabling service..."
systemctl daemon-reload
systemctl enable defenra-agent

# Don't auto-start if using placeholder credentials
if [ "$AGENT_ID" = "agent_change_me" ] || [ "$AGENT_KEY" = "change_me" ]; then
    print_warning "Service NOT started - placeholder credentials detected"
    echo ""
    echo -e "${YELLOW}⚠ IMPORTANT: Configure credentials before starting${NC}"
    echo ""
    echo "1. Edit service file:"
    echo "   sudo nano /etc/systemd/system/defenra-agent.service"
    echo ""
    echo "2. Update AGENT_ID and AGENT_KEY with real values"
    echo ""
    echo "3. Reload and start:"
    echo "   sudo systemctl daemon-reload"
    echo "   sudo systemctl start defenra-agent"
    echo ""
else
    print_info "Starting service..."
    systemctl start defenra-agent
    
    sleep 2
    if systemctl is-active --quiet defenra-agent; then
        print_success "Service started successfully!"
    else
        print_error "Service failed to start"
        echo "Check logs: sudo journalctl -u defenra-agent -n 50"
    fi
fi

# Cleanup
rm -f "/tmp/${BINARY_NAME}.tar.gz" "/tmp/${BINARY_NAME}"

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}   Installation Complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "Location: $INSTALL_DIR"
echo "Service: defenra-agent.service"
echo ""
echo "Useful commands:"
echo "  • Status:  sudo systemctl status defenra-agent"
echo "  • Logs:    sudo journalctl -u defenra-agent -f"
echo "  • Restart: sudo systemctl restart defenra-agent"
echo "  • Health:  curl http://localhost:8080/health"
echo ""

if [ "$AGENT_ID" != "agent_change_me" ] && [ "$AGENT_KEY" != "change_me" ]; then
    echo "Testing health endpoint..."
    sleep 1
    if curl -s http://localhost:8080/health > /dev/null 2>&1; then
        print_success "Agent is running!"
    else
        print_warning "Health endpoint not responding yet"
    fi
    echo ""
fi

echo "Documentation: https://github.com/Defenra/DefenraAgent"
echo "Support: support@defenra.com"
echo ""
