#!/bin/bash

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
INSTALL_DIR="/opt/defenra-agent"
SERVICE_FILE="/etc/systemd/system/defenra-agent.service"
GEOIP_URL="https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb"
GITHUB_REPO="Defenra/DefenraAgent"
GITHUB_API="https://api.github.com/repos/${GITHUB_REPO}/releases/latest"
MIN_GO_VERSION="1.21"

# Helper functions
print_header() {
    echo ""
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo ""
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

# Check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        print_error "This script must be run as root"
        echo "Please use: sudo ./install.sh"
        exit 1
    fi
    print_success "Running as root"
}

# Check if Go is installed
check_go() {
    if ! command -v go &> /dev/null; then
        print_error "Go is not installed"
        echo ""
        echo "Please install Go ${MIN_GO_VERSION} or higher first"
        echo "Visit: https://golang.org/dl/"
        echo ""
        echo "Quick install (Linux):"
        echo "  wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz"
        echo "  sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz"
        echo "  export PATH=\$PATH:/usr/local/go/bin"
        exit 1
    fi

    GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
    print_success "Go version $GO_VERSION detected"
}

# Detect platform and architecture
detect_platform() {
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)
    
    # Map architecture names
    case "$ARCH" in
        x86_64|amd64)
            ARCH="amd64"
            ;;
        aarch64|arm64)
            ARCH="arm64"
            ;;
        armv7l)
            ARCH="arm"
            ;;
        *)
            print_error "Unsupported architecture: $ARCH"
            return 1
            ;;
    esac
    
    # Map OS names
    case "$OS" in
        linux)
            OS="linux"
            ;;
        darwin)
            OS="darwin"
            ;;
        *)
            print_error "Unsupported operating system: $OS"
            return 1
            ;;
    esac
    
    PLATFORM="${OS}-${ARCH}"
    BINARY_NAME="defenra-agent-${PLATFORM}"
    
    print_success "Detected platform: ${PLATFORM}"
    return 0
}

# Download binary from GitHub releases
download_binary() {
    print_header "Downloading Pre-built Binary"
    
    if ! detect_platform; then
        print_warning "Could not detect platform, will build from source"
        return 1
    fi
    
    print_info "Fetching latest release information..."
    
    # Get latest release info
    RELEASE_INFO=$(curl -s "$GITHUB_API")
    
    if [ -z "$RELEASE_INFO" ]; then
        print_warning "Could not fetch release information"
        return 1
    fi
    
    # Extract tag name and download URL
    TAG_NAME=$(echo "$RELEASE_INFO" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
    DOWNLOAD_URL="https://github.com/${GITHUB_REPO}/releases/download/${TAG_NAME}/${BINARY_NAME}.tar.gz"
    CHECKSUM_URL="${DOWNLOAD_URL}.sha256"
    
    if [ -z "$TAG_NAME" ]; then
        print_warning "Could not determine latest release version"
        return 1
    fi
    
    print_info "Latest release: ${TAG_NAME}"
    print_info "Downloading binary from GitHub..."
    print_info "URL: ${DOWNLOAD_URL}"
    
    # Download binary
    if ! wget -q --show-progress -O "/tmp/${BINARY_NAME}.tar.gz" "$DOWNLOAD_URL" 2>&1; then
        print_warning "Failed to download binary from GitHub"
        print_info "Will build from source instead"
        return 1
    fi
    
    print_success "Binary downloaded"
    
    # Download checksum
    print_info "Downloading checksum..."
    if wget -q -O "/tmp/${BINARY_NAME}.tar.gz.sha256" "$CHECKSUM_URL" 2>&1; then
        print_info "Verifying checksum..."
        cd /tmp
        if sha256sum -c "${BINARY_NAME}.tar.gz.sha256" 2>&1 | grep -q "OK"; then
            print_success "Checksum verified"
        else
            print_warning "Checksum verification failed"
            print_info "Continuing anyway..."
        fi
        cd - > /dev/null
    else
        print_warning "Could not download checksum file"
        print_info "Skipping verification"
    fi
    
    # Extract binary
    print_info "Extracting binary..."
    if ! tar -xzf "/tmp/${BINARY_NAME}.tar.gz" -C /tmp; then
        print_error "Failed to extract binary"
        rm -f "/tmp/${BINARY_NAME}.tar.gz"
        return 1
    fi
    
    # Verify extracted binary exists
    if [ ! -f "/tmp/${BINARY_NAME}" ]; then
        print_error "Extracted binary not found"
        return 1
    fi
    
    # Move to working directory
    mv "/tmp/${BINARY_NAME}" "./defenra-agent"
    chmod +x "./defenra-agent"
    
    # Cleanup
    rm -f "/tmp/${BINARY_NAME}.tar.gz" "/tmp/${BINARY_NAME}.tar.gz.sha256"
    
    BINARY_SIZE=$(du -h defenra-agent | awk '{print $1}')
    print_success "Binary ready (size: $BINARY_SIZE)"
    
    return 0
}

# Check system requirements
check_requirements() {
    print_header "Checking System Requirements"
    
    check_root
    
    # Check for wget and curl (required for download)
    local missing_cmds=()
    for cmd in wget curl systemctl; do
        if ! command -v $cmd &> /dev/null; then
            missing_cmds+=($cmd)
        fi
    done
    
    if [ ${#missing_cmds[@]} -ne 0 ]; then
        print_error "Missing required commands: ${missing_cmds[*]}"
        echo "Please install them and try again"
        exit 1
    fi
    print_success "All required commands available"
    
    # Check Go only if we might need to build
    if ! command -v go &> /dev/null; then
        print_warning "Go is not installed"
        print_info "Will try to download pre-built binary"
        print_info "If download fails, you'll need to install Go"
    else
        GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
        print_success "Go version $GO_VERSION detected"
    fi
    
    # Check for required commands
    local missing_cmds=()
    for cmd in wget curl systemctl; do
        if ! command -v $cmd &> /dev/null; then
            missing_cmds+=($cmd)
        fi
    done
    
    if [ ${#missing_cmds[@]} -ne 0 ]; then
        print_error "Missing required commands: ${missing_cmds[*]}"
        echo "Please install them and try again"
        exit 1
    fi
    print_success "All required commands available"
    
    # Check available disk space (need at least 100MB)
    available_space=$(df /opt | tail -1 | awk '{print $4}')
    if [ $available_space -lt 102400 ]; then
        print_warning "Low disk space: ${available_space}KB available"
    else
        print_success "Sufficient disk space available"
    fi
}

# Check if running interactively
is_interactive() {
    [ -t 0 ]
}

# Get agent credentials
get_credentials() {
    print_header "Agent Configuration"
    
    # Check if credentials provided via environment
    if [ -n "$AGENT_ID" ] && [ -n "$AGENT_KEY" ]; then
        print_info "Using credentials from environment variables"
        CORE_URL=${CORE_URL:-https://core.defenra.com}
        POLLING_INTERVAL=${POLLING_INTERVAL:-60}
        LOG_LEVEL=${LOG_LEVEL:-info}
        
        echo ""
        print_info "Configuration:"
        echo "  Agent ID: $AGENT_ID"
        echo "  Core URL: $CORE_URL"
        echo "  Polling Interval: ${POLLING_INTERVAL}s"
        echo "  Log Level: $LOG_LEVEL"
        echo ""
        
        return 0
    fi
    
    # Check if running interactively
    if ! is_interactive; then
        print_error "Not running in interactive mode and no credentials provided"
        echo ""
        echo "For non-interactive installation, set environment variables:"
        echo "  export AGENT_ID=your_agent_id"
        echo "  export AGENT_KEY=your_agent_key"
        echo "  export CORE_URL=https://core.defenra.com"
        echo ""
        echo "Then run: curl -sSL https://raw.githubusercontent.com/Defenra/DefenraAgent/main/install.sh | sudo -E bash"
        echo ""
        echo "Or use quick-install.sh for a simpler setup"
        exit 1
    fi
    
    echo "Please enter your agent credentials from Defenra Core dashboard:"
    echo ""
    
    # Agent ID
    while [ -z "$AGENT_ID" ]; do
        read -p "Agent ID: " AGENT_ID
        if [ -z "$AGENT_ID" ]; then
            print_error "Agent ID cannot be empty"
        fi
    done
    
    # Agent Key
    while [ -z "$AGENT_KEY" ]; do
        read -sp "Agent Key: " AGENT_KEY
        echo ""
        if [ -z "$AGENT_KEY" ]; then
            print_error "Agent Key cannot be empty"
        fi
    done
    
    # Core URL
    read -p "Core URL (default: https://core.defenra.com): " CORE_URL
    CORE_URL=${CORE_URL:-https://core.defenra.com}
    
    # Polling interval
    read -p "Polling Interval in seconds (default: 60): " POLLING_INTERVAL
    POLLING_INTERVAL=${POLLING_INTERVAL:-60}
    
    # Log level
    read -p "Log Level (debug/info/warn/error, default: info): " LOG_LEVEL
    LOG_LEVEL=${LOG_LEVEL:-info}
    
    echo ""
    print_info "Configuration summary:"
    echo "  Agent ID: $AGENT_ID"
    echo "  Core URL: $CORE_URL"
    echo "  Polling Interval: ${POLLING_INTERVAL}s"
    echo "  Log Level: $LOG_LEVEL"
    echo ""
    
    read -p "Continue with this configuration? (y/N): " CONFIRM
    if [ "$CONFIRM" != "y" ] && [ "$CONFIRM" != "Y" ]; then
        print_error "Installation cancelled"
        exit 0
    fi
}

# Test connection to Core API
test_connection() {
    print_header "Testing Connection to Core API"
    
    print_info "Testing connection to $CORE_URL..."
    
    if curl -s --connect-timeout 10 "$CORE_URL/api/agent/poll" > /dev/null 2>&1; then
        print_success "Successfully connected to Core API"
    else
        print_warning "Could not connect to Core API"
        print_warning "This might be normal if the endpoint requires authentication"
        
        if is_interactive; then
            echo ""
            read -p "Continue anyway? (y/N): " CONTINUE
            if [ "$CONTINUE" != "y" ] && [ "$CONTINUE" != "Y" ]; then
                print_error "Installation cancelled"
                exit 0
            fi
        else
            print_info "Non-interactive mode: continuing installation"
        fi
    fi
}

# Create system user
create_user() {
    print_header "Creating System User"
    
    if id "defenra" &>/dev/null; then
        print_info "User 'defenra' already exists"
    else
        print_info "Creating user 'defenra'..."
        useradd -r -s /bin/false -d $INSTALL_DIR -c "Defenra Agent" defenra
        print_success "User 'defenra' created"
    fi
}

# Create installation directory
create_directory() {
    print_header "Creating Installation Directory"
    
    print_info "Creating directory: $INSTALL_DIR"
    mkdir -p $INSTALL_DIR
    chown defenra:defenra $INSTALL_DIR
    chmod 755 $INSTALL_DIR
    
    print_success "Installation directory created"
}

# Build the agent from source
build_agent() {
    print_header "Building Defenra Agent from Source"
    
    # Check if Go is available
    if ! command -v go &> /dev/null; then
        print_error "Go is not installed and binary download failed"
        echo ""
        echo "Please install Go ${MIN_GO_VERSION} or higher"
        echo "Visit: https://golang.org/dl/"
        echo ""
        echo "Quick install (Linux):"
        echo "  wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz"
        echo "  sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz"
        echo "  export PATH=\$PATH:/usr/local/go/bin"
        exit 1
    fi
    
    print_info "Downloading dependencies..."
    if ! go mod download; then
        print_error "Failed to download Go dependencies"
        exit 1
    fi
    
    print_info "Building binary..."
    if ! go build -ldflags "-s -w" -o defenra-agent .; then
        print_error "Build failed"
        exit 1
    fi
    
    if [ ! -f "defenra-agent" ]; then
        print_error "Build failed - binary not found"
        exit 1
    fi
    
    BINARY_SIZE=$(du -h defenra-agent | awk '{print $1}')
    print_success "Build completed (size: $BINARY_SIZE)"
}

# Get or build agent binary
get_agent_binary() {
    # First, try to download pre-built binary
    if download_binary; then
        print_success "Using pre-built binary from GitHub"
        return 0
    fi
    
    # If download fails, build from source
    print_warning "Pre-built binary not available, building from source..."
    build_agent
}

# Install binary
install_binary() {
    print_header "Installing Binary"
    
    print_info "Copying binary to $INSTALL_DIR..."
    cp defenra-agent $INSTALL_DIR/
    chown defenra:defenra $INSTALL_DIR/defenra-agent
    chmod 755 $INSTALL_DIR/defenra-agent
    
    # Note: Network capabilities are granted via systemd service
    # The service file includes: AmbientCapabilities=CAP_NET_BIND_SERVICE
    print_info "Network capabilities will be granted via systemd service"
    
    print_success "Binary installed"
}

# Download GeoIP database
download_geoip() {
    print_header "Downloading GeoIP Database"
    
    if [ -f "$INSTALL_DIR/GeoLite2-City.mmdb" ]; then
        print_info "GeoIP database already exists"
        read -p "Re-download? (y/N): " REDOWNLOAD
        if [ "$REDOWNLOAD" != "y" ] && [ "$REDOWNLOAD" != "Y" ]; then
            print_info "Skipping download"
            return
        fi
    fi
    
    print_info "Downloading from: $GEOIP_URL"
    print_info "This may take a few minutes..."
    
    if wget -q --show-progress -O "$INSTALL_DIR/GeoLite2-City.mmdb" "$GEOIP_URL"; then
        chown defenra:defenra "$INSTALL_DIR/GeoLite2-City.mmdb"
        chmod 644 "$INSTALL_DIR/GeoLite2-City.mmdb"
        
        DB_SIZE=$(du -h "$INSTALL_DIR/GeoLite2-City.mmdb" | awk '{print $1}')
        print_success "GeoIP database downloaded (size: $DB_SIZE)"
    else
        print_error "Failed to download GeoIP database"
        print_warning "Agent will work without GeoDNS features"
        echo ""
        read -p "Continue without GeoIP? (y/N): " CONTINUE
        if [ "$CONTINUE" != "y" ] && [ "$CONTINUE" != "Y" ]; then
            print_error "Installation cancelled"
            exit 1
        fi
    fi
}

# Create systemd service
create_service() {
    print_header "Creating Systemd Service"
    
    print_info "Creating service file: $SERVICE_FILE"
    
    cat > $SERVICE_FILE << EOF
[Unit]
Description=Defenra Agent - GeoDNS, HTTP/HTTPS Proxy, TCP/UDP Proxy, Lua WAF
Documentation=https://github.com/defenra/agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=defenra
Group=defenra
WorkingDirectory=$INSTALL_DIR

# Environment variables
Environment="AGENT_ID=$AGENT_ID"
Environment="AGENT_KEY=$AGENT_KEY"
Environment="CORE_URL=$CORE_URL"
Environment="POLLING_INTERVAL=$POLLING_INTERVAL"
Environment="LOG_LEVEL=$LOG_LEVEL"
Environment="CACHE_SIZE=10000"

# Start agent
ExecStart=$INSTALL_DIR/defenra-agent

# Restart policy
Restart=always
RestartSec=10
StartLimitInterval=0

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=defenra-agent

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$INSTALL_DIR
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictRealtime=true
RestrictNamespaces=true

# Resource limits
LimitNOFILE=65536
LimitNPROC=512
MemoryMax=2G
CPUQuota=200%

[Install]
WantedBy=multi-user.target
EOF
    
    print_success "Service file created"
}

# Configure firewall
configure_firewall() {
    print_header "Configuring Firewall"
    
    # Skip firewall configuration in non-interactive mode
    if ! is_interactive; then
        print_info "Non-interactive mode: skipping firewall configuration"
        print_warning "Remember to manually open ports: 53, 80, 443, 8080"
        return 0
    fi
    
    # Check if ufw is available
    if command -v ufw &> /dev/null; then
        print_info "UFW firewall detected"
        read -p "Configure UFW to allow Defenra Agent ports? (y/N): " CONFIGURE_UFW
        
        if [ "$CONFIGURE_UFW" = "y" ] || [ "$CONFIGURE_UFW" = "Y" ]; then
            print_info "Opening ports..."
            ufw allow 53/udp comment 'Defenra Agent - DNS (UDP)'
            ufw allow 53/tcp comment 'Defenra Agent - DNS (TCP)'
            ufw allow 80/tcp comment 'Defenra Agent - HTTP'
            ufw allow 443/tcp comment 'Defenra Agent - HTTPS'
            ufw allow 8080/tcp comment 'Defenra Agent - Health Check'
            print_success "Firewall rules added"
        else
            print_warning "Skipping firewall configuration"
            print_info "Remember to manually open ports: 53, 80, 443, 8080"
        fi
    elif command -v firewall-cmd &> /dev/null; then
        print_info "Firewalld detected"
        read -p "Configure firewalld to allow Defenra Agent ports? (y/N): " CONFIGURE_FW
        
        if [ "$CONFIGURE_FW" = "y" ] || [ "$CONFIGURE_FW" = "Y" ]; then
            print_info "Opening ports..."
            firewall-cmd --permanent --add-port=53/udp
            firewall-cmd --permanent --add-port=53/tcp
            firewall-cmd --permanent --add-port=80/tcp
            firewall-cmd --permanent --add-port=443/tcp
            firewall-cmd --permanent --add-port=8080/tcp
            firewall-cmd --reload
            print_success "Firewall rules added"
        else
            print_warning "Skipping firewall configuration"
            print_info "Remember to manually open ports: 53, 80, 443, 8080"
        fi
    else
        print_warning "No supported firewall detected (ufw/firewalld)"
        print_info "Remember to manually open ports: 53, 80, 443, 8080"
    fi
}

# Start the service
start_service() {
    print_header "Starting Defenra Agent"
    
    print_info "Reloading systemd daemon..."
    systemctl daemon-reload
    
    print_info "Enabling service..."
    systemctl enable defenra-agent
    
    print_info "Starting service..."
    systemctl start defenra-agent
    
    # Wait for service to start
    print_info "Waiting for service to start..."
    sleep 3
    
    if systemctl is-active --quiet defenra-agent; then
        print_success "Service started successfully"
    else
        print_error "Service failed to start"
        echo ""
        print_info "Checking logs..."
        journalctl -u defenra-agent -n 20 --no-pager
        echo ""
        print_error "Installation completed with errors"
        exit 1
    fi
}

# Verify installation
verify_installation() {
    print_header "Verifying Installation"
    
    # Check service status
    if systemctl is-active --quiet defenra-agent; then
        print_success "Service is running"
    else
        print_error "Service is not running"
        return 1
    fi
    
    # Check health endpoint
    print_info "Testing health endpoint..."
    sleep 2
    
    if curl -s http://localhost:8080/health > /dev/null 2>&1; then
        print_success "Health endpoint responding"
        
        # Show health status
        HEALTH=$(curl -s http://localhost:8080/health | python3 -m json.tool 2>/dev/null || curl -s http://localhost:8080/health)
        echo ""
        echo "$HEALTH"
        echo ""
    else
        print_warning "Health endpoint not responding yet"
        print_info "This might be normal if agent is still starting"
    fi
}

# Show installation summary
show_summary() {
    print_header "Installation Complete!"
    
    echo -e "${GREEN}Defenra Agent has been successfully installed!${NC}"
    echo ""
    echo "Installation Details:"
    echo "  • Location: $INSTALL_DIR"
    echo "  • Service: defenra-agent.service"
    echo "  • User: defenra"
    echo "  • Core URL: $CORE_URL"
    echo ""
    echo "Service Management:"
    echo "  • View logs:     sudo journalctl -u defenra-agent -f"
    echo "  • Check status:  sudo systemctl status defenra-agent"
    echo "  • Restart:       sudo systemctl restart defenra-agent"
    echo "  • Stop:          sudo systemctl stop defenra-agent"
    echo "  • Disable:       sudo systemctl disable defenra-agent"
    echo ""
    echo "Health Check:"
    echo "  • Local:  curl http://localhost:8080/health"
    echo "  • Stats:  curl http://localhost:8080/stats"
    echo ""
    echo "Testing DNS:"
    echo "  • dig @localhost example.com"
    echo ""
    echo "Uninstall:"
    echo "  • sudo ./uninstall.sh"
    echo ""
    echo -e "${BLUE}Documentation: https://github.com/defenra/agent${NC}"
    echo -e "${BLUE}Support: support@defenra.com${NC}"
    echo ""
}

# Main installation flow
main() {
    print_header "Defenra Agent Installation"
    
    check_requirements
    get_credentials
    test_connection
    create_user
    create_directory
    get_agent_binary  # Changed: now tries download first, then builds
    install_binary
    download_geoip
    create_service
    configure_firewall
    start_service
    verify_installation
    show_summary
}

# Run main installation
main
