#!/bin/bash

set -e

# Quick installation script for Defenra Agent
# Usage:
#   With connection URL:
#     curl -sSL https://raw.githubusercontent.com/Defenra/DefenraAgent/main/quick-install.sh | sudo CONNECT_URL="https://your-core.com/api/agent/connect/TOKEN" bash
#   
#   With manual credentials:
#     curl -sSL https://raw.githubusercontent.com/Defenra/DefenraAgent/main/quick-install.sh | sudo AGENT_ID="agent_xxx" AGENT_KEY="xxx" CORE_URL="https://your-core.com" bash

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
    echo "Please use: curl -sSL https://raw.githubusercontent.com/Defenra/DefenraAgent/main/quick-install.sh | sudo CONNECT_URL=\"YOUR_URL\" bash"
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

# Get credentials from connection URL or environment
AGENT_ID=""
AGENT_KEY=""
CORE_URL=""
POLLING_INTERVAL="60"

if [ -n "$CONNECT_URL" ]; then
    print_info "Using connection URL: $CONNECT_URL"
    
    # Extract Core URL from connection URL
    # Example: https://defenra.0c.md/api/agent/connect/token -> https://defenra.0c.md
    CORE_URL=$(echo "$CONNECT_URL" | sed -E 's|(https?://[^/]+).*|\1|')
    print_info "Core URL: $CORE_URL"
    
    # Make request to connection URL
    print_info "Connecting to agent registration..."
    CONNECT_RESPONSE=$(curl -s "$CONNECT_URL")
    
    # Check if request was successful
    if echo "$CONNECT_RESPONSE" | grep -q '"success":true'; then
        # Extract values from JSON response
        AGENT_ID=$(echo "$CONNECT_RESPONSE" | grep -o '"agentId":"[^"]*"' | sed 's/"agentId":"//;s/"//')
        AGENT_KEY=$(echo "$CONNECT_RESPONSE" | grep -o '"agentKey":"[^"]*"' | sed 's/"agentKey":"//;s/"//')
        POLLING_INTERVAL=$(echo "$CONNECT_RESPONSE" | grep -o '"pollingInterval":[0-9]*' | sed 's/"pollingInterval"://')
        
        if [ -z "$POLLING_INTERVAL" ]; then
            POLLING_INTERVAL="60"
        fi
        
        print_success "Agent registered successfully!"
        print_info "Agent ID: $AGENT_ID"
        
        # Show auto-assignment info if present
        if echo "$CONNECT_RESPONSE" | grep -q '"autoAssignment"'; then
            ASSIGNED_COUNT=$(echo "$CONNECT_RESPONSE" | grep -o '"assignedCount":[0-9]*' | sed 's/"assignedCount"://')
            AUTO_MSG=$(echo "$CONNECT_RESPONSE" | grep -o '"message":"[^"]*"' | tail -1 | sed 's/"message":"//;s/"//')
            if [ -n "$AUTO_MSG" ]; then
                print_success "$AUTO_MSG"
            fi
        fi
    else
        print_error "Failed to connect agent"
        ERROR_MSG=$(echo "$CONNECT_RESPONSE" | grep -o '"message":"[^"]*"' | sed 's/"message":"//;s/"//')
        if [ -n "$ERROR_MSG" ]; then
            echo "Error: $ERROR_MSG"
        else
            echo "Response: $CONNECT_RESPONSE"
        fi
        exit 1
    fi
elif [ -n "$AGENT_ID" ] && [ -n "$AGENT_KEY" ]; then
    print_info "Using credentials from environment"
    print_info "Agent ID: $AGENT_ID"
    
    if [ -z "$CORE_URL" ]; then
        CORE_URL="https://core.defenra.cc"
    fi
    print_info "Core URL: $CORE_URL"
else
    print_warning "No connection URL or credentials provided"
    print_info "Using placeholder - YOU MUST CONFIGURE BEFORE STARTING"
    AGENT_ID="agent_change_me"
    AGENT_KEY="change_me"
    CORE_URL="https://core.defenra.cc"
fi

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

# Вычисляем 80% от общего объема оперативной памяти (в мегабайтах)
# free -m выводит данные в MB, берем второе поле (total) из второй строки
TOTAL_MEM=$(free -m | awk '/^Mem:/{print $2}')
MEM_LIMIT=$(( TOTAL_MEM * 80 / 100 ))

print_info "Creating systemd service with 80% resource limits..."

cat > /etc/systemd/system/defenra-agent.service << EOF
[Unit]
Description=Defenra Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=$INSTALL_DIR
Environment="AGENT_ID=$AGENT_ID"
Environment="AGENT_KEY=$AGENT_KEY"
Environment="CORE_URL=$CORE_URL"
Environment="POLLING_INTERVAL=$POLLING_INTERVAL"
Environment="LOG_LEVEL=info"
ExecStart=$INSTALL_DIR/defenra-agent

# Health check via systemd watchdog
WatchdogSec=60
Restart=on-watchdog

# Restart policy for other failures
Restart=always
RestartSec=10

# Лимиты ресурсов
CPUQuota=80%
MemoryMax=${MEM_LIMIT}M
MemoryHigh=$(( MEM_LIMIT * 90 / 100 ))M

# Безопасность
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$INSTALL_DIR
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

# Create health check script
print_info "Creating health check script..."
cat > "$INSTALL_DIR/defenra-agent-healthcheck.sh" << 'HEALTHCHECK_EOF'
#!/bin/bash
HEALTH_URL="http://localhost:8080/health"
TIMEOUT=5
MAX_FAILURES=3
FAILURE_COUNT_FILE="/tmp/defenra-agent-health-failures"

if [ ! -f "$FAILURE_COUNT_FILE" ]; then
    echo "0" > "$FAILURE_COUNT_FILE"
fi

FAILURES=$(cat "$FAILURE_COUNT_FILE")
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time $TIMEOUT "$HEALTH_URL")

if [ "$HTTP_CODE" = "200" ]; then
    echo "0" > "$FAILURE_COUNT_FILE"
    exit 0
else
    FAILURES=$((FAILURES + 1))
    echo "$FAILURES" > "$FAILURE_COUNT_FILE"
    
    if [ $FAILURES -ge $MAX_FAILURES ]; then
        echo "Health check failed $FAILURES times, restarting service..."
        echo "0" > "$FAILURE_COUNT_FILE"
        exit 1
    else
        exit 0
    fi
fi
HEALTHCHECK_EOF

chmod +x "$INSTALL_DIR/defenra-agent-healthcheck.sh"
chown defenra:defenra "$INSTALL_DIR/defenra-agent-healthcheck.sh"

# Create health check service
cat > /etc/systemd/system/defenra-agent-healthcheck.service << EOF
[Unit]
Description=Defenra Agent Health Check
After=defenra-agent.service
Requires=defenra-agent.service

[Service]
Type=oneshot
ExecStart=$INSTALL_DIR/defenra-agent-healthcheck.sh
ExecStartPost=/bin/bash -c 'if [ \$EXIT_STATUS -ne 0 ]; then systemctl restart defenra-agent.service; fi'
StandardOutput=journal
StandardError=journal
SyslogIdentifier=defenra-agent-healthcheck
EOF

# Create health check timer
cat > /etc/systemd/system/defenra-agent-healthcheck.timer << EOF
[Unit]
Description=Defenra Agent Health Check Timer
Requires=defenra-agent.service

[Timer]
OnBootSec=30s
OnUnitActiveSec=30s
AccuracySec=5s

[Install]
WantedBy=timers.target
EOF

# Перезагрузка и запуск
print_info "Enabling service and health check..."
systemctl daemon-reload
systemctl enable --now defenra-agent
systemctl enable --now defenra-agent-healthcheck.timer
print_success "Health check timer enabled"

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
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}   Configuring DDoS Protection${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# ============================================================================
# Step 1: Install Required Packages
# ============================================================================

print_info "Installing required packages..."

# Detect package manager
if command -v apt-get &> /dev/null; then
    PKG_MANAGER="apt-get"
    UPDATE_CMD="apt-get update -qq"
    INSTALL_CMD="apt-get install -y -qq"
elif command -v yum &> /dev/null; then
    PKG_MANAGER="yum"
    UPDATE_CMD="yum check-update -q || true"
    INSTALL_CMD="yum install -y -q"
elif command -v dnf &> /dev/null; then
    PKG_MANAGER="dnf"
    UPDATE_CMD="dnf check-update -q || true"
    INSTALL_CMD="dnf install -y -q"
else
    print_warning "Unknown package manager, skipping package installation"
    PKG_MANAGER=""
fi

if [ -n "$PKG_MANAGER" ]; then
    print_info "Updating package lists..."
    $UPDATE_CMD > /dev/null 2>&1 || true
    
    # Install iptables
    if ! command -v iptables &> /dev/null; then
        print_info "Installing iptables..."
        $INSTALL_CMD iptables > /dev/null 2>&1
        print_success "iptables installed"
    else
        print_success "iptables already installed"
    fi
    
    # Install ipset
    if ! command -v ipset &> /dev/null; then
        print_info "Installing ipset..."
        $INSTALL_CMD ipset > /dev/null 2>&1
        print_success "ipset installed"
    else
        print_success "ipset already installed"
    fi
    
    # Install iptables-persistent (Debian/Ubuntu)
    if [ "$PKG_MANAGER" = "apt-get" ]; then
        if ! dpkg -l | grep -q iptables-persistent; then
            print_info "Installing iptables-persistent..."
            echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
            echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
            $INSTALL_CMD iptables-persistent > /dev/null 2>&1
            print_success "iptables-persistent installed"
        else
            print_success "iptables-persistent already installed"
        fi
    fi
fi

# ============================================================================
# Step 2: Apply Kernel Tuning (sysctl)
# ============================================================================

print_info "Applying kernel tuning for DDoS protection..."

cat > /etc/sysctl.d/99-defenra.conf << 'SYSCTL_EOF'
# Defenra Agent - Kernel Tuning for DDoS Protection

# SYN Flood Protection
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 40960
net.core.somaxconn = 65535
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 2

# Connection Tracking
net.netfilter.nf_conntrack_max = 2000000
net.netfilter.nf_conntrack_tcp_timeout_established = 600
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 30
net.netfilter.nf_conntrack_tcp_timeout_close_wait = 30

# TCP Performance
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_tw_reuse = 1
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.ipv4.tcp_window_scaling = 1

# Network Stack
net.core.netdev_max_backlog = 50000
fs.file-max = 2097152

# Security
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.log_martians = 1

# Memory
vm.swappiness = 10
vm.dirty_ratio = 15
vm.dirty_background_ratio = 5
SYSCTL_EOF

# Apply sysctl settings
sysctl -p /etc/sysctl.d/99-defenra.conf > /dev/null 2>&1
print_success "Kernel tuning applied"

# ============================================================================
# Step 3: Configure IPSet
# ============================================================================

if command -v ipset &> /dev/null; then
    print_info "Configuring ipset for efficient IP blacklisting..."
    
    # Create ipset sets
    BLACKLIST_SET="defenra-blacklist"
    TEMPBAN_SET="defenra-tempban"
    CIDR_SET="defenra-cidr"
    
    # IPv4 permanent blacklist
    if ! ipset list "$BLACKLIST_SET" &> /dev/null; then
        ipset create "$BLACKLIST_SET" hash:ip family inet hashsize 4096 maxelem 1000000 timeout 0 comment 2>/dev/null || true
        print_success "Created ipset: $BLACKLIST_SET"
    fi
    
    # IPv4 temporary bans (1 hour default timeout)
    if ! ipset list "$TEMPBAN_SET" &> /dev/null; then
        ipset create "$TEMPBAN_SET" hash:ip family inet hashsize 4096 maxelem 1000000 timeout 3600 comment 2>/dev/null || true
        print_success "Created ipset: $TEMPBAN_SET"
    fi
    
    # IPv4 CIDR ranges
    if ! ipset list "$CIDR_SET" &> /dev/null; then
        ipset create "$CIDR_SET" hash:net family inet hashsize 1024 maxelem 100000 timeout 0 comment 2>/dev/null || true
        print_success "Created ipset: $CIDR_SET"
    fi
    
    # Configure iptables rules
    print_info "Configuring iptables rules..."
    
    # Check if rules already exist
    if ! iptables -C INPUT -m set --match-set "$BLACKLIST_SET" src -j DROP 2>/dev/null; then
        iptables -I INPUT 1 -m set --match-set "$BLACKLIST_SET" src -j DROP
        print_success "Added iptables rule for $BLACKLIST_SET"
    fi
    
    if ! iptables -C INPUT -m set --match-set "$TEMPBAN_SET" src -j DROP 2>/dev/null; then
        iptables -I INPUT 2 -m set --match-set "$TEMPBAN_SET" src -j DROP
        print_success "Added iptables rule for $TEMPBAN_SET"
    fi
    
    if ! iptables -C INPUT -m set --match-set "$CIDR_SET" src -j DROP 2>/dev/null; then
        iptables -I INPUT 3 -m set --match-set "$CIDR_SET" src -j DROP
        print_success "Added iptables rule for $CIDR_SET"
    fi
    
    # Save ipset configuration
    ipset save > /etc/ipset.conf 2>/dev/null || true
    
    # Save iptables rules
    if [ -d /etc/iptables ]; then
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
        print_success "Saved iptables rules"
    fi
    
    # Create systemd service for ipset restore on boot
    cat > /etc/systemd/system/ipset-restore.service << 'IPSET_SERVICE_EOF'
[Unit]
Description=Restore ipset configuration
Before=netfilter-persistent.service
Before=iptables.service
DefaultDependencies=no

[Service]
Type=oneshot
ExecStart=/sbin/ipset restore -f /etc/ipset.conf
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
IPSET_SERVICE_EOF
    
    systemctl daemon-reload
    systemctl enable ipset-restore.service > /dev/null 2>&1
    print_success "ipset persistence configured"
    
else
    print_warning "ipset not available, skipping ipset configuration"
fi

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}   DDoS Protection Configured!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "Kernel Tuning:"
echo "  ✓ SYN cookies enabled"
echo "  ✓ Connection tracking optimized"
echo "  ✓ TCP performance tuned"
echo "  ✓ Network stack hardened"
echo ""
if command -v ipset &> /dev/null; then
    echo "IPSet Configuration:"
    echo "  ✓ Permanent blacklist: $BLACKLIST_SET"
    echo "  ✓ Temporary bans: $TEMPBAN_SET (1 hour timeout)"
    echo "  ✓ CIDR ranges: $CIDR_SET"
    echo ""
    echo "Usage Examples:"
    echo "  • Ban IP:     ipset add $TEMPBAN_SET 1.2.3.4 timeout 3600"
    echo "  • Unban IP:   ipset del $TEMPBAN_SET 1.2.3.4"
    echo "  • List bans:  ipset list $TEMPBAN_SET"
    echo ""
fi

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}   Installation Complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "Location: $INSTALL_DIR"
echo "Service: defenra-agent.service"
echo "Agent ID: $AGENT_ID"
echo "Core URL: $CORE_URL"
echo "Polling Interval: ${POLLING_INTERVAL}s"
echo ""
echo "Useful commands:"
echo "  • Status:  sudo systemctl status defenra-agent"
echo "  • Logs:    sudo journalctl -u defenra-agent -f"
echo "  • Restart: sudo systemctl restart defenra-agent"
echo "  • Health:  curl http://localhost:8080/health"
echo "  • Health Check: sudo systemctl status defenra-agent-healthcheck.timer"
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
echo "Support: support@defenra.cc"
echo ""
