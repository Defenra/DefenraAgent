#!/bin/bash

# Defenra Agent - Upgrade DDoS Protection
# This script upgrades existing agents with kernel-level protection and ipset

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_success() { echo -e "${GREEN}✓${NC} $1"; }
print_error() { echo -e "${RED}✗${NC} $1"; }
print_warning() { echo -e "${YELLOW}⚠${NC} $1"; }
print_info() { echo -e "${BLUE}ℹ${NC} $1"; }

echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}   Defenra Agent - DDoS Protection Upgrade${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    print_error "This script must be run as root"
    echo "Please use: curl -sSL https://raw.githubusercontent.com/Defenra/DefenraAgent/main/upgrade-ddos-protection.sh | sudo bash"
    exit 1
fi

print_success "Running as root"

# Check if defenra-agent is installed
if ! systemctl list-unit-files | grep -q defenra-agent.service; then
    print_error "DefenraAgent service not found"
    echo "This script is for upgrading existing installations only."
    echo "For new installations, use quick-install.sh"
    exit 1
fi

print_success "DefenraAgent service found"

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
    print_warning "Unknown package manager"
    PKG_MANAGER=""
fi

echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}   Step 1: Install Required Packages${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

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
else
    print_warning "Could not detect package manager"
    print_info "Please install iptables and ipset manually"
fi

echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}   Step 2: Apply Kernel Tuning${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

print_info "Applying kernel tuning for DDoS protection..."

# Check if already configured
if [ -f /etc/sysctl.d/99-defenra.conf ]; then
    print_warning "Kernel tuning already configured"
    print_info "Updating configuration..."
fi

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

echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}   Step 3: Configure IPSet${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

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
    else
        print_success "ipset already exists: $BLACKLIST_SET"
    fi
    
    # IPv4 temporary bans (1 hour default timeout)
    if ! ipset list "$TEMPBAN_SET" &> /dev/null; then
        ipset create "$TEMPBAN_SET" hash:ip family inet hashsize 4096 maxelem 1000000 timeout 3600 comment 2>/dev/null || true
        print_success "Created ipset: $TEMPBAN_SET"
    else
        print_success "ipset already exists: $TEMPBAN_SET"
    fi
    
    # IPv4 CIDR ranges
    if ! ipset list "$CIDR_SET" &> /dev/null; then
        ipset create "$CIDR_SET" hash:net family inet hashsize 1024 maxelem 100000 timeout 0 comment 2>/dev/null || true
        print_success "Created ipset: $CIDR_SET"
    else
        print_success "ipset already exists: $CIDR_SET"
    fi
    
    # Configure iptables rules
    print_info "Configuring iptables rules..."
    
    # Check if rules already exist
    if ! iptables -C INPUT -m set --match-set "$BLACKLIST_SET" src -j DROP 2>/dev/null; then
        iptables -I INPUT 1 -m set --match-set "$BLACKLIST_SET" src -j DROP
        print_success "Added iptables rule for $BLACKLIST_SET"
    else
        print_success "iptables rule already exists for $BLACKLIST_SET"
    fi
    
    if ! iptables -C INPUT -m set --match-set "$TEMPBAN_SET" src -j DROP 2>/dev/null; then
        iptables -I INPUT 2 -m set --match-set "$TEMPBAN_SET" src -j DROP
        print_success "Added iptables rule for $TEMPBAN_SET"
    else
        print_success "iptables rule already exists for $TEMPBAN_SET"
    fi
    
    if ! iptables -C INPUT -m set --match-set "$CIDR_SET" src -j DROP 2>/dev/null; then
        iptables -I INPUT 3 -m set --match-set "$CIDR_SET" src -j DROP
        print_success "Added iptables rule for $CIDR_SET"
    else
        print_success "iptables rule already exists for $CIDR_SET"
    fi
    
    # Save ipset configuration
    ipset save > /etc/ipset.conf 2>/dev/null || true
    
    # Save iptables rules
    if [ -d /etc/iptables ]; then
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
        print_success "Saved iptables rules"
    fi
    
    # Create systemd service for ipset restore on boot
    if [ ! -f /etc/systemd/system/ipset-restore.service ]; then
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
        print_success "ipset persistence already configured"
    fi
    
else
    print_warning "ipset not available, skipping ipset configuration"
fi

echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}   Step 4: Restart Agent${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

print_info "Restarting DefenraAgent to apply changes..."
systemctl restart defenra-agent

sleep 2

if systemctl is-active --quiet defenra-agent; then
    print_success "DefenraAgent restarted successfully"
else
    print_error "DefenraAgent failed to restart"
    echo "Check logs: sudo journalctl -u defenra-agent -n 50"
    exit 1
fi

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}   Upgrade Complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "DDoS Protection Upgraded:"
echo "  ✓ Kernel tuning applied (SYN cookies, connection tracking)"
echo "  ✓ IPSet configured (O(1) IP blocking)"
echo "  ✓ iptables rules configured"
echo "  ✓ Persistence enabled (survives reboot)"
echo "  ✓ DefenraAgent restarted"
echo ""

if command -v ipset &> /dev/null; then
    echo "IPSet Configuration:"
    echo "  • Permanent blacklist: $BLACKLIST_SET"
    echo "  • Temporary bans: $TEMPBAN_SET (1 hour timeout)"
    echo "  • CIDR ranges: $CIDR_SET"
    echo ""
    echo "Usage Examples:"
    echo "  • Ban IP:     ipset add $TEMPBAN_SET 1.2.3.4 timeout 3600"
    echo "  • Unban IP:   ipset del $TEMPBAN_SET 1.2.3.4"
    echo "  • List bans:  ipset list $TEMPBAN_SET"
    echo ""
fi

echo "Verify Protection:"
echo "  • Check kernel settings: sysctl -a | grep tcp_syncookies"
echo "  • Check ipset mode: sudo journalctl -u defenra-agent -n 50 | grep ipset"
echo "  • Monitor bans: watch -n 1 'ipset list $TEMPBAN_SET | tail -20'"
echo ""
echo "Expected log message:"
echo "  [Firewall] ipset detected, using ipset for IP blocking (O(1) lookup)"
echo ""
echo "Documentation: https://github.com/Defenra/DefenraAgent"
echo ""
