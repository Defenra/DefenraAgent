#!/bin/bash

# DefenraAgent - Fix IPTables Rules
# This script ensures iptables rules are properly configured to block IPs from ipset

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_info() {
    echo -e "${YELLOW}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    print_error "This script must be run as root"
    exit 1
fi

# Check if ipset is installed
if ! command -v ipset &> /dev/null; then
    print_error "ipset is not installed. Please run quick-install.sh first."
    exit 1
fi

# Check if iptables is installed
if ! command -v iptables &> /dev/null; then
    print_error "iptables is not installed. Please install it first."
    exit 1
fi

BLACKLIST_SET="defenra-blacklist"
TEMPBAN_SET="defenra-tempban"
CIDR_SET="defenra-cidr"

print_info "Checking ipset sets..."

# Check if ipset sets exist
for SET in "$BLACKLIST_SET" "$TEMPBAN_SET" "$CIDR_SET"; do
    if ! ipset list "$SET" &> /dev/null; then
        print_error "ipset set '$SET' does not exist. Please run quick-install.sh first."
        exit 1
    else
        print_success "ipset set '$SET' exists"
    fi
done

print_info "Checking current iptables rules..."
echo ""
echo "Current INPUT chain rules:"
iptables -L INPUT -n --line-numbers | head -20
echo ""

print_info "Checking if Defenra rules exist..."

# Function to check if rule exists
rule_exists() {
    iptables -C INPUT -m set --match-set "$1" src -j DROP 2>/dev/null
}

# Remove old rules if they exist (to re-add them in correct order)
print_info "Removing old Defenra rules (if any)..."
for SET in "$BLACKLIST_SET" "$TEMPBAN_SET" "$CIDR_SET"; do
    while rule_exists "$SET"; do
        iptables -D INPUT -m set --match-set "$SET" src -j DROP 2>/dev/null || break
        print_info "Removed old rule for $SET"
    done
done

print_info "Adding Defenra iptables rules..."

# Add rules in correct order (blacklist first, then tempban, then CIDR)
# Using -I INPUT 1 to insert at the beginning (highest priority)

# Rule 1: Drop packets from permanent blacklist
if ! rule_exists "$BLACKLIST_SET"; then
    iptables -I INPUT 1 -m set --match-set "$BLACKLIST_SET" src -j DROP
    print_success "Added rule: DROP packets from $BLACKLIST_SET"
else
    print_info "Rule for $BLACKLIST_SET already exists"
fi

# Rule 2: Drop packets from temporary bans
if ! rule_exists "$TEMPBAN_SET"; then
    iptables -I INPUT 2 -m set --match-set "$TEMPBAN_SET" src -j DROP
    print_success "Added rule: DROP packets from $TEMPBAN_SET"
else
    print_info "Rule for $TEMPBAN_SET already exists"
fi

# Rule 3: Drop packets from CIDR ranges
if ! rule_exists "$CIDR_SET"; then
    iptables -I INPUT 3 -m set --match-set "$CIDR_SET" src -j DROP
    print_success "Added rule: DROP packets from $CIDR_SET"
else
    print_info "Rule for $CIDR_SET already exists"
fi

print_info "Saving iptables rules..."

# Save iptables rules (different methods for different distros)
if command -v netfilter-persistent &> /dev/null; then
    netfilter-persistent save
    print_success "Saved with netfilter-persistent"
elif command -v iptables-save &> /dev/null; then
    if [ -d /etc/iptables ]; then
        iptables-save > /etc/iptables/rules.v4
        print_success "Saved to /etc/iptables/rules.v4"
    elif [ -d /etc/sysconfig ]; then
        iptables-save > /etc/sysconfig/iptables
        print_success "Saved to /etc/sysconfig/iptables"
    else
        print_warning "Could not find iptables rules directory, rules may not persist after reboot"
    fi
fi

# Save ipset configuration
ipset save > /etc/ipset.conf 2>/dev/null || true
print_success "Saved ipset configuration to /etc/ipset.conf"

# Ensure ipset-restore service exists
if [ ! -f /etc/systemd/system/ipset-restore.service ]; then
    print_info "Creating ipset-restore service..."
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
WantedBy=basic.target
IPSET_SERVICE_EOF

    systemctl daemon-reload
    systemctl enable ipset-restore.service
    print_success "Created and enabled ipset-restore service"
fi

echo ""
print_success "IPTables rules configured successfully!"
echo ""
echo "Current INPUT chain rules (first 10):"
iptables -L INPUT -n --line-numbers | head -15
echo ""

# Test with a sample IP
print_info "Testing ipset functionality..."
TEST_IP="1.2.3.4"

# Add test IP to tempban
ipset add "$TEMPBAN_SET" "$TEST_IP" timeout 10 -exist 2>/dev/null || true

# Check if it's in the set
if ipset test "$TEMPBAN_SET" "$TEST_IP" 2>/dev/null; then
    print_success "Test IP $TEST_IP successfully added to $TEMPBAN_SET"
    print_info "This IP will be automatically removed after 10 seconds"
else
    print_error "Failed to add test IP to ipset"
fi

echo ""
print_info "Verification complete!"
echo ""
echo "To verify bans are working:"
echo "  1. Check ipset: ipset list $TEMPBAN_SET"
echo "  2. Check iptables: iptables -L INPUT -n --line-numbers"
echo "  3. Test ban: ipset add $TEMPBAN_SET <IP> timeout 3600"
echo ""
