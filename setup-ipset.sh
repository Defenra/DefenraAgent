#!/bin/bash

# Defenra Agent - IPSet Setup for Efficient IP Blacklisting
# This script sets up ipset for fast IP blocking (O(1) lookup vs O(n) for iptables rules)

set -e

echo "=== Defenra Agent - IPSet Setup ==="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: This script must be run as root (use sudo)"
    exit 1
fi

# Check if ipset is installed
if ! command -v ipset &> /dev/null; then
    echo "ERROR: ipset is not installed"
    echo "Install with: apt-get install ipset (Debian/Ubuntu) or yum install ipset (CentOS/RHEL)"
    exit 1
fi

# Check if iptables is installed
if ! command -v iptables &> /dev/null; then
    echo "ERROR: iptables is not installed"
    exit 1
fi

echo "✓ ipset and iptables are installed"
echo ""

# ============================================================================
# Create IPSet for Blacklisted IPs
# ============================================================================

BLACKLIST_SET="defenra-blacklist"
BLACKLIST_V6_SET="defenra-blacklist-v6"

echo "Creating ipset for blacklisted IPs..."

# Create IPv4 blacklist (hash:ip for fast O(1) lookup)
if ipset list "$BLACKLIST_SET" &> /dev/null; then
    echo "  - IPv4 blacklist already exists: $BLACKLIST_SET"
else
    ipset create "$BLACKLIST_SET" hash:ip \
        family inet \
        hashsize 4096 \
        maxelem 1000000 \
        timeout 0 \
        comment
    echo "  ✓ Created IPv4 blacklist: $BLACKLIST_SET"
fi

# Create IPv6 blacklist
if ipset list "$BLACKLIST_V6_SET" &> /dev/null; then
    echo "  - IPv6 blacklist already exists: $BLACKLIST_V6_SET"
else
    ipset create "$BLACKLIST_V6_SET" hash:ip \
        family inet6 \
        hashsize 4096 \
        maxelem 1000000 \
        timeout 0 \
        comment
    echo "  ✓ Created IPv6 blacklist: $BLACKLIST_V6_SET"
fi

echo ""

# ============================================================================
# Create IPSet for Temporary Bans (with timeout)
# ============================================================================

TEMPBAN_SET="defenra-tempban"
TEMPBAN_V6_SET="defenra-tempban-v6"

echo "Creating ipset for temporary bans..."

# Create IPv4 temporary ban list (with default timeout)
if ipset list "$TEMPBAN_SET" &> /dev/null; then
    echo "  - IPv4 temp ban list already exists: $TEMPBAN_SET"
else
    ipset create "$TEMPBAN_SET" hash:ip \
        family inet \
        hashsize 4096 \
        maxelem 1000000 \
        timeout 3600 \
        comment
    echo "  ✓ Created IPv4 temp ban list: $TEMPBAN_SET (default timeout: 1 hour)"
fi

# Create IPv6 temporary ban list
if ipset list "$TEMPBAN_V6_SET" &> /dev/null; then
    echo "  - IPv6 temp ban list already exists: $TEMPBAN_V6_SET"
else
    ipset create "$TEMPBAN_V6_SET" hash:ip \
        family inet6 \
        hashsize 4096 \
        maxelem 1000000 \
        timeout 3600 \
        comment
    echo "  ✓ Created IPv6 temp ban list: $TEMPBAN_V6_SET (default timeout: 1 hour)"
fi

echo ""

# ============================================================================
# Create IPSet for CIDR Ranges
# ============================================================================

CIDR_SET="defenra-cidr"
CIDR_V6_SET="defenra-cidr-v6"

echo "Creating ipset for CIDR ranges..."

# Create IPv4 CIDR blacklist
if ipset list "$CIDR_SET" &> /dev/null; then
    echo "  - IPv4 CIDR list already exists: $CIDR_SET"
else
    ipset create "$CIDR_SET" hash:net \
        family inet \
        hashsize 1024 \
        maxelem 100000 \
        timeout 0 \
        comment
    echo "  ✓ Created IPv4 CIDR list: $CIDR_SET"
fi

# Create IPv6 CIDR blacklist
if ipset list "$CIDR_V6_SET" &> /dev/null; then
    echo "  - IPv6 CIDR list already exists: $CIDR_V6_SET"
else
    ipset create "$CIDR_V6_SET" hash:net \
        family inet6 \
        hashsize 1024 \
        maxelem 100000 \
        timeout 0 \
        comment
    echo "  ✓ Created IPv6 CIDR list: $CIDR_V6_SET"
fi

echo ""

# ============================================================================
# Configure iptables Rules
# ============================================================================

echo "Configuring iptables rules..."

# Function to check if rule exists
rule_exists() {
    iptables -C "$@" 2>/dev/null
}

rule_exists_v6() {
    ip6tables -C "$@" 2>/dev/null
}

# IPv4 Rules
echo "  - Configuring IPv4 rules..."

# Drop packets from blacklisted IPs (permanent bans)
if ! rule_exists INPUT -m set --match-set "$BLACKLIST_SET" src -j DROP; then
    iptables -I INPUT 1 -m set --match-set "$BLACKLIST_SET" src -j DROP
    echo "    ✓ Added rule: DROP packets from $BLACKLIST_SET"
else
    echo "    - Rule already exists: DROP packets from $BLACKLIST_SET"
fi

# Drop packets from temporarily banned IPs
if ! rule_exists INPUT -m set --match-set "$TEMPBAN_SET" src -j DROP; then
    iptables -I INPUT 2 -m set --match-set "$TEMPBAN_SET" src -j DROP
    echo "    ✓ Added rule: DROP packets from $TEMPBAN_SET"
else
    echo "    - Rule already exists: DROP packets from $TEMPBAN_SET"
fi

# Drop packets from blacklisted CIDR ranges
if ! rule_exists INPUT -m set --match-set "$CIDR_SET" src -j DROP; then
    iptables -I INPUT 3 -m set --match-set "$CIDR_SET" src -j DROP
    echo "    ✓ Added rule: DROP packets from $CIDR_SET"
else
    echo "    - Rule already exists: DROP packets from $CIDR_SET"
fi

# IPv6 Rules (if IPv6 is enabled)
if [ -f /proc/net/if_inet6 ]; then
    echo "  - Configuring IPv6 rules..."
    
    if ! rule_exists_v6 INPUT -m set --match-set "$BLACKLIST_V6_SET" src -j DROP; then
        ip6tables -I INPUT 1 -m set --match-set "$BLACKLIST_V6_SET" src -j DROP
        echo "    ✓ Added rule: DROP packets from $BLACKLIST_V6_SET"
    else
        echo "    - Rule already exists: DROP packets from $BLACKLIST_V6_SET"
    fi
    
    if ! rule_exists_v6 INPUT -m set --match-set "$TEMPBAN_V6_SET" src -j DROP; then
        ip6tables -I INPUT 2 -m set --match-set "$TEMPBAN_V6_SET" src -j DROP
        echo "    ✓ Added rule: DROP packets from $TEMPBAN_V6_SET"
    else
        echo "    - Rule already exists: DROP packets from $TEMPBAN_V6_SET"
    fi
    
    if ! rule_exists_v6 INPUT -m set --match-set "$CIDR_V6_SET" src -j DROP; then
        ip6tables -I INPUT 3 -m set --match-set "$CIDR_V6_SET" src -j DROP
        echo "    ✓ Added rule: DROP packets from $CIDR_V6_SET"
    else
        echo "    - Rule already exists: DROP packets from $CIDR_V6_SET"
    fi
else
    echo "  - IPv6 is disabled, skipping IPv6 rules"
fi

echo ""

# ============================================================================
# Save Configuration
# ============================================================================

echo "Saving configuration..."

# Save ipset configuration
ipset save > /etc/ipset.conf
echo "  ✓ Saved ipset configuration to /etc/ipset.conf"

# Save iptables rules (Debian/Ubuntu)
if command -v iptables-save &> /dev/null; then
    if [ -d /etc/iptables ]; then
        iptables-save > /etc/iptables/rules.v4
        echo "  ✓ Saved iptables rules to /etc/iptables/rules.v4"
        
        if [ -f /proc/net/if_inet6 ]; then
            ip6tables-save > /etc/iptables/rules.v6
            echo "  ✓ Saved ip6tables rules to /etc/iptables/rules.v6"
        fi
    else
        echo "  ⚠ /etc/iptables directory not found, rules not saved"
        echo "    Install iptables-persistent: apt-get install iptables-persistent"
    fi
fi

echo ""

# ============================================================================
# Enable Persistence on Boot
# ============================================================================

echo "Configuring persistence on boot..."

# Create systemd service for ipset restore
cat > /etc/systemd/system/ipset-restore.service << 'EOF'
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
EOF

systemctl daemon-reload
systemctl enable ipset-restore.service
echo "  ✓ Created and enabled ipset-restore.service"

echo ""

# ============================================================================
# Usage Examples
# ============================================================================

echo "=== Setup Complete ==="
echo ""
echo "IPSet Configuration:"
echo "  - Permanent blacklist: $BLACKLIST_SET (IPv4), $BLACKLIST_V6_SET (IPv6)"
echo "  - Temporary bans:      $TEMPBAN_SET (IPv4), $TEMPBAN_V6_SET (IPv6)"
echo "  - CIDR ranges:         $CIDR_SET (IPv4), $CIDR_V6_SET (IPv6)"
echo ""
echo "Usage Examples:"
echo ""
echo "  # Add IP to permanent blacklist"
echo "  ipset add $BLACKLIST_SET 1.2.3.4 comment \"Malicious bot\""
echo ""
echo "  # Add IP to temporary ban (1 hour default)"
echo "  ipset add $TEMPBAN_SET 5.6.7.8 timeout 3600 comment \"Rate limit exceeded\""
echo ""
echo "  # Add CIDR range"
echo "  ipset add $CIDR_SET 10.0.0.0/8 comment \"Private network\""
echo ""
echo "  # Remove IP from blacklist"
echo "  ipset del $BLACKLIST_SET 1.2.3.4"
echo ""
echo "  # List all blacklisted IPs"
echo "  ipset list $BLACKLIST_SET"
echo ""
echo "  # Test if IP is blacklisted"
echo "  ipset test $BLACKLIST_SET 1.2.3.4"
echo ""
echo "  # Flush all IPs from set (careful!)"
echo "  ipset flush $TEMPBAN_SET"
echo ""
echo "  # Get statistics"
echo "  ipset list -t"
echo ""
echo "Integration with DefenraAgent:"
echo "  - Update firewall/iptables.go to use ipset commands instead of iptables -A"
echo "  - Example: ipset add $TEMPBAN_SET <IP> timeout <seconds> comment \"<reason>\""
echo ""
echo "Performance:"
echo "  - ipset lookup: O(1) - constant time, even with millions of IPs"
echo "  - iptables rules: O(n) - linear time, slow with many rules"
echo ""
echo "Monitoring:"
echo "  - Watch bans: watch -n 1 'ipset list $TEMPBAN_SET | tail -20'"
echo "  - Count entries: ipset list $BLACKLIST_SET | grep -c \"^[0-9]\""
echo ""
