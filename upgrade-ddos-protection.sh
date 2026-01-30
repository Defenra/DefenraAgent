#!/bin/bash

# Defenra Agent - Upgrade DDoS Protection (Robust Version)
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

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}    Defenra Agent - DDoS Upgrade        ${NC}"
echo -e "${BLUE}========================================${NC}"

# 1. Проверка прав
if [ "$EUID" -ne 0 ]; then
    print_error "Нужны права root (sudo)"
    exit 1
fi

# 2. Подготовка ядра (nf_conntrack)
print_info "Checking kernel modules..."
# Пытаемся загрузить модуль, который вызвал сбой в прошлый раз
modprobe nf_conntrack 2>/dev/null || print_warning "nf_conntrack module not available (normal for some VPS)"

echo ""
echo -e "${BLUE}Step 2: Apply Kernel Tuning${NC}"
echo "----------------------------------------"

# Записываем конфиг
cat > /etc/sysctl.d/99-defenra.conf << 'SYSCTL_EOF'
# SYN Flood Protection
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 40960
net.core.somaxconn = 65535
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 2

# Connection Tracking (может не работать в контейнерах)
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
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
vm.swappiness = 10
SYSCTL_EOF

# КЛЮЧЕВОЕ ИСПРАВЛЕНИЕ: Мы добавляем || true, чтобы ошибка sysctl не убивала скрипт
print_info "Applying sysctl settings..."
sysctl -p /etc/sysctl.d/99-defenra.conf 2>&1 | grep -v "No such file" || true
print_success "Kernel tuning step finished (some errors ignored intentionally)"

echo ""
echo -e "${BLUE}Step 3: Configure IPSet${NC}"
echo "----------------------------------------"

# Проверяем наличие ipset и продолжаем
if command -v ipset &> /dev/null; then
    BLACKLIST_SET="defenra-blacklist"
    TEMPBAN_SET="defenra-tempban"
    CIDR_SET="defenra-cidr"

    # Создаем сеты, если их нет
    ipset create $BLACKLIST_SET hash:ip family inet hashsize 4096 maxelem 1000000 2>/dev/null || true
    ipset create $TEMPBAN_SET hash:ip family inet hashsize 4096 maxelem 1000000 timeout 3600 2>/dev/null || true
    ipset create $CIDR_SET hash:net family inet hashsize 1024 maxelem 100000 2>/dev/null || true
    
    # Добавляем правила в IPTables (проверка на дубликаты уже встроена через -C)
    iptables -C INPUT -m set --match-set $BLACKLIST_SET src -j DROP 2>/dev/null || iptables -I INPUT 1 -m set --match-set $BLACKLIST_SET src -j DROP
    iptables -C INPUT -m set --match-set $TEMPBAN_SET src -j DROP 2>/dev/null || iptables -I INPUT 2 -m set --match-set $TEMPBAN_SET src -j DROP
    
    print_success "IPSet and IPTables rules configured"
else
    print_error "IPSet not found. Step skipped."
fi

echo ""
echo -e "${BLUE}Step 4: Restart Agent${NC}"
echo "----------------------------------------"

if systemctl list-unit-files | grep -q defenra-agent.service; then
    systemctl restart defenra-agent
    print_success "DefenraAgent restarted"
else
    print_warning "DefenraAgent service not found, skip restart"
fi

echo -e "\n${GREEN}Успешно завершено!${NC}"