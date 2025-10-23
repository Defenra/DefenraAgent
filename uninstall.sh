#!/bin/bash

set -e

echo "====================================="
echo "Defenra Agent Uninstallation Script"
echo "====================================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Error: This script must be run as root"
    echo "Please use: sudo ./uninstall.sh"
    exit 1
fi

# Confirm uninstallation
read -p "Are you sure you want to uninstall Defenra Agent? (y/N): " CONFIRM
if [ "$CONFIRM" != "y" ] && [ "$CONFIRM" != "Y" ]; then
    echo "Uninstallation cancelled"
    exit 0
fi

INSTALL_DIR="/opt/defenra-agent"
SERVICE_FILE="/etc/systemd/system/defenra-agent.service"

# Stop service
if systemctl is-active --quiet defenra-agent; then
    echo "Stopping service..."
    systemctl stop defenra-agent
fi

# Disable service
if systemctl is-enabled --quiet defenra-agent; then
    echo "Disabling service..."
    systemctl disable defenra-agent
fi

# Remove service file
if [ -f "$SERVICE_FILE" ]; then
    echo "Removing service file..."
    rm -f $SERVICE_FILE
fi

# Reload systemd
echo "Reloading systemd..."
systemctl daemon-reload

# Remove installation directory
if [ -d "$INSTALL_DIR" ]; then
    echo "Removing installation directory..."
    rm -rf $INSTALL_DIR
fi

# Remove user (optional)
read -p "Remove user 'defenra'? (y/N): " REMOVE_USER
if [ "$REMOVE_USER" = "y" ] || [ "$REMOVE_USER" = "Y" ]; then
    if id "defenra" &>/dev/null; then
        echo "Removing user 'defenra'..."
        userdel defenra
    fi
fi

echo ""
echo "====================================="
echo "Uninstallation completed!"
echo "====================================="
echo ""
