# Installation Guide

This guide provides detailed instructions for installing Defenra Agent using the automated installation script.

## Features of the Installation Script

The `install.sh` script provides a fully automated installation with:

✅ **System Requirements Check**
- Verifies root access
- Checks Go installation (1.21+)
- Validates required commands (wget, curl, systemctl)
- Checks available disk space

✅ **Interactive Configuration**
- Prompts for Agent ID and Key
- Asks for Core URL
- Configurable polling interval
- Selectable log level

✅ **Connection Testing**
- Tests connectivity to Core API
- Validates configuration before installation

✅ **Complete Installation**
- Creates system user (defenra)
- Builds agent from source
- Downloads GeoIP database
- Grants network capabilities
- Creates systemd service

✅ **Firewall Configuration**
- Auto-detects UFW or firewalld
- Optionally opens required ports
- Shows manual instructions if needed

✅ **Service Management**
- Enables service for auto-start
- Starts service immediately
- Verifies installation success

✅ **Health Verification**
- Tests health endpoint
- Shows service status
- Displays helpful commands

## Prerequisites

### 1. Operating System
- **Supported:** Linux (Ubuntu, Debian, CentOS, RHEL, Fedora)
- **Architecture:** x86_64 (amd64) or ARM64
- **Kernel:** 3.10+ (4.x+ recommended)

### 2. Go Programming Language
- **Version:** 1.21 or higher
- **Installation:**
  ```bash
  # Download Go
  wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
  
  # Extract to /usr/local
  sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
  
  # Add to PATH
  echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
  source ~/.bashrc
  
  # Verify installation
  go version
  ```

### 3. Required Commands
- `wget` - For downloading files
- `curl` - For API calls
- `systemctl` - For service management
- `git` (optional) - For cloning repository

Install on Ubuntu/Debian:
```bash
sudo apt-get update
sudo apt-get install wget curl systemd git
```

Install on CentOS/RHEL:
```bash
sudo yum install wget curl systemd git
```

### 4. Network Requirements
- Outbound HTTPS access to Core API
- Ability to bind to ports 53, 80, 443, 8080
- No other services using these ports

### 5. Disk Space
- At least 200 MB free space in `/opt`
- 100 MB for GeoIP database
- 12 MB for agent binary

### 6. Credentials
- Agent ID from Defenra Core
- Agent Key from Defenra Core
- Core API URL

## Installation Steps

### Step 1: Download or Clone

**Option A: Clone Repository (Recommended)**
```bash
git clone https://github.com/defenra/agent.git
cd agent
```

**Option B: Download Release**
```bash
wget https://github.com/defenra/agent/archive/refs/heads/main.zip
unzip main.zip
cd agent-main
```

### Step 2: Make Script Executable

```bash
chmod +x install.sh
```

### Step 3: Run Installation Script

```bash
sudo ./install.sh
```

### Step 4: Follow Interactive Prompts

The script will guide you through:

1. **System Requirements Check**
   - Verifies all prerequisites
   - Shows detected Go version
   - Checks available disk space

2. **Agent Configuration**
   ```
   Agent ID: agent_xxx
   Agent Key: ******** (hidden)
   Core URL: https://core.defenra.com
   Polling Interval: 60
   Log Level: info
   ```

3. **Configuration Confirmation**
   - Review your settings
   - Confirm to proceed

4. **Connection Test**
   - Tests connectivity to Core API
   - Option to continue if test fails

5. **Installation Process**
   - Creates system user
   - Builds agent binary
   - Downloads GeoIP database
   - Installs to /opt/defenra-agent
   - Creates systemd service

6. **Firewall Configuration**
   - Auto-detects firewall (UFW/firewalld)
   - Prompts to open required ports
   - Shows manual instructions

7. **Service Start**
   - Enables service
   - Starts agent
   - Verifies startup

8. **Verification**
   - Checks service status
   - Tests health endpoint
   - Shows agent information

## What Gets Installed

### File Locations

```
/opt/defenra-agent/
├── defenra-agent              # Main binary (12 MB)
├── GeoLite2-City.mmdb         # GeoIP database (~100 MB)

/etc/systemd/system/
└── defenra-agent.service      # Systemd service file

System User:
└── defenra (system user, no login)
```

### Network Ports

| Port | Protocol | Purpose           |
|------|----------|-------------------|
| 53   | UDP/TCP  | DNS Server        |
| 80   | TCP      | HTTP Proxy        |
| 443  | TCP      | HTTPS Proxy       |
| 8080 | TCP      | Health Check      |

### Environment Variables

Set in systemd service:
- `AGENT_ID` - Your agent identifier
- `AGENT_KEY` - Authentication key
- `CORE_URL` - Core API endpoint
- `POLLING_INTERVAL` - Config polling interval (seconds)
- `LOG_LEVEL` - Logging level (debug/info/warn/error)
- `CACHE_SIZE` - DNS cache size (default: 10000)

## Post-Installation

### Verify Installation

1. **Check Service Status**
   ```bash
   sudo systemctl status defenra-agent
   ```

2. **Test Health Endpoint**
   ```bash
   curl http://localhost:8080/health
   ```
   
   Expected output:
   ```json
   {
     "status": "healthy",
     "uptime": "5m12s",
     "last_poll": "2025-10-23T10:15:00Z",
     "domains_loaded": 5,
     "proxies_active": 2
   }
   ```

3. **View Logs**
   ```bash
   sudo journalctl -u defenra-agent -f
   ```

4. **Test DNS**
   ```bash
   dig @localhost example.com
   ```

### Service Management

```bash
# View logs
sudo journalctl -u defenra-agent -f

# Check status
sudo systemctl status defenra-agent

# Restart service
sudo systemctl restart defenra-agent

# Stop service
sudo systemctl stop defenra-agent

# Start service
sudo systemctl start defenra-agent

# Disable auto-start
sudo systemctl disable defenra-agent

# Enable auto-start
sudo systemctl enable defenra-agent
```

### Configuration Changes

To change configuration:

1. Edit service file:
   ```bash
   sudo nano /etc/systemd/system/defenra-agent.service
   ```

2. Reload systemd:
   ```bash
   sudo systemctl daemon-reload
   ```

3. Restart service:
   ```bash
   sudo systemctl restart defenra-agent
   ```

## Troubleshooting

### Installation Fails

**Problem:** Go is not installed
```
✗ Go is not installed
```

**Solution:**
```bash
wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
go version
```

---

**Problem:** Missing required commands
```
✗ Missing required commands: wget curl
```

**Solution:**
```bash
# Ubuntu/Debian
sudo apt-get install wget curl

# CentOS/RHEL
sudo yum install wget curl
```

---

**Problem:** Low disk space
```
⚠ Low disk space: 50000KB available
```

**Solution:**
- Free up space in `/opt`
- Or install to different location (requires script modification)

---

**Problem:** Connection to Core API fails
```
⚠ Could not connect to Core API
```

**Solution:**
- Check Core URL is correct
- Verify network connectivity
- Check firewall rules on Core server
- Continue anyway if endpoint requires authentication

### Service Fails to Start

**Problem:** Port already in use
```
bind: address already in use
```

**Solution:**
1. Check what's using the port:
   ```bash
   sudo netstat -tulpn | grep :53
   sudo netstat -tulpn | grep :80
   sudo netstat -tulpn | grep :443
   ```

2. Stop conflicting services:
   ```bash
   # Example: systemd-resolved on port 53
   sudo systemctl stop systemd-resolved
   sudo systemctl disable systemd-resolved
   ```

---

**Problem:** Permission denied on ports
```
permission denied: bind
```

**Solution:**
- Ensure service runs as root OR
- Verify capabilities were set:
  ```bash
  getcap /opt/defenra-agent/defenra-agent
  # Should show: cap_net_bind_service=ep
  ```
- If not set, run:
  ```bash
  sudo setcap 'cap_net_bind_service=+ep' /opt/defenra-agent/defenra-agent
  ```

---

**Problem:** Agent can't connect to Core
```
Error: Failed to poll configuration
```

**Solution:**
1. Check credentials:
   ```bash
   sudo systemctl status defenra-agent
   ```

2. Test manually:
   ```bash
   curl -X POST https://core.defenra.com/api/agent/poll \
     -H "Content-Type: application/json" \
     -d '{"agentId":"agent_xxx","agentKey":"xxx"}'
   ```

3. Check logs:
   ```bash
   sudo journalctl -u defenra-agent -n 100
   ```

### GeoIP Database Issues

**Problem:** Failed to download GeoIP database
```
✗ Failed to download GeoIP database
```

**Solution:**
1. Download manually:
   ```bash
   cd /opt/defenra-agent
   sudo wget -O GeoLite2-City.mmdb \
     https://github.com/Defenra/DefenraCore/raw/refs/heads/main/data/GeoLite2-City.mmdb
   sudo chown defenra:defenra GeoLite2-City.mmdb
   ```

2. Or use MaxMind official:
   - Sign up at https://www.maxmind.com
   - Download GeoLite2-City database
   - Place in `/opt/defenra-agent/`

**Note:** Agent will work without GeoIP database, but GeoDNS features will be disabled.

### Firewall Issues

**Problem:** DNS queries not working from external hosts
```
dig @agent-ip example.com
# timeout
```

**Solution:**
```bash
# UFW
sudo ufw allow 53/udp
sudo ufw allow 53/tcp

# firewalld
sudo firewall-cmd --permanent --add-port=53/udp
sudo firewall-cmd --permanent --add-port=53/tcp
sudo firewall-cmd --reload

# iptables
sudo iptables -A INPUT -p udp --dport 53 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 53 -j ACCEPT
```

## Uninstallation

To completely remove Defenra Agent:

```bash
sudo ./uninstall.sh
```

Or manually:

```bash
# Stop and disable service
sudo systemctl stop defenra-agent
sudo systemctl disable defenra-agent

# Remove service file
sudo rm /etc/systemd/system/defenra-agent.service

# Reload systemd
sudo systemctl daemon-reload

# Remove installation directory
sudo rm -rf /opt/defenra-agent

# Remove user (optional)
sudo userdel defenra

# Remove firewall rules (if added)
# UFW
sudo ufw delete allow 53/udp
sudo ufw delete allow 53/tcp
sudo ufw delete allow 80/tcp
sudo ufw delete allow 443/tcp
sudo ufw delete allow 8080/tcp

# firewalld
sudo firewall-cmd --permanent --remove-port=53/udp
sudo firewall-cmd --permanent --remove-port=53/tcp
sudo firewall-cmd --permanent --remove-port=80/tcp
sudo firewall-cmd --permanent --remove-port=443/tcp
sudo firewall-cmd --permanent --remove-port=8080/tcp
sudo firewall-cmd --reload
```

## Upgrades

To upgrade to a new version:

1. **Stop service:**
   ```bash
   sudo systemctl stop defenra-agent
   ```

2. **Backup current binary:**
   ```bash
   sudo cp /opt/defenra-agent/defenra-agent \
          /opt/defenra-agent/defenra-agent.bak
   ```

3. **Download new version:**
   ```bash
   cd /path/to/new/version
   ```

4. **Build and install:**
   ```bash
   go build -o defenra-agent .
   sudo cp defenra-agent /opt/defenra-agent/
   sudo chown defenra:defenra /opt/defenra-agent/defenra-agent
   sudo chmod 755 /opt/defenra-agent/defenra-agent
   sudo setcap 'cap_net_bind_service=+ep' /opt/defenra-agent/defenra-agent
   ```

5. **Start service:**
   ```bash
   sudo systemctl start defenra-agent
   ```

6. **Verify:**
   ```bash
   sudo systemctl status defenra-agent
   curl http://localhost:8080/health
   ```

## Security Considerations

1. **Agent Key Protection**
   - Store securely in systemd service file
   - File permissions: 644 (readable by root)
   - Never expose in logs

2. **Network Security**
   - Use HTTPS for Core API connection
   - Restrict health endpoint access (port 8080)
   - Configure firewall rules

3. **Service Hardening**
   - Runs as non-root user (defenra)
   - Limited file system access
   - No new privileges
   - Protected home and system directories

4. **Regular Updates**
   - Update agent regularly
   - Update GeoIP database monthly
   - Monitor security advisories

## Support

For installation issues:

1. **Check Documentation**
   - README.md - Main documentation
   - QUICKSTART.md - Quick start guide
   - TROUBLESHOOTING.md - Common issues

2. **View Logs**
   ```bash
   sudo journalctl -u defenra-agent -f
   ```

3. **Report Issues**
   - GitHub: https://github.com/defenra/agent/issues
   - Email: support@defenra.com
   - Include: OS version, logs, error messages

## Additional Resources

- **GitHub Repository:** https://github.com/defenra/agent
- **Documentation:** https://docs.defenra.com
- **API Reference:** https://docs.defenra.com/api
- **Examples:** examples/waf-examples.lua

---

**Last Updated:** 2025-10-23  
**Script Version:** 1.0.0
