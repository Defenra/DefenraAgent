# Quick Start Guide

Get Defenra Agent up and running in 5 minutes!

## 🚀 One-Line Install (Fastest)

### With Your Credentials (Recommended)

```bash
export AGENT_ID="your_agent_id"
export AGENT_KEY="your_agent_key"
export CORE_URL="https://core.defenra.com"
curl -sSL https://raw.githubusercontent.com/Defenra/DefenraAgent/main/quick-install.sh | sudo -E bash
```

⚡ **Done in ~2 minutes!** The script will:
- ✅ Detect your platform automatically
- ✅ Download pre-built binary from GitHub Releases
- ✅ Verify checksums
- ✅ Download GeoIP database
- ✅ Create systemd service
- ✅ Start the agent

### Without Credentials (Configure Later)

```bash
curl -sSL https://raw.githubusercontent.com/Defenra/DefenraAgent/main/quick-install.sh | sudo bash
```

Then configure:
```bash
sudo nano /etc/systemd/system/defenra-agent.service
# Update AGENT_ID and AGENT_KEY
sudo systemctl daemon-reload
sudo systemctl start defenra-agent
```

---

## Option 1: Quick Start Script (Linux/macOS)

```bash
# Make script executable
chmod +x quick-start.sh

# Run script
./quick-start.sh
```

The script will:
- Check Go installation
- Create .env file with your credentials
- Download dependencies
- Download GeoIP database
- Build the agent
- Start the agent

## Option 2: Manual Setup

### 1. Install Go

Download and install Go 1.21+: https://golang.org/dl/

### 2. Clone and Build

```bash
# Clone repository
git clone https://github.com/defenra/agent.git
cd agent

# Download dependencies
go mod download

# Build
go build -o defenra-agent .
```

### 3. Download GeoIP Database

```bash
wget -O GeoLite2-City.mmdb \
  https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb
```

### 4. Configure

Create `.env` file:

```bash
AGENT_ID=your_agent_id
AGENT_KEY=your_agent_key
CORE_URL=https://core.defenra.com
POLLING_INTERVAL=60
LOG_LEVEL=info
```

Get your credentials from Defenra Core dashboard.

### 5. Run

```bash
# Export variables
export $(cat .env | xargs)

# Run agent (requires root for ports 53, 80, 443)
sudo -E ./defenra-agent
```

## Option 3: Docker

```bash
# Build image
docker build -t defenra-agent .

# Run container
docker run -d \
  -p 53:53/udp \
  -p 53:53/tcp \
  -p 80:80 \
  -p 443:443 \
  -p 8080:8080 \
  -e AGENT_ID=your_agent_id \
  -e AGENT_KEY=your_agent_key \
  -e CORE_URL=https://core.defenra.com \
  --name defenra-agent \
  defenra-agent
```

## Option 4: Docker Compose

```bash
# Create .env file
cat > .env << EOF
AGENT_ID=your_agent_id
AGENT_KEY=your_agent_key
CORE_URL=https://core.defenra.com
POLLING_INTERVAL=60
LOG_LEVEL=info
EOF

# Start
docker-compose up -d

# View logs
docker-compose logs -f
```

## Verify Installation

### 1. Check Health

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
  "proxies_active": 2,
  "memory_usage": "124MB"
}
```

### 2. Test DNS

```bash
# Test DNS resolution
dig @localhost example.com

# Expected output:
# ;; ANSWER SECTION:
# example.com.    3600    IN    A    1.2.3.4
```

### 3. Test HTTP Proxy

```bash
# Update your hosts file
echo "127.0.0.1 example.com" | sudo tee -a /etc/hosts

# Test HTTP
curl http://example.com
```

### 4. Test HTTPS Proxy

```bash
curl https://example.com
```

## Troubleshooting

### Port Permission Denied

If you get "permission denied" on ports 53, 80, 443:

**Option 1: Run as root**
```bash
sudo -E ./defenra-agent
```

**Option 2: Grant capabilities (Linux)**
```bash
sudo setcap 'cap_net_bind_service=+ep' ./defenra-agent
./defenra-agent
```

**Option 3: Use alternative ports**
Modify code to use ports > 1024 and setup port forwarding

### Agent Not Connecting to Core

Check:
1. CORE_URL is correct
2. AGENT_ID and AGENT_KEY are valid
3. Network connectivity: `curl $CORE_URL/api/agent/poll`
4. Check logs for errors

### DNS Not Resolving

Check:
1. Port 53 is open: `netstat -tulpn | grep :53`
2. No other DNS server running: `sudo service systemd-resolved stop`
3. Firewall allows UDP/TCP 53
4. Domain is configured in Core

### HTTP/HTTPS Not Working

Check:
1. Ports 80/443 are open
2. Domain points to agent IP
3. SSL certificate is configured (for HTTPS)
4. HTTP proxy is enabled in Core

## Next Steps

1. **Configure Domains** - Add domains in Core dashboard
2. **Setup DNS** - Point NS records to your agent IP
3. **Add SSL Certificates** - Configure SSL in Core
4. **Configure WAF** - Add Lua scripts for security
5. **Setup Monitoring** - Configure health checks

## Getting Help

- **Documentation:** https://docs.defenra.com
- **GitHub Issues:** https://github.com/defenra/agent/issues
- **Email Support:** support@defenra.com
- **Community:** https://discord.gg/defenra

## Useful Commands

```bash
# View logs (systemd)
sudo journalctl -u defenra-agent -f

# View logs (Docker)
docker logs -f defenra-agent

# Check status
systemctl status defenra-agent

# Restart
systemctl restart defenra-agent

# Stop
systemctl stop defenra-agent

# Health check
curl http://localhost:8080/health

# Stats
curl http://localhost:8080/stats

# Test DNS
dig @localhost example.com

# Test HTTP
curl http://example.com

# Test HTTPS
curl https://example.com
```

Happy deploying! 🚀
