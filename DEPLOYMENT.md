# Deployment Guide

This guide covers different deployment methods for Defenra Agent.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Binary Deployment](#binary-deployment)
- [Docker Deployment](#docker-deployment)
- [Systemd Service](#systemd-service)
- [Cloud Deployment](#cloud-deployment)

---

## Prerequisites

1. **Operating System:**
   - Linux (Ubuntu 20.04+, Debian 11+, CentOS 8+)
   - Windows Server 2019+
   - macOS 11+

2. **Network Requirements:**
   - Open ports: 53 (UDP/TCP), 80, 443, 8080
   - Outbound HTTPS access to Core API

3. **Resources:**
   - CPU: 2 cores minimum
   - RAM: 1GB minimum (2GB recommended)
   - Disk: 200MB for binary + 100MB for GeoIP DB

---

## Binary Deployment

### 1. Build from Source

```bash
# Clone repository
git clone https://github.com/defenra/agent.git
cd agent

# Download dependencies
go mod download

# Build
go build -o defenra-agent .
```

### 2. Download GeoIP Database

```bash
wget -O GeoLite2-City.mmdb https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb
```

### 3. Configure

Create `.env` file:

```bash
AGENT_ID=agent_xxx
AGENT_KEY=your_secret_key_here
CORE_URL=https://core.defenra.com
POLLING_INTERVAL=60
LOG_LEVEL=info
```

### 4. Run

```bash
# Load environment variables
export $(cat .env | xargs)

# Run agent
./defenra-agent
```

---

## Docker Deployment

### 1. Build Image

```bash
docker build -t defenra-agent:latest .
```

### 2. Run Container

```bash
docker run -d \
  --name defenra-agent \
  --restart unless-stopped \
  -p 53:53/udp \
  -p 53:53/tcp \
  -p 80:80 \
  -p 443:443 \
  -p 8080:8080 \
  -e AGENT_ID=agent_xxx \
  -e AGENT_KEY=xxx \
  -e CORE_URL=https://core.defenra.com \
  defenra-agent:latest
```

### 3. Check Logs

```bash
docker logs -f defenra-agent
```

### 4. Stop/Remove

```bash
docker stop defenra-agent
docker rm defenra-agent
```

---

## Systemd Service

### 1. Create Service File

Create `/etc/systemd/system/defenra-agent.service`:

```ini
[Unit]
Description=Defenra Agent
After=network.target

[Service]
Type=simple
User=defenra
Group=defenra
WorkingDirectory=/opt/defenra-agent
Environment="AGENT_ID=agent_xxx"
Environment="AGENT_KEY=xxx"
Environment="CORE_URL=https://core.defenra.com"
Environment="POLLING_INTERVAL=60"
Environment="LOG_LEVEL=info"
ExecStart=/opt/defenra-agent/defenra-agent
Restart=always
RestartSec=10

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/defenra-agent

# Allow binding to privileged ports
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
```

### 2. Create User and Directory

```bash
# Create user
sudo useradd -r -s /bin/false defenra

# Create directory
sudo mkdir -p /opt/defenra-agent
sudo chown defenra:defenra /opt/defenra-agent

# Copy binary
sudo cp defenra-agent /opt/defenra-agent/
sudo cp GeoLite2-City.mmdb /opt/defenra-agent/
```

### 3. Enable and Start Service

```bash
# Reload systemd
sudo systemctl daemon-reload

# Enable service
sudo systemctl enable defenra-agent

# Start service
sudo systemctl start defenra-agent

# Check status
sudo systemctl status defenra-agent
```

### 4. View Logs

```bash
# Follow logs
sudo journalctl -u defenra-agent -f

# View recent logs
sudo journalctl -u defenra-agent -n 100
```

---

## Cloud Deployment

### AWS EC2

1. Launch EC2 instance (t3.small or larger)
2. Open Security Groups:
   - UDP 53
   - TCP 53, 80, 443, 8080
3. Deploy using binary or Docker method

### Google Cloud Platform

1. Create Compute Engine instance (e2-small or larger)
2. Configure Firewall Rules:
   - Allow UDP 53
   - Allow TCP 53, 80, 443, 8080
3. Deploy using binary or Docker method

### DigitalOcean

1. Create Droplet (Basic $12/month or higher)
2. Configure Firewall:
   - Allow UDP 53
   - Allow TCP 53, 80, 443, 8080
3. Deploy using binary or Docker method

### Hetzner

1. Create Cloud Server (CX21 or larger)
2. Configure Firewall:
   - Allow UDP 53
   - Allow TCP 53, 80, 443, 8080
3. Deploy using binary or Docker method

---

## DNS Setup

After deployment, you need to configure NS records:

1. **At your domain registrar:**
   ```
   ns1.yourdomain.com → Your agent IP
   ns2.yourdomain.com → Your agent IP (optional backup)
   ```

2. **Set nameservers for your domain:**
   ```
   ns1.yourdomain.com
   ns2.yourdomain.com
   ```

3. **Wait for DNS propagation** (up to 48 hours)

4. **Test DNS resolution:**
   ```bash
   dig @your-agent-ip example.com
   ```

---

## Health Checks

Monitor agent health:

```bash
# Health check
curl http://your-agent-ip:8080/health

# Detailed stats
curl http://your-agent-ip:8080/stats
```

Expected response:
```json
{
  "status": "healthy",
  "uptime": "3h45m12s",
  "last_poll": "2025-10-23T10:15:00Z",
  "domains_loaded": 15,
  "proxies_active": 3,
  "memory_usage": "124MB"
}
```

---

## Troubleshooting

### Agent not starting

1. Check logs: `journalctl -u defenra-agent -n 100`
2. Verify environment variables
3. Check network connectivity to Core API
4. Verify GeoIP database exists

### DNS not resolving

1. Check if port 53 is open: `netstat -tulpn | grep :53`
2. Test locally: `dig @127.0.0.1 example.com`
3. Check firewall rules
4. Verify domain is configured in Core

### HTTP/HTTPS proxy not working

1. Check if ports 80/443 are open
2. Verify SSL certificates in Core config
3. Check domain configuration
4. Review proxy logs

---

## Monitoring

### Prometheus Metrics

Add Prometheus scrape config:

```yaml
scrape_configs:
  - job_name: 'defenra-agent'
    static_configs:
      - targets: ['agent-ip:8080']
```

### Grafana Dashboard

Import Grafana dashboard (coming soon)

---

## Security

### Firewall Rules

```bash
# Allow DNS
sudo ufw allow 53/udp
sudo ufw allow 53/tcp

# Allow HTTP/HTTPS
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Allow health check (restrict to monitoring IP)
sudo ufw allow from monitoring-ip to any port 8080

# Enable firewall
sudo ufw enable
```

### Agent Key Rotation

1. Generate new key in Core
2. Update environment variable
3. Restart agent
4. Old key expires after 24 hours

---

## Updates

### Binary Update

```bash
# Stop service
sudo systemctl stop defenra-agent

# Backup old binary
sudo cp /opt/defenra-agent/defenra-agent /opt/defenra-agent/defenra-agent.bak

# Download new binary
wget https://releases.defenra.com/agent/latest/defenra-agent

# Replace binary
sudo cp defenra-agent /opt/defenra-agent/

# Start service
sudo systemctl start defenra-agent
```

### Docker Update

```bash
# Pull new image
docker pull defenra-agent:latest

# Stop and remove old container
docker stop defenra-agent
docker rm defenra-agent

# Run new container
docker run -d ... (same as deployment)
```

---

## Support

For issues or questions:
- GitHub: https://github.com/defenra/agent/issues
- Email: support@defenra.com
