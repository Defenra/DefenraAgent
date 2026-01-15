# Defenra Agent

Edge node for distributed DDoS protection and GeoDNS routing. Written in Go.

## What It Does

- **DNS Server** (port 53) - Geographic routing based on client location
- **HTTP/HTTPS Proxy** (ports 80/443) - Reverse proxy with SSL termination
- **Lua WAF** - Web Application Firewall with scriptable rules
- **TCP/UDP Proxy** - Custom protocol forwarding
- **L4 DDoS Protection** - Connection limits, rate limiting, iptables integration

## Installation

### Quick Install

Get your connection token from Defenra Core dashboard, then run:

```bash
curl -sSL https://raw.githubusercontent.com/Defenra/DefenraAgent/main/quick-install.sh | \
  sudo CONNECT_URL="https://your-core.com/api/agent/connect/TOKEN" bash
```

This downloads the binary, registers the agent, and starts the systemd service.

### Manual Install

Download the binary for your platform:

```bash
# Linux x64
wget https://github.com/Defenra/DefenraAgent/releases/latest/download/defenra-agent-linux-amd64.tar.gz
tar -xzf defenra-agent-linux-amd64.tar.gz
sudo mv defenra-agent-linux-amd64 /usr/local/bin/defenra-agent
sudo chmod +x /usr/local/bin/defenra-agent

# Verify checksum
sha256sum -c defenra-agent-linux-amd64.tar.gz.sha256
```

Available platforms: `linux-amd64`, `linux-arm64`, `darwin-amd64`, `darwin-arm64`, `freebsd-amd64`, `freebsd-arm64`

### Configuration

Set environment variables:

```bash
export AGENT_ID=agent_xxx
export AGENT_KEY=your_secret_key
export CORE_URL=https://core.defenra.com
export POLLING_INTERVAL=60
```

Or create `/etc/defenra-agent/.env`:

```
AGENT_ID=agent_xxx
AGENT_KEY=your_secret_key
CORE_URL=https://core.defenra.com
POLLING_INTERVAL=60
```

### Run

```bash
defenra-agent
```

For systemd service setup, see [INSTALL_GUIDE.md](INSTALL_GUIDE.md).

## Updates

Check for new releases:

```bash
defenra-agent check-update
```

Update to latest version:

```bash
sudo defenra-agent update
```

The updater downloads the binary, verifies checksums, and replaces the current version. Restart the service after updating.

## Build from Source

Requirements: Go 1.21+

```bash
git clone https://github.com/Defenra/DefenraAgent.git
cd DefenraAgent
go mod download
go build -o defenra-agent .
```

## Docker

```bash
docker run -d \
  --name defenra-agent \
  -p 53:53/udp \
  -p 53:53/tcp \
  -p 80:80 \
  -p 443:443 \
  -p 8080:8080 \
  -e AGENT_ID=agent_xxx \
  -e AGENT_KEY=xxx \
  -e CORE_URL=https://core.defenra.com \
  defenra/agent:latest
```

## How It Works

The agent polls Defenra Core every 60 seconds for configuration updates (domains, DNS records, proxy rules, WAF scripts). When a client makes a request:

1. **DNS Query** - GeoDNS returns the IP of the nearest agent based on client's country
2. **HTTP/HTTPS Request** - Proxy forwards to origin, applying WAF rules and rate limits
3. **DDoS Protection** - L4 firewall blocks malicious traffic, bans IPs via iptables

Configuration is stored in memory. No local database required.

## GeoDNS

Routes clients to the nearest agent by country code. If no exact match exists, falls back to geographically close countries.

Example: Client from Ukraine → Ukrainian agent, or if unavailable → Poland, Russia, or Turkey.

Supported regions: Americas, Europe, Asia, Oceania, Africa. See [ARCHITECTURE.md](ARCHITECTURE.md) for full country list.

## API Endpoints

Health check:
```bash
curl http://localhost:8080/health
```

Statistics:
```bash
curl http://localhost:8080/stats
```

## Performance

Tested on 2-core VPS:
- DNS: 10,000+ queries/sec
- HTTP: 5,000+ requests/sec
- Memory: ~200MB idle, <512MB under load
- Startup: <5 seconds

## Documentation

- [Quick Start](QUICKSTART.md) - Step-by-step setup
- [Installation Guide](INSTALL_GUIDE.md) - Advanced installation scenarios
- [Architecture](ARCHITECTURE.md) - Component design and data flows
- [Testing](TESTING.md) - Running tests and benchmarks
- [Update Guide](docs/UPDATE.md) - Self-update documentation

## License

MIT
