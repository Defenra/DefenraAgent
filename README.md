# Defenra Agent

High-performance agent written in Go that provides:
- **GeoDNS Server** - DNS with geographic routing
- **HTTP/HTTPS Reverse Proxy** - with SSL termination
- **Lua WAF** - Web Application Firewall with Lua scripts
- **TCP/UDP Proxy** - for custom protocol proxying

## Features

- 🌍 **GeoDNS** - Geographic routing based on client location
- 🔒 **SSL Termination** - Dynamic certificate loading with SNI support
- 🛡️ **Lua WAF** - Scriptable firewall with nginx-like API
- ⚡ **High Performance** - 10,000+ DNS QPS, 5,000+ HTTP RPS
- 📊 **Monitoring** - Health check endpoint with metrics
- 🔄 **Auto Update** - Polls configuration from Defenra Core

## Quick Start

### 🚀 One-Line Installation (Recommended)

**Method 1: Using Connection URL (Easiest)**

Get your one-time connection URL from Defenra Core dashboard and run:

```bash
curl -sSL https://raw.githubusercontent.com/Defenra/DefenraAgent/main/quick-install.sh | \
  sudo CONNECT_URL="https://your-core.com/api/agent/connect/TOKEN" bash
```

⚡ **Done in ~1 minute!** Automatically registers, downloads, configures, and starts the agent.

**Method 2: Using Manual Credentials**

```bash
export AGENT_ID="your-agent-id"
export AGENT_KEY="your-agent-key"
export CORE_URL="https://core.defenra.com"
curl -sSL https://raw.githubusercontent.com/Defenra/DefenraAgent/main/quick-install.sh | sudo -E bash
```

### Alternative: Interactive Installation

```bash
curl -sSL https://raw.githubusercontent.com/Defenra/DefenraAgent/main/install.sh | sudo bash
```

The installer will prompt you for credentials and configure everything automatically.

**Or with Connection URL:**
```bash
export CONNECT_URL="https://your-core.com/api/agent/connect/TOKEN"
curl -sSL https://raw.githubusercontent.com/Defenra/DefenraAgent/main/install.sh | sudo -E bash
```

**See [QUICKSTART.md](QUICKSTART.md) for detailed instructions or [INSTALL_GUIDE.md](INSTALL_GUIDE.md) for advanced scenarios.**

### Manual Installation

**Prerequisites:**
- Linux or macOS
- x86_64 (AMD64) or ARM64 architecture

**Download Binary:**
```bash
# Linux AMD64
wget https://github.com/Defenra/DefenraAgent/releases/latest/download/defenra-agent-linux-amd64.tar.gz
tar -xzf defenra-agent-linux-amd64.tar.gz

# Linux ARM64
wget https://github.com/Defenra/DefenraAgent/releases/latest/download/defenra-agent-linux-arm64.tar.gz
tar -xzf defenra-agent-linux-arm64.tar.gz

# macOS (Intel)
wget https://github.com/Defenra/DefenraAgent/releases/latest/download/defenra-agent-darwin-amd64.tar.gz
tar -xzf defenra-agent-darwin-amd64.tar.gz

# macOS (Apple Silicon)
wget https://github.com/Defenra/DefenraAgent/releases/latest/download/defenra-agent-darwin-arm64.tar.gz
tar -xzf defenra-agent-darwin-arm64.tar.gz
```

**Verify Checksum:**
```bash
sha256sum -c defenra-agent-linux-amd64.tar.gz.sha256
```

### Build from Source

**Prerequisites:**
- Go 1.21 or higher

```bash
# Clone repository
git clone https://github.com/Defenra/DefenraAgent.git
cd DefenraAgent

# Download dependencies
go mod download

# Build
go build -o defenra-agent .

# Download GeoIP database (optional, for GeoDNS)
wget https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb
```

### Configuration

Create `.env` file:

```bash
AGENT_ID=agent_xxx
AGENT_KEY=your_secret_key_here
CORE_URL=https://core.defenra.com
POLLING_INTERVAL=60
LOG_LEVEL=info
```

### Run

```bash
# Run with environment variables
./defenra-agent

# Or export variables
export AGENT_ID=agent_xxx
export AGENT_KEY=xxx
export CORE_URL=https://core.defenra.com
./defenra-agent
```

### Update

DefenraAgent includes built-in self-update functionality:

```bash
# Check for updates
defenra-agent check-update

# Update to latest version
sudo defenra-agent update

# Show current version
defenra-agent version
```

The updater automatically:
- Checks GitHub releases for new versions
- Downloads the correct binary for your platform
- Verifies SHA256 checksums
- Backs up the current binary
- Installs the new version

**See [docs/UPDATE.md](docs/UPDATE.md) for detailed documentation.**

## Docker

**Pull from Docker Hub:**
```bash
docker pull defenra/agent:latest
```

**Run container:**
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

**Or use Docker Compose:**
```bash
# Create .env file with your credentials
docker-compose up -d
```

**Build from source:**
```bash
docker build -t defenra-agent .
```

## Architecture

```
┌─────────────────────────────────────────┐
│        Defenra Agent (GoLang)           │
├─────────────────────────────────────────┤
│                                         │
│  ┌──────────┐ ┌──────────┐ ┌─────────┐│
│  │DNS Server│ │HTTP Proxy│ │TCP/UDP  ││
│  │(Port 53) │ │(80/443)  │ │Proxy    ││
│  └──────────┘ └──────────┘ └─────────┘│
│         │            │           │     │
│         └────────────┴───────────┘     │
│                  │                     │
│         ┌────────▼─────────┐           │
│         │ Config Manager   │           │
│         │ (Poll Core API)  │           │
│         └──────────────────┘           │
│                                         │
└─────────────────────────────────────────┘
              ▲
              │ HTTPS Poll (every 60s)
              │
    ┌─────────▼──────────┐
    │   Defenra Core     │
    │   (Node.js API)    │
    └────────────────────┘
```

## API Endpoints

### Health Check

```bash
GET http://localhost:8080/health
```

Response:
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

### Stats

```bash
GET http://localhost:8080/stats
```

## GeoDNS

GeoDNS routes clients to the nearest agent based on their geographic location using country-level precision:

- Client from Ukraine → Ukrainian agent IP (or closest: Poland, Russia, Turkey)
- Client from USA → American agent IP (or closest: Canada, Mexico, UK)
- Client from Japan → Japanese agent IP (or closest: South Korea, China, Singapore)

If exact country match is not available, GeoDNS automatically selects the geographically closest agent from the fallback list.

### Supported Country Codes

**Americas:**
- `us` (USA), `ca` (Canada), `mx` (Mexico)
- `br` (Brazil), `ar` (Argentina), `cl` (Chile), `co` (Colombia)

**Europe:**
- `gb` (UK), `de` (Germany), `fr` (France), `it` (Italy), `es` (Spain)
- `nl` (Netherlands), `pl` (Poland), `ua` (Ukraine), `ru` (Russia), `tr` (Turkey)

**Asia:**
- `cn` (China), `jp` (Japan), `kr` (South Korea), `in` (India)
- `sg` (Singapore), `id` (Indonesia), `th` (Thailand)
- `ae` (UAE), `ir` (Iran), `kz` (Kazakhstan)

**Oceania:**
- `au` (Australia), `nz` (New Zealand)

**Africa:**
- `za` (South Africa), `eg` (Egypt), `ng` (Nigeria)

## Performance

- **DNS Queries:** 10,000+ QPS per agent
- **HTTP Requests:** 5,000+ RPS per agent
- **Memory Usage:** < 512MB under normal load
- **CPU Usage:** < 50% on 2 cores
- **Startup Time:** < 5 seconds

## License

MIT
