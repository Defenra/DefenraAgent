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

```bash
export AGENT_ID="your-agent-id"
export AGENT_KEY="your-agent-key"
export CORE_URL="https://core.defenra.com"
curl -sSL https://raw.githubusercontent.com/Defenra/DefenraAgent/main/quick-install.sh | sudo -E bash
```

⚡ **Done in ~1 minute!** Automatically downloads, configures, and starts the agent.

### Alternative: Interactive Installation

```bash
curl -sSL https://raw.githubusercontent.com/Defenra/DefenraAgent/main/install.sh | sudo bash
```

The installer will prompt you for credentials and configure everything automatically.

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

GeoDNS routes clients to the nearest agent based on their geographic location:

- Client from Europe → European agent IP
- Client from USA → American agent IP
- Client from Asia → Asian agent IP

### Supported Locations

- `us`, `ca`, `mx` - North America
- `br`, `ar`, `cl` - South America
- `gb`, `de`, `fr`, `it`, `es`, `nl` - Europe
- `ru` - Russia
- `cn`, `jp`, `kr`, `sg`, `in` - Asia
- `au`, `nz` - Oceania
- `za`, `eg`, `ng` - Africa

## Performance

- **DNS Queries:** 10,000+ QPS per agent
- **HTTP Requests:** 5,000+ RPS per agent
- **Memory Usage:** < 512MB under normal load
- **CPU Usage:** < 50% on 2 cores
- **Startup Time:** < 5 seconds

## License

MIT
