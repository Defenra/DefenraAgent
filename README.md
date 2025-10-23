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

### Prerequisites

- Go 1.21 or higher
- GeoLite2-City.mmdb (for GeoDNS)

### Installation

```bash
# Clone repository
git clone https://github.com/defenra/agent.git
cd agent

# Download dependencies
go mod download

# Download GeoIP database
wget https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb

# Build
go build -o defenra-agent .
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
  -e AGENT_ID=agent_xxx \
  -e AGENT_KEY=xxx \
  -e CORE_URL=https://core.defenra.com \
  defenra-agent
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
