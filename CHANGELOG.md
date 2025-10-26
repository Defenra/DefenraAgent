# Changelog

All notable changes to Defenra Agent will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.7] - 2025-10-26

### Added
- **WAF/Lua**: Added `ngx.var.request_uri` support (alias for `ngx.var.uri`)
- **WAF/Lua**: Added `ngx.say(text)` function to output text to response body
- **WAF/Lua**: Added `ngx.print(text)` function to output text to response body
- **WAF/Lua**: Custom responses with status code 200 now work correctly (e.g., for `.well-known` endpoints)

### Fixed
- **WAF/Lua**: Fixed default body initialization - now empty by default, only sets "Blocked by WAF" when actually blocking
- **WAF/Lua**: Response body from `ngx.say()` and `ngx.print()` no longer includes default text

### Improved
- **WAF/Lua**: Better compatibility with OpenResty/nginx Lua API

## [1.0.6] - 2025-10-26

### Fixed
- **WAF/Lua**: Added type assertion checks to prevent panics when Lua scripts set invalid types for `_status_code` or `_body`
- **WAF/Lua**: Fixed `ngx.exit()` to properly terminate script execution (now uses `L.RaiseError()`)
- **WAF/Lua**: Fixed `ngx.var.remote_addr` to return IP without port (consistent with nginx behavior)
- **WAF/Lua**: Fixed shared cache to be global instead of per-request (rate limiting now works correctly)
- **GeoDNS**: Added IPv4 address validation during configuration polling to prevent invalid IPs
- **GeoDNS**: Added country code validation (ISO 3166-1 alpha-2 format)
- **DNS**: Added IP address validation before sending DNS responses

### Added
- **WAF/Lua**: Added support for `ngx.header` to set custom HTTP headers from Lua scripts
- **WAF/Lua**: Added support for `ngx.var.method` to access HTTP method
- **WAF/Lua**: Security headers set in Lua are now properly applied in HTTP/HTTPS proxy responses
- **WAF/Lua**: Comprehensive unit tests covering all examples from `waf-examples.lua`

### Improved
- **GeoDNS Logging**: Condensed GeoDNS mappings into single compact log line (e.g., `GeoDNS: us->1.2.3.4, eu->5.6.7.8`) instead of multiple lines
- **Error Handling**: Better error messages for invalid IP addresses and type mismatches in WAF

### Security
- **Input Validation**: All IP addresses are now validated using `net.ParseIP()` before use
- **Type Safety**: Lua type assertions prevent runtime panics from malformed scripts

## [1.0.0] - 2025-10-23

### Added
- Initial release
- DNS Server with A, AAAA, CNAME, MX, TXT records support
- GeoDNS with geographic routing based on client location
- GeoIP database integration (MaxMind GeoLite2)
- HTTP Reverse Proxy with request forwarding
- HTTPS Reverse Proxy with SSL termination and SNI support
- Dynamic certificate loading from configuration
- Lua WAF (Web Application Firewall) with nginx-like API
- Lua sandbox with shared memory support
- TCP Proxy for custom protocol forwarding
- UDP Proxy for UDP-based protocols
- Config Manager with automatic polling from Core API
- Health check endpoint with uptime and stats
- Stats endpoint with detailed metrics
- Docker support with Dockerfile and docker-compose
- Comprehensive documentation (README, DEPLOYMENT, TESTING)
- Makefile for build automation
- Systemd service file template
- Performance optimization with caching
- Connection pooling for HTTP requests
- Graceful shutdown handling

### Security
- TLS 1.2+ for HTTPS connections
- Secure environment variable handling
- Lua script sandboxing
- Request validation and sanitization

### Performance
- DNS: 10,000+ QPS per agent
- HTTP: 5,000+ RPS per agent
- Memory: < 512MB under normal load
- CPU: < 50% on 2 cores
- Startup time: < 5 seconds

## [Unreleased]

### Planned Features
- Prometheus metrics endpoint
- Grafana dashboard
- Auto SSL certificate renewal (Let's Encrypt)
- Redis integration for shared cache
- IPv6 support improvements
- HTTP/2 and HTTP/3 support
- WebSocket proxy support
- Rate limiting per domain
- DDoS protection features
- Custom logging formats (JSON, structured)
- Configuration hot-reload without restart
- Multi-region health checks
- Automatic failover between agents
- Traffic mirroring for testing
- Request/Response transformation
- Circuit breaker pattern
- A/B testing support

### Known Issues
- None reported yet

---

## Version History

- **1.0.0** (2025-10-23) - Initial release with core features

---

## Support

For questions or issues:
- GitHub Issues: https://github.com/defenra/agent/issues
- Email: support@defenra.com
- Documentation: https://docs.defenra.com
