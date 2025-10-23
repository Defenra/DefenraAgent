# Testing Guide

This guide covers testing procedures for Defenra Agent.

## Table of Contents

- [Unit Tests](#unit-tests)
- [Integration Tests](#integration-tests)
- [Manual Testing](#manual-testing)
- [Performance Testing](#performance-testing)

---

## Unit Tests

### Running Tests

```bash
# Run all tests
go test -v ./...

# Run tests for specific package
go test -v ./config
go test -v ./dns
go test -v ./proxy

# Run with coverage
go test -v -cover ./...

# Generate coverage report
go test -v -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

---

## Integration Tests

### Prerequisites

1. Running Defenra Core instance
2. Valid agent credentials
3. Test domain configured

### Setup

Create `test.env`:

```bash
AGENT_ID=test_agent_xxx
AGENT_KEY=test_key
CORE_URL=http://localhost:3000
POLLING_INTERVAL=10
LOG_LEVEL=debug
```

### Run Integration Tests

```bash
# Load test environment
export $(cat test.env | xargs)

# Build and run
make build
./defenra-agent
```

---

## Manual Testing

### 1. DNS Server

**Test A Record:**
```bash
dig @localhost example.com A
```

Expected output:
```
;; ANSWER SECTION:
example.com.    3600    IN    A    1.2.3.4
```

**Test AAAA Record:**
```bash
dig @localhost example.com AAAA
```

**Test CNAME Record:**
```bash
dig @localhost www.example.com CNAME
```

**Test MX Record:**
```bash
dig @localhost example.com MX
```

### 2. GeoDNS

**Test from different locations using VPN:**

```bash
# From Europe
dig @agent-ip example.com A
# Should return: 51.91.242.9

# From USA
dig @agent-ip example.com A
# Should return: 45.xxx.xxx.xxx

# From Asia
dig @agent-ip example.com A
# Should return: 103.xxx.xxx.xxx
```

**Simulate different client IPs:**
```bash
# Use public DNS resolvers from different regions
dig @8.8.8.8 example.com  # Google DNS (USA)
dig @1.1.1.1 example.com  # Cloudflare DNS
```

### 3. HTTP Proxy

**Test HTTP request:**
```bash
curl -v http://example.com
```

**Test with custom headers:**
```bash
curl -H "User-Agent: TestAgent" http://example.com
```

**Test POST request:**
```bash
curl -X POST -d "data=test" http://example.com/api
```

### 4. HTTPS Proxy

**Test HTTPS request:**
```bash
curl -v https://example.com
```

**Test certificate:**
```bash
openssl s_client -connect example.com:443 -servername example.com
```

**Check SSL details:**
```bash
curl -vI https://example.com 2>&1 | grep SSL
```

### 5. Lua WAF

**Create test Lua script in Core:**

```lua
-- Block specific IP
if ngx.var.remote_addr == "1.2.3.4" then
  return ngx.exit(403)
end

-- Rate limiting (100 requests per minute)
local ip = ngx.var.remote_addr
local limit_key = "rate_limit:" .. ip
local count = ngx.shared.cache:get(limit_key) or 0

if count > 100 then
  return ngx.exit(429)
end

ngx.shared.cache:incr(limit_key, 1, 0, 60)
```

**Test blocked IP:**
```bash
curl -H "X-Real-IP: 1.2.3.4" http://example.com
# Should return: 403 Forbidden
```

**Test rate limiting:**
```bash
# Send 150 requests
for i in {1..150}; do
  curl http://example.com
done
# After 100 requests, should return: 429 Too Many Requests
```

### 6. TCP Proxy

**Test SSH proxy:**
```bash
# Configure TCP proxy in Core:
# Port 2222 → backend.internal:22

# Test connection
ssh -p 2222 user@agent-ip
```

**Test with telnet:**
```bash
telnet agent-ip 2222
```

### 7. UDP Proxy

**Test UDP proxy:**
```bash
# Configure UDP proxy in Core:
# Port 5353 → dns.internal:53

# Test with dig
dig @agent-ip -p 5353 example.com
```

### 8. Health Check

**Test health endpoint:**
```bash
curl http://localhost:8080/health | jq
```

Expected output:
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

**Test stats endpoint:**
```bash
curl http://localhost:8080/stats | jq
```

---

## Performance Testing

### DNS Performance

**Test with dnsperf:**
```bash
# Install dnsperf
sudo apt-get install dnsperf

# Create query file (queries.txt)
echo "example.com A" > queries.txt

# Run test
dnsperf -s localhost -d queries.txt -c 100 -l 60
```

Expected results:
- **QPS:** > 10,000
- **Latency:** < 10ms

### HTTP Performance

**Test with Apache Bench:**
```bash
ab -n 10000 -c 100 http://example.com/
```

Expected results:
- **RPS:** > 5,000
- **Mean latency:** < 20ms

**Test with wrk:**
```bash
wrk -t 4 -c 100 -d 60s http://example.com/
```

### HTTPS Performance

**Test with wrk:**
```bash
wrk -t 4 -c 100 -d 60s https://example.com/
```

### Load Testing

**Test with k6:**

Create `load-test.js`:
```javascript
import http from 'k6/http';
import { check, sleep } from 'k6';

export let options = {
  stages: [
    { duration: '2m', target: 100 },
    { duration: '5m', target: 100 },
    { duration: '2m', target: 200 },
    { duration: '5m', target: 200 },
    { duration: '2m', target: 0 },
  ],
};

export default function () {
  let response = http.get('http://example.com');
  check(response, {
    'status is 200': (r) => r.status === 200,
  });
  sleep(1);
}
```

Run test:
```bash
k6 run load-test.js
```

---

## Stress Testing

### Memory Leak Test

```bash
# Run agent with profiling
go build -o defenra-agent .
./defenra-agent &

# Monitor memory usage
watch -n 1 'ps aux | grep defenra-agent'

# Run load for 24 hours
ab -n 1000000000 -c 100 http://example.com/
```

Expected: Memory should stabilize and not continuously grow.

### CPU Usage Test

```bash
# Monitor CPU usage
top -p $(pgrep defenra-agent)

# Generate heavy DNS load
dnsperf -s localhost -d queries.txt -c 1000 -l 3600
```

Expected: CPU usage < 50% on 2 cores

---

## Security Testing

### 1. DNS Amplification Attack

```bash
# Try to send large DNS response
dig @agent-ip ANY example.com
```

Expected: Should not allow amplification attacks

### 2. HTTP Header Injection

```bash
curl -H "X-Forwarded-For: 1.2.3.4\r\nX-Evil: header" http://example.com
```

Expected: Should sanitize headers

### 3. SSL/TLS Security

```bash
# Test with ssllabs (online tool)
# Or use testssl.sh
./testssl.sh https://example.com
```

Expected: Grade A or higher

### 4. Lua WAF Bypass

Try various bypass techniques:
- Case manipulation
- URL encoding
- Double encoding
- Unicode characters

Expected: Lua WAF should block all malicious attempts

---

## Regression Testing

Create `regression-tests.sh`:

```bash
#!/bin/bash

echo "Running regression tests..."

# Test 1: DNS resolution
echo "Test 1: DNS resolution"
dig @localhost example.com A +short | grep -q "1.2.3.4" || exit 1

# Test 2: HTTP proxy
echo "Test 2: HTTP proxy"
curl -s http://example.com | grep -q "OK" || exit 1

# Test 3: HTTPS proxy
echo "Test 3: HTTPS proxy"
curl -s https://example.com | grep -q "OK" || exit 1

# Test 4: Health check
echo "Test 4: Health check"
curl -s http://localhost:8080/health | grep -q "healthy" || exit 1

echo "All tests passed!"
```

Run tests:
```bash
chmod +x regression-tests.sh
./regression-tests.sh
```

---

## Continuous Integration

### GitHub Actions

Create `.github/workflows/test.yml`:

```yaml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Go
        uses: actions/setup-go@v4
        with:
          go-version: '1.21'
      
      - name: Download dependencies
        run: go mod download
      
      - name: Run tests
        run: go test -v -cover ./...
      
      - name: Build
        run: go build -v .
```

---

## Test Coverage Goals

- **Unit tests:** > 80% coverage
- **Integration tests:** All critical paths
- **Performance tests:** All components
- **Security tests:** Common vulnerabilities

---

## Reporting Issues

When reporting bugs, include:

1. **Environment:**
   - OS version
   - Go version
   - Agent version

2. **Configuration:**
   - Environment variables
   - Domain configuration

3. **Logs:**
   - Agent logs
   - Core API logs

4. **Steps to reproduce:**
   - Exact commands used
   - Expected vs actual behavior

5. **Test results:**
   - DNS queries
   - HTTP requests
   - Performance metrics

---

## Support

For testing help:
- GitHub: https://github.com/defenra/agent/issues
- Email: support@defenra.com
