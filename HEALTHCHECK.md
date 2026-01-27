# Defenra Agent Health Check

The Defenra Agent includes automatic health monitoring and restart capabilities using systemd.

## How It Works

1. **Health Endpoint**: Agent exposes `/health` endpoint on port 8080
2. **Health Check Script**: Runs every 30 seconds via systemd timer
3. **Failure Threshold**: After 3 consecutive failures, service automatically restarts
4. **Systemd Watchdog**: Additional protection against deadlocks (60 second timeout)

## Components

### 1. Health Check Script
`/opt/defenra-agent/defenra-agent-healthcheck.sh`
- Checks if health endpoint responds with HTTP 200
- Tracks consecutive failures
- Triggers restart after 3 failures

### 2. Systemd Timer
`defenra-agent-healthcheck.timer`
- Runs health check every 30 seconds
- Starts automatically on boot
- Logs to systemd journal

### 3. Systemd Watchdog
`defenra-agent.service`
- 60 second watchdog timeout
- Restarts service if it becomes unresponsive
- Configured with `WatchdogSec=60` and `Restart=on-watchdog`

## Manual Commands

### Check health status
```bash
curl http://localhost:8080/health
```

### View health check logs
```bash
journalctl -u defenra-agent-healthcheck -f
```

### Check timer status
```bash
systemctl status defenra-agent-healthcheck.timer
```

### Manually trigger health check
```bash
systemctl start defenra-agent-healthcheck.service
```

### Disable health check
```bash
systemctl stop defenra-agent-healthcheck.timer
systemctl disable defenra-agent-healthcheck.timer
```

### Re-enable health check
```bash
systemctl enable defenra-agent-healthcheck.timer
systemctl start defenra-agent-healthcheck.timer
```

## Troubleshooting

### Health check keeps restarting service
If the service is restarting too frequently:

1. Check agent logs:
```bash
journalctl -u defenra-agent -n 100
```

2. Check health endpoint manually:
```bash
curl -v http://localhost:8080/health
```

3. Increase failure threshold in health check script:
```bash
# Edit /opt/defenra-agent/defenra-agent-healthcheck.sh
# Change MAX_FAILURES=3 to MAX_FAILURES=5
```

### Disable automatic restart temporarily
```bash
systemctl stop defenra-agent-healthcheck.timer
```

### Check failure counter
```bash
cat /tmp/defenra-agent-health-failures
```

## Configuration

### Adjust check interval
Edit `/etc/systemd/system/defenra-agent-healthcheck.timer`:
```ini
[Timer]
OnUnitActiveSec=60s  # Change from 30s to 60s
```

Then reload:
```bash
systemctl daemon-reload
systemctl restart defenra-agent-healthcheck.timer
```

### Adjust watchdog timeout
Edit `/etc/systemd/system/defenra-agent.service`:
```ini
[Service]
WatchdogSec=120  # Change from 60 to 120 seconds
```

Then reload:
```bash
systemctl daemon-reload
systemctl restart defenra-agent
```

## Benefits

- **Automatic Recovery**: Service restarts automatically if it becomes unresponsive
- **Deadlock Protection**: Watchdog catches cases where health endpoint stops responding
- **DDoS Resilience**: During attacks, if agent deadlocks, it will restart automatically
- **Minimal Downtime**: Fast detection (30s) and restart (10s) = ~40s total downtime
- **No Manual Intervention**: Works 24/7 without human monitoring

## Monitoring

The health check system logs all events to systemd journal:

```bash
# View all health-related logs
journalctl -u defenra-agent -u defenra-agent-healthcheck -f

# Count restarts in last hour
journalctl -u defenra-agent --since "1 hour ago" | grep "Started Defenra Agent" | wc -l

# Check if service is healthy
systemctl is-active defenra-agent && curl -s http://localhost:8080/health
```
