#!/bin/bash
# Defenra Agent Health Check Script
# This script checks if the agent is healthy and responsive

HEALTH_URL="http://localhost:8080/health"
TIMEOUT=5
MAX_FAILURES=3
FAILURE_COUNT_FILE="/tmp/defenra-agent-health-failures"

# Initialize failure counter
if [ ! -f "$FAILURE_COUNT_FILE" ]; then
    echo "0" > "$FAILURE_COUNT_FILE"
fi

# Read current failure count
FAILURES=$(cat "$FAILURE_COUNT_FILE")

# Check health endpoint
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time $TIMEOUT "$HEALTH_URL")

if [ "$HTTP_CODE" = "200" ]; then
    # Health check passed - reset failure counter
    echo "0" > "$FAILURE_COUNT_FILE"
    exit 0
else
    # Health check failed - increment counter
    FAILURES=$((FAILURES + 1))
    echo "$FAILURES" > "$FAILURE_COUNT_FILE"
    
    if [ $FAILURES -ge $MAX_FAILURES ]; then
        # Too many failures - restart service directly
        echo "Health check failed $FAILURES times, restarting service..."
        echo "0" > "$FAILURE_COUNT_FILE"
        systemctl restart defenra-agent.service
        exit 0
    else
        # Not enough failures yet - just log
        echo "Health check failed ($FAILURES/$MAX_FAILURES)"
        exit 0
    fi
fi
