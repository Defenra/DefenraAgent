# Load-Based Agent Routing

## Overview

Load-based routing ensures that traffic is distributed to healthy agents while avoiding overloaded ones. This prevents cascading failures and maintains optimal performance across the agent network.

## How It Works

### System Metrics Collection
1. **Agent Side**: Each agent collects system metrics every 60 seconds:
   - CPU usage percentage
   - Memory usage percentage  
   - Load average (1min, 5min, 15min)
   - Disk I/O (read/write bytes per second)
   - Network I/O (rx/tx bytes per second)
   - Number of goroutines

2. **Core Side**: Metrics are processed and a load score (0-100) is calculated:
   - CPU usage: 30% weight
   - Memory usage: 25% weight
   - Load average: 25% weight (normalized by CPU count)
   - Disk I/O: 10% weight (normalized to 100MB/s = 100%)
   - Network I/O: 10% weight (normalized to 1GB/s = 100%)

### Agent Selection Algorithm

#### Filtering Phase
1. **Health Check**: Only agents with health score > 0.3 are considered
2. **Load Check**: Agents with load score > 80% are marked as overloaded and excluded
3. **Availability**: Only non-overloaded agents are available for routing

#### Selection Phase
If healthy, non-overloaded agents are available:
- **Combined Score**: 70% health score + 30% inverted load score
- **Inverted Load**: (100 - loadScore) / 100 (lower load = higher score)
- **Best Agent**: Agent with highest combined score is selected

#### Fallback Behavior
- **All Agents Overloaded**: Route directly to origin server
- **No Agents Available**: Route directly to origin server
- **Agent Discovery Failed**: Route directly to origin server

## Configuration

### Load Threshold
The overload threshold is hardcoded at 80% load score. Agents above this threshold are excluded from routing.

### Scoring Weights
- Health Score: 70% (network connectivity and response time)
- Load Score: 30% (system resource utilization)

## Implementation Details

### Agent Discovery Integration
```go
type DiscoveredAgent struct {
    // ... existing fields
    LoadScore    float64 // 0-100, higher = more loaded
    IsOverloaded bool    // true if loadScore > 80
}
```

### Core API Integration
The `/api/agent/list` endpoint returns `loadScore` for each agent, which is used by the discovery service.

### Routing Decision Logic
```go
func selectBestAgent(agents []*DiscoveredAgent) *DiscoveredAgent {
    // Filter out overloaded agents
    availableAgents := filterNonOverloaded(agents)
    
    if len(availableAgents) == 0 {
        // All agents overloaded - fallback to origin
        return nil
    }
    
    // Select agent with best combined score
    return findBestCombinedScore(availableAgents)
}
```

## Monitoring and Logging

### Agent Discovery Logs
```
[AgentDiscovery] Found 3 healthy and non-overloaded agents out of 5 total
[Routing] Selected agent agent-123: health=0.85, load=45.2%, combined=0.76
[Routing] All 2 agents are overloaded (>80% load), falling back to origin
```

### System Metrics Logs
```
[Stats] System metrics collected: CPU=25.3%, Memory=67.8%, Load=1.45, Goroutines=42
[Statistics] Updated agent agent-123 with load score: 52
```

## Benefits

1. **Prevents Overload**: Automatically excludes overloaded agents from routing
2. **Optimal Distribution**: Routes traffic to agents with best health/load combination
3. **Graceful Degradation**: Falls back to origin when all agents are overloaded
4. **Real-time Adaptation**: Uses current system metrics for routing decisions
5. **Cascading Failure Prevention**: Avoids sending traffic to struggling agents

## Testing

Comprehensive test suite covers:
- Agent selection with various load/health combinations
- Overload threshold enforcement (>80%)
- Fallback behavior when all agents overloaded
- Combined scoring algorithm validation
- Health filtering integration

## Platform Support

- **Linux**: Full system metrics (CPU, memory, load, disk, network)
- **Windows/macOS**: Simulated metrics based on runtime stats and goroutine count
- **Cross-platform**: Load-based routing works on all platforms with appropriate metric collection