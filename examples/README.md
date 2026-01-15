# DefenraAgent Configuration Examples

This directory contains example configurations for various DefenraAgent features.

## Anycast Routing (BETA)

**File:** `anycast-config-example.json`

### Overview

Anycast routing allows HTTP/HTTPS traffic to be proxied through multiple DefenraAgent instances before reaching the origin server. This creates a multi-layer defense mesh and enables geographic optimization.

### Configuration

#### Routing Modes

- **`direct`** (default): Traffic goes directly from agent to origin server
- **`anycast`** (BETA): Traffic can be routed through other agents before reaching origin

#### HTTPProxy Configuration

```json
{
  "httpProxy": {
    "type": "both",
    "enabled": true,
    "routingMode": "anycast",
    "agentPool": [
      {
        "id": "agent-eu-west",
        "endpoint": "https://agent-eu.example.com",
        "region": "eu-west",
        "priority": 0
      }
    ],
    "maxHops": 3
  }
}
```

#### Fields

- **`routingMode`**: `"direct"` or `"anycast"`
- **`agentPool`**: Array of agent endpoints for anycast routing
  - **`id`**: Unique identifier for the agent
  - **`endpoint`**: Full URL to the agent (http:// or https://)
  - **`region`**: Optional geographic region label
  - **`priority`**: Optional routing priority (lower = higher priority, default: 0)
- **`maxHops`**: Maximum number of agent hops before routing to origin (default: 3)

### How It Works

1. Client sends request to Agent A (edge)
2. Agent A checks `routingMode`:
   - If `"direct"`: proxy directly to origin
   - If `"anycast"`: select next agent from `agentPool`
3. Agent A adds `X-Defenra-Hop` header with its ID
4. Agent A proxies request to selected Agent B
5. Agent B repeats the process
6. When hop count reaches `maxHops`, route to origin
7. Response flows back through the agent chain

### Agent Selection

For BETA, agents are selected using a simple algorithm:

1. Filter agents by priority (lower priority value = higher priority)
2. Randomly select from highest priority agents
3. Future versions will support health-based and load-based selection

### Hop Tracking

Each agent adds its ID to the `X-Defenra-Hop` header:

```
X-Defenra-Hop: agent-a,agent-b,agent-c
```

This allows:
- Tracking the full routing path
- Preventing routing loops
- Debugging routing decisions

### Use Cases

1. **Multi-layer DDoS protection**: Each agent applies WAF, rate limiting, and firewall rules
2. **Geographic optimization**: Route through agents closer to origin
3. **Load distribution**: Spread traffic across multiple agents
4. **Defense in depth**: Multiple filtering layers before reaching origin

### Limitations (BETA)

- Manual agent pool configuration (no automatic discovery)
- Simple random selection algorithm
- No agent health monitoring
- No agent-to-agent authentication (relies on network trust)
- Performance not optimized (focus on correctness)

### Example Scenarios

#### Scenario 1: Direct Routing (Default)

```json
{
  "routingMode": "direct",
  "agentPool": []
}
```

Client → Agent A → Origin

#### Scenario 2: Single Intermediate Agent

```json
{
  "routingMode": "anycast",
  "agentPool": [
    {"id": "agent-b", "endpoint": "https://agent-b.example.com"}
  ],
  "maxHops": 3
}
```

Client → Agent A → Agent B → Origin

#### Scenario 3: Multi-hop with Priority

```json
{
  "routingMode": "anycast",
  "agentPool": [
    {"id": "agent-eu", "endpoint": "https://agent-eu.example.com", "priority": 0},
    {"id": "agent-us", "endpoint": "https://agent-us.example.com", "priority": 0},
    {"id": "agent-backup", "endpoint": "https://agent-backup.example.com", "priority": 1}
  ],
  "maxHops": 2
}
```

- Agents with priority 0 (agent-eu, agent-us) are selected first
- agent-backup is only used if no priority 0 agents available
- Maximum 2 hops before routing to origin

### Monitoring

Check agent logs for routing decisions:

```
[HTTP] Routing decision: mode=anycast, target=https://agent-b.example.com, isAgent=true, hopCount=0, reason=selected agent agent-b from pool
[HTTP] Added hop header: agent-a-1234 (total hops: 1)
```

### Troubleshooting

**Problem:** Traffic not routing through agents

- Check `routingMode` is set to `"anycast"`
- Verify `agentPool` is not empty
- Check agent endpoints are reachable

**Problem:** Routing loops

- Verify `maxHops` is set (default: 3)
- Check `X-Defenra-Hop` header in logs
- Ensure agents don't reference themselves in pool

**Problem:** Agent unreachable

- Agent automatically falls back to origin
- Check logs for "fallback to origin" messages
- Verify agent endpoints and network connectivity

### Future Enhancements

- Automatic agent discovery via Core API
- Health-based routing (avoid unhealthy agents)
- Load-based routing (prefer less loaded agents)
- Geographic routing (prefer closer agents)
- Agent-to-agent authentication
- Performance optimization

### Documentation

- **ADR:** `docs/ADR/ADR-0005-agent-to-agent-anycast-routing.md`
- **Feature:** `docs/Features/Feature-AnycastRouting.md`
- **Architecture:** `docs/Architecture/Overview.md`

### Feedback

This is a BETA feature. Please report issues and feedback to help improve it.
