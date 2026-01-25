package proxy

import (
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/defenra/agent/config"
)

const (
	// DefaultMaxHops is the default maximum number of agent hops before routing to origin
	DefaultMaxHops = 3

	// HopHeaderName is the header used to track routing path
	HopHeaderName = "X-Defenra-Hop"
)

// RoutingDecision represents the result of a routing decision
type RoutingDecision struct {
	Mode     string // "direct" or "anycast"
	Target   string // target endpoint (agent or origin)
	IsAgent  bool   // true if target is an agent, false if origin
	HopCount int    // current hop count
	HopPath  string // comma-separated list of agent IDs in path
	Reason   string // reason for the decision (for logging)
}

// RouteRequest determines where to route the request based on configuration
func RouteRequest(r *http.Request, domainConfig *config.Domain, originTarget string) RoutingDecision {
	// Default to direct routing
	if domainConfig.HTTPProxy.RoutingMode == "" || domainConfig.HTTPProxy.RoutingMode == "direct" {
		return RoutingDecision{
			Mode:     "direct",
			Target:   originTarget,
			IsAgent:  false,
			HopCount: 0,
			HopPath:  "",
			Reason:   "routing mode is direct",
		}
	}

	// Anycast routing
	if domainConfig.HTTPProxy.RoutingMode == "anycast" {
		return routeAnycast(r, domainConfig, originTarget)
	}

	// Unknown routing mode, fallback to direct
	log.Printf("[Routing] Unknown routing mode: %s, falling back to direct", domainConfig.HTTPProxy.RoutingMode)
	return RoutingDecision{
		Mode:     "direct",
		Target:   originTarget,
		IsAgent:  false,
		HopCount: 0,
		HopPath:  "",
		Reason:   fmt.Sprintf("unknown routing mode: %s", domainConfig.HTTPProxy.RoutingMode),
	}
}

// routeAnycast implements anycast routing logic with automatic agent discovery
func routeAnycast(r *http.Request, domainConfig *config.Domain, originTarget string) RoutingDecision {
	// Parse current hop count and path from header
	hopCount, hopPath := parseHopHeader(r)

	// Determine max hops
	maxHops := domainConfig.HTTPProxy.MaxHops
	if maxHops <= 0 {
		maxHops = DefaultMaxHops
	}

	// Check if we've reached the hop limit
	if hopCount >= maxHops {
		return RoutingDecision{
			Mode:     "anycast",
			Target:   originTarget,
			IsAgent:  false,
			HopCount: hopCount,
			HopPath:  hopPath,
			Reason:   fmt.Sprintf("hop limit reached (%d >= %d)", hopCount, maxHops),
		}
	}

	// Get agent discovery service
	discovery := GetGlobalAgentDiscovery()
	if discovery == nil {
		return RoutingDecision{
			Mode:     "anycast",
			Target:   originTarget,
			IsAgent:  false,
			HopCount: hopCount,
			HopPath:  hopPath,
			Reason:   "agent discovery not initialized",
		}
	}

	// Get healthy agents from discovery
	healthyAgents := discovery.GetHealthyAgents()
	if len(healthyAgents) == 0 {
		return RoutingDecision{
			Mode:     "anycast",
			Target:   originTarget,
			IsAgent:  false,
			HopCount: hopCount,
			HopPath:  hopPath,
			Reason:   "no healthy agents available",
		}
	}

	// Filter out agents already in the hop path to prevent loops
	visitedAgents := make(map[string]bool)
	if hopPath != "" {
		for _, agentID := range strings.Split(hopPath, ",") {
			visitedAgents[strings.TrimSpace(agentID)] = true
		}
	}

	availableAgents := make([]*DiscoveredAgent, 0)
	for _, agent := range healthyAgents {
		if !visitedAgents[agent.AgentID] {
			availableAgents = append(availableAgents, agent)
		}
	}

	if len(availableAgents) == 0 {
		return RoutingDecision{
			Mode:     "anycast",
			Target:   originTarget,
			IsAgent:  false,
			HopCount: hopCount,
			HopPath:  hopPath,
			Reason:   "all agents already visited (loop prevention)",
		}
	}

	// Select best agent based on health score and latency
	selectedAgent := selectBestAgent(availableAgents)
	if selectedAgent == nil {
		return RoutingDecision{
			Mode:     "anycast",
			Target:   originTarget,
			IsAgent:  false,
			HopCount: hopCount,
			HopPath:  hopPath,
			Reason:   "no agent selected",
		}
	}

	return RoutingDecision{
		Mode:     "anycast",
		Target:   selectedAgent.Endpoint,
		IsAgent:  true,
		HopCount: hopCount,
		HopPath:  hopPath,
		Reason:   fmt.Sprintf("selected agent %s (health: %.2f, latency: %v)", selectedAgent.AgentID, selectedAgent.HealthScore, selectedAgent.Latency),
	}
}

// parseHopHeader extracts hop count and path from X-Defenra-Hop header
func parseHopHeader(r *http.Request) (int, string) {
	hopHeader := r.Header.Get(HopHeaderName)
	if hopHeader == "" {
		return 0, ""
	}

	// Header format: "agent-id-1,agent-id-2,agent-id-3"
	hops := strings.Split(hopHeader, ",")
	hopCount := len(hops)

	return hopCount, hopHeader
}

// AddHopHeader adds the current agent ID to the hop tracking header
func AddHopHeader(r *http.Request, agentID string) {
	currentHops := r.Header.Get(HopHeaderName)
	if currentHops == "" {
		r.Header.Set(HopHeaderName, agentID)
	} else {
		r.Header.Set(HopHeaderName, currentHops+","+agentID)
	}
}

// selectBestAgent selects the best agent based on health score and load score
func selectBestAgent(agents []*DiscoveredAgent) *DiscoveredAgent {
	if len(agents) == 0 {
		return nil
	}

	// Filter out overloaded agents first
	availableAgents := make([]*DiscoveredAgent, 0)
	for _, agent := range agents {
		if !agent.IsOverloaded {
			availableAgents = append(availableAgents, agent)
		}
	}

	// If all agents are overloaded, log warning and return nil (will fallback to origin)
	if len(availableAgents) == 0 {
		log.Printf("[Routing] All %d agents are overloaded (>80%% load), falling back to origin", len(agents))
		return nil
	}

	// Select agent with best combined score: health score (0-1) and inverted load score (0-1)
	var best *DiscoveredAgent
	bestScore := 0.0

	for _, agent := range availableAgents {
		// Combined score: 70% health score + 30% inverted load score
		// Load score is 0-100, so we invert it: (100 - loadScore) / 100
		invertedLoadScore := (100.0 - agent.LoadScore) / 100.0
		combinedScore := (agent.HealthScore * 0.7) + (invertedLoadScore * 0.3)

		if combinedScore > bestScore {
			bestScore = combinedScore
			best = agent
		}
	}

	if best != nil {
		log.Printf("[Routing] Selected agent %s: health=%.2f, load=%.1f%%, combined=%.2f",
			best.AgentID, best.HealthScore, best.LoadScore, bestScore)
	}

	return best
}

// GetGlobalAgentDiscovery returns the global agent discovery instance
// Returns nil if not initialized (will be initialized in main.go)
func GetGlobalAgentDiscovery() *AgentDiscovery {
	return globalAgentDiscovery
}

// selectAgent selects an agent from the pool using a simple algorithm
// DEPRECATED: Use automatic discovery instead
// For BETA: random selection with priority consideration
func selectAgent(pool []config.AgentInfo) *config.AgentInfo {
	if len(pool) == 0 {
		return nil
	}

	// Filter agents by priority (lower priority value = higher priority)
	// If no priorities set, all agents have priority 0
	minPriority := pool[0].Priority
	for _, agent := range pool {
		if agent.Priority < minPriority {
			minPriority = agent.Priority
		}
	}

	// Collect agents with highest priority (lowest priority value)
	highPriorityAgents := make([]config.AgentInfo, 0)
	for _, agent := range pool {
		if agent.Priority == minPriority {
			highPriorityAgents = append(highPriorityAgents, agent)
		}
	}

	// Random selection from high priority agents
	if len(highPriorityAgents) == 0 {
		return nil
	}

	rand.Seed(time.Now().UnixNano())
	selected := highPriorityAgents[rand.Intn(len(highPriorityAgents))]
	return &selected
}

// GetAgentID returns a unique identifier for this agent
// For BETA: use hostname or generate a simple ID
func GetAgentID() string {
	// TODO: In production, this should be configured or derived from agent registration
	// For BETA, use a simple timestamp-based ID
	return fmt.Sprintf("agent-%d", time.Now().Unix()%10000)
}
