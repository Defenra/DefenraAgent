package proxy

import (
	"net/http"
	"testing"

	"github.com/defenra/agent/config"
)

func TestRouteRequest_DirectMode(t *testing.T) {
	tests := []struct {
		name         string
		routingMode  string
		originTarget string
		wantMode     string
		wantIsAgent  bool
	}{
		{
			name:         "explicit direct mode",
			routingMode:  "direct",
			originTarget: "192.168.1.100",
			wantMode:     "direct",
			wantIsAgent:  false,
		},
		{
			name:         "empty routing mode defaults to direct",
			routingMode:  "",
			originTarget: "192.168.1.100",
			wantMode:     "direct",
			wantIsAgent:  false,
		},
		{
			name:         "unknown routing mode falls back to direct",
			routingMode:  "unknown",
			originTarget: "192.168.1.100",
			wantMode:     "direct",
			wantIsAgent:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			domainConfig := &config.Domain{
				HTTPProxy: config.HTTPProxy{
					RoutingMode: tt.routingMode,
				},
			}

			req, _ := http.NewRequest("GET", "http://example.com/test", nil)
			decision := RouteRequest(req, domainConfig, tt.originTarget)

			if decision.Mode != tt.wantMode {
				t.Errorf("Mode = %v, want %v", decision.Mode, tt.wantMode)
			}
			if decision.IsAgent != tt.wantIsAgent {
				t.Errorf("IsAgent = %v, want %v", decision.IsAgent, tt.wantIsAgent)
			}
			if decision.Target != tt.originTarget {
				t.Errorf("Target = %v, want %v", decision.Target, tt.originTarget)
			}
		})
	}
}

func TestRouteRequest_AnycastMode(t *testing.T) {
	tests := []struct {
		name         string
		agentPool    []config.AgentInfo
		maxHops      int
		hopCount     int
		originTarget string
		wantIsAgent  bool
		wantReason   string
	}{
		{
			name: "routes to agent when pool not empty and under hop limit",
			agentPool: []config.AgentInfo{
				{ID: "agent-1", Endpoint: "http://agent1:8080"},
			},
			maxHops:      3,
			hopCount:     0,
			originTarget: "192.168.1.100",
			wantIsAgent:  true,
			wantReason:   "selected agent",
		},
		{
			name:         "routes to origin when agent pool empty",
			agentPool:    []config.AgentInfo{},
			maxHops:      3,
			hopCount:     0,
			originTarget: "192.168.1.100",
			wantIsAgent:  false,
			wantReason:   "agent pool is empty",
		},
		{
			name: "routes to origin when hop limit reached",
			agentPool: []config.AgentInfo{
				{ID: "agent-1", Endpoint: "http://agent1:8080"},
			},
			maxHops:      3,
			hopCount:     3,
			originTarget: "192.168.1.100",
			wantIsAgent:  false,
			wantReason:   "hop limit reached",
		},
		{
			name: "uses default max hops when not configured",
			agentPool: []config.AgentInfo{
				{ID: "agent-1", Endpoint: "http://agent1:8080"},
			},
			maxHops:      0, // will use DefaultMaxHops
			hopCount:     0,
			originTarget: "192.168.1.100",
			wantIsAgent:  true,
			wantReason:   "selected agent",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			domainConfig := &config.Domain{
				HTTPProxy: config.HTTPProxy{
					RoutingMode: "anycast",
					AgentPool:   tt.agentPool,
					MaxHops:     tt.maxHops,
				},
			}

			req, _ := http.NewRequest("GET", "http://example.com/test", nil)

			// Simulate hop count by adding header
			if tt.hopCount > 0 {
				hopPath := ""
				for i := 0; i < tt.hopCount; i++ {
					if i > 0 {
						hopPath += ","
					}
					hopPath += "agent-" + string(rune('a'+i))
				}
				req.Header.Set(HopHeaderName, hopPath)
			}

			decision := RouteRequest(req, domainConfig, tt.originTarget)

			if decision.IsAgent != tt.wantIsAgent {
				t.Errorf("IsAgent = %v, want %v", decision.IsAgent, tt.wantIsAgent)
			}

			if !contains(decision.Reason, tt.wantReason) {
				t.Errorf("Reason = %v, want to contain %v", decision.Reason, tt.wantReason)
			}

			if decision.IsAgent && decision.Target == tt.originTarget {
				t.Errorf("Expected agent target, got origin target: %v", decision.Target)
			}

			if !decision.IsAgent && decision.Target != tt.originTarget {
				t.Errorf("Expected origin target %v, got %v", tt.originTarget, decision.Target)
			}
		})
	}
}

func TestParseHopHeader(t *testing.T) {
	tests := []struct {
		name         string
		headerValue  string
		wantHopCount int
		wantHopPath  string
	}{
		{
			name:         "no header",
			headerValue:  "",
			wantHopCount: 0,
			wantHopPath:  "",
		},
		{
			name:         "single hop",
			headerValue:  "agent-1",
			wantHopCount: 1,
			wantHopPath:  "agent-1",
		},
		{
			name:         "multiple hops",
			headerValue:  "agent-1,agent-2,agent-3",
			wantHopCount: 3,
			wantHopPath:  "agent-1,agent-2,agent-3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "http://example.com/test", nil)
			if tt.headerValue != "" {
				req.Header.Set(HopHeaderName, tt.headerValue)
			}

			hopCount, hopPath := parseHopHeader(req)

			if hopCount != tt.wantHopCount {
				t.Errorf("hopCount = %v, want %v", hopCount, tt.wantHopCount)
			}
			if hopPath != tt.wantHopPath {
				t.Errorf("hopPath = %v, want %v", hopPath, tt.wantHopPath)
			}
		})
	}
}

func TestAddHopHeader(t *testing.T) {
	tests := []struct {
		name            string
		existingHeader  string
		agentID         string
		wantHeaderValue string
	}{
		{
			name:            "add to empty header",
			existingHeader:  "",
			agentID:         "agent-1",
			wantHeaderValue: "agent-1",
		},
		{
			name:            "append to existing header",
			existingHeader:  "agent-1",
			agentID:         "agent-2",
			wantHeaderValue: "agent-1,agent-2",
		},
		{
			name:            "append to multiple hops",
			existingHeader:  "agent-1,agent-2",
			agentID:         "agent-3",
			wantHeaderValue: "agent-1,agent-2,agent-3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "http://example.com/test", nil)
			if tt.existingHeader != "" {
				req.Header.Set(HopHeaderName, tt.existingHeader)
			}

			AddHopHeader(req, tt.agentID)

			gotHeader := req.Header.Get(HopHeaderName)
			if gotHeader != tt.wantHeaderValue {
				t.Errorf("Header = %v, want %v", gotHeader, tt.wantHeaderValue)
			}
		})
	}
}

func TestSelectAgent(t *testing.T) {
	tests := []struct {
		name      string
		pool      []config.AgentInfo
		wantNil   bool
		wantInSet []string // agent IDs that could be selected
	}{
		{
			name:    "empty pool returns nil",
			pool:    []config.AgentInfo{},
			wantNil: true,
		},
		{
			name: "single agent selected",
			pool: []config.AgentInfo{
				{ID: "agent-1", Endpoint: "http://agent1:8080"},
			},
			wantNil:   false,
			wantInSet: []string{"agent-1"},
		},
		{
			name: "selects from multiple agents with same priority",
			pool: []config.AgentInfo{
				{ID: "agent-1", Endpoint: "http://agent1:8080", Priority: 0},
				{ID: "agent-2", Endpoint: "http://agent2:8080", Priority: 0},
				{ID: "agent-3", Endpoint: "http://agent3:8080", Priority: 0},
			},
			wantNil:   false,
			wantInSet: []string{"agent-1", "agent-2", "agent-3"},
		},
		{
			name: "selects only high priority agents",
			pool: []config.AgentInfo{
				{ID: "agent-1", Endpoint: "http://agent1:8080", Priority: 1},
				{ID: "agent-2", Endpoint: "http://agent2:8080", Priority: 0},
				{ID: "agent-3", Endpoint: "http://agent3:8080", Priority: 2},
			},
			wantNil:   false,
			wantInSet: []string{"agent-2"}, // only priority 0 (highest)
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			selected := selectAgent(tt.pool)

			if tt.wantNil {
				if selected != nil {
					t.Errorf("Expected nil, got %v", selected)
				}
				return
			}

			if selected == nil {
				t.Errorf("Expected agent, got nil")
				return
			}

			found := false
			for _, id := range tt.wantInSet {
				if selected.ID == id {
					found = true
					break
				}
			}

			if !found {
				t.Errorf("Selected agent %v not in expected set %v", selected.ID, tt.wantInSet)
			}
		})
	}
}

// Helper function
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || containsMiddle(s, substr)))
}

func containsMiddle(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
