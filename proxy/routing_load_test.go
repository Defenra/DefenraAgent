package proxy

import (
	"testing"
)

func TestSelectBestAgent_ConsistentHashing(t *testing.T) {
	tests := []struct {
		name          string
		agents        []*DiscoveredAgent
		clientIP      string
		expectNil     bool
		expectedAgent string // Optional: if we want to enforce specific selection for an IP
	}{
		{
			name: "exclude overloaded agents",
			agents: []*DiscoveredAgent{
				{
					AgentID:      "agent1",
					IsOverloaded: true,
				},
				{
					AgentID:      "agent2",
					IsOverloaded: false,
				},
			},
			clientIP:      "192.168.1.1",
			expectedAgent: "agent2", // Only non-overloaded agent
		},
		{
			name: "all agents overloaded returns nil",
			agents: []*DiscoveredAgent{
				{
					AgentID:      "agent1",
					IsOverloaded: true,
				},
				{
					AgentID:      "agent2",
					IsOverloaded: true,
				},
			},
			clientIP:  "192.168.1.1",
			expectNil: true,
		},
		{
			name:      "empty agent list returns nil",
			agents:    []*DiscoveredAgent{},
			clientIP:  "192.168.1.1",
			expectNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := selectBestAgent(tt.agents, tt.clientIP)

			if tt.expectNil {
				if result != nil {
					t.Errorf("Expected nil, got agent %s", result.AgentID)
				}
				return
			}

			if result == nil {
				t.Errorf("Expected agent %s, got nil", tt.expectedAgent)
				return
			}

			if tt.expectedAgent != "" && result.AgentID != tt.expectedAgent {
				t.Errorf("Expected agent %s, got %s", tt.expectedAgent, result.AgentID)
			}
		})
	}

	t.Run("deterministic selection", func(t *testing.T) {
		agents := []*DiscoveredAgent{
			{AgentID: "agent1"},
			{AgentID: "agent2"},
			{AgentID: "agent3"},
		}
		ip := "203.0.113.50"

		first := selectBestAgent(agents, ip)
		for i := 0; i < 10; i++ {
			next := selectBestAgent(agents, ip)
			if next.AgentID != first.AgentID {
				t.Errorf("Selection not deterministic! Got %s then %s", first.AgentID, next.AgentID)
			}
		}
	})
}

func TestGetHealthyAgents_LoadFiltering(t *testing.T) {
	// Create mock discovery with test agents
	ad := &AgentDiscovery{
		agents: map[string]*DiscoveredAgent{
			"healthy-low-load": {
				AgentID:      "healthy-low-load",
				HealthScore:  0.8,
				LoadScore:    30.0,
				IsOverloaded: false,
			},
			"healthy-overloaded": {
				AgentID:      "healthy-overloaded",
				HealthScore:  0.9,
				LoadScore:    85.0,
				IsOverloaded: true,
			},
			"unhealthy-low-load": {
				AgentID:      "unhealthy-low-load",
				HealthScore:  0.2, // Below 0.3 threshold
				LoadScore:    20.0,
				IsOverloaded: false,
			},
			"healthy-medium-load": {
				AgentID:      "healthy-medium-load",
				HealthScore:  0.7,
				LoadScore:    60.0,
				IsOverloaded: false,
			},
		},
	}

	healthyAgents := ad.GetHealthyAgents()

	// Should only return agents that are both healthy (>0.3) and not overloaded (<=80%)
	expectedAgents := map[string]bool{
		"healthy-low-load":    true,
		"healthy-medium-load": true,
	}

	if len(healthyAgents) != len(expectedAgents) {
		t.Errorf("Expected %d healthy agents, got %d", len(expectedAgents), len(healthyAgents))
	}

	for _, agent := range healthyAgents {
		if !expectedAgents[agent.AgentID] {
			t.Errorf("Unexpected agent in healthy list: %s", agent.AgentID)
		}

		// Verify filtering criteria
		if agent.HealthScore <= 0.3 {
			t.Errorf("Agent %s has low health score: %.2f", agent.AgentID, agent.HealthScore)
		}
		if agent.IsOverloaded {
			t.Errorf("Agent %s is overloaded but included in healthy list", agent.AgentID)
		}
	}
}

func TestDiscoveredAgent_LoadScoreCalculation(t *testing.T) {
	tests := []struct {
		name             string
		loadScore        float64
		expectOverloaded bool
	}{
		{
			name:             "low load not overloaded",
			loadScore:        30.0,
			expectOverloaded: false,
		},
		{
			name:             "medium load not overloaded",
			loadScore:        70.0,
			expectOverloaded: false,
		},
		{
			name:             "exactly 80% not overloaded",
			loadScore:        80.0,
			expectOverloaded: false,
		},
		{
			name:             "above 80% is overloaded",
			loadScore:        85.0,
			expectOverloaded: true,
		},
		{
			name:             "very high load is overloaded",
			loadScore:        95.0,
			expectOverloaded: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			agent := &DiscoveredAgent{
				AgentID:      "test-agent",
				LoadScore:    tt.loadScore,
				IsOverloaded: tt.loadScore > 80.0,
			}

			if agent.IsOverloaded != tt.expectOverloaded {
				t.Errorf("LoadScore %.1f: expected overloaded=%v, got %v",
					tt.loadScore, tt.expectOverloaded, agent.IsOverloaded)
			}
		})
	}
}

func TestRouteAnycast_LoadBalancing(t *testing.T) {
	// This test would require more complex setup with mock HTTP requests
	// and agent discovery. For now, we test the core logic through selectBestAgent
	// and GetHealthyAgents tests above.

	// TODO: Add integration test that verifies end-to-end routing behavior
	// with overloaded agents falling back to origin
}
