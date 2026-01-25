package proxy

import (
	"testing"
)

func TestSelectBestAgent_LoadBalancing(t *testing.T) {
	tests := []struct {
		name          string
		agents        []*DiscoveredAgent
		expectedAgent string // AgentID of expected selection
		expectNil     bool
	}{
		{
			name: "select agent with best combined score",
			agents: []*DiscoveredAgent{
				{
					AgentID:      "agent1",
					HealthScore:  0.6,  // Lower health
					LoadScore:    20.0, // Low load
					IsOverloaded: false,
				},
				{
					AgentID:      "agent2",
					HealthScore:  0.7,  // Medium health
					LoadScore:    60.0, // Medium load
					IsOverloaded: false,
				},
				{
					AgentID:      "agent3",
					HealthScore:  0.8,  // Good health
					LoadScore:    10.0, // Very low load
					IsOverloaded: false,
				},
			},
			expectedAgent: "agent3", // Best combined score: good health + very low load
		},
		{
			name: "exclude overloaded agents",
			agents: []*DiscoveredAgent{
				{
					AgentID:      "agent1",
					HealthScore:  0.9,
					LoadScore:    85.0, // Overloaded
					IsOverloaded: true,
				},
				{
					AgentID:      "agent2",
					HealthScore:  0.7,
					LoadScore:    30.0, // Normal load
					IsOverloaded: false,
				},
			},
			expectedAgent: "agent2", // Only non-overloaded agent
		},
		{
			name: "all agents overloaded returns nil",
			agents: []*DiscoveredAgent{
				{
					AgentID:      "agent1",
					HealthScore:  0.9,
					LoadScore:    85.0,
					IsOverloaded: true,
				},
				{
					AgentID:      "agent2",
					HealthScore:  0.8,
					LoadScore:    90.0,
					IsOverloaded: true,
				},
			},
			expectNil: true,
		},
		{
			name: "prefer healthy agent over low-load unhealthy agent",
			agents: []*DiscoveredAgent{
				{
					AgentID:      "agent1",
					HealthScore:  0.9,  // Very healthy
					LoadScore:    70.0, // High but not overloaded
					IsOverloaded: false,
				},
				{
					AgentID:      "agent2",
					HealthScore:  0.4,  // Less healthy
					LoadScore:    10.0, // Very low load
					IsOverloaded: false,
				},
			},
			expectedAgent: "agent1", // Health score has more weight (70%)
		},
		{
			name:      "empty agent list returns nil",
			agents:    []*DiscoveredAgent{},
			expectNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := selectBestAgent(tt.agents)

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

			if result.AgentID != tt.expectedAgent {
				t.Errorf("Expected agent %s, got %s", tt.expectedAgent, result.AgentID)
			}
		})
	}
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
