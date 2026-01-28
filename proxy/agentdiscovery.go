package proxy

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"sync"
	"time"
)

// AgentDiscovery manages discovery and health monitoring of other agents
type AgentDiscovery struct {
	mu            sync.RWMutex
	coreURL       string
	agentKey      string
	agents        map[string]*DiscoveredAgent // key: agentId
	lastUpdate    time.Time
	updateTicker  *time.Ticker
	healthChecker *AgentHealthChecker
}

// DiscoveredAgent represents a discovered agent in the network
type DiscoveredAgent struct {
	AgentID   string    `json:"agentId"`
	Endpoint  string    `json:"endpoint"` // https://ip:443
	IPAddress string    `json:"ipAddress"`
	Location  *Location `json:"location"`
	IsActive  bool      `json:"isActive"`
	LastSeen  time.Time `json:"lastSeen"`
	// Health metrics
	Latency         time.Duration `json:"-"`
	HealthScore     float64       `json:"-"` // 0.0 to 1.0
	LastHealthCheck time.Time     `json:"-"`
	// Load metrics from Core
	LoadScore    float64 `json:"-"` // 0-100, higher = more loaded
	IsOverloaded bool    `json:"-"` // true if loadScore > 80
}

// Location represents geographic location of an agent
type Location struct {
	Country     string  `json:"country"`
	CountryCode string  `json:"countryCode"`
	City        string  `json:"city"`
	Region      string  `json:"region"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
}

// AgentHealthChecker monitors health of discovered agents
type AgentHealthChecker struct {
	client *http.Client
}

// HealthCheckResult stores health check results for an agent
type HealthCheckResult struct {
	IsHealthy    bool
	Latency      time.Duration
	LastCheck    time.Time
	FailureCount int
}

var (
	globalAgentDiscovery     *AgentDiscovery
	globalAgentDiscoveryOnce sync.Once
)

// GetAgentDiscovery returns the global agent discovery instance
func GetAgentDiscovery(coreURL, agentKey string) *AgentDiscovery {
	globalAgentDiscoveryOnce.Do(func() {
		globalAgentDiscovery = &AgentDiscovery{
			coreURL:       coreURL,
			agentKey:      agentKey,
			agents:        make(map[string]*DiscoveredAgent),
			healthChecker: NewAgentHealthChecker(),
		}
		// Start periodic updates
		globalAgentDiscovery.Start()
	})
	return globalAgentDiscovery
}

// NewAgentHealthChecker creates a new health checker
func NewAgentHealthChecker() *AgentHealthChecker {
	return &AgentHealthChecker{
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

// Start begins periodic agent discovery and health checks
func (ad *AgentDiscovery) Start() {
	// Initial discovery
	if err := ad.DiscoverAgents(); err != nil {
		log.Printf("[AgentDiscovery] Initial discovery failed: %v", err)
	}

	// Start periodic discovery (every 60 seconds)
	ad.updateTicker = time.NewTicker(60 * time.Second)
	go func() {
		for range ad.updateTicker.C {
			if err := ad.DiscoverAgents(); err != nil {
				log.Printf("[AgentDiscovery] Periodic discovery failed: %v", err)
			}
		}
	}()

	// Start health checking (every 30 seconds)
	go ad.healthCheckLoop()
}

// Stop stops the discovery service
func (ad *AgentDiscovery) Stop() {
	if ad.updateTicker != nil {
		ad.updateTicker.Stop()
	}
}

// DiscoverAgents fetches list of active agents from Core API
func (ad *AgentDiscovery) DiscoverAgents() error {
	req, err := http.NewRequest("GET", ad.coreURL+"/api/agent/list", nil)
	if err != nil {
		log.Printf("[AgentDiscovery] Error creating request: %v", err)
		return err
	}

	req.Header.Set("Authorization", "Bearer "+ad.agentKey)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[AgentDiscovery] Error fetching agents: %v", err)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("[AgentDiscovery] Error response: %d", resp.StatusCode)
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[AgentDiscovery] Error reading response: %v", err)
		return err
	}

	var response struct {
		Agents []struct {
			AgentID   string  `json:"agentId"`
			IPAddress string  `json:"ipAddress"`
			IsActive  bool    `json:"isActive"`
			LastSeen  string  `json:"lastSeen"`
			LoadScore float64 `json:"loadScore"` // Load score from Core (0-100)
			IPInfo    *struct {
				Country     string  `json:"country"`
				CountryCode string  `json:"countryCode"`
				City        string  `json:"city"`
				Region      string  `json:"region"`
				Lat         float64 `json:"lat"`
				Lon         float64 `json:"lon"`
			} `json:"ipInfo"`
			ManualLocation *struct {
				Country string `json:"country"`
				City    string `json:"city"`
				Region  string `json:"region"`
			} `json:"manualLocation"`
		} `json:"agents"`
	}

	if err := json.Unmarshal(body, &response); err != nil {
		log.Printf("[AgentDiscovery] Error parsing response: %v", err)
		return err
	}

	ad.mu.Lock()
	defer ad.mu.Unlock()

	// Update agents map
	newAgents := make(map[string]*DiscoveredAgent)
	for _, agentData := range response.Agents {
		if !agentData.IsActive || agentData.IPAddress == "" {
			continue
		}

		// Build endpoint URL
		endpoint := fmt.Sprintf("https://%s", agentData.IPAddress)

		// Use manual location if set, otherwise use ipInfo
		var location *Location
		if agentData.ManualLocation != nil && agentData.ManualLocation.Country != "" {
			location = &Location{
				Country: agentData.ManualLocation.Country,
				City:    agentData.ManualLocation.City,
				Region:  agentData.ManualLocation.Region,
			}
		} else if agentData.IPInfo != nil {
			location = &Location{
				Country:     agentData.IPInfo.Country,
				CountryCode: agentData.IPInfo.CountryCode,
				City:        agentData.IPInfo.City,
				Region:      agentData.IPInfo.Region,
				Latitude:    agentData.IPInfo.Lat,
				Longitude:   agentData.IPInfo.Lon,
			}
		}

		lastSeen, _ := time.Parse(time.RFC3339, agentData.LastSeen)

		agent := &DiscoveredAgent{
			AgentID:      agentData.AgentID,
			Endpoint:     endpoint,
			IPAddress:    agentData.IPAddress,
			Location:     location,
			IsActive:     agentData.IsActive,
			LastSeen:     lastSeen,
			HealthScore:  1.0,                        // Default to healthy
			LoadScore:    agentData.LoadScore,        // Load score from Core (0-100)
			IsOverloaded: agentData.LoadScore > 80.0, // Mark as overloaded if >80%
		}

		// Preserve existing health metrics if agent was already known
		if existing, ok := ad.agents[agentData.AgentID]; ok {
			agent.Latency = existing.Latency
			agent.HealthScore = existing.HealthScore
			agent.LastHealthCheck = existing.LastHealthCheck
		}

		newAgents[agentData.AgentID] = agent
	}

	ad.agents = newAgents
	ad.lastUpdate = time.Now()

	log.Printf("[AgentDiscovery] Discovered %d active agents", len(newAgents))
	return nil
}

// healthCheckLoop periodically checks health of all discovered agents
func (ad *AgentDiscovery) healthCheckLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		ad.mu.RLock()
		agents := make([]*DiscoveredAgent, 0, len(ad.agents))
		for _, agent := range ad.agents {
			agents = append(agents, agent)
		}
		ad.mu.RUnlock()

		// Check health of each agent
		for _, agent := range agents {
			go ad.checkAgentHealth(agent)
		}
	}
}

// checkAgentHealth performs a health check on a single agent
func (ad *AgentDiscovery) checkAgentHealth(agent *DiscoveredAgent) {
	startTime := time.Now()

	// Try to reach agent's health endpoint
	healthURL := agent.Endpoint + "/health"
	req, err := http.NewRequest("GET", healthURL, nil)
	if err != nil {
		ad.updateHealthScore(agent.AgentID, false, 0)
		return
	}

	resp, err := ad.healthChecker.client.Do(req)
	latency := time.Since(startTime)

	if err != nil {
		ad.updateHealthScore(agent.AgentID, false, latency)
		return
	}
	defer resp.Body.Close()

	isHealthy := resp.StatusCode == http.StatusOK
	ad.updateHealthScore(agent.AgentID, isHealthy, latency)
}

// updateHealthScore updates health metrics for an agent
func (ad *AgentDiscovery) updateHealthScore(agentID string, isHealthy bool, latency time.Duration) {
	ad.mu.Lock()
	defer ad.mu.Unlock()

	agent, ok := ad.agents[agentID]
	if !ok {
		return
	}

	agent.Latency = latency
	agent.LastHealthCheck = time.Now()

	// Calculate health score based on:
	// - Is the agent responding? (0.5 weight)
	// - Latency (0.5 weight)
	healthScore := 0.0
	if isHealthy {
		healthScore += 0.5

		// Latency score: 0-100ms = 0.5, 100-500ms = 0.25-0.5, >500ms = 0-0.25
		if latency < 100*time.Millisecond {
			healthScore += 0.5
		} else if latency < 500*time.Millisecond {
			healthScore += 0.25 + (0.25 * (1.0 - float64(latency-100*time.Millisecond)/float64(400*time.Millisecond)))
		} else {
			healthScore += 0.25 * (1.0 - math.Min(1.0, float64(latency-500*time.Millisecond)/float64(2000*time.Millisecond)))
		}
	}

	agent.HealthScore = healthScore
}

// GetHealthyAgents returns list of healthy and non-overloaded agents sorted by health score
func (ad *AgentDiscovery) GetHealthyAgents() []*DiscoveredAgent {
	ad.mu.RLock()
	defer ad.mu.RUnlock()

	healthy := make([]*DiscoveredAgent, 0)
	for _, agent := range ad.agents {
		// Agent must be healthy (health score > 0.3) AND not overloaded (load score <= 80%)
		if agent.HealthScore > 0.3 && !agent.IsOverloaded {
			healthy = append(healthy, agent)
		}
	}

	log.Printf("[AgentDiscovery] Found %d healthy and non-overloaded agents out of %d total", len(healthy), len(ad.agents))
	return healthy
}

// GetNearestAgent returns the nearest healthy agent to a given location
func (ad *AgentDiscovery) GetNearestAgent(clientLat, clientLon float64) *DiscoveredAgent {
	agents := ad.GetHealthyAgents()
	if len(agents) == 0 {
		return nil
	}

	var nearest *DiscoveredAgent
	minDistance := math.MaxFloat64

	for _, agent := range agents {
		if agent.Location == nil {
			continue
		}

		distance := haversineDistance(clientLat, clientLon, agent.Location.Latitude, agent.Location.Longitude)

		// Weight distance by health score (prefer healthier agents)
		weightedDistance := distance / agent.HealthScore

		if weightedDistance < minDistance {
			minDistance = weightedDistance
			nearest = agent
		}
	}

	return nearest
}

// haversineDistance calculates distance between two points on Earth in kilometers
func haversineDistance(lat1, lon1, lat2, lon2 float64) float64 {
	const earthRadius = 6371.0 // km

	dLat := (lat2 - lat1) * math.Pi / 180.0
	dLon := (lon2 - lon1) * math.Pi / 180.0

	a := math.Sin(dLat/2)*math.Sin(dLat/2) +
		math.Cos(lat1*math.Pi/180.0)*math.Cos(lat2*math.Pi/180.0)*
			math.Sin(dLon/2)*math.Sin(dLon/2)

	c := 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))

	return earthRadius * c
}
