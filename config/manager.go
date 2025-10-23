package config

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"sync"
	"time"
)

type ConfigManager struct {
	coreURL  string
	agentID  string
	agentKey string
	config   *Config
	mu       sync.RWMutex
	client   *http.Client
	stats    Stats
}

type Stats struct {
	LastPollTime  time.Time
	TotalPolls    uint64
	FailedPolls   uint64
	DomainsLoaded int
	ProxiesActive int
	mu            sync.RWMutex
}

func NewConfigManager(coreURL, agentID, agentKey string) *ConfigManager {
	return &ConfigManager{
		coreURL:  coreURL,
		agentID:  agentID,
		agentKey: agentKey,
		config: &Config{
			Domains: []Domain{},
			Proxies: []Proxy{},
		},
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (cm *ConfigManager) StartPolling(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	cm.poll()

	for range ticker.C {
		cm.poll()
	}
}

func (cm *ConfigManager) poll() {
	cm.stats.mu.Lock()
	cm.stats.TotalPolls++
	cm.stats.mu.Unlock()

	log.Println("[Poll] Fetching configuration from Core...")

	reqBody := PollRequest{
		AgentID:  cm.agentID,
		AgentKey: cm.agentKey,
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		log.Printf("[Poll] Error marshaling request: %v", err)
		cm.recordFailedPoll()
		return
	}

	req, err := http.NewRequest("POST", cm.coreURL+"/api/agent/poll", bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("[Poll] Error creating request: %v", err)
		cm.recordFailedPoll()
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cm.agentKey)

	resp, err := cm.client.Do(req)
	if err != nil {
		log.Printf("[Poll] Error making request: %v", err)
		cm.recordFailedPoll()
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("[Poll] Error response (status %d): %s", resp.StatusCode, string(body))
		cm.recordFailedPoll()
		return
	}

	var pollResp PollResponse
	if err := json.NewDecoder(resp.Body).Decode(&pollResp); err != nil {
		log.Printf("[Poll] Error decoding response: %v", err)
		cm.recordFailedPoll()
		return
	}

	if !pollResp.Success {
		log.Println("[Poll] Core returned success=false")
		cm.recordFailedPoll()
		return
	}

	cm.updateConfig(pollResp)
	cm.recordSuccessfulPoll()

	log.Printf("[Poll] Configuration updated successfully: %d domains, %d proxies",
		len(pollResp.Domains), len(pollResp.Proxies))
}

func (cm *ConfigManager) updateConfig(resp PollResponse) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	cm.config.Domains = resp.Domains
	cm.config.Proxies = resp.Proxies
	cm.config.LastUpdate = time.Now()

	cm.stats.mu.Lock()
	cm.stats.DomainsLoaded = len(resp.Domains)
	cm.stats.ProxiesActive = len(resp.Proxies)
	cm.stats.mu.Unlock()
}

func (cm *ConfigManager) recordSuccessfulPoll() {
	cm.stats.mu.Lock()
	cm.stats.LastPollTime = time.Now()
	cm.stats.mu.Unlock()
}

func (cm *ConfigManager) recordFailedPoll() {
	cm.stats.mu.Lock()
	cm.stats.FailedPolls++
	cm.stats.mu.Unlock()
}

func (cm *ConfigManager) GetDomain(domain string) *Domain {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	for i := range cm.config.Domains {
		if cm.config.Domains[i].Domain == domain {
			return &cm.config.Domains[i]
		}
	}
	return nil
}

func (cm *ConfigManager) GetAllDomains() []Domain {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	domains := make([]Domain, len(cm.config.Domains))
	copy(domains, cm.config.Domains)
	return domains
}

func (cm *ConfigManager) GetProxies() []Proxy {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	proxies := make([]Proxy, len(cm.config.Proxies))
	copy(proxies, cm.config.Proxies)
	return proxies
}

func (cm *ConfigManager) GetStats() Stats {
	cm.stats.mu.RLock()
	defer cm.stats.mu.RUnlock()

	return Stats{
		LastPollTime:  cm.stats.LastPollTime,
		TotalPolls:    cm.stats.TotalPolls,
		FailedPolls:   cm.stats.FailedPolls,
		DomainsLoaded: cm.stats.DomainsLoaded,
		ProxiesActive: cm.stats.ProxiesActive,
	}
}

func (cm *ConfigManager) GetConfig() *Config {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.config
}
