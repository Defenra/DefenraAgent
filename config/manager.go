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

	// Convert DNS records with location names to GeoDNS map
	for i := range resp.Domains {
		domain := &resp.Domains[i]

		// Initialize GeoDNS map if not exists
		if domain.GeoDNSMap == nil {
			domain.GeoDNSMap = make(map[string]string)
		}

		// Known location identifiers
		geoLocations := map[string]bool{
			"europe": true, "north-america": true, "south-america": true,
			"africa": true, "asia": true, "oceania": true,
			"us": true, "ca": true, "mx": true, "br": true, "ar": true,
			"gb": true, "de": true, "fr": true, "it": true, "es": true, "nl": true,
			"ru": true, "cn": true, "jp": true, "kr": true, "sg": true, "in": true,
			"au": true, "nz": true, "za": true, "eg": true, "ng": true,
			"ae": true, "tr": true, "ir": true, "kz": true,
		}

		// Separate regular DNS records from GeoDNS records
		regularRecords := []DNSRecord{}
		hasHTTPProxyEnabled := false

		for _, record := range domain.DNSRecords {
			// Check if any DNS record has HTTPProxyEnabled
			if record.HTTPProxyEnabled {
				hasHTTPProxyEnabled = true
			}
			if record.Type == "A" {
				recordName := record.Name

				// Check if this is a GeoDNS location record
				if geoLocations[recordName] {
					domain.GeoDNSMap[recordName] = record.Value
					log.Printf("[Config] Converting DNS record to GeoDNS: %s -> %s", recordName, record.Value)
				} else if recordName == "@" || recordName == "" || recordName == domain.Domain {
					// This is the default record
					domain.GeoDNSMap["default"] = record.Value
					log.Printf("[Config] Setting default GeoDNS: @ -> %s", record.Value)
					// Keep @ record for regular DNS queries
					regularRecords = append(regularRecords, record)
				} else {
					// Regular DNS record (subdomain, etc)
					regularRecords = append(regularRecords, record)
				}
			} else {
				// Non-A records (AAAA, CNAME, MX, TXT)
				regularRecords = append(regularRecords, record)
			}
		}

		// Auto-enable HTTP proxy if type is set (Core doesn't send 'enabled' field)
		if domain.HTTPProxy.Type != "" && !domain.HTTPProxy.Enabled {
			log.Printf("[Config] Auto-enabling HTTP proxy for %s (type=%s)", domain.Domain, domain.HTTPProxy.Type)
			domain.HTTPProxy.Enabled = true
		}

		// Also auto-enable if any DNS record has HTTPProxyEnabled
		if hasHTTPProxyEnabled && !domain.HTTPProxy.Enabled {
			log.Printf("[Config] Auto-enabling HTTP proxy for %s (found HTTPProxyEnabled DNS records)", domain.Domain)
			domain.HTTPProxy.Enabled = true
		}

		// Update DNS records (without GeoDNS location records)
		domain.DNSRecords = regularRecords
	}

	cm.config.Domains = resp.Domains
	cm.config.Proxies = resp.Proxies
	cm.config.LastUpdate = time.Now()

	cm.stats.mu.Lock()
	cm.stats.DomainsLoaded = len(resp.Domains)
	cm.stats.ProxiesActive = len(resp.Proxies)
	cm.stats.mu.Unlock()

	// Log detailed configuration AFTER conversion
	for _, domain := range resp.Domains {
		log.Printf("[Poll] Domain: %s, DNS Records: %d, GeoDNS entries: %d, HTTP Proxy: %v, SSL: %v",
			domain.Domain, len(domain.DNSRecords), len(domain.GeoDNSMap),
			domain.HTTPProxy.Enabled, domain.SSL.Enabled)

		// Log DNS records
		for _, record := range domain.DNSRecords {
			log.Printf("[Poll]   DNS: %s %s -> %s (TTL: %d, HTTPProxy: %v)",
				record.Type, record.Name, record.Value, record.TTL, record.HTTPProxyEnabled)
		}

		// Log GeoDNS mappings
		if len(domain.GeoDNSMap) > 0 {
			for location, ip := range domain.GeoDNSMap {
				log.Printf("[Poll]   GeoDNS: %s -> %s", location, ip)
			}
		}
	}

	// Log proxy configurations
	for _, proxy := range resp.Proxies {
		log.Printf("[Poll] Proxy: %s, Protocol: '%s', Port: %d -> %s:%d",
			proxy.Name, proxy.Protocol, proxy.ListenPort, proxy.TargetHost, proxy.TargetPort)
	}
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
