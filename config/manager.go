package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

type ConfigManager struct {
	coreURL                string
	agentID                string
	agentKey               string
	geoCode                string // Agent's geo code (country code)
	config                 *Config
	mu                     sync.RWMutex
	client                 *http.Client
	stats                  Stats
	connectionLimitUpdater func(int) // Callback to update connection limits
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

	var resp *http.Response
	var reqErr error
	maxRetries := 3

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			log.Printf("[Poll] Retrying in 5 seconds (attempt %d/%d)...", attempt, maxRetries)
			time.Sleep(5 * time.Second)
		}

		// Re-create request for each attempt because Body is consumed
		req, err := http.NewRequest("POST", cm.coreURL+"/api/agent/poll", bytes.NewBuffer(jsonData))
		if err != nil {
			log.Printf("[Poll] Error creating request: %v", err)
			cm.recordFailedPoll()
			return
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+cm.agentKey)

		resp, reqErr = cm.client.Do(req)
		if reqErr == nil {
			if resp.StatusCode == http.StatusOK {
				// Success!
				break
			}
			// Server returned error status
			body, _ := io.ReadAll(resp.Body)
			log.Printf("[Poll] Error response (status %d): %s", resp.StatusCode, string(body))
			resp.Body.Close()
			reqErr = fmt.Errorf("status %d", resp.StatusCode)
		} else {
			log.Printf("[Poll] Error making request: %v", reqErr)
		}
	}

	if reqErr != nil {
		cm.recordFailedPoll()
		return
	}
	defer resp.Body.Close()

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

	// Helper function to validate IPv4 address
	isValidIPv4 := func(ip string) bool {
		if ip == "" {
			return false
		}
		parsedIP := net.ParseIP(ip)
		if parsedIP == nil {
			return false
		}
		// Check if it's IPv4
		return parsedIP.To4() != nil
	}

	// Helper function to check if a name is a valid ISO 3166-1 alpha-2 country code
	isCountryCode := func(name string) bool {
		if len(name) != 2 {
			return false
		}
		// Check if both characters are letters (uppercase or lowercase)
		for _, c := range name {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
				return false
			}
		}
		return true
	}

	// Convert DNS records with location names to GeoDNS map
	for i := range resp.Domains {
		domain := &resp.Domains[i]

		// Initialize GeoDNS map if not exists
		if domain.GeoDNSMap == nil {
			domain.GeoDNSMap = make(map[string]string)
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

				// Check if this is a GeoDNS location record (ISO 3166-1 alpha-2 country code)
				if isCountryCode(recordName) {
					// Validate IP address before adding to GeoDNS map
					if !isValidIPv4(record.Value) {
						log.Printf("[Config] WARNING: Invalid IPv4 address for GeoDNS %s: %s - skipping", recordName, record.Value)
						continue
					}
					// Store in lowercase for consistent GeoDNS lookups
					countryCode := strings.ToLower(recordName)
					domain.GeoDNSMap[countryCode] = record.Value
				} else if recordName == "@" || recordName == "" || recordName == domain.Domain {
					// This is the default record
					if !isValidIPv4(record.Value) {
						log.Printf("[Config] WARNING: Invalid IPv4 address for default GeoDNS: %s - skipping", record.Value)
					} else {
						domain.GeoDNSMap["default"] = record.Value
					}
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

	// Save agent's geo code for D-Agent-ID header
	if resp.GeoCode != "" {
		cm.geoCode = resp.GeoCode
	}

	// Update global connection limits based on domain configurations
	cm.updateConnectionLimits()

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

		// Log GeoDNS mappings in compact format
		if len(domain.GeoDNSMap) > 0 {
			// Sort keys for consistent output
			keys := make([]string, 0, len(domain.GeoDNSMap))
			for k := range domain.GeoDNSMap {
				keys = append(keys, k)
			}
			sort.Strings(keys)

			// Build compact string: "us->1.2.3.4, eu->5.6.7.8, default->9.10.11.12"
			var geoDNSPairs []string
			for _, location := range keys {
				geoDNSPairs = append(geoDNSPairs, location+"->"+domain.GeoDNSMap[location])
			}
			log.Printf("[Poll]   GeoDNS: %s", strings.Join(geoDNSPairs, ", "))
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

	// First, try exact match
	for i := range cm.config.Domains {
		if cm.config.Domains[i].Domain == domain {
			return &cm.config.Domains[i]
		}
	}

	// If no exact match, check for subdomain records (CNAME or A records)
	// For example, if requesting "api.ghost-cheats.com", check if "ghost-cheats.com" has records for "api"
	parts := strings.Split(domain, ".")
	if len(parts) >= 2 {
		subdomain := parts[0]
		parentDomain := strings.Join(parts[1:], ".")

		// Look for parent domain with DNS record for this subdomain
		for i := range cm.config.Domains {
			if cm.config.Domains[i].Domain == parentDomain {
				// Check if this domain has any DNS record for the subdomain
				for _, record := range cm.config.Domains[i].DNSRecords {
					if record.Name == subdomain {
						if record.Type == "CNAME" {
							log.Printf("[Config] Found CNAME record: %s.%s -> %s", subdomain, parentDomain, record.Value)
						} else if record.Type == "A" || record.Type == "AAAA" {
							log.Printf("[Config] Found %s record: %s.%s -> %s", record.Type, subdomain, parentDomain, record.Value)
						}
						// Return the parent domain configuration for subdomain resolution
						return &cm.config.Domains[i]
					}
				}
			}
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

// GetAllDomainNames возвращает список всех настроенных доменов для SNI validation
func (cm *ConfigManager) GetAllDomainNames() []string {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	domainNames := make([]string, 0, len(cm.config.Domains))
	for _, domain := range cm.config.Domains {
		domainNames = append(domainNames, domain.Domain)
	}
	return domainNames
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

func (cm *ConfigManager) GetAgentID() string {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.agentID
}

func (cm *ConfigManager) GetGeoCode() string {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	if cm.geoCode != "" {
		return cm.geoCode
	}

	return "XX" // Default if geo code not set
}

// SetConnectionLimitUpdater sets the callback function to update connection limits
func (cm *ConfigManager) SetConnectionLimitUpdater(updater func(int)) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.connectionLimitUpdater = updater
}

// GetAgentIP returns the agent's public IP address
// This is a best-effort attempt to determine the agent's IP
func (cm *ConfigManager) GetAgentIP() string {
	// Try to get IP from a public service
	// This is a simple implementation - in production you might want to cache this
	resp, err := http.Get("https://api.ipify.org")
	if err != nil {
		log.Printf("[Config] Failed to get agent IP from ipify: %v", err)
		return ""
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[Config] Failed to read agent IP response: %v", err)
		return ""
	}

	ip := strings.TrimSpace(string(body))
	if net.ParseIP(ip) == nil {
		log.Printf("[Config] Invalid IP address received: %s", ip)
		return ""
	}

	return ip
}

// updateConnectionLimits updates the global connection limiter with the LOWEST limit from all domains
// This ensures the most restrictive limit is applied for DDoS protection
func (cm *ConfigManager) updateConnectionLimits() {
	minLimit := 1000 // Start with high value
	foundAnyLimit := false

	// Find the LOWEST maxConnections value from all domains (most restrictive)
	for _, domain := range cm.config.Domains {
		if domain.HTTPProxy.AntiDDoS != nil && domain.HTTPProxy.AntiDDoS.Slowloris != nil {
			limit := domain.HTTPProxy.AntiDDoS.Slowloris.MaxConnections
			if limit > 0 { // Only consider positive limits
				if limit < minLimit {
					minLimit = limit
					foundAnyLimit = true
				}
				log.Printf("[Config] Domain %s has maxConnections=%d", domain.Domain, limit)
			}
		}
	}

	// If no limits found, use default
	if !foundAnyLimit {
		minLimit = 100
		log.Printf("[Config] No connection limits found in domains, using default: %d", minLimit)
	}

	log.Printf("[Config] Updating connection limits to %d connections per IP (most restrictive)", minLimit)

	// Call the callback if set
	if cm.connectionLimitUpdater != nil {
		cm.connectionLimitUpdater(minLimit)
	}
}
