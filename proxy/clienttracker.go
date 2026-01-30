package proxy

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// HTTPClientConnection represents an HTTP/HTTPS client connection
type HTTPClientConnection struct {
	IP            string
	ConnectedAt   time.Time
	LastActivity  time.Time
	BytesSent     uint64
	BytesReceived uint64
	Country       string
	City          string
	CountryCode   string
	UserAgent     string
	Domain        string
}

// HTTPClientTracker tracks HTTP/HTTPS client connections
type HTTPClientTracker struct {
	mu             sync.RWMutex
	clients        map[string]*HTTPClientConnection // key: IP address
	geoIP          *GeoIPService
	geoIPSemaphore chan struct{} // Semaphore to limit concurrent lookups
}

// GeoIPService provides IP geolocation lookup
type GeoIPService struct {
	mu    sync.RWMutex
	cache map[string]*GeoIPInfo
}

// GeoIPInfo contains geolocation information for an IP
type GeoIPInfo struct {
	Country     string
	CountryCode string
	City        string
	Region      string
	Timezone    string
	ISP         string
	CachedAt    time.Time
}

// ip-api.com response structure
type ipAPIResponse struct {
	Status      string  `json:"status"`
	Country     string  `json:"country"`
	CountryCode string  `json:"countryCode"`
	Region      string  `json:"region"`
	RegionName  string  `json:"regionName"`
	City        string  `json:"city"`
	Zip         string  `json:"zip"`
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
	Timezone    string  `json:"timezone"`
	ISP         string  `json:"isp"`
	Org         string  `json:"org"`
	AS          string  `json:"as"`
	Query       string  `json:"query"`
}

var (
	globalHTTPClientTracker     *HTTPClientTracker
	globalHTTPClientTrackerOnce sync.Once
)

// GetGlobalHTTPClientTracker returns the global HTTP client tracker instance
func GetGlobalHTTPClientTracker() *HTTPClientTracker {
	globalHTTPClientTrackerOnce.Do(func() {
		globalHTTPClientTracker = &HTTPClientTracker{
			clients:        make(map[string]*HTTPClientConnection),
			geoIP:          NewGeoIPService(),
			geoIPSemaphore: make(chan struct{}, 20), // Max 20 concurrent lookups
		}
		// Start cleanup goroutine
		go globalHTTPClientTracker.cleanupLoop()
	})
	return globalHTTPClientTracker
}

// NewGeoIPService creates a new GeoIP service
func NewGeoIPService() *GeoIPService {
	return &GeoIPService{
		cache: make(map[string]*GeoIPInfo),
	}
}

// Lookup performs a GeoIP lookup for the given IP address
func (g *GeoIPService) Lookup(ip string) (*GeoIPInfo, error) {
	// Check cache first
	g.mu.RLock()
	if cached, exists := g.cache[ip]; exists {
		// Cache for 24 hours
		if time.Since(cached.CachedAt) < 24*time.Hour {
			g.mu.RUnlock()
			return cached, nil
		}
	}
	g.mu.RUnlock()

	// Perform lookup using ip-api.com (free, no API key required)
	// Rate limit: 45 requests per minute
	url := fmt.Sprintf("http://ip-api.com/json/%s?fields=status,country,countryCode,region,regionName,city,timezone,isp", ip)

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("geoip lookup failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read geoip response: %w", err)
	}

	var apiResp ipAPIResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, fmt.Errorf("failed to parse geoip response: %w", err)
	}

	if apiResp.Status != "success" {
		return nil, fmt.Errorf("geoip lookup failed for IP %s", ip)
	}

	info := &GeoIPInfo{
		Country:     apiResp.Country,
		CountryCode: apiResp.CountryCode,
		City:        apiResp.City,
		Region:      apiResp.RegionName,
		Timezone:    apiResp.Timezone,
		ISP:         apiResp.ISP,
		CachedAt:    time.Now(),
	}

	// Cache the result
	g.mu.Lock()
	g.cache[ip] = info
	g.mu.Unlock()

	return info, nil
}

// TrackRequest tracks an HTTP/HTTPS request
func (ct *HTTPClientTracker) TrackRequest(ip, userAgent, domain string, bytesSent, bytesReceived uint64) {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	client, exists := ct.clients[ip]
	if !exists {
		// New client - create entry and lookup geolocation
		client = &HTTPClientConnection{
			IP:           ip,
			ConnectedAt:  time.Now(),
			LastActivity: time.Now(),
			UserAgent:    userAgent,
			Domain:       domain,
		}
		ct.clients[ip] = client

		// Lookup geolocation asynchronously with concurrency limit
		select {
		case ct.geoIPSemaphore <- struct{}{}:
			go func() {
				defer func() { <-ct.geoIPSemaphore }()
				if geoInfo, err := ct.geoIP.Lookup(ip); err == nil {
					ct.mu.Lock()
					if c, ok := ct.clients[ip]; ok {
						c.Country = geoInfo.Country
						c.City = geoInfo.City
						c.CountryCode = geoInfo.CountryCode
					}
					ct.mu.Unlock()
				} else {
					log.Printf("[ClientTracker] GeoIP lookup failed for %s: %v", ip, err)
				}
			}()
		default:
			// Semaphore full, skip lookup to protect system
			// We'll try again next time the client sends a request and we hit this block
			// (actually we won't hit this block again because client exists now)
			// TODO: Add a background queue for missed lookups if critical
		}
	}

	// Update traffic
	atomic.AddUint64(&client.BytesSent, bytesSent)
	atomic.AddUint64(&client.BytesReceived, bytesReceived)
	client.LastActivity = time.Now()
}

// GetClients returns all tracked clients
func (ct *HTTPClientTracker) GetClients() []*HTTPClientConnection {
	ct.mu.RLock()
	defer ct.mu.RUnlock()

	clients := make([]*HTTPClientConnection, 0, len(ct.clients))
	for _, client := range ct.clients {
		// Create a copy to avoid race conditions
		clientCopy := &HTTPClientConnection{
			IP:            client.IP,
			ConnectedAt:   client.ConnectedAt,
			LastActivity:  client.LastActivity,
			BytesSent:     atomic.LoadUint64(&client.BytesSent),
			BytesReceived: atomic.LoadUint64(&client.BytesReceived),
			Country:       client.Country,
			City:          client.City,
			CountryCode:   client.CountryCode,
			UserAgent:     client.UserAgent,
			Domain:        client.Domain,
		}
		clients = append(clients, clientCopy)
	}
	return clients
}

// GetClientsByDomain returns clients filtered by domain
func (ct *HTTPClientTracker) GetClientsByDomain(domain string) []*HTTPClientConnection {
	ct.mu.RLock()
	defer ct.mu.RUnlock()

	clients := make([]*HTTPClientConnection, 0)
	for _, client := range ct.clients {
		if client.Domain == domain {
			clientCopy := &HTTPClientConnection{
				IP:            client.IP,
				ConnectedAt:   client.ConnectedAt,
				LastActivity:  client.LastActivity,
				BytesSent:     atomic.LoadUint64(&client.BytesSent),
				BytesReceived: atomic.LoadUint64(&client.BytesReceived),
				Country:       client.Country,
				City:          client.City,
				CountryCode:   client.CountryCode,
				UserAgent:     client.UserAgent,
				Domain:        client.Domain,
			}
			clients = append(clients, clientCopy)
		}
	}
	return clients
}

// cleanupLoop removes inactive clients periodically
func (ct *HTTPClientTracker) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		ct.cleanup()
	}
}

// cleanup removes clients inactive for more than 30 minutes
func (ct *HTTPClientTracker) cleanup() {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	now := time.Now()
	inactiveThreshold := 30 * time.Minute

	for ip, client := range ct.clients {
		if now.Sub(client.LastActivity) > inactiveThreshold {
			delete(ct.clients, ip)
			log.Printf("[ClientTracker] Removed inactive client: %s", ip)
		}
	}
}
