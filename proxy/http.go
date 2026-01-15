package proxy

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/defenra/agent/config"
	"github.com/defenra/agent/firewall"
	"github.com/defenra/agent/health"
	"github.com/defenra/agent/waf"
)

var (
	globalHTTPServer  *HTTPProxyServer
	globalHTTPSServer *HTTPSProxyServer
)

type HTTPProxyServer struct {
	configMgr   *config.ConfigManager
	wafEngine   *waf.LuaWAF
	stats       *HTTPStats
	rateLimiter *RateLimiter
	firewallMgr *firewall.IPTablesManager
}

type HTTPStats struct {
	TotalRequests   uint64
	BlockedRequests uint64
	RateLimitBlocks uint64
	FirewallBlocks  uint64
	ProxyErrors     uint64
}

func StartHTTPProxy(configMgr *config.ConfigManager) {
	rateLimiter := NewRateLimiter()
	rateLimiter.StartCleanup()

	firewallMgr := firewall.GetIPTablesManager()
	health.SetFirewallManager(firewallMgr)

	server := &HTTPProxyServer{
		configMgr:   configMgr,
		wafEngine:   waf.NewLuaWAF(),
		stats:       &HTTPStats{},
		rateLimiter: rateLimiter,
		firewallMgr: firewallMgr,
	}

	globalHTTPServer = server

	httpServer := &http.Server{
		Addr:         ":80",
		Handler:      http.HandlerFunc(server.handleRequest),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	log.Fatal(httpServer.ListenAndServe())
}

func (s *HTTPProxyServer) handleRequest(w http.ResponseWriter, r *http.Request) {
	atomic.AddUint64(&s.stats.TotalRequests, 1)

	host := r.Host
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}

	clientIP := getClientIP(r)
	log.Printf("[HTTP] Request: %s %s from %s", r.Method, r.Host+r.RequestURI, clientIP)

	// проверка iptables банов
	if s.firewallMgr != nil && s.firewallMgr.IsBanned(clientIP) {
		log.Printf("[HTTP] Request blocked: IP %s is banned", clientIP)
		atomic.AddUint64(&s.stats.BlockedRequests, 1)
		atomic.AddUint64(&s.stats.FirewallBlocks, 1)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	domainConfig := s.configMgr.GetDomain(host)
	if domainConfig == nil {
		log.Printf("[HTTP] Domain not found: %s", host)
		http.Error(w, "Domain not found", http.StatusNotFound)
		return
	}

	// Применяем Page Rules
	requestURL := r.Host + r.RequestURI
	matchedRules := MatchPageRules(domainConfig.PageRules, requestURL)
	handled, skipSecurity, skipRateLimit, customBackend := ApplyPageRules(w, r, matchedRules, domainConfig)

	if handled {
		// Запрос уже обработан (redirect, block, etc)
		return
	}

	// проверка whitelist (если не отключено Page Rule)
	if !skipRateLimit && domainConfig.HTTPProxy.AntiDDoS != nil && domainConfig.HTTPProxy.AntiDDoS.Enabled {
		if len(domainConfig.HTTPProxy.AntiDDoS.IPWhitelist) > 0 {
			whitelisted := false
			for _, wlIP := range domainConfig.HTTPProxy.AntiDDoS.IPWhitelist {
				if wlIP == clientIP || strings.HasPrefix(clientIP, wlIP) {
					whitelisted = true
					break
				}
			}
			if !whitelisted {
				// проверяем whitelist с CIDR
				whitelisted = s.isIPInWhitelist(clientIP, domainConfig.HTTPProxy.AntiDDoS.IPWhitelist)
				if !whitelisted {
					log.Printf("[HTTP] Request blocked: IP %s not in whitelist", clientIP)
					atomic.AddUint64(&s.stats.BlockedRequests, 1)
					http.Error(w, "Forbidden", http.StatusForbidden)
					return
				}
			}
		}

		// rate limiting на L7
		if domainConfig.HTTPProxy.AntiDDoS.RateLimit != nil {
			rateLimitConfig := RateLimitConfig{
				WindowSeconds:        domainConfig.HTTPProxy.AntiDDoS.RateLimit.WindowSeconds,
				MaxRequests:          domainConfig.HTTPProxy.AntiDDoS.RateLimit.MaxRequests,
				BlockDurationSeconds: domainConfig.HTTPProxy.AntiDDoS.BlockDurationSeconds,
			}

			allowed, reason := s.rateLimiter.CheckRateLimit(clientIP, rateLimitConfig)
			if !allowed {
				log.Printf("[HTTP] Rate limit exceeded for %s: %s", clientIP, reason)
				atomic.AddUint64(&s.stats.BlockedRequests, 1)
				atomic.AddUint64(&s.stats.RateLimitBlocks, 1)

				// блокируем IP через iptables если превышен лимит
				if s.firewallMgr != nil {
					duration := time.Duration(domainConfig.HTTPProxy.AntiDDoS.BlockDurationSeconds) * time.Second
					if err := s.firewallMgr.BanIP(clientIP, duration); err != nil {
						log.Printf("[HTTP] Failed to ban IP %s: %v", clientIP, err)
					}
				}

				http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
				return
			}
		}
	}

	// Check if HTTP proxy is enabled OR if any DNS record has HTTPProxyEnabled
	httpEnabled := domainConfig.HTTPProxy.Enabled
	if !httpEnabled {
		// Check if any DNS record allows HTTP proxy
		for _, record := range domainConfig.DNSRecords {
			if record.HTTPProxyEnabled {
				httpEnabled = true
				break
			}
		}
	}

	if !httpEnabled {
		log.Printf("[HTTP] HTTP proxy not enabled for domain: %s (HTTPProxy.Enabled=%v)",
			host, domainConfig.HTTPProxy.Enabled)
		http.Error(w, "HTTP proxy not enabled", http.StatusForbidden)
		return
	}

	if domainConfig.HTTPProxy.Type == "https" {
		log.Printf("[HTTP] Only HTTPS allowed for domain: %s", host)
		http.Error(w, "HTTPS only", http.StatusForbidden)
		return
	}

	// WAF проверка (если не отключено Page Rule)
	if !skipSecurity && domainConfig.LuaCode != "" {
		blocked, response := s.wafEngine.Execute(domainConfig.LuaCode, r)

		// Apply headers from WAF (even if not blocked, for security headers)
		for key, value := range response.Headers {
			w.Header().Set(key, value)
		}

		if blocked {
			atomic.AddUint64(&s.stats.BlockedRequests, 1)
			log.Printf("[HTTP] Request blocked by WAF: %s", r.Host+r.RequestURI)
			w.WriteHeader(response.StatusCode)
			if _, err := w.Write([]byte(response.Body)); err != nil {
				log.Printf("[HTTP] Error writing WAF response: %v", err)
			}
			return
		}
	}

	// Determine proxy target (origin or custom backend from Page Rule)
	originTarget := s.findProxyTarget(domainConfig, host)
	if customBackend != "" {
		originTarget = customBackend
	}

	if originTarget == "" {
		log.Printf("[HTTP] No backend found for: %s", host)
		http.Error(w, "No backend available", http.StatusBadGateway)
		atomic.AddUint64(&s.stats.ProxyErrors, 1)
		return
	}

	// Make routing decision (direct or anycast)
	decision := RouteRequest(r, domainConfig, originTarget)
	log.Printf("[HTTP] Routing decision: mode=%s, target=%s, isAgent=%v, hopCount=%d, reason=%s",
		decision.Mode, decision.Target, decision.IsAgent, decision.HopCount, decision.Reason)

	// If routing to another agent, add hop tracking header
	if decision.IsAgent {
		agentID := GetAgentID()
		AddHopHeader(r, agentID)
		log.Printf("[HTTP] Added hop header: %s (total hops: %d)", agentID, decision.HopCount+1)
	}

	s.proxyRequest(w, r, decision.Target)
}

func (s *HTTPProxyServer) findProxyTarget(domainConfig *config.Domain, host string) string {
	for _, record := range domainConfig.DNSRecords {
		if record.HTTPProxyEnabled {
			if record.Type == "A" || record.Type == "AAAA" {
				return record.Value
			}
		}
	}

	if len(domainConfig.DNSRecords) > 0 {
		for _, record := range domainConfig.DNSRecords {
			if record.Type == "A" || record.Type == "AAAA" {
				return record.Value
			}
		}
	}

	return ""
}

func (s *HTTPProxyServer) proxyRequest(w http.ResponseWriter, r *http.Request, target string) {
	host := r.Host
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}

	domainConfig := s.configMgr.GetDomain(host)
	encryptionMode := "flexible" // default for HTTP proxy
	if domainConfig != nil && domainConfig.SSL.EncryptionMode != "" {
		encryptionMode = domainConfig.SSL.EncryptionMode
	}

	// Determine target URL scheme based on encryption mode
	scheme := "http"
	if encryptionMode == "full" || encryptionMode == "full_strict" {
		scheme = "https"
	}

	targetURL := fmt.Sprintf("%s://%s%s", scheme, target, r.RequestURI)

	proxyReq, err := http.NewRequest(r.Method, targetURL, r.Body)
	if err != nil {
		log.Printf("[HTTP] Error creating proxy request: %v", err)
		http.Error(w, "Proxy error", http.StatusInternalServerError)
		atomic.AddUint64(&s.stats.ProxyErrors, 1)
		return
	}

	for key, values := range r.Header {
		for _, value := range values {
			proxyReq.Header.Add(key, value)
		}
	}

	proxyReq.Header.Set("X-Forwarded-For", getClientIP(r))
	proxyReq.Header.Set("X-Forwarded-Proto", "http")
	proxyReq.Header.Set("X-Real-IP", getClientIP(r))

	// Create HTTP client with TLS configuration based on encryption mode
	client := createHTTPClient(encryptionMode)

	resp, err := client.Do(proxyReq)
	if err != nil {
		log.Printf("[HTTP] Error proxying request: %v", err)
		http.Error(w, "Backend error", http.StatusBadGateway)
		atomic.AddUint64(&s.stats.ProxyErrors, 1)
		return
	}
	defer resp.Body.Close()

	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil {
		log.Printf("[HTTP] Error copying response body: %v", err)
	}

	log.Printf("[HTTP] Proxied: %s → %s (status: %d)", r.Host+r.RequestURI, target, resp.StatusCode)
}

func getClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}

	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	if idx := strings.LastIndex(r.RemoteAddr, ":"); idx != -1 {
		return r.RemoteAddr[:idx]
	}

	return r.RemoteAddr
}

func (s *HTTPProxyServer) isIPInWhitelist(ip string, whitelist []string) bool {
	clientIP := net.ParseIP(ip)
	if clientIP == nil {
		return false
	}

	for _, wlEntry := range whitelist {
		if strings.Contains(wlEntry, "/") {
			// CIDR notation
			_, ipNet, err := net.ParseCIDR(wlEntry)
			if err != nil {
				continue
			}
			if ipNet.Contains(clientIP) {
				return true
			}
		} else {
			// single IP
			if wlEntry == ip {
				return true
			}
		}
	}

	return false
}

func (s *HTTPProxyServer) GetStats() HTTPStats {
	return HTTPStats{
		TotalRequests:   atomic.LoadUint64(&s.stats.TotalRequests),
		BlockedRequests: atomic.LoadUint64(&s.stats.BlockedRequests),
		RateLimitBlocks: atomic.LoadUint64(&s.stats.RateLimitBlocks),
		FirewallBlocks:  atomic.LoadUint64(&s.stats.FirewallBlocks),
		ProxyErrors:     atomic.LoadUint64(&s.stats.ProxyErrors),
	}
}

func GetHTTPStats() HTTPStats {
	if globalHTTPServer != nil {
		return globalHTTPServer.GetStats()
	}
	return HTTPStats{}
}

// createHTTPClient creates an HTTP client with TLS configuration based on encryption mode
func createHTTPClient(encryptionMode string) *http.Client {
	client := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Configure TLS based on encryption mode
	if encryptionMode == "full" {
		// Full mode: accept any certificate (self-signed, expired, etc.)
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		}
	} else if encryptionMode == "full_strict" {
		// Full (Strict) mode: validate certificates properly
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false,
			},
		}
	}
	// For "flexible" and "off" modes, use default HTTP transport (no TLS)

	return client
}
