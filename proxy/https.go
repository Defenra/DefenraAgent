package proxy

import (
	"crypto/tls"
	"errors"
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

type HTTPSProxyServer struct {
	configMgr   *config.ConfigManager
	wafEngine   *waf.LuaWAF
	stats       *HTTPStats
	rateLimiter *RateLimiter
	firewallMgr *firewall.IPTablesManager
}

func StartHTTPSProxy(configMgr *config.ConfigManager) {
	rateLimiter := NewRateLimiter()
	rateLimiter.StartCleanup()

	firewallMgr := firewall.GetIPTablesManager()
	health.SetFirewallManager(firewallMgr)

	server := &HTTPSProxyServer{
		configMgr:   configMgr,
		wafEngine:   waf.NewLuaWAF(),
		stats:       &HTTPStats{},
		rateLimiter: rateLimiter,
		firewallMgr: firewallMgr,
	}

	globalHTTPSServer = server

	tlsConfig := &tls.Config{
		GetCertificate: server.getCertificate,
		MinVersion:     tls.VersionTLS12,
	}

	httpsServer := &http.Server{
		Addr:         ":443",
		Handler:      http.HandlerFunc(server.handleRequest),
		TLSConfig:    tlsConfig,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	log.Fatal(httpsServer.ListenAndServeTLS("", ""))
}

func (s *HTTPSProxyServer) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	domainConfig := s.configMgr.GetDomain(hello.ServerName)
	if domainConfig == nil {
		log.Printf("[HTTPS] No config found for domain: %s", hello.ServerName)
		return nil, errors.New("no certificate available")
	}

	if !domainConfig.SSL.Enabled {
		log.Printf("[HTTPS] SSL not enabled for domain: %s", hello.ServerName)
		return nil, errors.New("ssl not enabled")
	}

	if domainConfig.SSL.Certificate == "" || domainConfig.SSL.PrivateKey == "" {
		log.Printf("[HTTPS] Certificate or key missing for domain: %s", hello.ServerName)
		return nil, errors.New("certificate or key missing")
	}

	cert, err := tls.X509KeyPair(
		[]byte(domainConfig.SSL.Certificate),
		[]byte(domainConfig.SSL.PrivateKey),
	)
	if err != nil {
		log.Printf("[HTTPS] Error loading certificate for %s: %v", hello.ServerName, err)
		return nil, err
	}

	log.Printf("[HTTPS] Certificate loaded for: %s", hello.ServerName)
	return &cert, nil
}

func (s *HTTPSProxyServer) handleRequest(w http.ResponseWriter, r *http.Request) {
	atomic.AddUint64(&s.stats.TotalRequests, 1)

	host := r.Host
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}

	clientIP := getClientIP(r)
	log.Printf("[HTTPS] Request: %s %s from %s", r.Method, r.Host+r.RequestURI, clientIP)

	// проверка iptables банов
	if s.firewallMgr != nil && s.firewallMgr.IsBanned(clientIP) {
		log.Printf("[HTTPS] Request blocked: IP %s is banned", clientIP)
		atomic.AddUint64(&s.stats.BlockedRequests, 1)
		atomic.AddUint64(&s.stats.FirewallBlocks, 1)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	domainConfig := s.configMgr.GetDomain(host)
	if domainConfig == nil {
		log.Printf("[HTTPS] Domain not found: %s", host)
		http.Error(w, "Domain not found", http.StatusNotFound)
		return
	}

	// проверка whitelist и rate limiting
	if domainConfig.HTTPProxy.AntiDDoS != nil && domainConfig.HTTPProxy.AntiDDoS.Enabled {
		if len(domainConfig.HTTPProxy.AntiDDoS.IPWhitelist) > 0 {
			whitelisted := s.isIPInWhitelist(clientIP, domainConfig.HTTPProxy.AntiDDoS.IPWhitelist)
			if !whitelisted {
				log.Printf("[HTTPS] Request blocked: IP %s not in whitelist", clientIP)
				atomic.AddUint64(&s.stats.BlockedRequests, 1)
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
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
				log.Printf("[HTTPS] Rate limit exceeded for %s: %s", clientIP, reason)
				atomic.AddUint64(&s.stats.BlockedRequests, 1)
				atomic.AddUint64(&s.stats.RateLimitBlocks, 1)

				// блокируем IP через iptables если превышен лимит
				if s.firewallMgr != nil {
					duration := time.Duration(domainConfig.HTTPProxy.AntiDDoS.BlockDurationSeconds) * time.Second
					if err := s.firewallMgr.BanIP(clientIP, duration); err != nil {
						log.Printf("[HTTPS] Failed to ban IP %s: %v", clientIP, err)
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
		log.Printf("[HTTPS] HTTP proxy not enabled for domain: %s (HTTPProxy.Enabled=%v)",
			host, domainConfig.HTTPProxy.Enabled)
		http.Error(w, "HTTP proxy not enabled", http.StatusForbidden)
		return
	}

	if domainConfig.HTTPProxy.Type == "http" {
		log.Printf("[HTTPS] Only HTTP allowed for domain: %s", host)
		http.Error(w, "HTTP only", http.StatusForbidden)
		return
	}

	if domainConfig.LuaCode != "" {
		blocked, response := s.wafEngine.Execute(domainConfig.LuaCode, r)

		// Apply headers from WAF (even if not blocked, for security headers)
		for key, value := range response.Headers {
			w.Header().Set(key, value)
		}

		if blocked {
			atomic.AddUint64(&s.stats.BlockedRequests, 1)
			log.Printf("[HTTPS] Request blocked by WAF: %s", r.Host+r.RequestURI)
			w.WriteHeader(response.StatusCode)
			if _, err := w.Write([]byte(response.Body)); err != nil {
				log.Printf("[HTTPS] Error writing WAF response: %v", err)
			}
			return
		}
	}

	target := s.findProxyTarget(domainConfig, host)
	if target == "" {
		log.Printf("[HTTPS] No backend found for: %s", host)
		http.Error(w, "No backend available", http.StatusBadGateway)
		atomic.AddUint64(&s.stats.ProxyErrors, 1)
		return
	}

	s.proxyRequest(w, r, target)
}

func (s *HTTPSProxyServer) findProxyTarget(domainConfig *config.Domain, host string) string {
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

func (s *HTTPSProxyServer) proxyRequest(w http.ResponseWriter, r *http.Request, target string) {
	targetURL := fmt.Sprintf("http://%s%s", target, r.RequestURI)

	proxyReq, err := http.NewRequest(r.Method, targetURL, r.Body)
	if err != nil {
		log.Printf("[HTTPS] Error creating proxy request: %v", err)
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
	proxyReq.Header.Set("X-Forwarded-Proto", "https")
	proxyReq.Header.Set("X-Real-IP", getClientIP(r))

	client := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Do(proxyReq)
	if err != nil {
		log.Printf("[HTTPS] Error proxying request: %v", err)
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
		log.Printf("[HTTPS] Error copying response body: %v", err)
	}

	log.Printf("[HTTPS] Proxied: %s → %s (status: %d)", r.Host+r.RequestURI, target, resp.StatusCode)
}

func (s *HTTPSProxyServer) isIPInWhitelist(ip string, whitelist []string) bool {
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

func (s *HTTPSProxyServer) GetStats() HTTPStats {
	return HTTPStats{
		TotalRequests:   atomic.LoadUint64(&s.stats.TotalRequests),
		BlockedRequests: atomic.LoadUint64(&s.stats.BlockedRequests),
		RateLimitBlocks: atomic.LoadUint64(&s.stats.RateLimitBlocks),
		FirewallBlocks:  atomic.LoadUint64(&s.stats.FirewallBlocks),
		ProxyErrors:     atomic.LoadUint64(&s.stats.ProxyErrors),
	}
}

func GetHTTPSStats() HTTPStats {
	if globalHTTPSServer != nil {
		return globalHTTPSServer.GetStats()
	}
	return HTTPStats{}
}
