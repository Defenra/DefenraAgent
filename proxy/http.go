package proxy

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/defenra/agent/config"
	"github.com/defenra/agent/waf"
)

type HTTPProxyServer struct {
	configMgr *config.ConfigManager
	wafEngine *waf.LuaWAF
	stats     *HTTPStats
	protector *AntiDDoSManager
	metrics   *MetricsCollector
}

type HTTPStats struct {
	TotalRequests   uint64
	BlockedRequests uint64
	ProxyErrors     uint64
	RateLimited     uint64
	SlowlorisBlocks uint64
	JSChallenges    uint64
}

func StartHTTPProxy(configMgr *config.ConfigManager, coreURL, agentID string) {
	server := &HTTPProxyServer{
		configMgr: configMgr,
		wafEngine: waf.NewLuaWAF(),
		stats:     &HTTPStats{},
		protector: NewAntiDDoSManager(),
		metrics:   NewMetricsCollector(coreURL, agentID),
	}

	httpServer := &http.Server{
		Addr:         ":80",
		Handler:      http.HandlerFunc(server.handleRequest),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	log.Fatal(httpServer.ListenAndServe())
}

func (s *HTTPProxyServer) handleRequest(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	atomic.AddUint64(&s.stats.TotalRequests, 1)
	w.Header().Set("X-Defenra-Agent", "protecting")

	host := r.Host
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}

	clientIP := getClientIP(r)
	log.Printf("[HTTP] Request: %s %s from %s", r.Method, r.Host+r.RequestURI, clientIP)

	// Track client connection
	if s.metrics != nil {
		s.metrics.AddClient(clientIP, r.UserAgent(), "", "", "")
		s.metrics.AddLog("info", fmt.Sprintf("HTTP request from %s", clientIP), 
			fmt.Sprintf("%s %s", r.Method, r.URL.Path), nil)
	}

	domainConfig := s.configMgr.GetDomain(host)
	if domainConfig == nil {
		log.Printf("[HTTP] Domain not found: %s", host)
		if s.metrics != nil {
			s.metrics.AddLog("warning", "Domain not found", host, nil)
		}
		http.Error(w, "Domain not found", http.StatusNotFound)
		return
	}

	var release func()
	if s.protector != nil {
		var blocked bool
		blocked, release = s.protector.Enforce(w, r, domainConfig, s.stats)
		if blocked {
			return
		}
		if release != nil {
			defer release()
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
		if s.metrics != nil {
			s.metrics.TrackDomainError(domainConfig.Domain)
			s.metrics.AddLog("warning", "HTTP proxy not enabled", host, nil)
		}
		http.Error(w, "HTTP proxy not enabled", http.StatusForbidden)
		return
	}

	if domainConfig.HTTPProxy.Type == "https" {
		log.Printf("[HTTP] Only HTTPS allowed for domain: %s", host)
		if s.metrics != nil {
			s.metrics.TrackDomainError(domainConfig.Domain)
		}
		http.Error(w, "HTTPS only", http.StatusForbidden)
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
			log.Printf("[HTTP] Request blocked by WAF: %s", r.Host+r.RequestURI)
			w.WriteHeader(response.StatusCode)
			if _, err := w.Write([]byte(response.Body)); err != nil {
				log.Printf("[HTTP] Error writing WAF response: %v", err)
			}
			return
		}
	}

	// Slowloris timeout guard
	if s.protector != nil {
		reqTimeout := time.Duration(domainConfig.HTTPProxy.AntiDDoS.Slowloris.MaxHeaderTimeoutSeconds) * time.Second
		if reqTimeout > 0 {
			_ = r.Body
			deadline := time.Now().Add(reqTimeout)
			type deadliner interface{ SetReadDeadline(time.Time) error }
			if conn, ok := w.(deadliner); ok {
				conn.SetReadDeadline(deadline)
			}
		}
	}

	target := s.findProxyTarget(domainConfig, host)
	if target == "" {
		log.Printf("[HTTP] No backend found for: %s", host)
		if s.metrics != nil {
			s.metrics.TrackDomainError(domainConfig.Domain)
			s.metrics.AddLog("error", "No backend found", host, nil)
		}
		http.Error(w, "No backend available", http.StatusBadGateway)
		atomic.AddUint64(&s.stats.ProxyErrors, 1)
		return
	}

	s.proxyRequest(w, r, target, domainConfig, startTime)
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

func (s *HTTPProxyServer) proxyRequest(w http.ResponseWriter, r *http.Request, target string, domainConfig *config.Domain, startTime time.Time) {
	targetURL := fmt.Sprintf("http://%s%s", target, r.RequestURI)

	proxyReq, err := http.NewRequest(r.Method, targetURL, r.Body)
	if err != nil {
		log.Printf("[HTTP] Error creating proxy request: %v", err)
		if s.metrics != nil {
			s.metrics.TrackDomainError(domainConfig.Domain)
			s.metrics.AddLog("error", "Failed to create proxy request", err.Error(), nil)
		}
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

	client := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Do(proxyReq)
	if err != nil {
		log.Printf("[HTTP] Error proxying request: %v", err)
		if s.metrics != nil {
			s.metrics.TrackDomainError(domainConfig.Domain)
			s.metrics.AddLog("error", "Backend connection failed", err.Error(), 
				map[string]interface{}{"target": target})
		}
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
	
	// Track traffic
	written, err := io.Copy(w, resp.Body)
	if err != nil {
		log.Printf("[HTTP] Error copying response body: %v", err)
		if s.metrics != nil {
			s.metrics.TrackDomainError(domainConfig.Domain)
		}
	}
	
	// Record metrics
	responseTime := time.Since(startTime)
	if s.metrics != nil {
		// Approximate inbound = request body size, outbound = response body size
		inbound := r.ContentLength
		if inbound < 0 {
			inbound = 0
		}
		s.metrics.TrackDomainTraffic(domainConfig.Domain, inbound, written)
		s.metrics.TrackDomainRequest(domainConfig.Domain, responseTime)
	}

	log.Printf("[HTTP] Proxied: %s → %s (status: %d, time: %v)", r.Host+r.RequestURI, target, resp.StatusCode, responseTime)
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

func (s *HTTPProxyServer) GetStats() HTTPStats {
	return HTTPStats{
		TotalRequests:   atomic.LoadUint64(&s.stats.TotalRequests),
		BlockedRequests: atomic.LoadUint64(&s.stats.BlockedRequests),
		ProxyErrors:     atomic.LoadUint64(&s.stats.ProxyErrors),
	}
}
