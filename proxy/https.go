package proxy

import (
	"crypto/tls"
	"errors"
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

type HTTPSProxyServer struct {
	configMgr *config.ConfigManager
	wafEngine *waf.LuaWAF
	stats     *HTTPStats
	protector *AntiDDoSManager
	metrics   *MetricsCollector
}

func StartHTTPSProxy(configMgr *config.ConfigManager, coreURL, agentID string) {
	server := &HTTPSProxyServer{
		configMgr: configMgr,
		wafEngine: waf.NewLuaWAF(),
		stats:     &HTTPStats{},
		protector: NewAntiDDoSManager(),
		metrics:   NewMetricsCollector(coreURL, agentID),
	}

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
	startTime := time.Now()
	atomic.AddUint64(&s.stats.TotalRequests, 1)

	host := r.Host
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}

	clientIP := getClientIP(r)
	log.Printf("[HTTPS] Request: %s %s from %s", r.Method, r.Host+r.RequestURI, clientIP)

	// Track client connection
	if s.metrics != nil {
		s.metrics.AddClient(clientIP, r.UserAgent(), "", "", "")
		s.metrics.AddLog("info", fmt.Sprintf("HTTPS request from %s", clientIP), 
			fmt.Sprintf("%s %s", r.Method, r.URL.Path), nil)
	}

	domainConfig := s.configMgr.GetDomain(host)
	if domainConfig == nil {
		log.Printf("[HTTPS] Domain not found: %s", host)
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
		log.Printf("[HTTPS] HTTP proxy not enabled for domain: %s (HTTPProxy.Enabled=%v)",
			host, domainConfig.HTTPProxy.Enabled)
		if s.metrics != nil {
			s.metrics.TrackDomainError(domainConfig.Domain)
			s.metrics.AddLog("warning", "HTTP proxy not enabled", host, nil)
		}
		http.Error(w, "HTTP proxy not enabled", http.StatusForbidden)
		return
	}

	if domainConfig.HTTPProxy.Type == "http" {
		log.Printf("[HTTPS] Only HTTP allowed for domain: %s", host)
		if s.metrics != nil {
			s.metrics.TrackDomainError(domainConfig.Domain)
		}
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

func (s *HTTPSProxyServer) proxyRequest(w http.ResponseWriter, r *http.Request, target string, domainConfig *config.Domain, startTime time.Time) {
	targetURL := fmt.Sprintf("http://%s%s", target, r.RequestURI)

	proxyReq, err := http.NewRequest(r.Method, targetURL, r.Body)
	if err != nil {
		log.Printf("[HTTPS] Error creating proxy request: %v", err)
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
		log.Printf("[HTTPS] Error copying response body: %v", err)
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

	log.Printf("[HTTPS] Proxied: %s → %s (status: %d, time: %v)", r.Host+r.RequestURI, target, resp.StatusCode, responseTime)
}

func (s *HTTPSProxyServer) GetStats() HTTPStats {
	return HTTPStats{
		TotalRequests:   atomic.LoadUint64(&s.stats.TotalRequests),
		BlockedRequests: atomic.LoadUint64(&s.stats.BlockedRequests),
		ProxyErrors:     atomic.LoadUint64(&s.stats.ProxyErrors),
	}
}
