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
}

type HTTPStats struct {
	TotalRequests   uint64
	BlockedRequests uint64
	ProxyErrors     uint64
}

func StartHTTPProxy(configMgr *config.ConfigManager) {
	server := &HTTPProxyServer{
		configMgr: configMgr,
		wafEngine: waf.NewLuaWAF(),
		stats:     &HTTPStats{},
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
	atomic.AddUint64(&s.stats.TotalRequests, 1)

	host := r.Host
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}

	log.Printf("[HTTP] Request: %s %s from %s", r.Method, r.Host+r.RequestURI, r.RemoteAddr)

	domainConfig := s.configMgr.GetDomain(host)
	if domainConfig == nil {
		log.Printf("[HTTP] Domain not found: %s", host)
		http.Error(w, "Domain not found", http.StatusNotFound)
		return
	}

	if !domainConfig.HTTPProxy.Enabled {
		log.Printf("[HTTP] HTTP proxy not enabled for domain: %s", host)
		http.Error(w, "HTTP proxy not enabled", http.StatusForbidden)
		return
	}

	if domainConfig.HTTPProxy.Type == "https" {
		log.Printf("[HTTP] Only HTTPS allowed for domain: %s", host)
		http.Error(w, "HTTPS only", http.StatusForbidden)
		return
	}

	if domainConfig.LuaCode != "" {
		blocked, response := s.wafEngine.Execute(domainConfig.LuaCode, r)
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

	target := s.findProxyTarget(domainConfig, host)
	if target == "" {
		log.Printf("[HTTP] No backend found for: %s", host)
		http.Error(w, "No backend available", http.StatusBadGateway)
		atomic.AddUint64(&s.stats.ProxyErrors, 1)
		return
	}

	s.proxyRequest(w, r, target)
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
	targetURL := fmt.Sprintf("http://%s%s", target, r.RequestURI)

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

	client := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

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

func (s *HTTPProxyServer) GetStats() HTTPStats {
	return HTTPStats{
		TotalRequests:   atomic.LoadUint64(&s.stats.TotalRequests),
		BlockedRequests: atomic.LoadUint64(&s.stats.BlockedRequests),
		ProxyErrors:     atomic.LoadUint64(&s.stats.ProxyErrors),
	}
}
