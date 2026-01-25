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
	// Note: SetFirewallManager will be called from main.go to avoid circular imports

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
	// Extract TLS fingerprint for L7 protection
	tlsFingerprint := firewall.ExtractTLSFingerprint(hello)
	if tlsFingerprint != "" {
		// Store fingerprint for this connection
		remoteAddr := hello.Conn.RemoteAddr().String()
		firewall.StoreTLSFingerprint(remoteAddr, tlsFingerprint)
	}

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

	// Get TLS fingerprint for this connection
	tlsFingerprint := firewall.GetTLSFingerprint(r.RemoteAddr)

	// проверка iptables банов
	if s.firewallMgr != nil && s.firewallMgr.IsBanned(clientIP) {
		log.Printf("[HTTPS] Request blocked: IP %s is banned", clientIP)
		atomic.AddUint64(&s.stats.BlockedRequests, 1)
		atomic.AddUint64(&s.stats.FirewallBlocks, 1)

		// Use beautiful error page instead of generic Forbidden
		challengeMgr := firewall.GetChallengeManager()
		response := challengeMgr.IssueErrorPage(w, r, clientIP, 403, "Доступ заблокирован. Ваш IP-адрес временно заблокирован системой безопасности.")
		s.sendChallengeResponse(w, response)
		return
	}

	domainConfig := s.configMgr.GetDomain(host)
	if domainConfig == nil {
		log.Printf("[HTTPS] Domain not found: %s", host)
		http.Error(w, "Domain not found", http.StatusNotFound)
		return
	}

	// Apply Page Rules
	requestURL := r.Host + r.RequestURI
	matchedRules := MatchPageRules(domainConfig.PageRules, requestURL)
	handled, skipSecurity, skipRateLimit, customBackend := ApplyPageRules(w, r, matchedRules, domainConfig)
	if handled {
		// Request was handled by Page Rules (redirect, etc)
		return
	}

	// L7 Anti-DDoS Protection
	if !skipSecurity && domainConfig.HTTPProxy.AntiDDoS != nil && domainConfig.HTTPProxy.AntiDDoS.L7Protection != nil && domainConfig.HTTPProxy.AntiDDoS.L7Protection.Enabled {
		l7Config := &firewall.L7Config{
			FingerprintRateLimit:   domainConfig.HTTPProxy.AntiDDoS.L7Protection.FingerprintRateLimit,
			IPRateLimit:            domainConfig.HTTPProxy.AntiDDoS.L7Protection.IPRateLimit,
			FailChallengeRateLimit: domainConfig.HTTPProxy.AntiDDoS.L7Protection.FailChallengeRateLimit,
			SuspiciousThreshold:    domainConfig.HTTPProxy.AntiDDoS.L7Protection.SuspiciousThreshold,
			RateWindow:             10 * time.Second,
			KnownFingerprints:      firewall.GetKnownFingerprints(),
			BotFingerprints:        firewall.GetBotFingerprints(),
			BlockedFingerprints:    make(map[string]string),
			AllowedFingerprints:    make(map[string]string),
		}

		// Add custom blocked/allowed fingerprints
		for _, fp := range domainConfig.HTTPProxy.AntiDDoS.L7Protection.BlockedFingerprints {
			l7Config.BlockedFingerprints[fp] = "Custom Block"
		}
		for _, fp := range domainConfig.HTTPProxy.AntiDDoS.L7Protection.AllowedFingerprints {
			l7Config.AllowedFingerprints[fp] = "Custom Allow"
		}

		l7Protection := firewall.NewL7Protection(l7Config)
		defer l7Protection.Stop()

		suspicionLevel, browserType, err := l7Protection.AnalyzeRequest(r, clientIP, tlsFingerprint)

		if err != nil {
			log.Printf("[HTTPS] L7 analysis error: %v", err)
			atomic.AddUint64(&s.stats.BlockedRequests, 1)

			// Use beautiful error page instead of generic Forbidden
			challengeMgr := firewall.GetChallengeManager()
			response := challengeMgr.IssueErrorPage(w, r, clientIP, 403, "Запрос заблокирован системой безопасности.")
			s.sendChallengeResponse(w, response)
			return
		}

		if suspicionLevel < 0 {
			log.Printf("[HTTPS] Request blocked by L7 protection: %s", browserType)
			atomic.AddUint64(&s.stats.BlockedRequests, 1)

			// Use beautiful error page instead of generic Forbidden
			challengeMgr := firewall.GetChallengeManager()
			response := challengeMgr.IssueErrorPage(w, r, clientIP, 403, fmt.Sprintf("Запрос заблокирован. Причина: %s", browserType))
			s.sendChallengeResponse(w, response)
			return
		}

		// Apply custom firewall rules if configured
		if len(domainConfig.HTTPProxy.AntiDDoS.CustomRules) > 0 {
			ruleEngine := firewall.NewRuleEngine()
			for _, rule := range domainConfig.HTTPProxy.AntiDDoS.CustomRules {
				if rule.Enabled {
					ruleEngine.AddRule(rule.Name, rule.Expression, rule.Action, rule.Enabled)
				}
			}

			// Get connection info for rule context
			connInfo := l7Protection.GetConnectionInfo(clientIP)
			requestCount := 0
			challengeCount := 0
			if connInfo != nil {
				requestCount = int(connInfo.RequestCount)
				challengeCount = int(connInfo.ChallengeFails)
			}

			// Build rule context
			country, asn := firewall.GetGeoInfo(clientIP)
			ctx := firewall.BuildRequestContext(r, clientIP, country, asn, browserType, "", tlsFingerprint,
				requestCount, challengeCount, suspicionLevel, 0, false)

			// Evaluate rules
			suspicionLevel = ruleEngine.EvaluateRules(ctx, suspicionLevel)
		}

		// Handle challenges based on suspicion level
		challengeSettings := domainConfig.HTTPProxy.AntiDDoS.ChallengeSettings
		if challengeSettings != nil && suspicionLevel > 0 {
			challengeMgr := firewall.GetChallengeManager()

			switch suspicionLevel {
			case 1:
				// Cookie challenge
				if challengeSettings.CookieChallenge != nil && challengeSettings.CookieChallenge.Enabled {
					if !challengeMgr.ValidateCookieChallenge(r, clientIP) {
						l7Protection.RecordChallengeFailure(clientIP)
						response := challengeMgr.IssueCookieChallenge(w, r, clientIP)
						s.sendChallengeResponse(w, response)
						return
					}
				}
			case 2:
				// JavaScript PoW challenge
				if challengeSettings.JSChallenge != nil && challengeSettings.JSChallenge.Enabled {
					if !challengeMgr.ValidateJSChallenge(r, challengeSettings.JSChallenge.Difficulty) {
						l7Protection.RecordChallengeFailure(clientIP)
						response := challengeMgr.IssueJSChallenge(w, r, clientIP, challengeSettings.JSChallenge.Difficulty)
						s.sendChallengeResponse(w, response)
						return
					}
				}
			case 3:
				// CAPTCHA challenge
				if challengeSettings.CaptchaChallenge != nil && challengeSettings.CaptchaChallenge.Enabled {
					if !challengeMgr.ValidateCaptchaChallenge(r) {
						l7Protection.RecordChallengeFailure(clientIP)
						response := challengeMgr.IssueCaptchaChallenge(w, r, clientIP)
						s.sendChallengeResponse(w, response)
						return
					}
				}
			default:
				if suspicionLevel >= 4 {
					// Block high suspicion requests with beautiful error page
					log.Printf("[HTTPS] Request blocked: high suspicion level %d", suspicionLevel)
					atomic.AddUint64(&s.stats.BlockedRequests, 1)

					challengeMgr := firewall.GetChallengeManager()
					response := challengeMgr.IssueErrorPage(w, r, clientIP, 403, "Запрос заблокирован из-за высокого уровня подозрительности.")
					s.sendChallengeResponse(w, response)
					return
				}
			}
		}

		// If we reach here, all challenges have been passed successfully
		// Create a session to avoid repeating challenges
		if suspicionLevel > 0 {
			challengeMgr := firewall.GetChallengeManager()
			sessionID := challengeMgr.CreateSessionAfterChallenge(clientIP, r.UserAgent(), r.Host)
			sessionCookie := challengeMgr.CreateSessionCookie(sessionID, r.TLS != nil)
			http.SetCookie(w, sessionCookie)
		}
	}

	// проверка whitelist и rate limiting
	if !skipRateLimit && domainConfig.HTTPProxy.AntiDDoS != nil && domainConfig.HTTPProxy.AntiDDoS.Enabled {
		if len(domainConfig.HTTPProxy.AntiDDoS.IPWhitelist) > 0 {
			whitelisted := s.isIPInWhitelist(clientIP, domainConfig.HTTPProxy.AntiDDoS.IPWhitelist)
			if !whitelisted {
				log.Printf("[HTTPS] Request blocked: IP %s not in whitelist", clientIP)
				atomic.AddUint64(&s.stats.BlockedRequests, 1)

				// Use beautiful error page instead of generic Forbidden
				challengeMgr := firewall.GetChallengeManager()
				response := challengeMgr.IssueErrorPage(w, r, clientIP, 403, "Доступ запрещен. Ваш IP-адрес не находится в списке разрешенных.")
				s.sendChallengeResponse(w, response)
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

				// Use progressive blocking system instead of immediate ban
				violationTracker := firewall.GetViolationTracker()
				escalationLevel := violationTracker.RecordViolation(clientIP, "rate_limit")

				challengeMgr := firewall.GetChallengeManager()

				switch escalationLevel {
				case 1:
					// First violation - show CAPTCHA challenge
					log.Printf("[HTTPS] Rate limit violation #1 for %s: showing CAPTCHA", clientIP)
					response := challengeMgr.IssueCaptchaChallenge(w, r, clientIP)
					s.sendChallengeResponse(w, response)
					return

				case 2:
					// Second violation - 10 minute block with error page
					log.Printf("[HTTPS] Rate limit violation #2 for %s: 10 minute block", clientIP)
					response := challengeMgr.IssueErrorPage(w, r, clientIP, 429, "Слишком много запросов. Вы заблокированы на 10 минут за превышение лимита скорости.")
					s.sendChallengeResponse(w, response)

					// Also ban via iptables for the same duration
					if s.firewallMgr != nil {
						if err := s.firewallMgr.BanIP(clientIP, 10*time.Minute); err != nil {
							log.Printf("[HTTPS] Failed to ban IP %s: %v", clientIP, err)
						}
					}
					return

				case 3:
					// Third+ violation - 30 minute block with error page
					log.Printf("[HTTPS] Rate limit violation #3+ for %s: 30 minute block", clientIP)
					response := challengeMgr.IssueErrorPage(w, r, clientIP, 429, "Слишком много запросов. Вы заблокированы на 30 минут за повторные нарушения лимита скорости.")
					s.sendChallengeResponse(w, response)

					// Also ban via iptables for the same duration
					if s.firewallMgr != nil {
						if err := s.firewallMgr.BanIP(clientIP, 30*time.Minute); err != nil {
							log.Printf("[HTTPS] Failed to ban IP %s: %v", clientIP, err)
						}
					}
					return

				default:
					// IP is currently blocked, check remaining time
					if blocked, remaining := violationTracker.IsBlocked(clientIP); blocked {
						log.Printf("[HTTPS] IP %s still blocked for %v", clientIP, remaining)
						response := challengeMgr.IssueErrorPage(w, r, clientIP, 429, fmt.Sprintf("Вы заблокированы за превышение лимита скорости. Осталось: %v", remaining.Round(time.Second)))
						s.sendChallengeResponse(w, response)
						return
					}
				}
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

		// Use beautiful error page instead of generic Forbidden
		challengeMgr := firewall.GetChallengeManager()
		response := challengeMgr.IssueErrorPage(w, r, clientIP, 403, "HTTP прокси не включен для данного домена.")
		s.sendChallengeResponse(w, response)
		return
	}

	if domainConfig.HTTPProxy.Type == "http" {
		log.Printf("[HTTPS] Only HTTP allowed for domain: %s", host)

		// Use beautiful error page instead of generic Forbidden
		challengeMgr := firewall.GetChallengeManager()
		response := challengeMgr.IssueErrorPage(w, r, clientIP, 403, "Для данного домена разрешен только HTTP.")
		s.sendChallengeResponse(w, response)
		return
	}

	if !skipSecurity && domainConfig.LuaCode != "" {
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

	// Determine proxy target (origin or custom backend from Page Rule)
	originTarget := customBackend
	if originTarget == "" {
		originTarget = s.findProxyTarget(domainConfig, host)
	}
	if originTarget == "" {
		log.Printf("[HTTPS] No backend found for: %s", host)
		http.Error(w, "No backend available", http.StatusBadGateway)
		atomic.AddUint64(&s.stats.ProxyErrors, 1)
		return
	}

	// Make routing decision (direct or anycast)
	decision := RouteRequest(r, domainConfig, originTarget)
	log.Printf("[HTTPS] Routing decision: mode=%s, target=%s, isAgent=%v, hopCount=%d, reason=%s",
		decision.Mode, decision.Target, decision.IsAgent, decision.HopCount, decision.Reason)

	// If routing to another agent, add hop tracking header
	if decision.IsAgent {
		agentID := GetAgentID()
		AddHopHeader(r, agentID)
		log.Printf("[HTTPS] Added hop header: %s (total hops: %d)", agentID, decision.HopCount+1)
	}

	s.proxyRequest(w, r, decision.Target)
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
	host := r.Host
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}

	// Check if target is another agent (has X-Defenra-Hop header or target looks like agent endpoint)
	isAgentTarget := r.Header.Get(HopHeaderName) != "" || strings.HasPrefix(target, "https://")

	domainConfig := s.configMgr.GetDomain(host)

	var scheme string
	var encryptionMode string

	if isAgentTarget {
		// Agent-to-agent communication: always use HTTPS
		scheme = "https"
		encryptionMode = "agent_to_agent"
	} else {
		// Agent-to-origin communication: use domain's encryption mode from Core
		if domainConfig != nil && domainConfig.SSL.EncryptionMode != "" {
			encryptionMode = domainConfig.SSL.EncryptionMode
		} else {
			// No encryption mode configured - use flexible as fallback
			encryptionMode = "flexible"
		}

		// Determine target URL scheme based on encryption mode
		// Flexible mode: HTTP to origin (client-to-agent is HTTPS, agent-to-origin is HTTP)
		// Full modes: HTTPS to origin with different validation levels
		// Off mode: HTTP to origin (no encryption at all)
		scheme = "http"
		if encryptionMode == "full" || encryptionMode == "full_strict" {
			scheme = "https"
		}
		// "flexible" and "off" modes use HTTP to origin
	}

	targetURL := fmt.Sprintf("%s://%s%s", scheme, target, r.RequestURI)

	proxyReq, err := http.NewRequest(r.Method, targetURL, r.Body)
	if err != nil {
		log.Printf("[HTTPS] Error creating proxy request: %v", err)
		http.Error(w, "Proxy error", http.StatusInternalServerError)
		atomic.AddUint64(&s.stats.ProxyErrors, 1)
		return
	}

	// Copy all headers from client request
	for key, values := range r.Header {
		for _, value := range values {
			proxyReq.Header.Add(key, value)
		}
	}

	// Set/override proxy headers
	clientIP := getClientIP(r)
	proxyReq.Header.Set("X-Forwarded-For", clientIP)
	proxyReq.Header.Set("X-Forwarded-Proto", "https")
	proxyReq.Header.Set("X-Real-IP", clientIP)

	// Add unique agent identifier header
	if s.configMgr != nil {
		agentID := s.configMgr.GetAgentID()
		geoCode := s.configMgr.GetGeoCode()
		if agentID != "" && geoCode != "" {
			proxyReq.Header.Set("D-Agent-ID", geoCode+"+"+agentID[:8]) // Use first 8 chars of agent ID
		}
	}

	// Preserve original Host header from client (important for virtual hosting on origin)
	// Go's http.NewRequest sets Host from URL, but we want the original domain
	proxyReq.Host = r.Host

	// Create HTTP client with TLS configuration based on encryption mode
	client := createHTTPClient(encryptionMode)

	startTime := time.Now()
	resp, err := client.Do(proxyReq)
	if err != nil {
		log.Printf("[HTTPS] Error proxying request: %v", err)

		// Use new error page template for origin server errors
		challengeMgr := firewall.GetChallengeManager()
		errorResponse := challengeMgr.IssueErrorPage(w, r, clientIP, 502, "Backend server unavailable")

		// Apply error response headers
		for key, value := range errorResponse.Headers {
			w.Header().Set(key, value)
		}
		w.WriteHeader(errorResponse.StatusCode)
		w.Write([]byte(errorResponse.Body))

		atomic.AddUint64(&s.stats.ProxyErrors, 1)
		return
	}
	defer resp.Body.Close()

	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	// Add unique agent identifier header to response
	if s.configMgr != nil {
		agentID := s.configMgr.GetAgentID()
		geoCode := s.configMgr.GetGeoCode()
		if agentID != "" && geoCode != "" {
			w.Header().Set("D-Agent-ID", geoCode+"+"+agentID[:8]) // Use first 8 chars of agent ID
		}
	}

	w.WriteHeader(resp.StatusCode)

	// Track traffic
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[HTTPS] Error reading response body: %v", err)
		return
	}

	if _, err := w.Write(bodyBytes); err != nil {
		log.Printf("[HTTPS] Error writing response: %v", err)
		return
	}

	// Calculate traffic
	requestSize := uint64(len(r.RequestURI) + len(r.Method) + 100) // approximate request size
	responseSize := uint64(len(bodyBytes))

	// Track client with traffic and geolocation
	tracker := GetGlobalHTTPClientTracker()
	userAgent := r.Header.Get("User-Agent")
	tracker.TrackRequest(clientIP, userAgent, host, requestSize, responseSize)

	duration := time.Since(startTime)
	log.Printf("[HTTPS] Proxied: %s → %s (status: %d, duration: %v, sent: %d, received: %d)",
		r.Host+r.RequestURI, target, resp.StatusCode, duration, requestSize, responseSize)
}

func (s *HTTPSProxyServer) sendChallengeResponse(w http.ResponseWriter, response firewall.ChallengeResponse) {
	for key, value := range response.Headers {
		w.Header().Set(key, value)
	}
	w.WriteHeader(response.StatusCode)
	w.Write([]byte(response.Body))
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
