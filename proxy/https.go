package proxy

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/defenra/agent/config"
	"github.com/defenra/agent/firewall"
	"github.com/defenra/agent/waf"
	"golang.org/x/net/http2"
	"golang.org/x/net/netutil"
)

type HTTPSProxyServer struct {
	configMgr   *config.ConfigManager
	wafEngine   *waf.LuaWAF
	stats       *HTTPStats
	rateLimiter *RateLimiter
	firewallMgr *firewall.IPTablesManager
	certCache   sync.Map // Key: string (domain), Value: *tls.Certificate
}

// TLSErrorFilter фильтрует шумовые ошибки TLS handshake от заблокированных соединений
// Эти ошибки возникают из-за race condition: FirewallListener закрывает соединение,
// но TLS layer уже начал читать ClientHello. Это штатная работа защиты, а не баг.
type TLSErrorFilter struct{}

func (f *TLSErrorFilter) Write(p []byte) (n int, err error) {
	msg := string(p)

	// Игнорируем EOF ошибки от TLS handshake (заблокированные соединения)
	if strings.Contains(msg, "http: TLS handshake error") &&
		(strings.Contains(msg, "EOF") || strings.Contains(msg, "connection reset by peer")) {
		return len(p), nil // Глотаем шум
	}

	// Все остальные ошибки (реальные проблемы) пишем в stderr
	return os.Stderr.Write(p)
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

	// === FORTRESS EDITION: Получаем список настроенных доменов для SNI validation ===
	configuredDomains := server.configMgr.GetAllDomainNames()
	log.Printf("[HTTPS] Fortress Edition: Protecting %d configured domains", len(configuredDomains))

	tlsConfig := &tls.Config{
		GetCertificate: server.getCertificate,
		MinVersion:     tls.VersionTLS12,
		// === FORTRESS EDITION: GetConfigForClient - главная точка защиты ===
		// Layer 1: SNI Validation (отсекает сканеры)
		// Layer 2: Handshake Rate Limiting (защита от velocity attacks)
		// Layer 3: TLS Fingerprinting (обнаружение ботнетов)
		GetConfigForClient: firewall.GetConfigForClientWrapper(
			nil, // baseConfig (nil = use default)
			configuredDomains,
			server.getCertificate,
		),
	}

	httpsServer := &http.Server{
		Addr:         ":443",
		Handler:      http.HandlerFunc(server.handleRequest),
		TLSConfig:    tlsConfig,
		// === EDGE-ЗАЩИТА: Адаптивные таймауты ===
		// ReadHeaderTimeout - критично для Edge: отсекает медленные TLS handshake
		// Легитимный клиент успеет за 2 секунды, slow-loris бот - нет
		ReadHeaderTimeout: 2 * time.Second,
		// ReadTimeout - полное время на чтение запроса (включая тело)
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 30 * time.Second,
		// IdleTimeout - время между запросами в Keep-Alive соединении
		IdleTimeout: 30 * time.Second, // Снижено со 120s для Edge
		// Limit max header size to prevent memory exhaustion
		MaxHeaderBytes: 1 << 20, // 1 MB
		// Фильтруем шумовые TLS ошибки от заблокированных соединений
		ErrorLog: log.New(&TLSErrorFilter{}, "", 0),
	}

	// === EDGE-ЗАЩИТА: HTTP/2 Stream Limiting ===
	// Защита от HTTP/2 Rapid Reset (CVE-2023-44487) и Stream Exhaustion
	// Ограничиваем количество одновременных потоков на одно соединение
	h2Server := &http2.Server{
		MaxConcurrentStreams: 50, // Не даем одному клиенту плодить тысячи потоков
		// MaxReadFrameSize по умолчанию 1MB (достаточно)
		// IdleTimeout наследуется от http.Server
	}
	if err := http2.ConfigureServer(httpsServer, h2Server); err != nil {
		log.Printf("[HTTPS] Warning: failed to configure HTTP/2: %v", err)
	} else {
		log.Println("[HTTPS] HTTP/2 configured with MaxConcurrentStreams=50")
	}

	// === CUSTOM LISTENER WITH L4 FIREWALL ===
	// Вместо стандартного ListenAndServeTLS используем custom listener
	// для фильтрации соединений ДО TLS handshake

	// 1. Создаем обычный TCP listener
	ln, err := net.Listen("tcp", ":443")
	if err != nil {
		log.Fatalf("[HTTPS] Failed to create TCP listener: %v", err)
	}

	log.Println("[HTTPS] TCP listener created on :443")

	// 2. === EDGE-ЗАЩИТА: LimitListener (защита от FD exhaustion) ===
	// Ограничиваем общее количество одновременных соединений
	// Предотвращает исчерпание файловых дескрипторов и OOM
	limitedLn := netutil.LimitListener(ln, 10000)
	log.Println("[HTTPS] LimitListener enabled (max 10000 concurrent connections)")

	// 3. Оборачиваем в FirewallListener для L4 защиты (IP filtering)
	// Проверяет IP в черном списке ДО TLS handshake
	guardedLn := firewall.NewFirewallListener(limitedLn, 10000)
	log.Println("[HTTPS] FirewallListener enabled (IP blacklist filtering)")

	// 4. Оборачиваем в TLS listener
	tlsLn := tls.NewListener(guardedLn, tlsConfig)
	log.Println("[HTTPS] TLS listener ready with certificate caching")

	// 5. Запускаем HTTPS сервер
	log.Println("[HTTPS] Starting HTTPS server with Fortress Edition protection:")
	log.Println("[HTTPS]   - Layer 0: Fortress GetConfigForClient (SNI validation, handshake rate limiting, TLS fingerprinting)")
	log.Println("[HTTPS]   - Layer 1: LimitListener (10000 max connections, FD exhaustion protection)")
	log.Println("[HTTPS]   - Layer 2: FirewallListener (IP blacklist filtering, pre-TLS)")
	log.Println("[HTTPS]   - Layer 3: ReadHeaderTimeout 2s (slow-loris protection)")
	log.Println("[HTTPS]   - Layer 4: HTTP/2 MaxStreams 50 (rapid reset protection)")
	log.Println("[HTTPS]   - Layer 5: TLS 1.2+ only (security)")
	log.Fatal(httpsServer.Serve(tlsLn))
}

func (s *HTTPSProxyServer) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	// 1. Проверяем кэш первым делом (операция чтения из памяти, наносекунды)
	if cached, ok := s.certCache.Load(hello.ServerName); ok {
		return cached.(*tls.Certificate), nil
	}

	// 2. Extract TLS fingerprint for L7 protection (только при cache miss)
	tlsFingerprint := firewall.ExtractTLSFingerprint(hello)
	if tlsFingerprint != "" {
		// Store fingerprint for this connection
		remoteAddr := hello.Conn.RemoteAddr().String()
		firewall.StoreTLSFingerprint(remoteAddr, tlsFingerprint)
	}

	// 3. Поиск конфигурации домена
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

	// 4. Парсинг сертификата (ТЯЖЕЛАЯ операция - только при cache miss)
	cert, err := tls.X509KeyPair(
		[]byte(domainConfig.SSL.Certificate),
		[]byte(domainConfig.SSL.PrivateKey),
	)
	if err != nil {
		log.Printf("[ERROR] Failed to load certificate for %s: %v", hello.ServerName, err)
		return nil, err
	}

	// 5. Сохраняем в кэш и логируем ТОЛЬКО ОДИН РАЗ
	s.certCache.Store(hello.ServerName, &cert)
	log.Printf("[HTTPS] Certificate loaded and CACHED for: %s", hello.ServerName)

	return &cert, nil
}

// ClearCertificateCache очищает кэш сертификатов (вызывается при обновлении конфигурации)
func (s *HTTPSProxyServer) ClearCertificateCache() {
	s.certCache.Range(func(key, value interface{}) bool {
		s.certCache.Delete(key)
		return true
	})
	log.Println("[HTTPS] Certificate cache cleared")
}

// InvalidateCertificate удаляет конкретный сертификат из кэша
func (s *HTTPSProxyServer) InvalidateCertificate(domain string) {
	s.certCache.Delete(domain)
	log.Printf("[HTTPS] Certificate cache invalidated for: %s", domain)
}

func (s *HTTPSProxyServer) handleRequest(w http.ResponseWriter, r *http.Request) {
	atomic.AddUint64(&s.stats.TotalRequests, 1)

	clientIP := getClientIP(r)

	// === HTTP/2 Direct Connection Attack Protection ===
	// Block HTTP/2 requests without proper Host/SNI (PRI * requests)
	// These are malicious attempts to bypass L7 protection
	if r.Method == "PRI" || (r.Host == "" && r.URL.Host == "") {
		log.Printf("[HTTPS] HTTP/2 direct connection attack blocked from %s (method=%s, host=%s)", 
			clientIP, r.Method, r.Host)
		atomic.AddUint64(&s.stats.BlockedRequests, 1)
		atomic.AddUint64(&s.stats.FirewallBlocks, 1)

		// Ban IP immediately for HTTP/2 direct connection attacks
		if s.firewallMgr != nil {
			if err := s.firewallMgr.BanIP(clientIP, 1*time.Hour); err != nil {
				log.Printf("[HTTPS] Failed to ban IP %s: %v", clientIP, err)
			} else {
				log.Printf("[HTTPS] Banned IP %s for 1 hour (HTTP/2 direct connection attack)", clientIP)
			}
		}

		// Close connection immediately without response (save bandwidth)
		// HTTP/2 attackers don't care about response anyway
		if hj, ok := w.(http.Hijacker); ok {
			conn, _, err := hj.Hijack()
			if err == nil {
				conn.Close()
				return
			}
		}

		// Fallback: send minimal error response
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	// Connection-level protection - check before any processing
	connLimiter := firewall.GetConnectionLimiter()
	if !connLimiter.CheckConnection(r.RemoteAddr) {
		// Don't log every blocked connection - too much spam
		atomic.AddUint64(&s.stats.BlockedRequests, 1)
		atomic.AddUint64(&s.stats.FirewallBlocks, 1)

		// Use beautiful error page for connection limit exceeded
		challengeMgr := firewall.GetChallengeManager()
		response := challengeMgr.IssueErrorPage(w, r, clientIP, 429, "Слишком много подключений. Превышен лимит подключений с вашего IP-адреса.")
		s.sendChallengeResponse(w, response)
		return
	}
	// Release connection when request is done
	defer connLimiter.ReleaseConnection(r.RemoteAddr)

	host := r.Host
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}

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

		// Use beautiful error page instead of generic error
		challengeMgr := firewall.GetChallengeManager()
		response := challengeMgr.IssueErrorPage(w, r, clientIP, 404, "Домен не найден. Данный домен не настроен на этом агенте.")
		s.sendChallengeResponse(w, response)
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

	// Apply custom firewall rules BEFORE L7 protection (for early allow/block)
	// This allows rules to work even when L7 protection is disabled
	if domainConfig.HTTPProxy.AntiDDoS != nil && len(domainConfig.HTTPProxy.AntiDDoS.CustomRules) > 0 {
		ruleEngine := firewall.NewRuleEngine()
		for _, rule := range domainConfig.HTTPProxy.AntiDDoS.CustomRules {
			if rule.Enabled {
				ruleEngine.AddRule(rule.Name, rule.Expression, rule.Action, rule.Enabled)
			}
		}

		// Build minimal rule context for early evaluation
		country, asn := firewall.GetGeoInfo(clientIP)
		ctx := firewall.BuildRequestContext(r, clientIP, country, asn, "", "", "",
			0, 0, 0, 0, false)

		// Evaluate rules with base suspicion of -1 (no match indicator)
		suspicionLevel := ruleEngine.EvaluateRules(ctx, -1)

		// Handle early allow/block actions
		if suspicionLevel == 0 {
			// Rule explicitly allowed this request - skip all security checks
			log.Printf("[HTTPS] Request allowed by custom rule for IP %s", clientIP)
			skipSecurity = true
			skipRateLimit = true
		} else if suspicionLevel >= 999 {
			// Rule explicitly blocked this request
			log.Printf("[HTTPS] Request blocked by custom rule for IP %s", clientIP)
			atomic.AddUint64(&s.stats.BlockedRequests, 1)

			challengeMgr := firewall.GetChallengeManager()
			response := challengeMgr.IssueErrorPage(w, r, clientIP, 403, "Запрос заблокирован пользовательским правилом.")
			s.sendChallengeResponse(w, response)
			return
		}
		// If suspicionLevel == -1, no rule matched - continue with normal security checks
	}

	// L7 Anti-DDoS Protection
	if !skipSecurity && domainConfig.HTTPProxy.AntiDDoS != nil && domainConfig.HTTPProxy.AntiDDoS.L7Protection != nil && domainConfig.HTTPProxy.AntiDDoS.L7Protection.Enabled {
		l7Config := &firewall.L7Config{
			FingerprintRateLimit:   domainConfig.HTTPProxy.AntiDDoS.L7Protection.FingerprintRateLimit,
			IPRateLimit:            domainConfig.HTTPProxy.AntiDDoS.L7Protection.IPRateLimit,
			FailChallengeRateLimit: domainConfig.HTTPProxy.AntiDDoS.L7Protection.FailChallengeRateLimit,
			SuspiciousThreshold:    domainConfig.HTTPProxy.AntiDDoS.L7Protection.SuspiciousThreshold,
			RateWindow:             5 * time.Second, // Reduced from 10 seconds
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

			// === FORTRESS OFFLOADING: Инициализация tracker ===
			offloadingTracker := firewall.GetChallengeOffloadingTracker()
			
			// Обновляем конфигурацию offloading из настроек домена
			if challengeSettings.AutoOffloading != nil {
				offloadingTracker.UpdateConfig(
					challengeSettings.AutoOffloading.Enabled,
					challengeSettings.AutoOffloading.FailureThreshold,
					challengeSettings.AutoOffloading.TimeWindowSeconds,
					challengeSettings.AutoOffloading.BanDurationMinutes,
				)
			}

			switch suspicionLevel {
			case 1:
				// Cookie challenge
				if challengeSettings.CookieChallenge != nil && challengeSettings.CookieChallenge.Enabled {
					if !challengeMgr.ValidateCookieChallenge(r, clientIP) {
						l7Protection.RecordChallengeFailure(clientIP)
						
						// === FORTRESS OFFLOADING: Записываем failure ===
						if offloadingTracker.RecordFailure(clientIP, "cookie") {
							log.Printf("[HTTPS] IP %s offloaded to iptables (repeated cookie challenge failures)", clientIP)
							atomic.AddUint64(&s.stats.BlockedRequests, 1)
							// IP уже заблокирован в iptables, просто закрываем соединение
							return
						}
						
						response := challengeMgr.IssueCookieChallenge(w, r, clientIP)
						s.sendChallengeResponse(w, response)
						return
					} else {
						// Cookie challenge was successfully validated, create session
						sessionID := challengeMgr.CreateSessionAfterChallenge(clientIP, r.UserAgent(), r.Host)
						sessionCookie := challengeMgr.CreateSessionCookie(sessionID, r.TLS != nil)
						http.SetCookie(w, sessionCookie)
						
						// === FORTRESS OFFLOADING: Сбрасываем счетчик при успехе ===
						offloadingTracker.ResetIP(clientIP)
						// Continue processing the request
					}
				}
			case 2:
				// JavaScript PoW challenge
				if challengeSettings.JSChallenge != nil && challengeSettings.JSChallenge.Enabled {
					if !challengeMgr.ValidateJSChallenge(r, challengeSettings.JSChallenge.Difficulty) {
						l7Protection.RecordChallengeFailure(clientIP)
						
						// === FORTRESS OFFLOADING: Записываем failure ===
						if offloadingTracker.RecordFailure(clientIP, "js_pow") {
							log.Printf("[HTTPS] IP %s offloaded to iptables (repeated JS PoW challenge failures)", clientIP)
							atomic.AddUint64(&s.stats.BlockedRequests, 1)
							return
						}
						
						response := challengeMgr.IssueJSChallenge(w, r, clientIP, challengeSettings.JSChallenge.Difficulty)
						s.sendChallengeResponse(w, response)
						return
					} else {
						// JS challenge was successfully validated
						sessionID := challengeMgr.CreateSessionAfterChallenge(clientIP, r.UserAgent(), r.Host)
						sessionCookie := challengeMgr.CreateSessionCookie(sessionID, r.TLS != nil)

						log.Printf("[HTTPS] JS PoW challenge passed for IP %s, creating session %s", clientIP, sessionID)

						// === FORTRESS OFFLOADING: Сбрасываем счетчик при успехе ===
						offloadingTracker.ResetIP(clientIP)

						if r.Method == "POST" {
							// POST request - redirect to clean URL
							redirectURL := r.URL.Path
							if r.URL.RawQuery != "" {
								// Remove PoW parameters from query string
								query := r.URL.Query()
								query.Del("defenra_pow_nonce")
								query.Del("defenra_pow_salt")
								if len(query) > 0 {
									redirectURL += "?" + query.Encode()
								}
							}

							// Manually create redirect response to ensure cookie is set
							w.Header().Set("Set-Cookie", sessionCookie.String())
							w.Header().Set("Location", redirectURL)
							w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
							w.WriteHeader(http.StatusFound)

							log.Printf("[HTTPS] Redirecting to %s with session cookie: %s", redirectURL, sessionCookie.String())
							return
						} else {
							// GET request with valid PoW - set session cookie and continue processing
							http.SetCookie(w, sessionCookie)
							log.Printf("[HTTPS] GET request with valid PoW, session created, continuing to origin")
							// Continue processing the request normally
						}
					}
				}
			case 3:
				// CAPTCHA challenge
				if challengeSettings.CaptchaChallenge != nil && challengeSettings.CaptchaChallenge.Enabled {
					if !challengeMgr.ValidateCaptchaChallenge(r) {
						l7Protection.RecordChallengeFailure(clientIP)
						
						// === FORTRESS OFFLOADING: Записываем failure ===
						if offloadingTracker.RecordFailure(clientIP, "captcha") {
							log.Printf("[HTTPS] IP %s offloaded to iptables (repeated CAPTCHA challenge failures)", clientIP)
							atomic.AddUint64(&s.stats.BlockedRequests, 1)
							return
						}
						
						response := challengeMgr.IssueCaptchaChallenge(w, r, clientIP)
						s.sendChallengeResponse(w, response)
						return
					} else if r.Method == "POST" {
						// CAPTCHA was successfully validated, create session and redirect
						sessionID := challengeMgr.CreateSessionAfterChallenge(clientIP, r.UserAgent(), r.Host)
						sessionCookie := challengeMgr.CreateSessionCookie(sessionID, r.TLS != nil)

						log.Printf("[HTTPS] CAPTCHA challenge passed for IP %s, creating session %s", clientIP, sessionID)

						// === FORTRESS OFFLOADING: Сбрасываем счетчик при успехе ===
						offloadingTracker.ResetIP(clientIP)

						// Redirect to the original URL with query parameters
						redirectURL := r.URL.Path
						if r.URL.RawQuery != "" {
							redirectURL += "?" + r.URL.RawQuery
						}

						// Manually create redirect response to ensure cookie is set
						w.Header().Set("Set-Cookie", sessionCookie.String())
						w.Header().Set("Location", redirectURL)
						w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
						w.WriteHeader(http.StatusFound)

						log.Printf("[HTTPS] Redirecting to %s with session cookie: %s", redirectURL, sessionCookie.String())
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

	// Check if HTTP proxy is enabled for this specific domain/subdomain
	httpEnabled := domainConfig.HTTPProxy.Enabled
	if !httpEnabled {
		// For subdomains, check if the specific DNS record has HTTPProxyEnabled
		parts := strings.Split(host, ".")
		if len(parts) >= 2 {
			subdomain := parts[0]
			parentDomain := strings.Join(parts[1:], ".")

			// If this is a subdomain request and domain config is for parent
			if domainConfig.Domain == parentDomain {
				// Check if the specific subdomain record has HTTP proxy enabled
				for _, record := range domainConfig.DNSRecords {
					if record.Name == subdomain && record.HTTPProxyEnabled {
						httpEnabled = true
						log.Printf("[HTTPS] HTTP proxy enabled for subdomain %s via DNS record", host)
						break
					}
				}
			}
		}

		// If still not enabled, check if any DNS record allows HTTP proxy (fallback)
		if !httpEnabled {
			for _, record := range domainConfig.DNSRecords {
				if record.HTTPProxyEnabled {
					httpEnabled = true
					break
				}
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
	// Check if this is a subdomain resolution case
	parts := strings.Split(host, ".")
	if len(parts) >= 2 {
		subdomain := parts[0]
		parentDomain := strings.Join(parts[1:], ".")

		// If the domain config is for the parent domain, look for DNS record for this subdomain
		if domainConfig.Domain == parentDomain {
			for _, record := range domainConfig.DNSRecords {
				if record.Name == subdomain {
					if record.Type == "CNAME" {
						log.Printf("[HTTPS] Resolving CNAME: %s -> %s", host, record.Value)
						// CNAME record found, use its value as target
						// The value could be another domain name or IP
						// For now, we'll treat it as the target to proxy to

						// If CNAME value looks like a domain, we need to resolve it
						// For simplicity, let's check if it's an IP or domain
						if net.ParseIP(record.Value) != nil {
							// It's an IP address
							return record.Value
						} else {
							// It's a domain name, we should resolve it
							// For now, let's look for A records in the same domain that match
							for _, aRecord := range domainConfig.DNSRecords {
								if aRecord.Type == "A" && (aRecord.Name == record.Value || aRecord.Name == "@") {
									return aRecord.Value
								}
							}
							// If no A record found, return the CNAME value as-is
							// The HTTP client will resolve it
							return record.Value
						}
					} else if record.Type == "A" || record.Type == "AAAA" {
						log.Printf("[HTTPS] Resolving %s record: %s -> %s", record.Type, host, record.Value)
						// Direct A/AAAA record for subdomain
						return record.Value
					}
				}
			}
		}
	}

	// Original logic for direct domain matches
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
	// Set headers
	for key, value := range response.Headers {
		w.Header().Set(key, value)
	}
	w.WriteHeader(response.StatusCode)

	// Write body with timeout protection
	// If client is not reading (slow loris attack), this will timeout
	done := make(chan bool, 1)
	go func() {
		w.Write([]byte(response.Body))
		done <- true
	}()

	// Wait max 5 seconds for write to complete
	select {
	case <-done:
		// Write completed successfully
		return
	case <-time.After(5 * time.Second):
		// Write timeout - client not reading
		// Connection will be closed by HTTP server
		log.Printf("[HTTPS] Challenge response write timeout - client not reading")
		return
	}
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
