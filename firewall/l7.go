package firewall

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

var (
	// Global TLS fingerprint storage
	tlsFingerprintMu    sync.RWMutex
	tlsFingerprints     = make(map[string]string) // remoteAddr -> fingerprint
)

// StoreTLSFingerprint stores a TLS fingerprint for a connection
func StoreTLSFingerprint(remoteAddr, fingerprint string) {
	tlsFingerprintMu.Lock()
	defer tlsFingerprintMu.Unlock()
	tlsFingerprints[remoteAddr] = fingerprint
}

// GetTLSFingerprint retrieves a TLS fingerprint for a connection
func GetTLSFingerprint(remoteAddr string) string {
	tlsFingerprintMu.RLock()
	defer tlsFingerprintMu.RUnlock()
	return tlsFingerprints[remoteAddr]
}

// CleanupTLSFingerprint removes a TLS fingerprint for a connection
func CleanupTLSFingerprint(remoteAddr string) {
	tlsFingerprintMu.Lock()
	defer tlsFingerprintMu.Unlock()
	delete(tlsFingerprints, remoteAddr)
}

type L7Protection struct {
	mu                   sync.RWMutex
	connectionTracker    map[string]*connectionInfo
	fingerprintTracker   map[string]*fingerprintInfo
	challengeTracker     map[string]*challengeInfo
	suspiciousIPs        map[string]int64
	config               *L7Config
	stopChan             chan struct{}
}

type L7Config struct {
	FingerprintRateLimit   int
	IPRateLimit            int
	FailChallengeRateLimit int
	SuspiciousThreshold    int
	RateWindow             time.Duration
	BlockedFingerprints    map[string]string
	AllowedFingerprints    map[string]string
	KnownFingerprints      map[string]string
	BotFingerprints        map[string]string
}

type connectionInfo struct {
	Fingerprint    string
	RequestCount   int64
	ChallengeFails int64
	LastAccess     time.Time
	RateReset      time.Time
}

type fingerprintInfo struct {
	RequestCount int64
	LastAccess   time.Time
	RateReset    time.Time
	BrowserType  string
}

type challengeInfo struct {
	ChallengeType string
	Issued        time.Time
	Attempts      int
	Solved        bool
}

// Known browser fingerprints (from balooProxyX)
var knownFingerprints = map[string]string{
	// Windows
	"0x1301,0x1302,0x1303,0xc02b,0xc02f,0xc02c,0xc030,0xcca9,0xcca8,0xc013,0xc014,0x9c,0x9d,0x2f,0x35,0x583235353139,0x437572766550323536,0x437572766550333834,0x0,": "Chromium",
	"0x1303,0x1302,0xc02b,0xc02f,0xcca9,0xcca8,0xc02c,0xc030,0xc00a,0xc009,0xc013,0xc014,0x9c,0x9d,0x2f,0x35,0x437572766550323536,0x437572766550333834,0x437572766550353231,0x437572766549442832353629,0x437572766549442832353729,0x0,": "Firefox",
	"0x1301,0x1302,0x1302,0x1303,0xc02b,0xc02f,0xc02c,0xc030,0xcca9,0xcca8,0xc013,0xc014,0x9c,0x9d,0x2f,0x35,0x583235353139,0x437572766550323536,0x437572766550333834,0x0,": "Edge",
	// iPhone
	"0x1301,0x1302,0x1303,0xc02c,0xc02b,0xcca9,0xc030,0xc02f,0xcca8,0xc00a,0xc009,0xc014,0xc013,0x9d,0x9c,0x35,0x2f,0xc008,0xc012,0xa,0x583235353139,0x437572766550323536,0x437572766550333834,0x437572766550353231,0x0,": "Safari",
	// Android
	"0xc02c,0xc02f,0xc02b,0x9f,0x9e,0xc032,0xc02e,0xc031,0xc02d,0xa5,0xa1,0xa4,0xa0,0xc028,0xc024,0xc014,0xc00a,0xc02a,0xc026,0xc00f,0xc005,0xc027,0xc023,0xc013,0xc009,0xc029,0xc025,0xc00e,0xc004,0x6b,0x69,0x68,0x39,0x37,0x36,0x67,0x3f,0x3e,0x33,0x31,0x30,0x9d,0x9c,0x3d,0x35,0x3c,0x2f,0xff,0x437572766550353231,0x437572766550333834,0x4375727665494428323229,0x0,": "Dalvik",
}

// Bot fingerprints (from balooProxyX)
var botFingerprints = map[string]string{
	"0xc030,0x9f,0xcca9,0xcca8,0xccaa,0xc02b,0xc02f,0x9e,0xc024,0xc028,0x6b,0xc023,0xc027,0x67,0xc00a,0xc014,0x39,0xc009,0xc013,0x33,0x9d,0x9c,0x3d,0x3c,0x35,0x2f,0xff,0x437572766550323536,0x437572766550353231,0x437572766550333834,0x0,": "Checkhost",
	"0x1303,0x1301,0xc02c,0xc030,0x9f,0xcca9,0xcca8,0xccaa,0xc02b,0xc02f,0x9e,0xc024,0xc028,0x6b,0xc023,0xc027,0x67,0xc00a,0xc014,0x39,0xc009,0xc013,0x33,0x9d,0x9c,0x3d,0x3c,0x35,0x2f,0xff,0x437572766550323536,0x4375727665494428333029,0x437572766550353231,0x437572766550333834,0x0,": "Curl",
	"0x1303,0x1301,0xc02c,0xc030,0xc02b,0xc02f,0xcca9,0xcca8,0x9f,0x9e,0xccaa,0xc0af,0xc0ad,0xc0ae,0xc0ac,0xc024,0xc028,0xc023,0xc027,0xc00a,0xc014,0xc009,0xc013,0xc0a3,0xc09f,0xc0a2,0xc09e,0x6b,0x67,0x39,0x33,0x9d,0x9c,0xc0a1,0xc09d,0xc0a0,0xc09c,0x3d,0x3c,0x35,0x2f,0xff,0x437572766550323536,0x4375727665494428333029,0x437572766550353231,0x437572766550333834,0x0,": "Python-Requests",
}

// Malicious fingerprints (from balooProxyX)
var maliciousFingerprints = map[string]string{
	"0x1303,0x1302,0xc02f,0xc02b,0xc030,0xc02c,0x9e,0xc027,0x67,0xc028,0x6b,0x9f,0xcca9,0xcca8,0xccaa,0xc0af,0xc0ad,0xc0a3,0xc09f,0xc05d,0xc061,0xc053,0xc0ae,0xc0ac,0xc0a2,0xc09e,0xc05c,0xc060,0xc052,0xc024,0xc023,0xc00a,0xc014,0x39,0xc009,0xc013,0x33,0x9d,0xc0a1,0xc09d,0xc051,0x9c,0xc0a0,0xc09c,0xc050,0x3d,0x3c,0x35,0x2f,0xff,0x437572766550323536,0x4375727665494428333029,0x437572766550353231,0x437572766550333834,0x437572766549442832353629,0x437572766549442832353729,0x437572766549442832353829,0x437572766549442832353929,0x437572766549442832363029,0x0,": "Http-Flood",
}

func NewL7Protection(config *L7Config) *L7Protection {
	if config == nil {
		config = &L7Config{
			FingerprintRateLimit:   50,
			IPRateLimit:            100,
			FailChallengeRateLimit: 10,
			SuspiciousThreshold:    1,
			RateWindow:             10 * time.Second,
			KnownFingerprints:      knownFingerprints,
			BotFingerprints:        botFingerprints,
			BlockedFingerprints:    maliciousFingerprints,
			AllowedFingerprints:    make(map[string]string),
		}
	}

	l7 := &L7Protection{
		connectionTracker:  make(map[string]*connectionInfo),
		fingerprintTracker: make(map[string]*fingerprintInfo),
		challengeTracker:   make(map[string]*challengeInfo),
		suspiciousIPs:      make(map[string]int64),
		config:             config,
		stopChan:           make(chan struct{}),
	}

	go l7.cleanup()
	return l7
}

func (l7 *L7Protection) AnalyzeRequest(r *http.Request, clientIP string, tlsFingerprint string) (int, string, error) {
	l7.mu.Lock()
	defer l7.mu.Unlock()

	now := time.Now()
	
	// Get or create connection info
	connInfo, exists := l7.connectionTracker[clientIP]
	if !exists {
		connInfo = &connectionInfo{
			Fingerprint: tlsFingerprint,
			LastAccess:  now,
			RateReset:   now,
		}
		l7.connectionTracker[clientIP] = connInfo
	}

	// Reset rate counters if window expired
	if now.Sub(connInfo.RateReset) > l7.config.RateWindow {
		connInfo.RequestCount = 0
		connInfo.RateReset = now
	}

	connInfo.RequestCount++
	connInfo.LastAccess = now

	// Check IP rate limit
	if int(connInfo.RequestCount) > l7.config.IPRateLimit {
		IncRateLimitBlocks()
		return -1, fmt.Sprintf("IP rate limit exceeded (%d/%v)", l7.config.IPRateLimit, l7.config.RateWindow), nil
	}

	// Check challenge failure rate limit
	if int(connInfo.ChallengeFails) > l7.config.FailChallengeRateLimit {
		IncRateLimitBlocks()
		return -1, fmt.Sprintf("Challenge failure rate limit exceeded (%d)", l7.config.FailChallengeRateLimit), nil
	}

	// Analyze TLS fingerprint if available
	suspicionLevel := l7.config.SuspiciousThreshold
	browserType := ""
	
	if tlsFingerprint != "" {
		// Check if fingerprint is explicitly blocked
		if blockedType, isBlocked := l7.config.BlockedFingerprints[tlsFingerprint]; isBlocked {
			IncL4Blocks()
			return -1, fmt.Sprintf("Blocked fingerprint: %s", blockedType), nil
		}

		// Check if fingerprint is explicitly allowed
		if allowedType, isAllowed := l7.config.AllowedFingerprints[tlsFingerprint]; isAllowed {
			return 0, fmt.Sprintf("Allowed fingerprint: %s", allowedType), nil
		}

		// Check known browser fingerprints
		if knownType, isKnown := l7.config.KnownFingerprints[tlsFingerprint]; isKnown {
			browserType = knownType
			suspicionLevel = 0 // Known browsers are not suspicious
		} else if botType, isBot := l7.config.BotFingerprints[tlsFingerprint]; isBot {
			browserType = botType
			suspicionLevel = 2 // Bots are more suspicious
		} else {
			// Unknown fingerprint - track and rate limit
			fpInfo, fpExists := l7.fingerprintTracker[tlsFingerprint]
			if !fpExists {
				fpInfo = &fingerprintInfo{
					LastAccess: now,
					RateReset:  now,
				}
				l7.fingerprintTracker[tlsFingerprint] = fpInfo
			}

			// Reset fingerprint rate counter if window expired
			if now.Sub(fpInfo.RateReset) > l7.config.RateWindow {
				fpInfo.RequestCount = 0
				fpInfo.RateReset = now
			}

			fpInfo.RequestCount++
			fpInfo.LastAccess = now

			// Check fingerprint rate limit
			if int(fpInfo.RequestCount) > l7.config.FingerprintRateLimit {
				IncRateLimitBlocks()
				return -1, fmt.Sprintf("Unknown fingerprint rate limit exceeded (%d/%v)", l7.config.FingerprintRateLimit, l7.config.RateWindow), nil
			}

			browserType = "Unknown"
			suspicionLevel = 1 // Unknown fingerprints are suspicious
		}

		connInfo.Fingerprint = tlsFingerprint
	}

	return suspicionLevel, browserType, nil
}

func (l7 *L7Protection) RecordChallengeFailure(clientIP string) {
	l7.mu.Lock()
	defer l7.mu.Unlock()

	connInfo, exists := l7.connectionTracker[clientIP]
	if !exists {
		connInfo = &connectionInfo{
			LastAccess: time.Now(),
		}
		l7.connectionTracker[clientIP] = connInfo
	}

	connInfo.ChallengeFails++
}

func (l7 *L7Protection) IssueChallengeToken(clientIP string, challengeType string) string {
	l7.mu.Lock()
	defer l7.mu.Unlock()

	challenge := &challengeInfo{
		ChallengeType: challengeType,
		Issued:        time.Now(),
		Attempts:      0,
		Solved:        false,
	}

	l7.challengeTracker[clientIP] = challenge
	
	// Generate challenge token (simplified - in production use proper crypto)
	return fmt.Sprintf("%s_%d_%s", challengeType, challenge.Issued.Unix(), clientIP)
}

func (l7 *L7Protection) ValidateChallengeToken(clientIP string, token string) bool {
	l7.mu.Lock()
	defer l7.mu.Unlock()

	challenge, exists := l7.challengeTracker[clientIP]
	if !exists {
		return false
	}

	challenge.Attempts++

	// Simple token validation (in production use proper crypto)
	expectedToken := fmt.Sprintf("%s_%d_%s", challenge.ChallengeType, challenge.Issued.Unix(), clientIP)
	if token == expectedToken {
		challenge.Solved = true
		return true
	}

	return false
}

func (l7 *L7Protection) GetConnectionInfo(clientIP string) *connectionInfo {
	l7.mu.RLock()
	defer l7.mu.RUnlock()

	return l7.connectionTracker[clientIP]
}

func (l7 *L7Protection) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			l7.mu.Lock()
			now := time.Now()
			
			// Clean up old connection info
			for ip, info := range l7.connectionTracker {
				if now.Sub(info.LastAccess) > 30*time.Minute {
					delete(l7.connectionTracker, ip)
				}
			}

			// Clean up old fingerprint info
			for fp, info := range l7.fingerprintTracker {
				if now.Sub(info.LastAccess) > 30*time.Minute {
					delete(l7.fingerprintTracker, fp)
				}
			}

			// Clean up old challenges
			for ip, challenge := range l7.challengeTracker {
				if now.Sub(challenge.Issued) > 10*time.Minute {
					delete(l7.challengeTracker, ip)
				}
			}

			l7.mu.Unlock()

		case <-l7.stopChan:
			return
		}
	}
}

// GetKnownFingerprints returns the known browser fingerprints
func GetKnownFingerprints() map[string]string {
	return knownFingerprints
}

// GetBotFingerprints returns the bot fingerprints
func GetBotFingerprints() map[string]string {
	return botFingerprints
}

func (l7 *L7Protection) Stop() {
	close(l7.stopChan)
}

// ExtractTLSFingerprint extracts TLS fingerprint from ClientHello
func ExtractTLSFingerprint(clientHello *tls.ClientHelloInfo) string {
	if clientHello == nil || len(clientHello.CipherSuites) == 0 {
		return ""
	}

	fingerprint := ""

	// Skip first cipher suite as it may be randomized
	for _, suite := range clientHello.CipherSuites[1:] {
		fingerprint += fmt.Sprintf("0x%x,", suite)
	}

	// Add supported curves (skip first as it may be randomized)
	if len(clientHello.SupportedCurves) > 1 {
		for _, curve := range clientHello.SupportedCurves[1:] {
			fingerprint += fmt.Sprintf("0x%x,", curve)
		}
	}

	// Add supported points (take only first)
	if len(clientHello.SupportedPoints) > 0 {
		for _, point := range clientHello.SupportedPoints[:1] {
			fingerprint += fmt.Sprintf("0x%x,", point)
		}
	}

	return fingerprint
}

// GetClientIP extracts real client IP from request headers
func GetClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP in the chain
		if idx := strings.Index(xff, ","); idx != -1 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Check CF-Connecting-IP (Cloudflare)
	if cfIP := r.Header.Get("CF-Connecting-IP"); cfIP != "" {
		return cfIP
	}

	// Fall back to RemoteAddr
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}