package firewall

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestL7Protection(t *testing.T) {
	config := &L7Config{
		FingerprintRateLimit:   5,
		IPRateLimit:            10,
		FailChallengeRateLimit: 3,
		SuspiciousThreshold:    1,
		RateWindow:             1 * time.Second,
		KnownFingerprints:      knownFingerprints,
		BotFingerprints:        botFingerprints,
		BlockedFingerprints:    maliciousFingerprints,
		AllowedFingerprints:    make(map[string]string),
	}

	l7 := NewL7Protection(config)
	defer l7.Stop()

	t.Run("known browser fingerprint", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/", nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
		clientIP := "192.168.1.100"
		// Use a known Chrome fingerprint
		tlsFingerprint := "0x1301,0x1302,0x1303,0xc02b,0xc02f,0xc02c,0xc030,0xcca9,0xcca8,0xc013,0xc014,0x9c,0x9d,0x2f,0x35,0x583235353139,0x437572766550323536,0x437572766550333834,0x0,"

		suspicion, browserType, err := l7.AnalyzeRequest(req, clientIP, tlsFingerprint)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}

		if suspicion != 0 {
			t.Errorf("Expected suspicion level 0 for known browser, got %d", suspicion)
		}

		if browserType != "Chromium" {
			t.Errorf("Expected browser type 'Chromium', got '%s'", browserType)
		}
	})

	t.Run("unknown fingerprint", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/", nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
		clientIP := "192.168.1.101"
		tlsFingerprint := "unknown_fingerprint_12345"

		suspicion, browserType, err := l7.AnalyzeRequest(req, clientIP, tlsFingerprint)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}

		if suspicion != 1 {
			t.Errorf("Expected suspicion level 1 for unknown fingerprint, got %d", suspicion)
		}

		if browserType != "Unknown" {
			t.Errorf("Expected browser type 'Unknown', got '%s'", browserType)
		}
	})

	t.Run("blocked fingerprint", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/", nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
		clientIP := "192.168.1.102"
		// Use a malicious fingerprint
		tlsFingerprint := "0x1303,0x1302,0xc02f,0xc02b,0xc030,0xc02c,0x9e,0xc027,0x67,0xc028,0x6b,0x9f,0xcca9,0xcca8,0xccaa,0xc0af,0xc0ad,0xc0a3,0xc09f,0xc05d,0xc061,0xc053,0xc0ae,0xc0ac,0xc0a2,0xc09e,0xc05c,0xc060,0xc052,0xc024,0xc023,0xc00a,0xc014,0x39,0xc009,0xc013,0x33,0x9d,0xc0a1,0xc09d,0xc051,0x9c,0xc0a0,0xc09c,0xc050,0x3d,0x3c,0x35,0x2f,0xff,0x437572766550323536,0x4375727665494428333029,0x437572766550353231,0x437572766550333834,0x437572766549442832353629,0x437572766549442832353729,0x437572766549442832353829,0x437572766549442832353929,0x437572766549442832363029,0x0,"

		suspicion, _, err := l7.AnalyzeRequest(req, clientIP, tlsFingerprint)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}

		if suspicion != -1 {
			t.Errorf("Expected suspicion level -1 (blocked) for malicious fingerprint, got %d", suspicion)
		}
	})

	t.Run("IP rate limiting", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/", nil)
		clientIP := "192.168.1.103"
		tlsFingerprint := ""

		// Make requests up to the limit
		for i := 0; i < 10; i++ {
			suspicion, _, err := l7.AnalyzeRequest(req, clientIP, tlsFingerprint)
			if err != nil {
				t.Fatalf("Unexpected error on request %d: %v", i+1, err)
			}
			if suspicion < 0 {
				t.Fatalf("Request %d was blocked unexpectedly", i+1)
			}
		}

		// Next request should be blocked
		suspicion, _, err := l7.AnalyzeRequest(req, clientIP, tlsFingerprint)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}

		if suspicion != -1 {
			t.Errorf("Expected request to be blocked (suspicion -1), got %d", suspicion)
		}
	})

	t.Run("challenge failure tracking", func(t *testing.T) {
		clientIP := "192.168.1.104"

		// Record multiple challenge failures first
		for i := 0; i < 4; i++ { // More than the limit of 3
			l7.RecordChallengeFailure(clientIP)
		}

		req, _ := http.NewRequest("GET", "/", nil)
		suspicion, _, err := l7.AnalyzeRequest(req, clientIP, "")
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}

		if suspicion != -1 {
			t.Errorf("Expected request to be blocked due to challenge failures, got suspicion %d", suspicion)
		}
	})

	t.Run("suspicious user agent", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/", nil)
		req.Header.Set("User-Agent", "curl/7.68.0") // Suspicious User-Agent
		clientIP := "192.168.1.105"
		tlsFingerprint := "" // No TLS fingerprint

		suspicion, browserType, err := l7.AnalyzeRequest(req, clientIP, tlsFingerprint)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}

		if suspicion < 3 {
			t.Errorf("Expected high suspicion level for curl user agent, got %d", suspicion)
		}

		if !strings.Contains(strings.ToLower(browserType), "curl") {
			t.Errorf("Expected browser type to contain 'curl', got '%s'", browserType)
		}
	})
}

func TestChallengeManager(t *testing.T) {
	cm := NewChallengeManager()
	defer cm.Stop()

	t.Run("cookie challenge validation", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/test", nil)
		clientIP := "192.168.1.200"

		// Initially should not validate (no cookie)
		if cm.ValidateCookieChallenge(req, clientIP) {
			t.Error("Expected cookie challenge to fail without cookie")
		}

		// Issue challenge and get cookie value
		response := cm.IssueCookieChallenge(nil, req, clientIP)
		if !response.Blocked {
			t.Error("Expected challenge response to be blocked")
		}

		if response.StatusCode != http.StatusFound {
			t.Errorf("Expected status code %d, got %d", http.StatusFound, response.StatusCode)
		}

		// Extract cookie from headers
		setCookieHeader := response.Headers["Set-Cookie"]
		if setCookieHeader == "" {
			t.Fatal("Expected Set-Cookie header in challenge response")
		}

		// Create new request with cookie
		req2, _ := http.NewRequest("GET", "/test", nil)
		req2.Header.Set("Cookie", setCookieHeader)

		// Should validate now
		if !cm.ValidateCookieChallenge(req2, clientIP) {
			t.Error("Expected cookie challenge to pass with valid cookie")
		}
	})

	t.Run("JS challenge validation", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/test", nil)

		// Should fail without PoW solution
		if cm.ValidateJSChallenge(req, 4) {
			t.Error("Expected JS challenge to fail without solution")
		}

		// Test GET request with PoW parameters in URL
		getReqWithPoW, _ := http.NewRequest("GET", "/test?defenra_pow_nonce=12345&defenra_pow_salt=test", nil)

		// Should fail with wrong nonce
		if cm.ValidateJSChallenge(getReqWithPoW, 4) {
			t.Error("Expected JS challenge to fail with wrong nonce in GET request")
		}

		// Test POST request with PoW parameters
		postData := "defenra_pow_nonce=12345&defenra_pow_salt=test"
		postReq, _ := http.NewRequest("POST", "/test", strings.NewReader(postData))
		postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		// Should also fail with wrong nonce
		if cm.ValidateJSChallenge(postReq, 4) {
			t.Error("Expected JS challenge to fail with wrong nonce in POST request")
		}

		// Issue challenge
		response := cm.IssueJSChallenge(nil, req, "192.168.1.201", 4)
		if !response.Blocked {
			t.Error("Expected challenge response to be blocked")
		}

		if response.StatusCode != http.StatusOK {
			t.Errorf("Expected status code %d, got %d", http.StatusOK, response.StatusCode)
		}

		// Should contain HTML with JavaScript
		if !contains(response.Body, "sha256") {
			t.Error("Expected challenge response to contain JavaScript PoW code")
		}
	})

	t.Run("CAPTCHA challenge validation", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/test", nil)

		// Should fail without CAPTCHA solution
		if cm.ValidateCaptchaChallenge(req) {
			t.Error("Expected CAPTCHA challenge to fail without solution")
		}

		// Issue challenge
		response := cm.IssueCaptchaChallenge(nil, req, "192.168.1.202")
		if !response.Blocked {
			t.Error("Expected challenge response to be blocked")
		}

		if response.StatusCode != http.StatusOK {
			t.Errorf("Expected status code %d, got %d", http.StatusOK, response.StatusCode)
		}

		// Should contain HTML with CAPTCHA
		if !contains(response.Body, "captcha") {
			t.Error("Expected challenge response to contain CAPTCHA HTML")
		}
	})
}

func TestRuleEngine(t *testing.T) {
	engine := NewRuleEngine()

	t.Run("add and evaluate rules", func(t *testing.T) {
		// Add a rule to block requests from China
		err := engine.AddRule("Block China", "ip.country == 'cn'", "block", true)
		if err != nil {
			t.Fatalf("Failed to add rule: %v", err)
		}

		// Create request context
		req, _ := http.NewRequest("GET", "/", nil)
		ctx := BuildRequestContext(req, "1.2.3.4", "cn", "AS12345", "Chrome", "", "", 1, 0, 1, 10, false)

		// Evaluate rules
		result := engine.EvaluateRules(ctx, 1)
		if result != 999 { // "block" action should set high suspicion
			t.Errorf("Expected suspicion level 999 (block), got %d", result)
		}
	})

	t.Run("relative action rules", func(t *testing.T) {
		engine := NewRuleEngine()

		// Add rule to increase suspicion for high request rate
		err := engine.AddRule("High Rate", "ip.requests > 50", "+2", true)
		if err != nil {
			t.Fatalf("Failed to add rule: %v", err)
		}

		// Create request context with high request count
		req, _ := http.NewRequest("GET", "/", nil)
		ctx := BuildRequestContext(req, "1.2.3.4", "us", "AS12345", "Chrome", "", "", 100, 0, 1, 10, false)

		// Evaluate rules
		result := engine.EvaluateRules(ctx, 1)
		if result != 3 { // 1 + 2 = 3
			t.Errorf("Expected suspicion level 3, got %d", result)
		}
	})

	t.Run("disabled rule", func(t *testing.T) {
		engine := NewRuleEngine()

		// Add disabled rule
		err := engine.AddRule("Disabled Rule", "ip.country == 'cn'", "block", false)
		if err != nil {
			t.Fatalf("Failed to add rule: %v", err)
		}

		// Create request context
		req, _ := http.NewRequest("GET", "/", nil)
		ctx := BuildRequestContext(req, "1.2.3.4", "cn", "AS12345", "Chrome", "", "", 1, 0, 1, 10, false)

		// Evaluate rules - should not be affected by disabled rule
		result := engine.EvaluateRules(ctx, 1)
		if result != 1 { // Should remain unchanged
			t.Errorf("Expected suspicion level 1 (unchanged), got %d", result)
		}
	})
}

// Helper function to check if string contains substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr ||
			func() bool {
				for i := 1; i <= len(s)-len(substr); i++ {
					if s[i:i+len(substr)] == substr {
						return true
					}
				}
				return false
			}())))
}
