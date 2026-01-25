package firewall

import (
	"net/http"
	"testing"
	"time"
)

func TestAggressiveL7Protection(t *testing.T) {
	// Create L7 protection with aggressive settings
	config := &L7Config{
		FingerprintRateLimit:   20,  // Reduced from 50
		IPRateLimit:            30,  // Reduced from 100
		FailChallengeRateLimit: 5,   // Reduced from 10
		SuspiciousThreshold:    1,
		RateWindow:             5 * time.Second, // Reduced from 10 seconds
		KnownFingerprints:      GetKnownFingerprints(),
		BotFingerprints:        GetBotFingerprints(),
		BlockedFingerprints:    make(map[string]string),
		AllowedFingerprints:    make(map[string]string),
	}

	l7 := NewL7Protection(config)
	defer l7.Stop()

	testIP := "192.168.1.100"

	// Test 1: Suspicious User-Agent should be blocked immediately
	req, _ := http.NewRequest("GET", "http://example.com/", nil)
	req.Header.Set("User-Agent", "curl/7.68.0")
	req.RemoteAddr = testIP + ":12345"

	suspicion, reason, err := l7.AnalyzeRequest(req, testIP, "")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if suspicion != 4 {
		t.Errorf("Expected suspicion level 4 for curl, got %d", suspicion)
	}

	if suspicion < 4 {
		t.Errorf("Curl should be blocked immediately, suspicion: %d, reason: %s", suspicion, reason)
	}

	// Test 2: Empty User-Agent should be blocked immediately
	req2, _ := http.NewRequest("GET", "http://example.com/", nil)
	req2.Header.Set("User-Agent", "")
	req2.RemoteAddr = testIP + ":12346"

	suspicion2, reason2, err2 := l7.AnalyzeRequest(req2, testIP, "")
	if err2 != nil {
		t.Errorf("Unexpected error: %v", err2)
	}

	if suspicion2 != 4 {
		t.Errorf("Expected suspicion level 4 for empty UA, got %d", suspicion2)
	}

	if suspicion2 < 4 {
		t.Errorf("Empty User-Agent should be blocked immediately, suspicion: %d, reason: %s", suspicion2, reason2)
	}

	// Test 3: Short User-Agent should be blocked immediately
	req3, _ := http.NewRequest("GET", "http://example.com/", nil)
	req3.Header.Set("User-Agent", "x")
	req3.RemoteAddr = testIP + ":12347"

	suspicion3, reason3, err3 := l7.AnalyzeRequest(req3, testIP, "")
	if err3 != nil {
		t.Errorf("Unexpected error: %v", err3)
	}

	if suspicion3 != 4 {
		t.Errorf("Expected suspicion level 4 for short UA, got %d", suspicion3)
	}

	if suspicion3 < 4 {
		t.Errorf("Short User-Agent should be blocked immediately, suspicion: %d, reason: %s", suspicion3, reason3)
	}

	// Test 4: Normal browser should be allowed
	req4, _ := http.NewRequest("GET", "http://example.com/", nil)
	req4.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
	req4.RemoteAddr = testIP + ":12348"

	suspicion4, reason4, err4 := l7.AnalyzeRequest(req4, testIP, "")
	if err4 != nil {
		t.Errorf("Unexpected error: %v", err4)
	}

	if suspicion4 > 1 {
		t.Errorf("Normal browser should have low suspicion, got %d, reason: %s", suspicion4, reason4)
	}

	// Test 5: Allowed bot should be allowed
	req5, _ := http.NewRequest("GET", "http://example.com/", nil)
	req5.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)")
	req5.RemoteAddr = testIP + ":12349"

	suspicion5, reason5, err5 := l7.AnalyzeRequest(req5, testIP, "")
	if err5 != nil {
		t.Errorf("Unexpected error: %v", err5)
	}

	if suspicion5 != 0 {
		t.Errorf("Googlebot should be allowed, got suspicion %d, reason: %s", suspicion5, reason5)
	}
}

func TestAggressiveRateLimiting(t *testing.T) {
	// Create L7 protection with very aggressive rate limiting
	config := &L7Config{
		FingerprintRateLimit:   5,   // Very low limit
		IPRateLimit:            10,  // Very low limit
		FailChallengeRateLimit: 2,   // Very low limit
		SuspiciousThreshold:    1,
		RateWindow:             5 * time.Second,
		KnownFingerprints:      GetKnownFingerprints(),
		BotFingerprints:        GetBotFingerprints(),
		BlockedFingerprints:    make(map[string]string),
		AllowedFingerprints:    make(map[string]string),
	}

	l7 := NewL7Protection(config)
	defer l7.Stop()

	testIP := "192.168.1.101"

	// Create a normal browser request for rate limiting test
	req, _ := http.NewRequest("GET", "http://example.com/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36") // Normal browser
	req.RemoteAddr = testIP + ":12345"

	// Send requests up to the limit
	for i := 0; i < 10; i++ {
		suspicion, reason, err := l7.AnalyzeRequest(req, testIP, "")
		if err != nil {
			t.Logf("Request %d blocked by rate limit: %v", i+1, err)
			return // Rate limit hit as expected
		}
		if suspicion < 0 {
			t.Errorf("Request %d should not be blocked yet, suspicion: %d, reason: %s", i+1, suspicion, reason)
		}
	}

	// Next request should be rate limited
	suspicion, reason, err := l7.AnalyzeRequest(req, testIP, "")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if suspicion != -1 {
		t.Errorf("Request should be blocked by rate limit, suspicion: %d, reason: %s", suspicion, reason)
	}
}

func TestSpamAttackSimulation(t *testing.T) {
	// Simulate a spam attack with curl requests
	config := &L7Config{
		FingerprintRateLimit:   20,
		IPRateLimit:            30,
		FailChallengeRateLimit: 5,
		SuspiciousThreshold:    1,
		RateWindow:             5 * time.Second,
		KnownFingerprints:      GetKnownFingerprints(),
		BotFingerprints:        GetBotFingerprints(),
		BlockedFingerprints:    make(map[string]string),
		AllowedFingerprints:    make(map[string]string),
	}

	l7 := NewL7Protection(config)
	defer l7.Stop()

	testIP := "192.168.1.102"
	blockedBySuspicion := 0
	blockedByRateLimit := 0
	totalRequests := 100

	// Simulate spam attack with curl
	for i := 0; i < totalRequests; i++ {
		req, _ := http.NewRequest("GET", "http://example.com/", nil)
		req.Header.Set("User-Agent", "curl/7.68.0")
		req.RemoteAddr = testIP + ":12345"

		suspicion, reason, err := l7.AnalyzeRequest(req, testIP, "")
		
		if suspicion >= 4 {
			blockedBySuspicion++
		} else if err != nil {
			blockedByRateLimit++
		}
		
		// Log first few for debugging
		if i < 5 {
			t.Logf("Request %d: suspicion=%d, reason='%s', err=%v", i+1, suspicion, reason, err)
		}
	}

	totalBlocked := blockedBySuspicion + blockedByRateLimit
	
	t.Logf("Spam attack simulation results:")
	t.Logf("- Total requests: %d", totalRequests)
	t.Logf("- Blocked by suspicion (User-Agent): %d", blockedBySuspicion)
	t.Logf("- Blocked by rate limit: %d", blockedByRateLimit)
	t.Logf("- Total blocked: %d (%.1f%%)", totalBlocked, float64(totalBlocked)/float64(totalRequests)*100)

	// Most requests should be blocked by User-Agent analysis
	if blockedBySuspicion < 90 {
		t.Errorf("Expected at least 90 requests blocked by User-Agent analysis, got %d", blockedBySuspicion)
	}

	// Verify that the protection is working effectively
	blockRate := float64(totalBlocked) / float64(totalRequests) * 100
	if blockRate < 90.0 {
		t.Errorf("Block rate too low: %.1f%% (expected >= 90%%)", blockRate)
	} else {
		t.Logf("✓ Effective protection: %.1f%% of spam requests blocked", blockRate)
	}
}