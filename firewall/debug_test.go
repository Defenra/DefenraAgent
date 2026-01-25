package firewall

import (
	"net/http"
	"testing"
	"time"
)

func TestDebugUserAgentAnalysis(t *testing.T) {
	// Test individual User-Agent analysis
	testCases := []struct {
		userAgent       string
		expectedLevel   int
		expectedBlocked bool
	}{
		{"curl/7.68.0", 4, true},
		{"", 4, true},
		{"x", 4, true},
		{"MyClient/1.0", 2, false}, // Non-browser but not immediately blocked
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", 0, false},
		{"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", 0, false},
	}

	for _, tc := range testCases {
		level, reason := AnalyzeUserAgent(tc.userAgent)
		t.Logf("User-Agent: '%s' -> Level: %d, Reason: %s", tc.userAgent, level, reason)
		
		if level != tc.expectedLevel {
			t.Errorf("Expected level %d for '%s', got %d", tc.expectedLevel, tc.userAgent, level)
		}
		
		blocked := level >= 4
		if blocked != tc.expectedBlocked {
			t.Errorf("Expected blocked=%v for '%s', got %v", tc.expectedBlocked, tc.userAgent, blocked)
		}
	}
}

func TestDebugL7Analysis(t *testing.T) {
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

	testIP := "192.168.1.200"

	// Test first few requests with curl
	for i := 0; i < 5; i++ {
		req, _ := http.NewRequest("GET", "http://example.com/", nil)
		req.Header.Set("User-Agent", "curl/7.68.0")
		req.RemoteAddr = testIP + ":12345"

		suspicion, reason, err := l7.AnalyzeRequest(req, testIP, "")
		t.Logf("Request %d: suspicion=%d, reason='%s', err=%v", i+1, suspicion, reason, err)
		
		if suspicion < 4 && err == nil {
			t.Errorf("Request %d should be blocked (suspicion >= 4 or error), got suspicion=%d, err=%v", i+1, suspicion, err)
		}
	}
}