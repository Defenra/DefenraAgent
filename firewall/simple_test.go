package firewall

import (
	"net/http"
	"testing"
	"time"
)

func TestSimpleRateLimit(t *testing.T) {
	config := &L7Config{
		FingerprintRateLimit:   5,
		IPRateLimit:            3, // Very low limit for testing
		FailChallengeRateLimit: 2,
		SuspiciousThreshold:    1,
		RateWindow:             1 * time.Second,
		KnownFingerprints:      GetKnownFingerprints(),
		BotFingerprints:        GetBotFingerprints(),
		BlockedFingerprints:    make(map[string]string),
		AllowedFingerprints:    make(map[string]string),
	}

	l7 := NewL7Protection(config)
	defer l7.Stop()

	testIP := "192.168.1.200"

	// Create normal browser request
	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	req.RemoteAddr = testIP + ":12345"

	// Send requests up to the limit
	for i := 0; i < 3; i++ {
		suspicion, reason, err := l7.AnalyzeRequest(req, testIP, "")
		t.Logf("Request %d: suspicion=%d, reason='%s', err=%v", i+1, suspicion, reason, err)

		if err != nil {
			t.Fatalf("Unexpected error on request %d: %v", i+1, err)
		}
		if suspicion < 0 {
			t.Fatalf("Request %d was blocked unexpectedly", i+1)
		}
	}

	// Next request should be blocked by IP rate limit
	suspicion, reason, err := l7.AnalyzeRequest(req, testIP, "")
	t.Logf("Request 4 (should be blocked): suspicion=%d, reason='%s', err=%v", suspicion, reason, err)

	if err == nil {
		t.Error("Expected request to be blocked by IP rate limit")
	}

	if suspicion != -1 {
		t.Errorf("Expected request to be blocked (suspicion -1), got %d", suspicion)
	}
}
