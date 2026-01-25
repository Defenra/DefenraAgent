package firewall

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestChallengeIntegration(t *testing.T) {
	challengeMgr := NewChallengeManager()
	defer challengeMgr.Stop()

	// Use global violation tracker
	violationTracker := GetViolationTracker()

	testIP := "192.168.1.100"

	t.Run("JS challenge clears violations", func(t *testing.T) {
		// Clear any existing violations first
		violationTracker.ClearViolations(testIP)

		// Record a violation first
		level := violationTracker.RecordViolation(testIP, "rate_limit")
		if level != 1 {
			t.Errorf("Expected violation level 1, got %d", level)
		}

		// Create a POST request with valid PoW solution
		salt := "ABCD1234EFGH5678"
		target := "00" // 2 zeros for easy testing

		// Find a valid nonce (brute force for testing)
		var validNonce string
		for i := 0; i < 1000; i++ {
			nonce := generateRandomString(8)
			input := salt + nonce
			hash := sha256Hash(input)
			if strings.HasPrefix(hash, target) {
				validNonce = nonce
				break
			}
		}

		if validNonce == "" {
			t.Skip("Could not find valid nonce for test")
		}

		// Create form data
		formData := url.Values{}
		formData.Set("defenra_pow_nonce", validNonce)
		formData.Set("defenra_pow_salt", salt)

		// Create request
		req := httptest.NewRequest("POST", "/test", strings.NewReader(formData.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("X-Real-IP", testIP)

		// Validate JS challenge
		isValid := challengeMgr.ValidateJSChallenge(req, 2) // 2 zeros difficulty
		if !isValid {
			t.Error("JS challenge should be valid")
		}

		// Check that violations were cleared
		count := violationTracker.GetViolationCount(testIP)
		if count != 0 {
			t.Errorf("Expected violation count 0 after JS challenge, got %d", count)
		}
	})

	t.Run("CAPTCHA challenge clears violations", func(t *testing.T) {
		testIP2 := "192.168.1.101"

		// Clear any existing violations first
		violationTracker.ClearViolations(testIP2)

		// Record a violation first
		level := violationTracker.RecordViolation(testIP2, "rate_limit")
		if level != 1 {
			t.Errorf("Expected violation level 1, got %d", level)
		}

		// Generate CAPTCHA
		captchaID := "test123"
		captchaData := challengeMgr.generateCaptcha(captchaID)

		// Store in cache
		challengeMgr.mu.Lock()
		challengeMgr.captchaCache[captchaID] = captchaData
		challengeMgr.mu.Unlock()

		// Create form data with correct answer
		formData := url.Values{}
		formData.Set("captcha_id", captchaID)
		formData.Set("captcha_answer", captchaData.Answer)

		// Create request
		req := httptest.NewRequest("POST", "/test", strings.NewReader(formData.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("X-Real-IP", testIP2)

		// Validate CAPTCHA challenge
		isValid := challengeMgr.ValidateCaptchaChallenge(req)
		if !isValid {
			t.Error("CAPTCHA challenge should be valid")
		}

		// Check that violations were cleared
		count := violationTracker.GetViolationCount(testIP2)
		if count != 0 {
			t.Errorf("Expected violation count 0 after CAPTCHA challenge, got %d", count)
		}
	})

	t.Run("Cookie challenge clears violations", func(t *testing.T) {
		testIP3 := "192.168.1.102"

		// Clear any existing violations first
		violationTracker.ClearViolations(testIP3)

		// Record a violation first
		level := violationTracker.RecordViolation(testIP3, "rate_limit")
		if level != 1 {
			t.Errorf("Expected violation level 1, got %d", level)
		}

		// Generate valid cookie using current hour (same as ValidateCookieChallenge does)
		userAgent := "Mozilla/5.0 (Test Browser)"
		host := "example.com"

		// Create request first to get proper setup
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("X-Real-IP", testIP3)
		req.Header.Set("User-Agent", userAgent)
		req.Host = host

		// Generate cookie using the same logic as ValidateCookieChallenge
		accessKey := fmt.Sprintf("%s_%s_%s_%d", testIP3, userAgent, host, time.Now().Hour())
		expectedCookie := challengeMgr.generateVerificationCookie(accessKey)

		req.AddCookie(&http.Cookie{
			Name:  "__defenra_v",
			Value: expectedCookie,
		})

		// Validate cookie challenge
		isValid := challengeMgr.ValidateCookieChallenge(req, testIP3)
		if !isValid {
			t.Error("Cookie challenge should be valid")
		}

		// Check that violations were cleared
		count := violationTracker.GetViolationCount(testIP3)
		if count != 0 {
			t.Errorf("Expected violation count 0 after cookie challenge, got %d", count)
		}
	})
}
