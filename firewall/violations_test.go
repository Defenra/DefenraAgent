package firewall

import (
	"testing"
	"time"
)

func TestViolationTracker(t *testing.T) {
	tracker := NewViolationTracker()
	defer tracker.Stop()

	testIP := "192.168.1.100"

	t.Run("first violation triggers CAPTCHA", func(t *testing.T) {
		level := tracker.RecordViolation(testIP, "rate_limit")
		if level != 1 {
			t.Errorf("Expected escalation level 1 (CAPTCHA), got %d", level)
		}
	})

	t.Run("second violation triggers 10min block", func(t *testing.T) {
		level := tracker.RecordViolation(testIP, "rate_limit")
		if level != 2 {
			t.Errorf("Expected escalation level 2 (10min block), got %d", level)
		}

		// Check if IP is blocked
		blocked, remaining := tracker.IsBlocked(testIP)
		if !blocked {
			t.Error("IP should be blocked after second violation")
		}
		if remaining <= 0 || remaining > 10*time.Minute {
			t.Errorf("Block duration should be around 10 minutes, got %v", remaining)
		}
	})

	t.Run("third violation triggers 30min block", func(t *testing.T) {
		testIP3 := "192.168.1.103" // Use different IP to avoid interference

		// Record violations with time gaps to avoid being blocked
		tracker.RecordViolation(testIP3, "rate_limit") // 1st - CAPTCHA

		// Wait a bit and record second violation
		time.Sleep(1 * time.Millisecond)
		tracker.RecordViolation(testIP3, "rate_limit") // 2nd - 10min block

		// Clear the block to allow third violation
		tracker.mu.Lock()
		if violation, exists := tracker.violations[testIP3]; exists {
			violation.BlockedUntil = time.Now().Add(-1 * time.Minute) // Set to past
		}
		tracker.mu.Unlock()

		level := tracker.RecordViolation(testIP3, "rate_limit") // 3rd

		if level != 3 {
			t.Errorf("Expected escalation level 3 (30min block), got %d", level)
		}

		// Check if IP is blocked with longer duration
		blocked, remaining := tracker.IsBlocked(testIP3)
		if !blocked {
			t.Error("IP should be blocked after third violation")
		}
		if remaining <= 10*time.Minute || remaining > 30*time.Minute {
			t.Errorf("Block duration should be around 30 minutes, got %v", remaining)
		}
	})

	t.Run("clear violations resets count", func(t *testing.T) {
		tracker.ClearViolations(testIP)

		count := tracker.GetViolationCount(testIP)
		if count != 0 {
			t.Errorf("Expected violation count 0 after clearing, got %d", count)
		}

		// Next violation should be level 1 again
		level := tracker.RecordViolation(testIP, "rate_limit")
		if level != 1 {
			t.Errorf("Expected escalation level 1 after clearing, got %d", level)
		}
	})

	t.Run("violations expire after 1 hour", func(t *testing.T) {
		testIP2 := "192.168.1.101"

		// Record a violation
		tracker.RecordViolation(testIP2, "rate_limit")

		// Manually set last time to more than 1 hour ago
		tracker.mu.Lock()
		if violation, exists := tracker.violations[testIP2]; exists {
			violation.LastTime = time.Now().Add(-2 * time.Hour)
		}
		tracker.mu.Unlock()

		// Next violation should be level 1 (reset)
		level := tracker.RecordViolation(testIP2, "rate_limit")
		if level != 1 {
			t.Errorf("Expected escalation level 1 after expiration, got %d", level)
		}
	})

	t.Run("blocked IP returns 0 escalation", func(t *testing.T) {
		testIP3 := "192.168.1.102"

		// Create a blocked IP
		tracker.RecordViolation(testIP3, "rate_limit") // 1st
		tracker.RecordViolation(testIP3, "rate_limit") // 2nd - should block for 10min

		// Try to record another violation while blocked
		level := tracker.RecordViolation(testIP3, "rate_limit")
		if level != 0 {
			t.Errorf("Expected escalation level 0 for blocked IP, got %d", level)
		}
	})
}
