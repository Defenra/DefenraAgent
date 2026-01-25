package firewall

import (
	"sync"
	"time"
)

// ViolationTracker tracks rate limit violations and escalates penalties
type ViolationTracker struct {
	mu         sync.RWMutex
	violations map[string]*ViolationInfo
	stopChan   chan struct{}
}

type ViolationInfo struct {
	Count         int
	FirstTime     time.Time
	LastTime      time.Time
	BlockedUntil  time.Time
	ViolationType string // "rate_limit", "challenge_fail", etc.
}

var globalViolationTracker *ViolationTracker

func init() {
	globalViolationTracker = NewViolationTracker()
}

func NewViolationTracker() *ViolationTracker {
	vt := &ViolationTracker{
		violations: make(map[string]*ViolationInfo),
		stopChan:   make(chan struct{}),
	}

	go vt.cleanup()
	return vt
}

func GetViolationTracker() *ViolationTracker {
	return globalViolationTracker
}

// RecordViolation records a violation and returns the escalation level
// Returns: 0 = no penalty, 1 = CAPTCHA challenge, 2 = 10min block, 3+ = 30min block
func (vt *ViolationTracker) RecordViolation(clientIP, violationType string) int {
	vt.mu.Lock()
	defer vt.mu.Unlock()

	now := time.Now()

	violation, exists := vt.violations[clientIP]
	if !exists {
		violation = &ViolationInfo{
			Count:         1,
			FirstTime:     now,
			LastTime:      now,
			ViolationType: violationType,
		}
		vt.violations[clientIP] = violation

		// First violation - trigger CAPTCHA
		return 1
	}

	// Check if still blocked from previous violation
	if now.Before(violation.BlockedUntil) {
		// Still blocked, don't escalate further
		return 0
	}

	// Reset count if more than 1 hour has passed since last violation
	if now.Sub(violation.LastTime) > time.Hour {
		violation.Count = 1
		violation.FirstTime = now
	} else {
		violation.Count++
	}

	violation.LastTime = now
	violation.ViolationType = violationType

	// Escalate based on violation count
	switch violation.Count {
	case 1:
		// First violation - CAPTCHA challenge
		return 1
	case 2:
		// Second violation - 10 minute block
		violation.BlockedUntil = now.Add(10 * time.Minute)
		return 2
	default:
		// Third+ violation - 30 minute block
		violation.BlockedUntil = now.Add(30 * time.Minute)
		return 3
	}
}

// CheckViolationStatus checks if an IP should be blocked and returns appropriate action
// Returns: 0 = allow, 1 = show CAPTCHA, 2 = show 10min block page, 3 = show 30min block page
func (vt *ViolationTracker) CheckViolationStatus(clientIP string) int {
	vt.mu.RLock()
	defer vt.mu.RUnlock()

	violation, exists := vt.violations[clientIP]
	if !exists {
		return 0 // No violations, allow
	}

	now := time.Now()
	
	// Check if currently blocked
	if now.Before(violation.BlockedUntil) {
		// Return appropriate block level based on violation count
		if violation.Count >= 3 {
			return 3 // 30min block page
		} else if violation.Count >= 2 {
			return 2 // 10min block page
		}
		return 1 // Should not happen, but fallback to CAPTCHA
	}

	return 0 // Not blocked, allow
}
func (vt *ViolationTracker) IsBlocked(clientIP string) (bool, time.Duration) {
	vt.mu.RLock()
	defer vt.mu.RUnlock()

	violation, exists := vt.violations[clientIP]
	if !exists {
		return false, 0
	}

	now := time.Now()
	if now.Before(violation.BlockedUntil) {
		remaining := violation.BlockedUntil.Sub(now)
		return true, remaining
	}

	return false, 0
}

// GetViolationCount returns the current violation count for an IP
func (vt *ViolationTracker) GetViolationCount(clientIP string) int {
	vt.mu.RLock()
	defer vt.mu.RUnlock()

	violation, exists := vt.violations[clientIP]
	if !exists {
		return 0
	}

	// Reset count if more than 1 hour has passed
	if time.Since(violation.LastTime) > time.Hour {
		return 0
	}

	return violation.Count
}

// ClearViolations clears violations for an IP (e.g., after successful CAPTCHA)
func (vt *ViolationTracker) ClearViolations(clientIP string) {
	vt.mu.Lock()
	defer vt.mu.Unlock()

	delete(vt.violations, clientIP)
}

// cleanup removes old violation records
func (vt *ViolationTracker) cleanup() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			vt.mu.Lock()
			now := time.Now()

			for ip, violation := range vt.violations {
				// Remove violations older than 2 hours and not currently blocked
				if now.Sub(violation.LastTime) > 2*time.Hour && now.After(violation.BlockedUntil) {
					delete(vt.violations, ip)
				}
			}

			vt.mu.Unlock()

		case <-vt.stopChan:
			return
		}
	}
}

func (vt *ViolationTracker) Stop() {
	close(vt.stopChan)
}
