package firewall

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// SessionData represents a user session after passing challenges
type SessionData struct {
	ID        string
	ClientIP  string
	UserAgent string
	Host      string
	CreatedAt time.Time
	ExpiresAt time.Time
	Verified  bool
}

// SessionManager manages user sessions after challenge completion
type SessionManager struct {
	mu       sync.RWMutex
	sessions map[string]*SessionData
	stopChan chan struct{}
}

var globalSessionManager *SessionManager

func init() {
	globalSessionManager = NewSessionManager()
}

// NewSessionManager creates a new session manager
func NewSessionManager() *SessionManager {
	sm := &SessionManager{
		sessions: make(map[string]*SessionData),
		stopChan: make(chan struct{}),
	}

	go sm.cleanup()
	return sm
}

// GetSessionManager returns the global session manager
func GetSessionManager() *SessionManager {
	return globalSessionManager
}

// CreateSession creates a new verified session
func (sm *SessionManager) CreateSession(clientIP, userAgent, host string) string {
	sessionID := generateSessionID()

	session := &SessionData{
		ID:        sessionID,
		ClientIP:  clientIP,
		UserAgent: userAgent,
		Host:      host,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour), // Session valid for 24 hours
		Verified:  true,
	}

	sm.mu.Lock()
	sm.sessions[sessionID] = session
	sm.mu.Unlock()

	return sessionID
}

// IsSessionValid checks if a session is valid and not expired
func (sm *SessionManager) IsSessionValid(sessionID, clientIP, userAgent, host string) bool {
	if sessionID == "" {
		return false
	}

	sm.mu.RLock()
	session, exists := sm.sessions[sessionID]
	sm.mu.RUnlock()

	if !exists {
		return false
	}

	// Check if session is expired
	if time.Now().After(session.ExpiresAt) {
		sm.mu.Lock()
		delete(sm.sessions, sessionID)
		sm.mu.Unlock()
		return false
	}

	// Verify session matches client details
	if session.ClientIP != clientIP || session.UserAgent != userAgent || session.Host != host {
		return false
	}

	return session.Verified
}

// ExtendSession extends the expiration time of a valid session
func (sm *SessionManager) ExtendSession(sessionID string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if session, exists := sm.sessions[sessionID]; exists {
		session.ExpiresAt = time.Now().Add(24 * time.Hour)
	}
}

// InvalidateSession removes a session
func (sm *SessionManager) InvalidateSession(sessionID string) {
	sm.mu.Lock()
	delete(sm.sessions, sessionID)
	sm.mu.Unlock()
}

// GetSessionStats returns session statistics
func (sm *SessionManager) GetSessionStats() (int, int) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	total := len(sm.sessions)
	active := 0
	now := time.Now()

	for _, session := range sm.sessions {
		if now.Before(session.ExpiresAt) {
			active++
		}
	}

	return total, active
}

// cleanup removes expired sessions periodically
func (sm *SessionManager) cleanup() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			sm.mu.Lock()
			now := time.Now()
			for id, session := range sm.sessions {
				if now.After(session.ExpiresAt) {
					delete(sm.sessions, id)
				}
			}
			sm.mu.Unlock()

		case <-sm.stopChan:
			return
		}
	}
}

// Stop stops the session manager
func (sm *SessionManager) Stop() {
	close(sm.stopChan)
}

// generateSessionID generates a random session ID
func generateSessionID() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}
