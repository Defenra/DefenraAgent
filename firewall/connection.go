package firewall

import (
	"log"
	"net"
	"sync"
	"time"
)

// ConnectionLimiter provides connection-level rate limiting and protection
type ConnectionLimiter struct {
	mu                sync.RWMutex
	connections       map[string]*connectionState
	maxConnPerIP      int
	connectionTimeout time.Duration
	cleanupInterval   time.Duration
	stopChan          chan struct{}
}

type connectionState struct {
	count      int
	lastAccess time.Time
	blocked    bool
	blockUntil time.Time
}

// NewConnectionLimiter creates a new connection limiter
func NewConnectionLimiter(maxConnPerIP int, connectionTimeout time.Duration) *ConnectionLimiter {
	cl := &ConnectionLimiter{
		connections:       make(map[string]*connectionState),
		maxConnPerIP:      maxConnPerIP,
		connectionTimeout: connectionTimeout,
		cleanupInterval:   30 * time.Second,
		stopChan:          make(chan struct{}),
	}

	go cl.cleanup()
	return cl
}

// CheckConnection checks if a new connection from IP should be allowed
func (cl *ConnectionLimiter) CheckConnection(remoteAddr string) bool {
	ip, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		ip = remoteAddr
	}

	cl.mu.Lock()
	defer cl.mu.Unlock()

	now := time.Now()
	state, exists := cl.connections[ip]
	if !exists {
		state = &connectionState{
			count:      0,
			lastAccess: now,
		}
		cl.connections[ip] = state
	}

	// Check if IP is currently blocked
	if state.blocked && now.Before(state.blockUntil) {
		log.Printf("[CONN] Connection blocked: IP %s is temporarily blocked until %v", ip, state.blockUntil)
		return false
	}

	// Reset block status if expired
	if state.blocked && now.After(state.blockUntil) {
		state.blocked = false
		state.count = 0
		log.Printf("[CONN] Block expired for IP %s", ip)
	}

	// Check connection limit
	if state.count >= cl.maxConnPerIP {
		// Block IP for 5 minutes on connection limit exceeded
		state.blocked = true
		state.blockUntil = now.Add(5 * time.Minute)
		log.Printf("[CONN] Connection limit exceeded for IP %s (%d/%d), blocking for 5 minutes",
			ip, state.count, cl.maxConnPerIP)
		return false
	}

	// Allow connection
	state.count++
	state.lastAccess = now
	log.Printf("[CONN] Connection allowed for IP %s (%d/%d)", ip, state.count, cl.maxConnPerIP)
	return true
}

// ReleaseConnection decrements the connection count for an IP
func (cl *ConnectionLimiter) ReleaseConnection(remoteAddr string) {
	ip, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		ip = remoteAddr
	}

	cl.mu.Lock()
	defer cl.mu.Unlock()

	if state, exists := cl.connections[ip]; exists {
		if state.count > 0 {
			state.count--
		}
		state.lastAccess = time.Now()
		log.Printf("[CONN] Connection released for IP %s (%d connections remaining)", ip, state.count)
	}
}

// IsBlocked checks if an IP is currently blocked
func (cl *ConnectionLimiter) IsBlocked(remoteAddr string) bool {
	ip, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		ip = remoteAddr
	}

	cl.mu.RLock()
	defer cl.mu.RUnlock()

	if state, exists := cl.connections[ip]; exists {
		return state.blocked && time.Now().Before(state.blockUntil)
	}
	return false
}

// BlockIP manually blocks an IP for a specified duration
func (cl *ConnectionLimiter) BlockIP(remoteAddr string, duration time.Duration) {
	ip, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		ip = remoteAddr
	}

	cl.mu.Lock()
	defer cl.mu.Unlock()

	now := time.Now()
	state, exists := cl.connections[ip]
	if !exists {
		state = &connectionState{
			lastAccess: now,
		}
		cl.connections[ip] = state
	}

	state.blocked = true
	state.blockUntil = now.Add(duration)
	log.Printf("[CONN] IP %s manually blocked for %v", ip, duration)
}

// cleanup removes old connection states
func (cl *ConnectionLimiter) cleanup() {
	ticker := time.NewTicker(cl.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			cl.mu.Lock()
			now := time.Now()
			var toRemove []string

			for ip, state := range cl.connections {
				// Remove if no active connections and not blocked, or if inactive for too long
				if (state.count == 0 && !state.blocked && now.Sub(state.lastAccess) > cl.connectionTimeout) ||
					(state.blocked && now.After(state.blockUntil) && now.Sub(state.lastAccess) > cl.connectionTimeout) {
					toRemove = append(toRemove, ip)
				}
			}

			for _, ip := range toRemove {
				delete(cl.connections, ip)
			}

			if len(toRemove) > 0 {
				log.Printf("[CONN] Cleaned up %d inactive connection states", len(toRemove))
			}
			cl.mu.Unlock()

		case <-cl.stopChan:
			return
		}
	}
}

// GetStats returns connection limiter statistics
func (cl *ConnectionLimiter) GetStats() map[string]interface{} {
	cl.mu.RLock()
	defer cl.mu.RUnlock()

	totalConnections := 0
	blockedIPs := 0
	activeIPs := len(cl.connections)

	for _, state := range cl.connections {
		totalConnections += state.count
		if state.blocked && time.Now().Before(state.blockUntil) {
			blockedIPs++
		}
	}

	return map[string]interface{}{
		"active_ips":        activeIPs,
		"total_connections": totalConnections,
		"blocked_ips":       blockedIPs,
		"max_conn_per_ip":   cl.maxConnPerIP,
	}
}

// UpdateLimits updates the connection limits dynamically
func (cl *ConnectionLimiter) UpdateLimits(maxConnPerIP int) {
	cl.mu.Lock()
	defer cl.mu.Unlock()

	oldLimit := cl.maxConnPerIP
	cl.maxConnPerIP = maxConnPerIP

	if oldLimit != maxConnPerIP {
		log.Printf("[CONN] Connection limit updated: %d -> %d connections per IP", oldLimit, maxConnPerIP)
	}
}

// GetCurrentLimit returns the current connection limit per IP
func (cl *ConnectionLimiter) GetCurrentLimit() int {
	cl.mu.RLock()
	defer cl.mu.RUnlock()
	return cl.maxConnPerIP
}

// Stop stops the connection limiter
func (cl *ConnectionLimiter) Stop() {
	close(cl.stopChan)
}

var globalConnectionLimiter *ConnectionLimiter

// GetConnectionLimiter returns the global connection limiter instance
func GetConnectionLimiter() *ConnectionLimiter {
	if globalConnectionLimiter == nil {
		// Default: max 100 connections per IP, 5 minute timeout (increased from 10)
		globalConnectionLimiter = NewConnectionLimiter(100, 5*time.Minute)
	}
	return globalConnectionLimiter
}

// InitConnectionLimiter initializes the global connection limiter with custom settings
func InitConnectionLimiter(maxConnPerIP int, connectionTimeout time.Duration) {
	if globalConnectionLimiter != nil {
		globalConnectionLimiter.Stop()
	}
	globalConnectionLimiter = NewConnectionLimiter(maxConnPerIP, connectionTimeout)
}
