package firewall

import (
	"log"
	"net"
	"sync"
	"time"
)

// ConnectionLimiter provides connection-level rate limiting and protection
type ConnectionLimiter struct {
	connections       sync.Map // map[string]*connectionState - lock-free
	maxConnPerIP      int
	connectionTimeout time.Duration
	cleanupInterval   time.Duration
	stopChan          chan struct{}
}

type connectionState struct {
	mu         sync.Mutex
	count      int
	lastAccess time.Time
	blocked    bool
	blockUntil time.Time
}

// NewConnectionLimiter creates a new connection limiter
func NewConnectionLimiter(maxConnPerIP int, connectionTimeout time.Duration) *ConnectionLimiter {
	cl := &ConnectionLimiter{
		connections:       sync.Map{},
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

	now := time.Now()
	
	// Load or create state
	val, _ := cl.connections.LoadOrStore(ip, &connectionState{
		lastAccess: now,
	})
	state := val.(*connectionState)
	
	// Lock only this IP's state, not the entire map
	state.mu.Lock()
	defer state.mu.Unlock()

	// Check if IP is currently blocked
	if state.blocked && now.Before(state.blockUntil) {
		// Don't log every blocked attempt - too much spam
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
		// Block IP for 1 hour on connection limit exceeded (increased from 5 minutes)
		state.blocked = true
		state.blockUntil = now.Add(1 * time.Hour)
		log.Printf("[CONN] Connection limit exceeded for IP %s (%d/%d), blocking for 1 hour",
			ip, state.count, cl.maxConnPerIP)
		return false
	}

	// Allow connection - only log every 10th connection to reduce spam
	state.count++
	state.lastAccess = now
	if state.count%10 == 1 || state.count <= 5 {
		log.Printf("[CONN] Connection allowed for IP %s (%d/%d)", ip, state.count, cl.maxConnPerIP)
	}
	return true
}

// ReleaseConnection decrements the connection count for an IP
func (cl *ConnectionLimiter) ReleaseConnection(remoteAddr string) {
	ip, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		ip = remoteAddr
	}

	val, ok := cl.connections.Load(ip)
	if !ok {
		return
	}
	
	state := val.(*connectionState)
	state.mu.Lock()
	defer state.mu.Unlock()
	
	if state.count > 0 {
		state.count--
	}
	state.lastAccess = time.Now()
	
	// Only log every 10th release to reduce spam
	if state.count%10 == 0 || state.count <= 5 {
		log.Printf("[CONN] Connection released for IP %s (%d connections remaining)", ip, state.count)
	}
}

// IsBlocked checks if an IP is currently blocked
func (cl *ConnectionLimiter) IsBlocked(remoteAddr string) bool {
	ip, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		ip = remoteAddr
	}

	val, ok := cl.connections.Load(ip)
	if !ok {
		return false
	}
	
	state := val.(*connectionState)
	state.mu.Lock()
	defer state.mu.Unlock()
	
	return state.blocked && time.Now().Before(state.blockUntil)
}

// BlockIP manually blocks an IP for a specified duration
func (cl *ConnectionLimiter) BlockIP(remoteAddr string, duration time.Duration) {
	ip, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		ip = remoteAddr
	}

	now := time.Now()
	val, _ := cl.connections.LoadOrStore(ip, &connectionState{
		lastAccess: now,
	})
	
	state := val.(*connectionState)
	state.mu.Lock()
	defer state.mu.Unlock()
	
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
			now := time.Now()
			var toRemove []string

			// Iterate over sync.Map
			cl.connections.Range(func(key, value interface{}) bool {
				ip := key.(string)
				state := value.(*connectionState)
				
				state.mu.Lock()
				shouldRemove := (state.count == 0 && !state.blocked && now.Sub(state.lastAccess) > cl.connectionTimeout) ||
					(state.blocked && now.After(state.blockUntil) && now.Sub(state.lastAccess) > cl.connectionTimeout)
				state.mu.Unlock()
				
				if shouldRemove {
					toRemove = append(toRemove, ip)
				}
				return true
			})

			for _, ip := range toRemove {
				cl.connections.Delete(ip)
			}

			if len(toRemove) > 0 {
				log.Printf("[CONN] Cleaned up %d inactive connection states", len(toRemove))
			}

		case <-cl.stopChan:
			return
		}
	}
}

// GetStats returns connection limiter statistics
func (cl *ConnectionLimiter) GetStats() map[string]interface{} {
	totalConnections := 0
	blockedIPs := 0
	activeIPs := 0

	now := time.Now()
	cl.connections.Range(func(key, value interface{}) bool {
		state := value.(*connectionState)
		state.mu.Lock()
		activeIPs++
		totalConnections += state.count
		if state.blocked && now.Before(state.blockUntil) {
			blockedIPs++
		}
		state.mu.Unlock()
		return true
	})

	return map[string]interface{}{
		"active_ips":        activeIPs,
		"total_connections": totalConnections,
		"blocked_ips":       blockedIPs,
		"max_conn_per_ip":   cl.maxConnPerIP,
	}
}

// UpdateLimits updates the connection limits dynamically
func (cl *ConnectionLimiter) UpdateLimits(maxConnPerIP int) {
	oldLimit := cl.maxConnPerIP
	cl.maxConnPerIP = maxConnPerIP

	if oldLimit != maxConnPerIP {
		log.Printf("[CONN] Connection limit updated: %d -> %d connections per IP", oldLimit, maxConnPerIP)
	}
}

// GetCurrentLimit returns the current connection limit per IP
func (cl *ConnectionLimiter) GetCurrentLimit() int {
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
