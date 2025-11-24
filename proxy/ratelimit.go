package proxy

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type RateLimiter struct {
	mu      sync.RWMutex
	clients map[string]*clientTracker
}

type clientTracker struct {
	requests   []time.Time
	blockedUntil time.Time
	mu          sync.Mutex
}

type RateLimitConfig struct {
	WindowSeconds       int
	MaxRequests         int
	BlockDurationSeconds int
}

func NewRateLimiter() *RateLimiter {
	return &RateLimiter{
		clients: make(map[string]*clientTracker),
	}
}

func (rl *RateLimiter) CheckRateLimit(ip string, config RateLimitConfig) (bool, string) {
	rl.mu.Lock()
	tracker, exists := rl.clients[ip]
	if !exists {
		tracker = &clientTracker{
			requests: make([]time.Time, 0, config.MaxRequests*2),
		}
		rl.clients[ip] = tracker
	}
	rl.mu.Unlock()

	tracker.mu.Lock()
	defer tracker.mu.Unlock()

	now := time.Now()

	// проверяем блокировку
	if now.Before(tracker.blockedUntil) {
		remaining := tracker.blockedUntil.Sub(now)
		return false, fmt.Sprintf("rate limit exceeded, blocked for %v", remaining)
	}

	// удаляем старые запросы
	windowStart := now.Add(-time.Duration(config.WindowSeconds) * time.Second)
	validRequests := tracker.requests[:0]
	for _, reqTime := range tracker.requests {
		if reqTime.After(windowStart) {
			validRequests = append(validRequests, reqTime)
		}
	}
	tracker.requests = validRequests

	// проверяем лимит
	if len(tracker.requests) >= config.MaxRequests {
		tracker.blockedUntil = now.Add(time.Duration(config.BlockDurationSeconds) * time.Second)
		return false, fmt.Sprintf("rate limit exceeded (%d requests in %ds)", config.MaxRequests, config.WindowSeconds)
	}

	// добавляем текущий запрос
	tracker.requests = append(tracker.requests, now)

	return true, ""
}

func (rl *RateLimiter) GetClientIP(r *http.Request) string {
	// проверяем заголовки proxy (X-Forwarded-For, X-Real-IP и т.д.)
	for _, header := range []string{"X-Forwarded-For", "X-Real-IP", "CF-Connecting-IP"} {
		if val := r.Header.Get(header); val != "" {
			// берем первый IP из списка
			ips := strings.Split(val, ",")
			if len(ips) > 0 {
				ip := strings.TrimSpace(ips[0])
				if net.ParseIP(ip) != nil {
					return ip
				}
			}
		}
	}

	// если нет заголовков, берем из RemoteAddr
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}

	return ip
}

func (rl *RateLimiter) Cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	var toRemove []string

	for ip, tracker := range rl.clients {
		tracker.mu.Lock()
		if len(tracker.requests) == 0 && now.After(tracker.blockedUntil) {
			toRemove = append(toRemove, ip)
		}
		tracker.mu.Unlock()
	}

	for _, ip := range toRemove {
		delete(rl.clients, ip)
	}
}

func (rl *RateLimiter) StartCleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	go func() {
		for range ticker.C {
			rl.Cleanup()
		}
	}()
}

func (rl *RateLimiter) ResetIP(ip string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	delete(rl.clients, ip)
}