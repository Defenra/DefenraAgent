package proxy

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"html"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/defenra/agent/config"
)

const jsChallengeSecret = "defenra-js-challenge"
const challengePath = "/__antiddos/challenge"
const acmeChallengePath = "/.well-known/acme-challenge/"
const cleanupInterval = 5 * time.Minute
const entryTTL = 30 * time.Minute

type rateEntry struct {
	Count       int
	WindowStart time.Time
	LastAccess  time.Time
}

type blockEntry struct {
	Until time.Time
}

// AntiDDoSManager uses sync.Map for better concurrency performance
type AntiDDoSManager struct {
	rates       sync.Map // map[string]*rateEntry
	blocks      sync.Map // map[string]*blockEntry
	connections sync.Map // map[string]*int32
	stopCleanup chan struct{}
}

func NewAntiDDoSManager() *AntiDDoSManager {
	mgr := &AntiDDoSManager{
		stopCleanup: make(chan struct{}),
	}
	
	// Start cleanup goroutine
	go mgr.cleanupLoop()
	
	return mgr
}

func (m *AntiDDoSManager) Stop() {
	close(m.stopCleanup)
}

func (m *AntiDDoSManager) cleanupLoop() {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			m.cleanup()
		case <-m.stopCleanup:
			return
		}
	}
}

func (m *AntiDDoSManager) cleanup() {
	now := time.Now()
	
	// Cleanup expired rate entries
	m.rates.Range(func(key, value interface{}) bool {
		entry := value.(*rateEntry)
		if now.Sub(entry.LastAccess) > entryTTL {
			m.rates.Delete(key)
		}
		return true
	})
	
	// Cleanup expired blocks
	m.blocks.Range(func(key, value interface{}) bool {
		entry := value.(*blockEntry)
		if now.After(entry.Until) {
			m.blocks.Delete(key)
		}
		return true
	})
	
	// Cleanup stale connections
	m.connections.Range(func(key, value interface{}) bool {
		count := value.(*int32)
		if atomic.LoadInt32(count) == 0 {
			m.connections.Delete(key)
		}
		return true
	})
	
	log.Printf("[AntiDDoS] Cleanup completed")
}

func (m *AntiDDoSManager) Enforce(w http.ResponseWriter, r *http.Request, domain *config.Domain, stats *HTTPStats) (bool, func()) {
	if domain == nil {
		return false, nil
	}
	cfg := domain.HTTPProxy.AntiDDoS
	if !cfg.Enabled {
		return false, nil
	}

	// ACME HTTP-01 Challenge bypass (CRITICAL for Let's Encrypt)
	if strings.HasPrefix(r.URL.Path, acmeChallengePath) {
		return false, nil
	}

	ip := resolveClientIP(r, cfg)
	if ip == "" {
		return false, nil
	}

	if ipInWhitelist(ip, cfg.IPWhitelist) {
		return false, nil
	}

	// Challenge endpoint handler
	if strings.HasPrefix(r.URL.Path, challengePath) {
		return m.handleChallengeEndpoint(w, r, cfg, ip), nil
	}

	now := time.Now()
	
	// Check if IP is blocked (using sync.Map)
	if blockVal, ok := m.blocks.Load(ip); ok {
		entry := blockVal.(*blockEntry)
		if now.Before(entry.Until) {
			atomic.AddUint64(&stats.RateLimited, 1)
			logAnti(cfg, "Blocked IP %s (still banned)", ip)
			respondTooMany(w)
			return true, nil
		}
		m.blocks.Delete(ip)
	}

	// Rate limiting with sync.Map
	window := time.Duration(cfg.RateLimit.WindowSeconds) * time.Second
	if window <= 0 {
		window = 5 * time.Second
	}

	entryVal, _ := m.rates.LoadOrStore(ip, &rateEntry{
		WindowStart: now,
		LastAccess:  now,
		Count:       0,
	})
	entry := entryVal.(*rateEntry)

	// Reset window if expired
	if now.Sub(entry.WindowStart) > window {
		entry.Count = 0
		entry.WindowStart = now
	}
	entry.LastAccess = now
	entry.Count++

	if cfg.RateLimit.MaxRequests > 0 && entry.Count > cfg.RateLimit.MaxRequests {
		blockFor := time.Duration(cfg.BlockDurationSeconds) * time.Second
		if blockFor <= 0 {
			blockFor = 5 * time.Minute
		}
		m.blocks.Store(ip, &blockEntry{Until: now.Add(blockFor)})
		atomic.AddUint64(&stats.RateLimited, 1)
		logAnti(cfg, "Rate limit exceeded for %s", ip)
		respondTooMany(w)
		return true, nil
	}

	// Concurrent connection tracking with sync.Map and atomic counters
	maxConn := cfg.Slowloris.MaxConnections
	if maxConn <= 0 {
		maxConn = 1000
	}

	countVal, _ := m.connections.LoadOrStore(ip, new(int32))
	countPtr := countVal.(*int32)
	current := atomic.AddInt32(countPtr, 1)

	release := func() {
		if val := atomic.AddInt32(countPtr, -1); val <= 0 {
			m.connections.Delete(ip)
		}
	}

	if int(current) > maxConn {
		release()
		atomic.AddUint64(&stats.SlowlorisBlocks, 1)
		logAnti(cfg, "Too many concurrent connections for %s", ip)
		respondTooMany(w)
		return true, nil
	}

	// Slowloris-style checks (simplified)
	if cfg.Slowloris.MinContentLength > 0 && r.ContentLength > 0 && r.ContentLength < int64(cfg.Slowloris.MinContentLength) {
		atomic.AddUint64(&stats.SlowlorisBlocks, 1)
		logAnti(cfg, "Slowloris small content-length from %s", ip)
		http.Error(w, "Request body too small", http.StatusBadRequest)
		return true, release
	}

	if cfg.JSChallenge.Enabled && !hasValidChallengeCookie(r, cfg, ip) {
		atomic.AddUint64(&stats.JSChallenges, 1)
		issueJSChallenge(w, r, cfg, ip)
		return true, release
	}

	return false, release
}

func (m *AntiDDoSManager) handleChallengeEndpoint(w http.ResponseWriter, r *http.Request, cfg config.AntiDDoSConfig, ip string) bool {
	if !cfg.JSChallenge.Enabled {
		return false
	}
	issueJSChallenge(w, r, cfg, ip)
	return true
}

func resolveClientIP(r *http.Request, cfg config.AntiDDoSConfig) string {
	for _, header := range cfg.ProxyIPHeaders {
		header = strings.TrimSpace(header)
		if header == "" {
			continue
		}
		if value := r.Header.Get(header); value != "" {
			parts := strings.Split(value, ",")
			candidate := strings.TrimSpace(parts[0])
			if net.ParseIP(candidate) != nil {
				return candidate
			}
		}
	}

	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		candidate := strings.TrimSpace(parts[0])
		if net.ParseIP(candidate) != nil {
			return candidate
		}
	}

	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		if net.ParseIP(xri) != nil {
			return xri
		}
	}

	remote := r.RemoteAddr
	if strings.Contains(remote, ":") {
		host, _, err := net.SplitHostPort(remote)
		if err == nil {
			remote = host
		}
	}
	if net.ParseIP(remote) == nil {
		return ""
	}
	return remote
}

func ipInWhitelist(ip string, whitelist []string) bool {
	ipAddr := net.ParseIP(ip)
	if ipAddr == nil {
		return false
	}
	for _, entry := range whitelist {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if strings.Contains(entry, "/") {
			_, network, err := net.ParseCIDR(entry)
			if err == nil && network.Contains(ipAddr) {
				return true
			}
		} else if entry == ip {
			return true
		}
	}
	return false
}

func hasValidChallengeCookie(r *http.Request, cfg config.AntiDDoSConfig, ip string) bool {
	cookie, err := r.Cookie(cfg.JSChallenge.CookieName)
	if err != nil {
		return false
	}
	expires, sig, ok := decodeChallengeToken(cookie.Value)
	if !ok {
		return false
	}
	if time.Now().Unix() > expires {
		return false
	}
	return sig == computeChallengeSignature(ip, expires)
}

func issueJSChallenge(w http.ResponseWriter, r *http.Request, cfg config.AntiDDoSConfig, ip string) {
	ttl := cfg.JSChallenge.TTLSeconds
	if ttl <= 0 {
		ttl = 900
	}
	expires := time.Now().Add(time.Duration(ttl) * time.Second)
	token := encodeChallengeToken(ip, expires.Unix())
	http.SetCookie(w, &http.Cookie{
		Name:     cfg.JSChallenge.CookieName,
		Value:    token,
		Path:     "/",
		Expires:  expires,
		HttpOnly: false,
	})

	back := r.URL.RequestURI()
	if back == "" {
		back = "/"
	}
	challenge := fmt.Sprintf(`<!DOCTYPE html>
<html><head><meta charset="utf-8" />
<title>Verifying...</title>
<style>body{font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;background:#0f172a;color:#f8fafc;} .card{padding:2rem;border-radius:0.75rem;background:#1e293b;box-shadow:0 10px 40px rgba(15,23,42,0.6);} .spinner{width:40px;height:40px;border:4px solid rgba(255,255,255,0.2);border-top-color:#38bdf8;border-radius:50%%;animation:spin 1s linear infinite;margin-bottom:1rem;} @keyframes spin{to{transform:rotate(360deg);}}</style>
<script>setTimeout(function(){window.location.href = %q;}, 1200);</script>
</head><body>
<div class="card"><div class="spinner"></div><p>Проверяем браузер...</p></div>
</body></html>`, html.EscapeString(back))

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(challenge))
}

func respondTooMany(w http.ResponseWriter) {
	http.Error(w, "Too many requests", http.StatusTooManyRequests)
}

func encodeChallengeToken(ip string, expires int64) string {
	data := fmt.Sprintf("%d:%s", expires, computeChallengeSignature(ip, expires))
	return base64.StdEncoding.EncodeToString([]byte(data))
}

func decodeChallengeToken(val string) (int64, string, bool) {
	decoded, err := base64.StdEncoding.DecodeString(val)
	if err != nil {
		return 0, "", false
	}
	parts := strings.Split(string(decoded), ":")
	if len(parts) != 2 {
		return 0, "", false
	}
	expires, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return 0, "", false
	}
	return expires, parts[1], true
}

func computeChallengeSignature(ip string, expires int64) string {
	payload := fmt.Sprintf("%s|%d|%s", ip, expires, jsChallengeSecret)
	hash := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(hash[:])
}

func parseInt64(val string) (int64, error) {
	return strconv.ParseInt(val, 10, 64)
}

func logAnti(cfg config.AntiDDoSConfig, format string, args ...interface{}) {
	if cfg.Logging.Enabled {
		log.Printf("[AntiDDoS] "+format, args...)
	}
}
