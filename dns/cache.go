package dns

import (
	"sync"
	"time"
)

type DNSCache struct {
	cache   map[string]*CacheEntry
	mu      sync.RWMutex
	maxSize int
}

type CacheEntry struct {
	Value     string
	ExpiresAt time.Time
}

func NewDNSCache(maxSize int) *DNSCache {
	cache := &DNSCache{
		cache:   make(map[string]*CacheEntry),
		maxSize: maxSize,
	}

	go cache.cleanupLoop()

	return cache
}

func (c *DNSCache) Get(key string) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.cache[key]
	if !ok {
		return "", false
	}

	if time.Now().After(entry.ExpiresAt) {
		return "", false
	}

	return entry.Value, true
}

func (c *DNSCache) Set(key string, value string, ttl uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.cache) >= c.maxSize {
		return
	}

	c.cache[key] = &CacheEntry{
		Value:     value,
		ExpiresAt: time.Now().Add(time.Duration(ttl) * time.Second),
	}
}

func (c *DNSCache) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		c.cleanup()
	}
}

func (c *DNSCache) cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for key, entry := range c.cache {
		if now.After(entry.ExpiresAt) {
			delete(c.cache, key)
		}
	}
}
