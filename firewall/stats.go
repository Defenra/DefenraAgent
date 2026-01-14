package firewall

import (
	"sync"
	"sync/atomic"
)

var globalStats = &FirewallStats{}

type FirewallStats struct {
	TotalBans             uint64
	ActiveBans            uint64
	L4Blocks              uint64
	TCPFlagBlocks         uint64
	RateLimitBlocks       uint64
	ConnectionLimitBlocks uint64
}

func IncTotalBans() {
	atomic.AddUint64(&globalStats.TotalBans, 1)
}

func IncActiveBans() {
	atomic.AddUint64(&globalStats.ActiveBans, 1)
}

func DecActiveBans() {
	atomic.AddUint64(&globalStats.ActiveBans, ^uint64(0))
}

func IncL4Blocks() {
	atomic.AddUint64(&globalStats.L4Blocks, 1)
}

func IncTCPFlagBlocks() {
	atomic.AddUint64(&globalStats.TCPFlagBlocks, 1)
}

func IncRateLimitBlocks() {
	atomic.AddUint64(&globalStats.RateLimitBlocks, 1)
}

func IncConnectionLimitBlocks() {
	atomic.AddUint64(&globalStats.ConnectionLimitBlocks, 1)
}

func GetStats() FirewallStats {
	return FirewallStats{
		TotalBans:             atomic.LoadUint64(&globalStats.TotalBans),
		ActiveBans:            atomic.LoadUint64(&globalStats.ActiveBans),
		L4Blocks:              atomic.LoadUint64(&globalStats.L4Blocks),
		TCPFlagBlocks:         atomic.LoadUint64(&globalStats.TCPFlagBlocks),
		RateLimitBlocks:       atomic.LoadUint64(&globalStats.RateLimitBlocks),
		ConnectionLimitBlocks: atomic.LoadUint64(&globalStats.ConnectionLimitBlocks),
	}
}

func ResetStats() {
	atomic.StoreUint64(&globalStats.TotalBans, 0)
	atomic.StoreUint64(&globalStats.ActiveBans, 0)
	atomic.StoreUint64(&globalStats.L4Blocks, 0)
	atomic.StoreUint64(&globalStats.TCPFlagBlocks, 0)
	atomic.StoreUint64(&globalStats.RateLimitBlocks, 0)
	atomic.StoreUint64(&globalStats.ConnectionLimitBlocks, 0)
}

type ProxyStatsCollector struct {
	mu    sync.RWMutex
	stats map[string]interface{}
}

var proxyStatsCollector = &ProxyStatsCollector{
	stats: make(map[string]interface{}),
}

func SetProxyStats(key string, value interface{}) {
	proxyStatsCollector.mu.Lock()
	defer proxyStatsCollector.mu.Unlock()
	proxyStatsCollector.stats[key] = value
}

func GetProxyStats() map[string]interface{} {
	proxyStatsCollector.mu.RLock()
	defer proxyStatsCollector.mu.RUnlock()

	result := make(map[string]interface{})
	for k, v := range proxyStatsCollector.stats {
		result[k] = v
	}
	return result
}
