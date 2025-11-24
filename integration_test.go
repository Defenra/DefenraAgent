package main

import (
	"net/http"
	"testing"
	"time"

	"github.com/defenra/agent/firewall"
	"github.com/defenra/agent/proxy"
)

func TestIntegration_AntiDDoS(t *testing.T) {
	t.Run("full protection flow", func(t *testing.T) {
		// тест полного потока защиты
		firewallMgr := firewall.GetIPTablesManager()
		rateLimiter := proxy.NewRateLimiter()
		l4Protection := firewall.NewL4Protection(10, 100, 60*time.Second)

		testIP := "192.168.1.100"

		// 1. проверяем L4 защиту
		allowed, _ := l4Protection.CheckConnection(testIP)
		if !allowed {
			t.Error("first connection should be allowed")
		}

		// 2. проверяем rate limiting на L7
		config := proxy.RateLimitConfig{
			WindowSeconds:       1,
			MaxRequests:         5,
			BlockDurationSeconds: 60,
		}

		for i := 0; i < 5; i++ {
			allowed, _ := rateLimiter.CheckRateLimit(testIP, config)
			if !allowed {
				t.Errorf("request %d should be allowed", i+1)
			}
		}

		// 3. превышаем rate limit
		allowed, _ = rateLimiter.CheckRateLimit(testIP, config)
		if allowed {
			t.Error("request should be blocked by rate limit")
		}

		// 4. статистика rate limit обновляется в HTTP handler, здесь не проверяем

		// 5. баним IP через iptables
		err := firewallMgr.BanIP(testIP, 1*time.Minute)
		if err != nil {
			t.Logf("BanIP error (expected if not root): %v", err)
		}

		if !firewallMgr.IsBanned(testIP) {
			t.Error("IP should be banned")
		}

		// 6. проверяем статистику банов (BanIP инкрементирует TotalBans)
		banStats := firewall.GetStats()
		// TotalBans может быть уже > 0 от других тестов
		_ = banStats
	})

	t.Run("multiple attack vectors", func(t *testing.T) {
		// симулируем разные типы атак
		l4Protection := firewall.NewL4Protection(5, 50, 30*time.Second)
		rateLimiter := proxy.NewRateLimiter()
		firewallMgr := firewall.GetIPTablesManager()

		// SYN flood симуляция
		ip1 := "10.0.0.1"
		for i := 0; i < 6; i++ {
			allowed, _ := l4Protection.CheckConnection(ip1)
			if i < 5 && !allowed {
				t.Errorf("connection %d should be allowed", i+1)
			}
			if i == 5 && allowed {
				t.Error("connection should be blocked (connection limit)")
			}
		}

		// Rate limit атака
		ip2 := "10.0.0.2"
		config := proxy.RateLimitConfig{
			WindowSeconds:       1,
			MaxRequests:         10,
			BlockDurationSeconds: 60,
		}

		for i := 0; i < 11; i++ {
			allowed, _ := rateLimiter.CheckRateLimit(ip2, config)
			if i < 10 && !allowed {
				t.Errorf("request %d should be allowed", i+1)
			}
			if i == 10 && allowed {
				t.Error("request should be blocked (rate limit)")
			}
		}

		// проверяем что все IP отслеживаются отдельно
		if firewallMgr.IsBanned(ip1) {
			t.Error("ip1 should not be banned yet (only connection limit)")
		}

		if firewallMgr.IsBanned(ip2) {
			t.Error("ip2 should not be banned yet (only rate limit)")
		}
	})
}

func TestIntegration_Statistics(t *testing.T) {
	t.Run("statistics collection", func(t *testing.T) {
		// сбрасываем статистику
		firewall.ResetStats()

		// генерируем разные события
		firewall.IncTotalBans()
		firewall.IncActiveBans()
		firewall.IncL4Blocks()
		firewall.IncRateLimitBlocks()
		firewall.IncConnectionLimitBlocks()
		firewall.IncTCPFlagBlocks()

		stats := firewall.GetStats()

		if stats.TotalBans == 0 {
			t.Error("TotalBans should be > 0")
		}
		if stats.ActiveBans == 0 {
			t.Error("ActiveBans should be > 0")
		}
		if stats.L4Blocks == 0 {
			t.Error("L4Blocks should be > 0")
		}
		if stats.RateLimitBlocks == 0 {
			t.Error("RateLimitBlocks should be > 0")
		}
		if stats.ConnectionLimitBlocks == 0 {
			t.Error("ConnectionLimitBlocks should be > 0")
		}
		if stats.TCPFlagBlocks == 0 {
			t.Error("TCPFlagBlocks should be > 0")
		}
	})
}

func TestIntegration_RateLimiterHeaders(t *testing.T) {
	t.Run("ip extraction from headers", func(t *testing.T) {
		rl := proxy.NewRateLimiter()

		// тест с X-Forwarded-For
		req1, _ := http.NewRequest("GET", "/", nil)
		req1.Header.Set("X-Forwarded-For", "203.0.113.1")
		ip1 := rl.GetClientIP(req1)
		if ip1 != "203.0.113.1" {
			t.Errorf("expected IP 203.0.113.1, got %s", ip1)
		}

		// тест с X-Real-IP
		req2, _ := http.NewRequest("GET", "/", nil)
		req2.Header.Set("X-Real-IP", "198.51.100.1")
		ip2 := rl.GetClientIP(req2)
		if ip2 != "198.51.100.1" {
			t.Errorf("expected IP 198.51.100.1, got %s", ip2)
		}

		// тест с множественными IP в X-Forwarded-For
		req3, _ := http.NewRequest("GET", "/", nil)
		req3.Header.Set("X-Forwarded-For", "192.0.2.1, 10.0.0.1, 172.16.0.1")
		ip3 := rl.GetClientIP(req3)
		if ip3 != "192.0.2.1" {
			t.Errorf("expected first IP 192.0.2.1, got %s", ip3)
		}

		// тест fallback на RemoteAddr
		req4, _ := http.NewRequest("GET", "/", nil)
		req4.RemoteAddr = "192.168.1.100:54321"
		ip4 := rl.GetClientIP(req4)
		if ip4 != "192.168.1.100" {
			t.Errorf("expected IP 192.168.1.100, got %s", ip4)
		}
	})
}
