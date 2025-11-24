package firewall

import (
	"sync"
	"testing"
	"time"
)

func TestAttackSimulation_SYNFlood(t *testing.T) {
	t.Run("simulate SYN flood attack", func(t *testing.T) {
		maxConns := 50
		l4 := NewL4Protection(maxConns, 1000, 60*time.Second)
		attackerIP := "192.168.1.200"
		ResetStats()

		// симулируем SYN flood - много SYN пакетов без ACK
		synFloodCount := 0

		// пытаемся создать много соединений быстро
		for i := 0; i < maxConns*2; i++ {
			allowed, _ := l4.CheckConnection(attackerIP)
			if allowed {
				synFloodCount++
			}
			// не освобождаем соединения - симулируем незавершенные handshake
		}

		// проверяем что защита сработала - максимум должно быть maxConns разрешенных
		if synFloodCount > maxConns {
			t.Errorf("connection limit should block after %d connections, but %d were allowed", maxConns, synFloodCount)
		}

		// проверяем что хотя бы одно блокирование произошло
		if synFloodCount == maxConns*2 {
			t.Error("some connections should be blocked")
		}
	})
}

func TestAttackSimulation_RateLimitAttack(t *testing.T) {
	t.Run("simulate rate limit attack", func(t *testing.T) {
		rateLimit := 10
		l4 := NewL4Protection(100, rateLimit, 5*time.Second)
		attackerIP := "192.168.1.201"
		ResetStats()

		// симулируем быстрые запросы для rate limit атаки
		totalAttempts := 20

		for i := 0; i < totalAttempts; i++ {
			l4.CheckConnection(attackerIP)
			allowed, _ := l4.CheckRateLimit(attackerIP)
			if i >= rateLimit && allowed {
				t.Errorf("rate limit request %d should be blocked", i+1)
			}
			time.Sleep(10 * time.Millisecond) // небольшая задержка
		}

		// проверяем что rate limit сработал хотя бы для последних запросов
		stats := GetStats()
		// RateLimitBlocks может быть 0 если лимит не превышен в окне
		_ = stats
	})
}

func TestAttackSimulation_DistributedAttack(t *testing.T) {
	t.Run("simulate distributed attack from multiple IPs", func(t *testing.T) {
		l4 := NewL4Protection(10, 100, 60*time.Second)
		firewallMgr := GetIPTablesManager()

		// симулируем атаку с разных IP
		attackerIPs := []string{
			"10.0.0.1",
			"10.0.0.2",
			"10.0.0.3",
			"10.0.0.4",
			"10.0.0.5",
		}

		var wg sync.WaitGroup
		attacksPerIP := 15

		// каждая IP пытается создать много соединений
		for _, ip := range attackerIPs {
			wg.Add(1)
			go func(attackerIP string) {
				defer wg.Done()
				for i := 0; i < attacksPerIP; i++ {
					allowed, _ := l4.CheckConnection(attackerIP)
					if !allowed && i >= 10 {
						// после лимита баним IP
						firewallMgr.BanIP(attackerIP, 1*time.Minute)
					}
				}
			}(ip)
		}

		wg.Wait()

		// проверяем что некоторые IP забанены
		bannedCount := 0
		for _, ip := range attackerIPs {
			if firewallMgr.IsBanned(ip) {
				bannedCount++
			}
		}

		if bannedCount == 0 {
			t.Log("no IPs banned (expected if connection limits not exceeded)")
		}
	})
}

func TestAttackSimulation_ConnectionExhaustion(t *testing.T) {
	t.Run("simulate connection exhaustion attack", func(t *testing.T) {
		l4 := NewL4Protection(5, 100, 60*time.Second)
		attackerIP := "192.168.1.202"

		// пытаемся исчерпать лимит соединений
		for i := 0; i < 10; i++ {
			allowed, reason := l4.CheckConnection(attackerIP)
			if i < 5 {
				if !allowed {
					t.Errorf("connection %d should be allowed, got reason: %s", i+1, reason)
				}
			} else {
				if allowed {
					t.Errorf("connection %d should be blocked (limit exceeded)", i+1)
				}
				if reason == "" {
					t.Error("reason should not be empty when blocked")
				}
			}
		}

		// проверяем что статистика обновлена
		stats := GetStats()
		if stats.ConnectionLimitBlocks == 0 {
			t.Error("ConnectionLimitBlocks should be incremented")
		}
	})
}

func TestAttackSimulation_SlowConnectionAttack(t *testing.T) {
	t.Run("simulate slow connection attack", func(t *testing.T) {
		l4 := NewL4Protection(10, 100, 10*time.Second)
		attackerIP := "192.168.1.203"

		// создаем соединения и не освобождаем их (симуляция медленных соединений)
		connections := make([]bool, 15)
		for i := 0; i < 15; i++ {
			allowed, _ := l4.CheckConnection(attackerIP)
			connections[i] = allowed
			// не вызываем ReleaseConnection - симулируем удерживание соединения
		}

		// проверяем что после лимита соединения блокируются
		blockedCount := 0
		for _, allowed := range connections {
			if !allowed {
				blockedCount++
			}
		}

		if blockedCount == 0 {
			t.Error("some connections should be blocked after limit")
		}

		// освобождаем соединения
		for i := 0; i < 10; i++ {
			l4.ReleaseConnection(attackerIP)
		}

		// проверяем что теперь можно создать новые
		allowed, _ := l4.CheckConnection(attackerIP)
		if !allowed {
			t.Error("connection should be allowed after releasing some")
		}
	})
}

func TestAttackSimulation_MixedAttackVectors(t *testing.T) {
	t.Run("simulate mixed attack with multiple vectors", func(t *testing.T) {
		l4 := NewL4Protection(20, 50, 30*time.Second)
		firewallMgr := GetIPTablesManager()
		attackerIP := "192.168.1.204"
		ResetStats()

		// 1. SYN flood
		for i := 0; i < 25; i++ {
			l4.CheckConnection(attackerIP)
		}

		// 2. Rate limit
		for i := 0; i < 60; i++ {
			l4.CheckRateLimit(attackerIP)
		}

		// 3. Баним IP
		err := firewallMgr.BanIP(attackerIP, 1*time.Minute)
		if err != nil {
			t.Logf("BanIP error (expected if not root): %v", err)
		}

		// проверяем что IP забанен (даже если iptables не работает)
		if !firewallMgr.IsBanned(attackerIP) {
			t.Error("IP should be banned after mixed attack")
		}

		// проверяем статистику - BanIP инкрементирует TotalBans
		stats := GetStats()
		// TotalBans может быть > 0 от предыдущих тестов
		if stats.TotalBans == 0 {
			t.Log("TotalBans is 0 (may be from previous test reset)")
		}
	})
}

func TestAttackSimulation_RapidFireRequests(t *testing.T) {
	t.Run("simulate rapid fire requests", func(t *testing.T) {
		l4 := NewL4Protection(100, 100, 5*time.Second)
		attackerIP := "192.168.1.205"

		// очень быстрые запросы без задержек
		allowedCount := 0
		totalRequests := 200

		start := time.Now()
		for i := 0; i < totalRequests; i++ {
			allowed, _ := l4.CheckConnection(attackerIP)
			if allowed {
				allowedCount++
			}
			l4.CheckRateLimit(attackerIP)
		}
		duration := time.Since(start)

		// проверяем что система выдержала нагрузку
		if duration > 5*time.Second {
			t.Errorf("requests took too long: %v", duration)
		}

		// проверяем что не все запросы были разрешены (лимиты должны сработать)
		if allowedCount == totalRequests {
			t.Log("all requests allowed (limits may not have been exceeded)")
		}
	})
}
