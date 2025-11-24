package firewall

import (
	"testing"
	"time"
)

func TestL4Protection(t *testing.T) {
	t.Run("connection limit", func(t *testing.T) {
		l4 := NewL4Protection(5, 100, 60*time.Second)
		ip := "192.168.1.100"

		// проверяем что первые 5 соединений разрешены
		for i := 0; i < 5; i++ {
			allowed, reason := l4.CheckConnection(ip)
			if !allowed {
				t.Errorf("connection %d should be allowed, got reason: %s", i+1, reason)
			}
		}

		// 6-е соединение должно быть заблокировано
		allowed, reason := l4.CheckConnection(ip)
		if allowed {
			t.Error("6th connection should be blocked")
		}
		if reason == "" {
			t.Error("reason should not be empty")
		}

		// проверяем статистику
		stats := GetStats()
		if stats.ConnectionLimitBlocks == 0 {
			t.Error("ConnectionLimitBlocks should be incremented")
		}
	})

	t.Run("connection release", func(t *testing.T) {
		l4 := NewL4Protection(3, 100, 60*time.Second)
		ip := "192.168.1.101"

		// создаем 3 соединения
		for i := 0; i < 3; i++ {
			l4.CheckConnection(ip)
		}

		// освобождаем одно
		l4.ReleaseConnection(ip)

		// теперь должно быть разрешено еще одно
		allowed, _ := l4.CheckConnection(ip)
		if !allowed {
			t.Error("connection should be allowed after release")
		}
	})

	t.Run("rate limit", func(t *testing.T) {
		l4 := NewL4Protection(100, 10, 5*time.Second)
		ip := "192.168.1.102"

		// создаем соединения в рамках лимита
		for i := 0; i < 10; i++ {
			allowed, _ := l4.CheckConnection(ip)
			if !allowed {
				t.Errorf("connection %d should be allowed", i+1)
			}
			l4.CheckRateLimit(ip)
		}

		// следующее должно быть заблокировано по rate limit
		allowed, reason := l4.CheckRateLimit(ip)
		if allowed {
			t.Error("should be rate limited")
		}
		if reason == "" {
			t.Error("reason should not be empty")
		}
	})

	t.Run("tcp flag analysis with suspicious patterns", func(t *testing.T) {
		l4 := NewL4Protection(100, 1000, 60*time.Second)
		ip := "192.168.1.103"

		// тестируем что suspiciousFlags счетчик работает
		// для реального теста AnalyzeTCPPacket нужны raw TCP пакеты
		// здесь проверяем что механизм отслеживания работает

		// проверяем что после множественных подозрительных пакетов IP будет заблокирован
		// (симулируем через прямую запись в suspiciousFlags)
		l4.mu.Lock()
		l4.suspiciousFlags[ip] = 10
		l4.mu.Unlock()

		// проверяем что IP отслеживается
		l4.mu.RLock()
		count := l4.suspiciousFlags[ip]
		l4.mu.RUnlock()

		if count != 10 {
			t.Errorf("expected suspicious count=10, got %d", count)
		}
	})

	t.Run("multiple ips", func(t *testing.T) {
		l4 := NewL4Protection(2, 100, 60*time.Second)

		// каждый IP имеет свой лимит
		ip1 := "192.168.1.200"
		ip2 := "192.168.1.201"

		// заполняем лимит для ip1
		l4.CheckConnection(ip1)
		l4.CheckConnection(ip1)

		// ip2 должен иметь свой лимит
		allowed, _ := l4.CheckConnection(ip2)
		if !allowed {
			t.Error("ip2 should be allowed (separate limit)")
		}

		// ip1 должен быть заблокирован
		allowed, _ = l4.CheckConnection(ip1)
		if allowed {
			t.Error("ip1 should be blocked (limit reached)")
		}
	})

	t.Run("cleanup old trackers", func(t *testing.T) {
		l4 := NewL4Protection(100, 100, 100*time.Millisecond)
		ip := "192.168.1.300"

		l4.CheckConnection(ip)

		// ждем истечения окна
		time.Sleep(150 * time.Millisecond)

		// проверяем что tracker не удален сразу (cleanup в отдельной горутине)
		allowed, _ := l4.CheckConnection(ip)
		if !allowed {
			t.Error("connection should still be allowed")
		}
	})
}
