package proxy

import (
	"testing"
	"time"

	"github.com/defenra/agent/firewall"
)

func TestTCPProxy_L4Protection(t *testing.T) {
	t.Run("tcp proxy with L4 protection", func(t *testing.T) {
		l4Protection := firewall.NewL4Protection(10, 100, 60*time.Second)
		firewallMgr := firewall.GetIPTablesManager()

		testIP := "192.168.1.100"

		// симулируем TCP соединения
		for i := 0; i < 12; i++ {
			allowed, reason := l4Protection.CheckConnection(testIP)
			if i < 10 {
				if !allowed {
					t.Errorf("connection %d should be allowed, got reason: %s", i+1, reason)
				}
			} else {
				if allowed {
					t.Errorf("connection %d should be blocked (limit exceeded)", i+1)
				}
			}
		}

		// проверяем rate limit на L4
		for i := 0; i < 110; i++ {
			allowed, _ := l4Protection.CheckRateLimit(testIP)
			if i < 100 && !allowed {
				t.Errorf("rate limit request %d should be allowed", i+1)
			}
		}

		// баним IP если превышен лимит
		err := firewallMgr.BanIP(testIP, 1*time.Minute)
		if err != nil {
			t.Logf("BanIP error (expected if not root): %v", err)
		}

		if !firewallMgr.IsBanned(testIP) {
			t.Error("IP should be banned after L4 violations")
		}
	})
}

func TestTCPProxy_ConnectionTracking(t *testing.T) {
	t.Run("connection tracking and release", func(t *testing.T) {
		l4Protection := firewall.NewL4Protection(5, 100, 60*time.Second)
		ip := "192.168.1.101"

		// создаем максимальное количество соединений
		for i := 0; i < 5; i++ {
			allowed, _ := l4Protection.CheckConnection(ip)
			if !allowed {
				t.Errorf("connection %d should be allowed", i+1)
			}
		}

		// следующее должно быть заблокировано
		allowed, _ := l4Protection.CheckConnection(ip)
		if allowed {
			t.Error("6th connection should be blocked")
		}

		// освобождаем одно соединение
		l4Protection.ReleaseConnection(ip)

		// теперь должно быть разрешено
		allowed, _ = l4Protection.CheckConnection(ip)
		if !allowed {
			t.Error("connection should be allowed after release")
		}
	})
}

func TestTCPProxy_MultipleIPs(t *testing.T) {
	t.Run("separate limits for different IPs", func(t *testing.T) {
		l4Protection := firewall.NewL4Protection(3, 50, 60*time.Second)

		ip1 := "192.168.1.200"
		ip2 := "192.168.1.201"

		// заполняем лимит для ip1
		for i := 0; i < 3; i++ {
			l4Protection.CheckConnection(ip1)
		}

		// ip2 должен иметь свой отдельный лимит
		allowed, _ := l4Protection.CheckConnection(ip2)
		if !allowed {
			t.Error("ip2 should be allowed (separate limit)")
		}

		// ip1 должен быть заблокирован
		allowed, _ = l4Protection.CheckConnection(ip1)
		if allowed {
			t.Error("ip1 should be blocked (limit reached)")
		}
	})
}

func TestTCPProxy_RateLimitWindow(t *testing.T) {
	t.Run("rate limit window expiration", func(t *testing.T) {
		l4Protection := firewall.NewL4Protection(100, 5, 1*time.Second)
		ip := "192.168.1.202"

		// создаем 5 соединений быстро
		for i := 0; i < 5; i++ {
			l4Protection.CheckConnection(ip)
			l4Protection.CheckRateLimit(ip)
		}

		// следующее должно быть заблокировано
		allowed, _ := l4Protection.CheckRateLimit(ip)
		if allowed {
			t.Error("should be rate limited")
		}

		// ждем истечения окна
		time.Sleep(1100 * time.Millisecond)

		// теперь должно быть разрешено
		allowed, _ = l4Protection.CheckRateLimit(ip)
		if !allowed {
			t.Error("should be allowed after window expiration")
		}
	})
}
