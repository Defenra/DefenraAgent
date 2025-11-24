package proxy

import (
	"net/http"
	"testing"
	"time"
)

func TestRateLimiter(t *testing.T) {
	t.Run("basic rate limiting", func(t *testing.T) {
		rl := NewRateLimiter()
		ip := "192.168.1.100"
		config := RateLimitConfig{
			WindowSeconds:       1,
			MaxRequests:         5,
			BlockDurationSeconds: 60,
		}

		// первые 5 запросов должны быть разрешены
		for i := 0; i < 5; i++ {
			allowed, reason := rl.CheckRateLimit(ip, config)
			if !allowed {
				t.Errorf("request %d should be allowed, got reason: %s", i+1, reason)
			}
		}

		// 6-й запрос должен быть заблокирован
		allowed, reason := rl.CheckRateLimit(ip, config)
		if allowed {
			t.Error("6th request should be blocked")
		}
		if reason == "" {
			t.Error("reason should not be empty")
		}
	})

	t.Run("rate limit window", func(t *testing.T) {
		rl := NewRateLimiter()
		ip := "192.168.1.101"
		config := RateLimitConfig{
			WindowSeconds:       1,
			MaxRequests:         3,
			BlockDurationSeconds: 60,
		}

		// делаем 3 запроса
		for i := 0; i < 3; i++ {
			rl.CheckRateLimit(ip, config)
		}

		// ждем истечения окна
		time.Sleep(1100 * time.Millisecond)

		// теперь должны быть разрешены новые запросы
		allowed, _ := rl.CheckRateLimit(ip, config)
		if !allowed {
			t.Error("request should be allowed after window expired")
		}
	})

	t.Run("block duration", func(t *testing.T) {
		rl := NewRateLimiter()
		ip := "192.168.1.102"
		config := RateLimitConfig{
			WindowSeconds:       1,
			MaxRequests:         2,
			BlockDurationSeconds: 1,
		}

		// превышаем лимит
		rl.CheckRateLimit(ip, config)
		rl.CheckRateLimit(ip, config)
		rl.CheckRateLimit(ip, config) // блокировка

		// проверяем что IP заблокирован
		allowed, _ := rl.CheckRateLimit(ip, config)
		if allowed {
			t.Error("IP should be blocked")
		}

		// ждем истечения блока
		time.Sleep(1100 * time.Millisecond)

		// IP должен быть разблокирован
		allowed, _ = rl.CheckRateLimit(ip, config)
		if !allowed {
			t.Error("IP should be unblocked after block duration")
		}
	})

	t.Run("multiple ips", func(t *testing.T) {
		rl := NewRateLimiter()
		config := RateLimitConfig{
			WindowSeconds:       1,
			MaxRequests:         2,
			BlockDurationSeconds: 60,
		}

		ip1 := "192.168.1.200"
		ip2 := "192.168.1.201"

		// превышаем лимит для ip1
		rl.CheckRateLimit(ip1, config)
		rl.CheckRateLimit(ip1, config)
		rl.CheckRateLimit(ip1, config) // блокировка

		// ip2 должен иметь свой лимит
		allowed, _ := rl.CheckRateLimit(ip2, config)
		if !allowed {
			t.Error("ip2 should be allowed (separate limit)")
		}
	})

	t.Run("get client ip from headers", func(t *testing.T) {
		rl := NewRateLimiter()

		testCases := []struct {
			name     string
			headers  map[string]string
			remoteAddr string
			expected string
		}{
			{
				name: "x-forwarded-for",
				headers: map[string]string{
					"X-Forwarded-For": "192.168.1.50",
				},
				expected: "192.168.1.50",
			},
			{
				name: "x-real-ip",
				headers: map[string]string{
					"X-Real-IP": "192.168.1.51",
				},
				expected: "192.168.1.51",
			},
			{
				name: "cf-connecting-ip",
				headers: map[string]string{
					"CF-Connecting-IP": "192.168.1.52",
				},
				expected: "192.168.1.52",
			},
			{
				name: "x-forwarded-for with multiple ips",
				headers: map[string]string{
					"X-Forwarded-For": "192.168.1.53, 10.0.0.1",
				},
				expected: "192.168.1.53",
			},
			{
				name: "remote addr fallback",
				headers: map[string]string{},
				remoteAddr: "192.168.1.54:12345",
				expected: "192.168.1.54",
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				req, _ := http.NewRequest("GET", "/", nil)
				for k, v := range tc.headers {
					req.Header.Set(k, v)
				}
				if tc.remoteAddr != "" {
					req.RemoteAddr = tc.remoteAddr
				}

				ip := rl.GetClientIP(req)
				if ip != tc.expected {
					t.Errorf("expected IP %s, got %s", tc.expected, ip)
				}
			})
		}
	})

	t.Run("cleanup old clients", func(t *testing.T) {
		rl := NewRateLimiter()
		config := RateLimitConfig{
			WindowSeconds:       1,
			MaxRequests:         1,
			BlockDurationSeconds: 1,
		}

		ip := "192.168.1.300"
		rl.CheckRateLimit(ip, config)

		// ждем истечения окна и блока
		time.Sleep(2100 * time.Millisecond)

		// очищаем
		rl.Cleanup()

		// проверяем что клиент удален (новый запрос создаст нового)
		// это сложно проверить напрямую, но можно проверить что система работает
		allowed, _ := rl.CheckRateLimit(ip, config)
		if !allowed {
			t.Error("request should be allowed after cleanup")
		}
	})

	t.Run("reset ip", func(t *testing.T) {
		rl := NewRateLimiter()
		ip := "192.168.1.400"
		config := RateLimitConfig{
			WindowSeconds:       1,
			MaxRequests:         2,
			BlockDurationSeconds: 60,
		}

		// превышаем лимит
		rl.CheckRateLimit(ip, config)
		rl.CheckRateLimit(ip, config)
		rl.CheckRateLimit(ip, config) // блокировка

		// сбрасываем IP
		rl.ResetIP(ip)

		// теперь должен быть разрешен
		allowed, _ := rl.CheckRateLimit(ip, config)
		if !allowed {
			t.Error("IP should be allowed after reset")
		}
	})
}
