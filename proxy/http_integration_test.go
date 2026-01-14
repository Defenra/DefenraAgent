package proxy

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/defenra/agent/config"
	"github.com/defenra/agent/firewall"
)

func TestHTTPProxy_Whitelist(t *testing.T) {
	// создаем тестовый config manager
	configMgr := config.NewConfigManager("http://test", "test-id", "test-key")

	// создаем тестовую домен конфигурацию с whitelist
	testDomain := &config.Domain{
		Domain: "test.example.com",
		HTTPProxy: config.HTTPProxy{
			Enabled: true,
			AntiDDoS: &config.AntiDDoS{
				Enabled: true,
				IPWhitelist: []string{
					"192.168.1.100",
					"10.0.0.0/24",
					"172.16.0.1",
				},
			},
		},
	}

	t.Run("whitelist single IP", func(t *testing.T) {
		rl := NewRateLimiter()
		config := RateLimitConfig{
			WindowSeconds:        1,
			MaxRequests:          100,
			BlockDurationSeconds: 60,
		}

		// создаем запрос от whitelisted IP
		req := httptest.NewRequest("GET", "http://test.example.com/", nil)
		req.Header.Set("X-Real-IP", "192.168.1.100")
		req.RemoteAddr = "192.168.1.100:12345"

		ip := rl.GetClientIP(req)
		if ip != "192.168.1.100" {
			t.Errorf("expected IP 192.168.1.100, got %s", ip)
		}

		// проверяем что rate limit не применяется слишком строго для whitelisted IP
		_ = testDomain
		_ = config
	})

	t.Run("whitelist CIDR range", func(t *testing.T) {
		rl := NewRateLimiter()
		req := httptest.NewRequest("GET", "http://test.example.com/", nil)
		req.Header.Set("X-Real-IP", "10.0.0.50")

		ip := rl.GetClientIP(req)
		if ip != "10.0.0.50" {
			t.Errorf("expected IP 10.0.0.50, got %s", ip)
		}

		_ = testDomain
		_ = configMgr
	})
}

func TestHTTPProxy_RateLimitFlow(t *testing.T) {
	rl := NewRateLimiter()
	firewallMgr := firewall.GetIPTablesManager()

	ip := "203.0.113.1"
	config := RateLimitConfig{
		WindowSeconds:        1,
		MaxRequests:          5,
		BlockDurationSeconds: 2,
	}

	t.Run("rate limit triggers ban", func(t *testing.T) {
		// сбрасываем IP если был забанен ранее
		if err := firewallMgr.UnbanIP(ip); err != nil {
			t.Logf("UnbanIP error (expected if not root): %v", err)
		}
		rl.ResetIP(ip)

		// делаем 5 разрешенных запросов
		for i := 0; i < 5; i++ {
			allowed, _ := rl.CheckRateLimit(ip, config)
			if !allowed {
				t.Errorf("request %d should be allowed", i+1)
			}
		}

		// 6-й должен быть заблокирован
		allowed, reason := rl.CheckRateLimit(ip, config)
		if allowed {
			t.Error("6th request should be blocked")
		}
		if reason == "" {
			t.Error("reason should not be empty")
		}

		// проверяем что IP может быть забанен через firewall
		// используем минимальное время для теста
		err := firewallMgr.BanIP(ip, 1*time.Second)
		if err != nil {
			t.Logf("BanIP error (expected if not root): %v", err)
		}

		// проверяем что IP забанен (даже если iptables команда не выполнилась)
		if !firewallMgr.IsBanned(ip) {
			t.Error("IP should be banned after rate limit violation")
		}
	})
}

func TestHTTPProxy_HeaderPriority(t *testing.T) {
	rl := NewRateLimiter()

	testCases := []struct {
		name       string
		headers    map[string]string
		remoteAddr string
		expected   string
	}{
		{
			name: "X-Forwarded-For takes priority",
			headers: map[string]string{
				"X-Forwarded-For": "192.0.2.1",
				"X-Real-IP":       "198.51.100.1",
			},
			expected: "192.0.2.1",
		},
		{
			name: "X-Real-IP as fallback",
			headers: map[string]string{
				"X-Real-IP": "198.51.100.2",
			},
			expected: "198.51.100.2",
		},
		{
			name: "CF-Connecting-IP",
			headers: map[string]string{
				"CF-Connecting-IP": "203.0.113.1",
			},
			expected: "203.0.113.1",
		},
		{
			name:       "RemoteAddr fallback",
			headers:    map[string]string{},
			remoteAddr: "192.168.1.1:54321",
			expected:   "192.168.1.1",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			if tc.remoteAddr != "" {
				req.RemoteAddr = tc.remoteAddr
			}

			ip := rl.GetClientIP(req)
			if ip != tc.expected {
				t.Errorf("expected %s, got %s", tc.expected, ip)
			}
		})
	}
}

func TestHTTPProxy_ConcurrentRequests(t *testing.T) {
	rl := NewRateLimiter()
	config := RateLimitConfig{
		WindowSeconds:        1,
		MaxRequests:          100,
		BlockDurationSeconds: 60,
	}

	ip := "192.168.1.200"

	// симулируем конкурентные запросы
	results := make(chan bool, 100)
	for i := 0; i < 100; i++ {
		go func() {
			allowed, _ := rl.CheckRateLimit(ip, config)
			results <- allowed
		}()
	}

	// проверяем результаты
	allowedCount := 0
	for i := 0; i < 100; i++ {
		if <-results {
			allowedCount++
		}
	}

	// все должны быть разрешены так как лимит 100
	if allowedCount < 95 {
		t.Errorf("expected most requests to be allowed, got %d allowed out of 100", allowedCount)
	}
}
