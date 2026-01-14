package waf

import (
	"net/http"
	"testing"
)

func TestLuaWAF_BasicBlocking(t *testing.T) {
	waf := NewLuaWAF()

	tests := []struct {
		name       string
		luaCode    string
		requestIP  string
		requestURI string
		wantBlock  bool
		wantStatus int
	}{
		{
			name: "Block specific IP",
			luaCode: `
				if ngx.var.remote_addr == "1.2.3.4" then
					return ngx.exit(403)
				end
			`,
			requestIP:  "1.2.3.4",
			requestURI: "/test",
			wantBlock:  true,
			wantStatus: 403,
		},
		{
			name: "Allow different IP",
			luaCode: `
				if ngx.var.remote_addr == "1.2.3.4" then
					return ngx.exit(403)
				end
			`,
			requestIP:  "5.6.7.8",
			requestURI: "/test",
			wantBlock:  false,
			wantStatus: 0,
		},
		{
			name: "Block SQL injection in URI",
			luaCode: `
				local uri = string.lower(ngx.var.uri)
				if string.find(uri, "union") and string.find(uri, "select") then
					return ngx.exit(403)
				end
			`,
			requestIP:  "1.1.1.1",
			requestURI: "/test?id=1%20UNION%20SELECT",
			wantBlock:  true,
			wantStatus: 403,
		},
		{
			name: "Block path traversal",
			luaCode: `
				if string.find(ngx.var.uri, "%.%.") then
					return ngx.exit(403)
				end
			`,
			requestIP:  "1.1.1.1",
			requestURI: "/../../etc/passwd",
			wantBlock:  true,
			wantStatus: 403,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", "http://example.com"+tt.requestURI, nil)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}
			req.RemoteAddr = tt.requestIP + ":12345"
			req.RequestURI = tt.requestURI // Set explicitly for WAF to use

			blocked, response := waf.Execute(tt.luaCode, req)

			if blocked != tt.wantBlock {
				t.Errorf("Execute() blocked = %v, want %v", blocked, tt.wantBlock)
			}

			if blocked && response.StatusCode != tt.wantStatus {
				t.Errorf("Execute() status = %v, want %v", response.StatusCode, tt.wantStatus)
			}
		})
	}
}

func TestLuaWAF_SecurityHeaders(t *testing.T) {
	waf := NewLuaWAF()

	luaCode := `
		ngx.header["X-Frame-Options"] = "DENY"
		ngx.header["X-Content-Type-Options"] = "nosniff"
		ngx.header["X-XSS-Protection"] = "1; mode=block"
	`

	req, err := http.NewRequest("GET", "http://example.com/test", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.RemoteAddr = "1.1.1.1:12345"
	req.RequestURI = "/test"

	blocked, response := waf.Execute(luaCode, req)

	if blocked {
		t.Errorf("Execute() blocked = %v, want false", blocked)
	}

	expectedHeaders := map[string]string{
		"X-Frame-Options":        "DENY",
		"X-Content-Type-Options": "nosniff",
		"X-XSS-Protection":       "1; mode=block",
	}

	for key, expectedValue := range expectedHeaders {
		if actualValue, ok := response.Headers[key]; !ok {
			t.Errorf("Header %s not found in response", key)
		} else if actualValue != expectedValue {
			t.Errorf("Header %s = %v, want %v", key, actualValue, expectedValue)
		}
	}
}

func TestLuaWAF_RateLimiting(t *testing.T) {
	waf := NewLuaWAF()

	luaCode := `
		local ip = ngx.var.remote_addr
		local limit_key = "rate_limit:" .. ip
		local count = ngx.shared.cache:get(limit_key) or 0

		if count > 5 then
			return ngx.exit(429)
		end

		ngx.shared.cache:incr(limit_key, 1, 0, 60)
	`

	req, err := http.NewRequest("GET", "http://example.com/test", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.RemoteAddr = "1.2.3.4:12345"
	req.RequestURI = "/test"

	// First 6 requests should pass
	for i := 0; i < 6; i++ {
		blocked, _ := waf.Execute(luaCode, req)
		if blocked {
			t.Errorf("Request %d was blocked, expected to pass", i+1)
		}
	}

	// 7th request should be blocked
	blocked, response := waf.Execute(luaCode, req)
	if !blocked {
		t.Errorf("Request 7 was not blocked, expected to be blocked")
	}
	if response.StatusCode != 429 {
		t.Errorf("Status code = %v, want 429", response.StatusCode)
	}
}

func TestLuaWAF_UserAgentBlocking(t *testing.T) {
	waf := NewLuaWAF()

	luaCode := `
		local user_agent = request.headers["User-Agent"] or ""
		local bad_agents = {"bot", "crawler", "scanner"}

		for _, agent in ipairs(bad_agents) do
			if string.find(string.lower(user_agent), agent) then
				return ngx.exit(403)
			end
		end
	`

	tests := []struct {
		name      string
		userAgent string
		wantBlock bool
	}{
		{"Block bot", "BadBot/1.0", true},
		{"Block crawler", "WebCrawler/2.0", true},
		{"Block scanner", "Security Scanner", true},
		{"Allow normal", "Mozilla/5.0", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", "http://example.com/test", nil)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}
			req.RemoteAddr = "1.1.1.1:12345"
			req.RequestURI = "/test"
			req.Header.Set("User-Agent", tt.userAgent)

			blocked, _ := waf.Execute(luaCode, req)

			if blocked != tt.wantBlock {
				t.Errorf("Execute() blocked = %v, want %v for User-Agent: %s",
					blocked, tt.wantBlock, tt.userAgent)
			}
		})
	}
}

func TestLuaWAF_NoPanic(t *testing.T) {
	waf := NewLuaWAF()

	// Test with invalid type assignments that should not panic
	luaCode := `
		_status_code = "not a number"
		_body = 12345
		_blocked = true
	`

	req, err := http.NewRequest("GET", "http://example.com/test", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.RemoteAddr = "1.1.1.1:12345"
	req.RequestURI = "/test"

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Execute() panicked: %v", r)
		}
	}()

	blocked, response := waf.Execute(luaCode, req)

	if !blocked {
		t.Errorf("Execute() blocked = %v, want true", blocked)
	}

	// Should use default values
	if response.StatusCode != 403 {
		t.Errorf("StatusCode = %v, want 403 (default)", response.StatusCode)
	}
	if response.Body != "Blocked by WAF" {
		t.Errorf("Body = %v, want 'Blocked by WAF' (default)", response.Body)
	}
}
