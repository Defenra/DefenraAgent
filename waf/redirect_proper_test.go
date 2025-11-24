package waf

import (
	"net/http"
	"testing"
)

func TestRedirectExamples(t *testing.T) {
	tests := []struct {
		name           string
		luaCode        string
		requestURI     string
		wantBlocked    bool
		wantStatus     int
		wantBody       string
		wantHeader     map[string]string
		description    string
	}{
		{
			name: "Неправильно - статус 200 с Location (НЕ редирект)",
			luaCode: `
ngx.header["Server"] = "Defenra"
if ngx.var.request_uri == "/" then
    ngx.header["Location"] = "https://github.com/Defenra"
    return ngx.exit(200)
end
`,
			requestURI:  "/",
			wantBlocked: true,
			wantStatus:  200,
			wantBody:    "Blocked by WAF",
			wantHeader: map[string]string{
				"Server":   "Defenra",
				"Location": "https://github.com/Defenra",
			},
			description: "Браузер НЕ сделает редирект, потому что статус 200",
		},
		{
			name: "Правильно - временный редирект 302",
			luaCode: `
ngx.header["Server"] = "Defenra"
if ngx.var.request_uri == "/" then
    ngx.header["Location"] = "https://github.com/Defenra"
    return ngx.exit(302)
end
`,
			requestURI:  "/",
			wantBlocked: true,
			wantStatus:  302,
			wantBody:    "Blocked by WAF",
			wantHeader: map[string]string{
				"Server":   "Defenra",
				"Location": "https://github.com/Defenra",
			},
			description: "✅ Браузер сделает ВРЕМЕННЫЙ редирект",
		},
		{
			name: "Правильно - постоянный редирект 301",
			luaCode: `
ngx.header["Server"] = "Defenra"
if ngx.var.request_uri == "/" then
    ngx.header["Location"] = "https://github.com/Defenra"
    return ngx.exit(301)
end
`,
			requestURI:  "/",
			wantBlocked: true,
			wantStatus:  301,
			wantBody:    "Blocked by WAF",
			wantHeader: map[string]string{
				"Server":   "Defenra",
				"Location": "https://github.com/Defenra",
			},
			description: "✅ Браузер сделает ПОСТОЯННЫЙ редирект (кэшируется)",
		},
		{
			name: "Правильно - кастомный body для редиректа",
			luaCode: `
ngx.header["Server"] = "Defenra"
if ngx.var.request_uri == "/" then
    ngx.header["Location"] = "https://github.com/Defenra"
    ngx.say("Redirecting to GitHub...")
    return ngx.exit(302)
end
`,
			requestURI:  "/",
			wantBlocked: true,
			wantStatus:  302,
			wantBody:    "Redirecting to GitHub...",
			wantHeader: map[string]string{
				"Server":   "Defenra",
				"Location": "https://github.com/Defenra",
			},
			description: "✅ Редирект с кастомным сообщением",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", tt.requestURI, nil)
			req.RemoteAddr = "1.1.1.1:12345"
			req.Host = "example.com"
			req.RequestURI = tt.requestURI // Must set manually in tests

			waf := NewLuaWAF()
			blocked, resp := waf.Execute(tt.luaCode, req)

			// Check blocked status
			if blocked != tt.wantBlocked {
				t.Errorf("blocked = %v, want %v", blocked, tt.wantBlocked)
			}

			// Check status code
			if resp.StatusCode != tt.wantStatus {
				t.Errorf("StatusCode = %d, want %d", resp.StatusCode, tt.wantStatus)
			}

			// Check body
			if resp.Body != tt.wantBody {
				t.Errorf("Body = %q, want %q", resp.Body, tt.wantBody)
			}

			// Check headers
			for key, wantValue := range tt.wantHeader {
				if gotValue := resp.Headers[key]; gotValue != wantValue {
					t.Errorf("Header[%s] = %q, want %q", key, gotValue, wantValue)
				}
			}

			t.Logf("✅ %s", tt.description)
		})
	}
}
