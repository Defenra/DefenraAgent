package proxy

import (
	"net/http/httptest"
	"testing"

	"github.com/defenra/agent/config"
)

func TestMatchesPattern(t *testing.T) {
	tests := []struct {
		pattern string
		url     string
		want    bool
	}{
		{"example.com/*", "example.com/api/test", true},
		{"example.com/*", "example.com/", true},
		{"example.com/api/*", "example.com/api/users", true},
		{"example.com/api/*", "example.com/other", false},
		{"example.com/test?", "example.com/test1", true},
		{"example.com/test?", "example.com/test12", false},
		{"*.example.com", "api.example.com", true},
		{"*.example.com", "example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.pattern+"_"+tt.url, func(t *testing.T) {
			got := matchesPattern(tt.pattern, tt.url)
			if got != tt.want {
				t.Errorf("matchesPattern(%q, %q) = %v, want %v", tt.pattern, tt.url, got, tt.want)
			}
		})
	}
}

func TestMatchPageRules(t *testing.T) {
	rules := []config.PageRule{
		{
			Enabled:    true,
			Priority:   1,
			URLPattern: "example.com/api/*",
			Actions:    config.PageRuleActions{},
		},
		{
			Enabled:    true,
			Priority:   2,
			URLPattern: "example.com/*",
			Actions:    config.PageRuleActions{},
		},
		{
			Enabled:    false,
			Priority:   3,
			URLPattern: "example.com/disabled/*",
			Actions:    config.PageRuleActions{},
		},
	}

	tests := []struct {
		url       string
		wantCount int
		wantFirst int // priority of first matched rule
	}{
		{"example.com/api/users", 2, 1},
		{"example.com/other", 1, 2},
		{"example.com/disabled/test", 1, 2}, // disabled rule should not match
		{"other.com/test", 0, 0},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			matched := MatchPageRules(rules, tt.url)
			if len(matched) != tt.wantCount {
				t.Errorf("MatchPageRules(%q) matched %d rules, want %d", tt.url, len(matched), tt.wantCount)
			}
			if tt.wantCount > 0 && matched[0].Priority != tt.wantFirst {
				t.Errorf("First matched rule priority = %d, want %d", matched[0].Priority, tt.wantFirst)
			}
		})
	}
}

func TestApplyPageRules_Redirect(t *testing.T) {
	rules := []*config.PageRule{
		{
			Enabled:    true,
			Priority:   1,
			URLPattern: "example.com/old/*",
			Actions: config.PageRuleActions{
				ForwardingURL: &config.ForwardingURL{
					StatusCode: 301,
					URL:        "https://example.com/new",
				},
			},
		},
	}

	req := httptest.NewRequest("GET", "http://example.com/old/page", nil)
	w := httptest.NewRecorder()

	handled, _, _, _ := ApplyPageRules(w, req, rules, nil)

	if !handled {
		t.Error("Expected redirect to be handled")
	}

	if w.Code != 301 {
		t.Errorf("Expected status 301, got %d", w.Code)
	}

	location := w.Header().Get("Location")
	if location != "https://example.com/new" {
		t.Errorf("Expected Location header 'https://example.com/new', got %q", location)
	}
}

func TestApplyPageRules_AlwaysHTTPS(t *testing.T) {
	trueVal := true
	rules := []*config.PageRule{
		{
			Enabled:    true,
			Priority:   1,
			URLPattern: "example.com/*",
			Actions: config.PageRuleActions{
				AlwaysUseHTTPS: &trueVal,
			},
		},
	}

	req := httptest.NewRequest("GET", "/page", nil)
	req.Host = "example.com"
	w := httptest.NewRecorder()

	handled, _, _, _ := ApplyPageRules(w, req, rules, nil)

	if !handled {
		t.Error("Expected HTTPS redirect to be handled")
	}

	if w.Code != 301 {
		t.Errorf("Expected status 301, got %d", w.Code)
	}

	location := w.Header().Get("Location")
	if location != "https://example.com/page" {
		t.Errorf("Expected Location header 'https://example.com/page', got %q", location)
	}
}

func TestApplyPageRules_DisableSecurity(t *testing.T) {
	trueVal := true
	rules := []*config.PageRule{
		{
			Enabled:    true,
			Priority:   1,
			URLPattern: "example.com/public/*",
			Actions: config.PageRuleActions{
				DisableSecurity: &trueVal,
			},
		},
	}

	req := httptest.NewRequest("GET", "http://example.com/public/api", nil)
	w := httptest.NewRecorder()

	handled, skipSecurity, skipRateLimit, _ := ApplyPageRules(w, req, rules, nil)

	if handled {
		t.Error("Expected request not to be handled (no redirect)")
	}

	if !skipSecurity {
		t.Error("Expected security to be skipped")
	}

	if skipRateLimit {
		t.Error("Expected rate limiting not to be skipped")
	}
}

func TestApplyPageRules_CustomBackend(t *testing.T) {
	rules := []*config.PageRule{
		{
			Enabled:    true,
			Priority:   1,
			URLPattern: "example.com/special/*",
			Actions: config.PageRuleActions{
				ResolveOverride: "192.168.1.100:8080",
			},
		},
	}

	req := httptest.NewRequest("GET", "http://example.com/special/api", nil)
	w := httptest.NewRecorder()

	handled, _, _, customBackend := ApplyPageRules(w, req, rules, nil)

	if handled {
		t.Error("Expected request not to be handled (no redirect)")
	}

	if customBackend != "192.168.1.100:8080" {
		t.Errorf("Expected custom backend '192.168.1.100:8080', got %q", customBackend)
	}
}

func TestApplyPageRules_SecurityHeaders(t *testing.T) {
	rules := []*config.PageRule{
		{
			Enabled:    true,
			Priority:   1,
			URLPattern: "example.com/*",
			Actions: config.PageRuleActions{
				SecurityLevel: "high",
			},
		},
	}

	req := httptest.NewRequest("GET", "http://example.com/page", nil)
	w := httptest.NewRecorder()

	ApplyPageRules(w, req, rules, nil)

	if w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("Expected X-Content-Type-Options header")
	}

	if w.Header().Get("X-Frame-Options") != "DENY" {
		t.Error("Expected X-Frame-Options header")
	}

	if w.Header().Get("Strict-Transport-Security") == "" {
		t.Error("Expected Strict-Transport-Security header")
	}
}
