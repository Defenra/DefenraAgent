package waf

import (
	"net/http"
	"testing"
)

func TestRedirectCode(t *testing.T) {
	// First test - check what ngx.var.request_uri returns
	debugCode := `
local uri = ngx.var.request_uri
local plain_uri = ngx.var.uri
if uri == nil then
    ngx.say("request_uri is NIL")
elseif uri == "" then
    ngx.say("request_uri is EMPTY, but uri=" .. plain_uri)
else
    ngx.say("request_uri = '" .. uri .. "', uri = '" .. plain_uri .. "'")
end
return ngx.exit(200)
`
	req1, _ := http.NewRequest("GET", "/", nil)
	req1.RemoteAddr = "1.1.1.1:12345"
	req1.Host = "example.com"
	req1.RequestURI = "/" // Must set manually in tests
	t.Logf("DEBUG: req1.RequestURI = '%s'", req1.RequestURI)
	
	waf := NewLuaWAF()
	blocked1, resp1 := waf.Execute(debugCode, req1)
	t.Logf("DEBUG: Blocked=%v, Body=%s", blocked1, resp1.Body)
	
	// Now the actual test
	luaCode := `
ngx.header["Server"] = "Defenra"
if ngx.var.request_uri == "/" then
    ngx.header["Location"] = "https://github.com/Defenra"
    return ngx.exit(200)
end
`

	req, _ := http.NewRequest("GET", "/", nil)
	req.RemoteAddr = "1.1.1.1:12345"
	req.Host = "example.com"
	req.RequestURI = "/" // Must set manually in tests

	blocked, resp := waf.Execute(luaCode, req)

	t.Logf("Blocked: %v", blocked)
	t.Logf("StatusCode: %d", resp.StatusCode)
	t.Logf("Body: %s", resp.Body)
	t.Logf("Headers: %+v", resp.Headers)
	
	// Check if it blocked (exit was called)
	if !blocked {
		t.Error("Expected blocked=true when ngx.exit(200) is called")
	}
	
	// Check status code
	if resp.StatusCode != 200 {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}
	
	// Check Server header
	if resp.Headers["Server"] != "Defenra" {
		t.Errorf("Expected Server header 'Defenra', got '%s'", resp.Headers["Server"])
	}
	
	// Check Location header
	if resp.Headers["Location"] != "https://github.com/Defenra" {
		t.Errorf("Expected Location header 'https://github.com/Defenra', got '%s'", resp.Headers["Location"])
	}
	
	t.Log("✅ Технически код работает!")
	t.Log("⚠️ НО это НЕ редирект! Для редиректа нужен код 301 или 302")
}
