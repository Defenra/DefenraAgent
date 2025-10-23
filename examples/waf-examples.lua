-- Defenra Agent Lua WAF Examples
-- These examples show how to use Lua scripts for Web Application Firewall

--------------------------------------------------------------------------------
-- Example 1: Block Specific IP Address
--------------------------------------------------------------------------------
if ngx.var.remote_addr == "1.2.3.4" then
  return ngx.exit(403)
end

--------------------------------------------------------------------------------
-- Example 2: Block IP Range (using pattern matching)
--------------------------------------------------------------------------------
if string.match(ngx.var.remote_addr, "^192%.168%.") then
  return ngx.exit(403)
end

--------------------------------------------------------------------------------
-- Example 3: Simple Rate Limiting (100 requests per minute per IP)
--------------------------------------------------------------------------------
local ip = ngx.var.remote_addr
local limit_key = "rate_limit:" .. ip
local count = ngx.shared.cache:get(limit_key) or 0

if count > 100 then
  return ngx.exit(429)
end

ngx.shared.cache:incr(limit_key, 1, 0, 60)  -- TTL: 60 seconds

--------------------------------------------------------------------------------
-- Example 4: Block Bad User Agents
--------------------------------------------------------------------------------
local user_agent = request.headers["User-Agent"] or ""
local bad_agents = {"bot", "crawler", "scanner", "exploit"}

for _, agent in ipairs(bad_agents) do
  if string.find(string.lower(user_agent), agent) then
    return ngx.exit(403)
  end
end

--------------------------------------------------------------------------------
-- Example 5: Block SQL Injection Attempts
--------------------------------------------------------------------------------
local uri = ngx.var.uri
local sql_patterns = {
  "union.*select",
  "select.*from",
  "insert.*into",
  "delete.*from",
  "drop.*table",
  "'; *--",
}

for _, pattern in ipairs(sql_patterns) do
  if string.find(string.lower(uri), pattern) then
    return ngx.exit(403)
  end
end

--------------------------------------------------------------------------------
-- Example 6: Block XSS Attempts
--------------------------------------------------------------------------------
local xss_patterns = {
  "<script",
  "javascript:",
  "onerror=",
  "onload=",
  "alert%(.*%)",
}

for _, pattern in ipairs(xss_patterns) do
  if string.find(string.lower(uri), pattern) then
    return ngx.exit(403)
  end
end

--------------------------------------------------------------------------------
-- Example 7: Require Specific Header
--------------------------------------------------------------------------------
local api_key = request.headers["X-API-Key"]
if not api_key or api_key ~= "secret123" then
  return ngx.exit(401)
end

--------------------------------------------------------------------------------
-- Example 8: Block Requests to Admin Panel (except from specific IP)
--------------------------------------------------------------------------------
if string.match(ngx.var.uri, "^/admin") then
  if ngx.var.remote_addr ~= "10.0.0.1" then
    return ngx.exit(403)
  end
end

--------------------------------------------------------------------------------
-- Example 9: Geographic Restriction (using GeoIP)
-- Note: In this example, we assume country code is set in a custom header
--------------------------------------------------------------------------------
local country = request.headers["X-Country"]
local blocked_countries = {"CN", "RU", "KP"}

for _, c in ipairs(blocked_countries) do
  if country == c then
    return ngx.exit(403)
  end
end

--------------------------------------------------------------------------------
-- Example 10: Time-Based Access Control
--------------------------------------------------------------------------------
local hour = tonumber(os.date("%H"))
if hour >= 2 and hour <= 6 then
  -- Block access during maintenance window (2 AM - 6 AM)
  return ngx.exit(503)
end

--------------------------------------------------------------------------------
-- Example 11: Path Traversal Protection
--------------------------------------------------------------------------------
if string.find(ngx.var.uri, "%.%.") then
  return ngx.exit(403)
end

--------------------------------------------------------------------------------
-- Example 12: File Extension Blacklist
--------------------------------------------------------------------------------
local blocked_extensions = {".php", ".asp", ".jsp", ".cgi"}

for _, ext in ipairs(blocked_extensions) do
  if string.match(ngx.var.uri, ext .. "$") then
    return ngx.exit(403)
  end
end

--------------------------------------------------------------------------------
-- Example 13: Add Security Headers
--------------------------------------------------------------------------------
ngx.header["X-Frame-Options"] = "DENY"
ngx.header["X-Content-Type-Options"] = "nosniff"
ngx.header["X-XSS-Protection"] = "1; mode=block"
ngx.header["Referrer-Policy"] = "strict-origin-when-cross-origin"

--------------------------------------------------------------------------------
-- Example 14: Request Size Limit
--------------------------------------------------------------------------------
local content_length = tonumber(request.headers["Content-Length"] or 0)
local max_size = 10 * 1024 * 1024  -- 10 MB

if content_length > max_size then
  return ngx.exit(413)
end

--------------------------------------------------------------------------------
-- Example 15: Advanced Rate Limiting with Burst
--------------------------------------------------------------------------------
local ip = ngx.var.remote_addr
local rate_key = "rate:" .. ip
local burst_key = "burst:" .. ip

local rate_count = ngx.shared.cache:get(rate_key) or 0
local burst_count = ngx.shared.cache:get(burst_key) or 0

-- Allow 100 requests per minute with burst of 20
if rate_count > 100 or burst_count > 20 then
  return ngx.exit(429)
end

ngx.shared.cache:incr(rate_key, 1, 0, 60)     -- Rate limit window: 60s
ngx.shared.cache:incr(burst_key, 1, 0, 1)     -- Burst window: 1s

--------------------------------------------------------------------------------
-- Example 16: Whitelist Mode (only allow specific IPs)
--------------------------------------------------------------------------------
local whitelist = {"10.0.0.1", "192.168.1.1", "172.16.0.1"}
local is_whitelisted = false

for _, ip in ipairs(whitelist) do
  if ngx.var.remote_addr == ip then
    is_whitelisted = true
    break
  end
end

if not is_whitelisted then
  return ngx.exit(403)
end

--------------------------------------------------------------------------------
-- Example 17: Custom Error Response
--------------------------------------------------------------------------------
if ngx.var.uri == "/blocked" then
  ngx.header["Content-Type"] = "application/json"
  return ngx.exit(403)
end

--------------------------------------------------------------------------------
-- Example 18: Log Suspicious Activity
-- Note: In a real implementation, you would send this to a logging service
--------------------------------------------------------------------------------
local uri = ngx.var.uri
if string.find(uri, "hack") or string.find(uri, "exploit") then
  -- Log and block
  return ngx.exit(403)
end

--------------------------------------------------------------------------------
-- Example 19: Challenge-Response (Simple CAPTCHA simulation)
--------------------------------------------------------------------------------
local challenge_cookie = request.headers["Cookie"]
if not challenge_cookie or not string.find(challenge_cookie, "challenge=passed") then
  -- In real implementation, serve CAPTCHA page
  return ngx.exit(403)
end

--------------------------------------------------------------------------------
-- Example 20: Combined Protection (Production Ready)
--------------------------------------------------------------------------------

-- 1. Block bad IPs
local blocked_ips = {"1.2.3.4", "5.6.7.8"}
for _, ip in ipairs(blocked_ips) do
  if ngx.var.remote_addr == ip then
    return ngx.exit(403)
  end
end

-- 2. Rate limiting
local ip = ngx.var.remote_addr
local rate_key = "rate:" .. ip
local count = ngx.shared.cache:get(rate_key) or 0
if count > 100 then
  return ngx.exit(429)
end
ngx.shared.cache:incr(rate_key, 1, 0, 60)

-- 3. Security headers
ngx.header["X-Frame-Options"] = "DENY"
ngx.header["X-Content-Type-Options"] = "nosniff"
ngx.header["Strict-Transport-Security"] = "max-age=31536000"

-- 4. SQL Injection & XSS protection
local uri = string.lower(ngx.var.uri)
local dangerous = {"union", "select", "insert", "delete", "<script", "javascript:"}
for _, pattern in ipairs(dangerous) do
  if string.find(uri, pattern) then
    return ngx.exit(403)
  end
end

-- 5. Path traversal protection
if string.find(ngx.var.uri, "%.%.") then
  return ngx.exit(403)
end

-- Request passed all checks, allow it to proceed
