# Defenra Agent Examples

This directory contains example configurations and scripts for Defenra Agent.

## WAF Examples

The `waf-examples.lua` file contains 20 different Lua WAF examples:

1. **Block Specific IP** - Block individual IP addresses
2. **Block IP Range** - Block entire IP ranges
3. **Rate Limiting** - Limit requests per IP
4. **Block Bad User Agents** - Block bots and scanners
5. **SQL Injection Protection** - Block SQL injection attempts
6. **XSS Protection** - Block cross-site scripting attempts
7. **API Key Authentication** - Require API keys
8. **Admin Panel Protection** - Restrict admin access
9. **Geographic Restrictions** - Block by country
10. **Time-Based Access** - Maintenance windows
11. **Path Traversal Protection** - Prevent directory attacks
12. **File Extension Blacklist** - Block dangerous files
13. **Security Headers** - Add security headers
14. **Request Size Limits** - Prevent large uploads
15. **Advanced Rate Limiting** - Rate limiting with burst
16. **Whitelist Mode** - Allow only specific IPs
17. **Custom Error Responses** - Custom error pages
18. **Suspicious Activity Logging** - Log attacks
19. **Challenge-Response** - CAPTCHA simulation
20. **Combined Protection** - Production-ready example

## Usage

To use a WAF example in Defenra Core:

1. Copy the desired Lua code from `waf-examples.lua`
2. Go to Defenra Core dashboard
3. Navigate to your domain settings
4. Paste the Lua code in the WAF section
5. Save and wait for agent to poll the config

## Testing WAF Rules

### Test Rate Limiting

```bash
# Send 150 requests
for i in {1..150}; do
  curl http://example.com
done
# After 100 requests, you should see: 429 Too Many Requests
```

### Test SQL Injection Block

```bash
curl "http://example.com/?id=1' OR '1'='1"
# Should return: 403 Forbidden
```

### Test XSS Block

```bash
curl "http://example.com/?name=<script>alert(1)</script>"
# Should return: 403 Forbidden
```

### Test IP Block

```bash
# In Core, add your IP to blocked list
curl http://example.com
# Should return: 403 Forbidden
```

### Test Security Headers

```bash
curl -I http://example.com
# Should see headers:
# X-Frame-Options: DENY
# X-Content-Type-Options: nosniff
```

## Custom WAF Rules

You can create your own custom rules. The Lua environment provides:

### Available Variables

- `ngx.var.remote_addr` - Client IP address
- `ngx.var.uri` - Request URI
- `ngx.var.host` - Host header
- `request.method` - HTTP method (GET, POST, etc.)
- `request.uri` - Request URI
- `request.host` - Host name
- `request.headers` - Request headers table

### Available Functions

- `ngx.exit(status_code)` - Block request with status code
- `ngx.shared.cache:get(key)` - Get value from shared cache
- `ngx.shared.cache:set(key, value, ttl)` - Set value in cache
- `ngx.shared.cache:incr(key, value, init, ttl)` - Increment counter
- `ngx.header[name] = value` - Set response header

### Example: Custom Rate Limiter

```lua
local ip = ngx.var.remote_addr
local key = "custom_limit:" .. ip
local count = ngx.shared.cache:get(key) or 0

-- Allow 50 requests per 5 minutes
if count > 50 then
  return ngx.exit(429)
end

ngx.shared.cache:incr(key, 1, 0, 300)  -- TTL: 300 seconds (5 min)
```

### Example: Block by Referer

```lua
local referer = request.headers["Referer"] or ""

if string.find(referer, "badsite.com") then
  return ngx.exit(403)
end
```

### Example: Allow Only Specific Methods

```lua
local allowed_methods = {GET = true, POST = true, HEAD = true}

if not allowed_methods[request.method] then
  return ngx.exit(405)
end
```

## Performance Tips

1. **Use shared cache** - Store data in `ngx.shared.cache` instead of local variables
2. **Early exit** - Put most common blocks first
3. **Minimize regex** - Use string.find() instead of complex patterns
4. **Cache results** - Cache expensive lookups
5. **Keep it simple** - Complex Lua scripts can slow down requests

## Security Considerations

1. **Test before production** - Always test rules in staging
2. **Monitor logs** - Check if legitimate users are blocked
3. **Set reasonable limits** - Don't block too aggressively
4. **Keep rules updated** - Update attack patterns regularly
5. **Use whitelists** - Whitelist known good IPs

## Debugging

To debug WAF rules, check agent logs:

```bash
# If using systemd
sudo journalctl -u defenra-agent -f | grep WAF

# If using Docker
docker logs -f defenra-agent | grep WAF
```

You'll see logs like:
```
[WAF] Request blocked by WAF: http://example.com/admin
[WAF] Lua execution error: attempt to call nil value
```

## Support

For questions about WAF rules:
- GitHub: https://github.com/defenra/agent/issues
- Documentation: https://docs.defenra.com/waf
- Email: support@defenra.com
