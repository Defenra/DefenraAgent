# CNAME Flattening Implementation

## Overview

CNAME Flattening is a DNS feature similar to Cloudflare's implementation that automatically converts CNAME records to A records when the CNAME has HTTP proxy enabled and an A record is requested.

## How It Works

### Normal CNAME Behavior
```
Query: dig A www.example.com
Response: CNAME www.example.com -> example.com
          A example.com -> 1.2.3.4
```

### CNAME Flattening Behavior
When a CNAME record has `HTTPProxyEnabled=true` and an A record is requested:

```
Query: dig A www.example.com
Response: A www.example.com -> 94.159.110.227 (agent IP)
```

## Implementation Details

### DNS Server Logic
1. When processing an A record query, check for matching CNAME records first
2. If CNAME record found with `HTTPProxyEnabled=true`, apply flattening:
   - Use GeoDNS logic to select best agent IP if GeoDNS map available
   - Fall back to agent's own IP via `GetAgentIP()` if no GeoDNS map
   - Return A record with agent IP instead of CNAME record
3. If CNAME record found without `HTTPProxyEnabled`, return normal CNAME record
4. For CNAME queries (not A), always return CNAME record regardless of proxy setting

### Agent IP Selection Priority
1. **GeoDNS Map**: Use `findBestAgentIP()` with client location if GeoDNS map exists
2. **Agent's Own IP**: Use `configMgr.GetAgentIP()` as fallback
3. **Regular CNAME**: Fall back to normal CNAME processing if no agent IP available

### Configuration
CNAME flattening is automatically enabled when:
- DNS record type is "CNAME"
- `HTTPProxyEnabled` field is set to `true`
- Client requests an A record (not CNAME)

## Example Configuration

```json
{
  "DNSRecords": [
    {
      "Type": "CNAME",
      "Name": "www",
      "Value": "example.com",
      "TTL": 300,
      "HTTPProxyEnabled": true
    }
  ]
}
```

## Benefits

1. **Seamless Proxy Integration**: CNAME records work with HTTP proxy without additional configuration
2. **GeoDNS Compatibility**: Flattened records use same GeoDNS logic as regular A records
3. **Cloudflare-like Behavior**: Familiar behavior for users migrating from Cloudflare
4. **Automatic Failover**: Falls back gracefully if agent IP is not available

## Testing

The implementation includes comprehensive tests in `dns/server_test.go`:
- CNAME with HTTPProxyEnabled returns A record with agent IP
- CNAME without HTTPProxyEnabled returns normal CNAME record
- GeoDNS integration with CNAME flattening
- CNAME queries (not A) return CNAME records even with proxy enabled

## Logging

CNAME flattening operations are logged with `[DNS] CNAME Flattening:` prefix for debugging:
- Agent selection method (GeoDNS vs own IP)
- IP addresses used
- Fallback scenarios