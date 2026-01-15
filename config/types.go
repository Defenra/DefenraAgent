package config

import (
	"time"
)

type Config struct {
	Domains    []Domain `json:"domains"`
	Proxies    []Proxy  `json:"proxies"`
	LastUpdate time.Time
}

type Domain struct {
	ID         string            `json:"id,omitempty"` // MongoDB ObjectId домена
	Domain     string            `json:"domain"`
	DNSRecords []DNSRecord       `json:"dnsRecords"`
	GeoDNSMap  map[string]string `json:"geoDnsMap"`
	HTTPProxy  HTTPProxy         `json:"httpProxy"`
	SSL        SSL               `json:"ssl"`
	LuaCode    string            `json:"luaCode"`
	PageRules  []PageRule        `json:"pageRules"`
}

type DNSRecord struct {
	Name             string `json:"name"`
	Type             string `json:"type"`
	Value            string `json:"value"`
	TTL              uint32 `json:"ttl"`
	HTTPProxyEnabled bool   `json:"httpProxyEnabled"`
	Priority         uint16 `json:"priority"`
}

type HTTPProxy struct {
	Type        string      `json:"type"`
	Enabled     bool        `json:"enabled"`
	RoutingMode string      `json:"routingMode"` // "direct" (default) or "anycast" (BETA)
	AgentPool   []AgentInfo `json:"agentPool"`   // for anycast mode
	MaxHops     int         `json:"maxHops"`     // default: 3
	AntiDDoS    *AntiDDoS   `json:"antiDDoS,omitempty"`
}

type AgentInfo struct {
	ID       string `json:"id"`       // agent identifier
	Endpoint string `json:"endpoint"` // https://agent-ip:port or http://agent-ip:port
	Region   string `json:"region"`   // optional: geographic region
	Priority int    `json:"priority"` // optional: routing priority (lower = higher priority)
}

type AntiDDoS struct {
	Enabled              bool       `json:"enabled"`
	RateLimit            *RateLimit `json:"rateLimit,omitempty"`
	BlockDurationSeconds int        `json:"blockDurationSeconds"`
	Slowloris            *Slowloris `json:"slowloris,omitempty"`
	IPWhitelist          []string   `json:"ipWhitelist,omitempty"`
	ProxyIPHeaders       []string   `json:"proxyIpHeaders,omitempty"`
}

type RateLimit struct {
	WindowSeconds int `json:"windowSeconds"`
	MaxRequests   int `json:"maxRequests"`
}

type Slowloris struct {
	MinContentLength        int `json:"minContentLength"`
	MaxHeaderTimeoutSeconds int `json:"maxHeaderTimeoutSeconds"`
	MaxConnections          int `json:"maxConnections"`
}

type SSL struct {
	Enabled        bool   `json:"enabled"`
	EncryptionMode string `json:"encryptionMode"` // off, flexible, full, full_strict
	Certificate    string `json:"certificate"`
	PrivateKey     string `json:"privateKey"`
	AutoRenew      bool   `json:"autoRenew"`
}

type Proxy struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Protocol      string `json:"type"`            // Core sends "type", not "protocol"
	ListenPort    int    `json:"sourcePort"`      // Core sends "sourcePort", not "listenPort"
	TargetHost    string `json:"destinationHost"` // Core sends "destinationHost", not "targetHost"
	TargetPort    int    `json:"destinationPort"` // Core sends "destinationPort", not "targetPort"
	Enabled       bool   `json:"enabled"`
	ProxyProtocol bool   `json:"proxyProtocol"` // включить PROXY protocol v2 для проброса source IP
}

type PollRequest struct {
	AgentID  string `json:"agentId"`
	AgentKey string `json:"agentKey"`
}

type PollResponse struct {
	Success bool     `json:"success"`
	Domains []Domain `json:"domains"`
	Proxies []Proxy  `json:"proxies"`
}

type PageRule struct {
	Enabled    bool            `json:"enabled"`
	Priority   int             `json:"priority"`
	URLPattern string          `json:"urlPattern"`
	Actions    PageRuleActions `json:"actions"`
}

type PageRuleActions struct {
	SecurityLevel       string            `json:"securityLevel,omitempty"`
	CacheLevel          string            `json:"cacheLevel,omitempty"`
	BrowserCacheTTL     *int              `json:"browserCacheTtl,omitempty"`
	EdgeCacheTTL        *int              `json:"edgeCacheTtl,omitempty"`
	AlwaysUseHTTPS      *bool             `json:"alwaysUseHttps,omitempty"`
	ForwardingURL       *ForwardingURL    `json:"forwardingUrl,omitempty"`
	DisableSecurity     *bool             `json:"disableSecurity,omitempty"`
	DisableRateLimiting *bool             `json:"disableRateLimiting,omitempty"`
	CustomHeaders       map[string]string `json:"customHeaders,omitempty"`
	IPGeolocationHeader *bool             `json:"ipGeolocationHeader,omitempty"`
	OriginCacheControl  *bool             `json:"originCacheControl,omitempty"`
	ResolveOverride     string            `json:"resolveOverride,omitempty"`
}

type ForwardingURL struct {
	StatusCode int    `json:"statusCode"`
	URL        string `json:"url"`
}
