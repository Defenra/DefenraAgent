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
	Domain     string            `json:"domain"`
	DNSRecords []DNSRecord       `json:"dnsRecords"`
	GeoDNSMap  map[string]string `json:"geoDnsMap"`
	HTTPProxy  HTTPProxy         `json:"httpProxy"`
	SSL        SSL               `json:"ssl"`
	LuaCode    string            `json:"luaCode"`
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
	Type     string          `json:"type"`
	Enabled  bool            `json:"enabled"`
	AntiDDoS AntiDDoSConfig  `json:"antiDDoS"`
}

type AntiDDoSConfig struct {
	Enabled              bool             `json:"enabled"`
	RateLimit            RateLimitConfig  `json:"rateLimit"`
	BlockDurationSeconds int              `json:"blockDurationSeconds"`
	Slowloris            SlowlorisConfig  `json:"slowloris"`
	JSChallenge          JSChallengeConfig `json:"jsChallenge"`
	Logging              LoggingConfig    `json:"logging"`
	IPWhitelist          []string         `json:"ipWhitelist"`
	ProxyIPHeaders       []string         `json:"proxyIpHeaders"`
}

type RateLimitConfig struct {
	WindowSeconds int `json:"windowSeconds"`
	MaxRequests   int `json:"maxRequests"`
}

type SlowlorisConfig struct {
	MinContentLength        int `json:"minContentLength"`
	MaxHeaderTimeoutSeconds int `json:"maxHeaderTimeoutSeconds"`
	MaxConnections          int `json:"maxConnections"`
}

type JSChallengeConfig struct {
	Enabled    bool   `json:"enabled"`
	CookieName string `json:"cookieName"`
	TTLSeconds int    `json:"ttlSeconds"`
}

type LoggingConfig struct {
	Enabled bool `json:"enabled"`
}

type SSL struct {
	Enabled     bool   `json:"enabled"`
	Certificate string `json:"certificate"`
	PrivateKey  string `json:"privateKey"`
	AutoRenew   bool   `json:"autoRenew"`
}

type Proxy struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Protocol   string `json:"type"`            // Core sends "type", not "protocol"
	ListenPort int    `json:"sourcePort"`      // Core sends "sourcePort", not "listenPort"
	TargetHost string `json:"destinationHost"` // Core sends "destinationHost", not "targetHost"
	TargetPort int    `json:"destinationPort"` // Core sends "destinationPort", not "targetPort"
	Enabled    bool   `json:"enabled"`
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
