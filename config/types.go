package config

import (
	"sync"
	"time"
)

type Config struct {
	Domains    []Domain `json:"domains"`
	Proxies    []Proxy  `json:"proxies"`
	LastUpdate time.Time
	mu         sync.RWMutex
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
	Type    string `json:"type"`
	Enabled bool   `json:"enabled"`
}

type SSL struct {
	Enabled     bool   `json:"enabled"`
	Certificate string `json:"certificate"`
	PrivateKey  string `json:"privateKey"`
	AutoRenew   bool   `json:"autoRenew"`
}

type Proxy struct {
	Name       string `json:"name"`
	Protocol   string `json:"protocol"`
	ListenPort int    `json:"listenPort"`
	TargetHost string `json:"targetHost"`
	TargetPort int    `json:"targetPort"`
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
