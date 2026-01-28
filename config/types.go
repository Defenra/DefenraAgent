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
	ID                  string                       `json:"id,omitempty"` // MongoDB ObjectId домена
	Domain              string                       `json:"domain"`
	DNSRecords          []DNSRecord                  `json:"dnsRecords"`
	GeoDNSMap           map[string]string            `json:"geoDnsMap"`           // Backward compatibility: location -> best agent IP
	GeoDnsFallbackMap   map[string]string            `json:"geoDnsFallbackMap"`   // Country fallbacks: cz -> de agent IP (nearest)
	GeoDNSAgentPools    map[string][]GeoDNSAgentInfo `json:"geoDnsAgentPools"`    // New: location -> array of agents with weights
	HTTPProxy           HTTPProxy                    `json:"httpProxy"`
	SSL                 SSL                          `json:"ssl"`
	LuaCode             string                       `json:"luaCode"`
	PageRules           []PageRule                   `json:"pageRules"`
}

type GeoDNSAgentInfo struct {
	IP        string  `json:"ip"`
	Weight    int     `json:"weight"`    // Weight for load balancing (higher = more traffic)
	LoadScore float64 `json:"loadScore"` // Current load score (0-100%)
	AgentID   string  `json:"agentId"`
	AgentName string  `json:"agentName"`
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
	Enabled              bool                 `json:"enabled"`
	RateLimit            *RateLimit           `json:"rateLimit,omitempty"`
	BlockDurationSeconds int                  `json:"blockDurationSeconds"`
	Slowloris            *Slowloris           `json:"slowloris,omitempty"`
	IPWhitelist          []string             `json:"ipWhitelist,omitempty"`
	ProxyIPHeaders       []string             `json:"proxyIpHeaders,omitempty"`
	L7Protection         *L7Protection        `json:"l7Protection,omitempty"`
	ChallengeSettings    *ChallengeSettings   `json:"challengeSettings,omitempty"`
	CustomRules          []CustomFirewallRule `json:"customRules,omitempty"`
}

type L7Protection struct {
	Enabled                  bool     `json:"enabled"`
	TLSFingerprintEnabled    bool     `json:"tlsFingerprintEnabled"`
	BotDetectionEnabled      bool     `json:"botDetectionEnabled"`
	BrowserValidationEnabled bool     `json:"browserValidationEnabled"`
	FingerprintRateLimit     int      `json:"fingerprintRateLimit"`   // requests per window for unknown fingerprints
	IPRateLimit              int      `json:"ipRateLimit"`            // requests per window per IP
	FailChallengeRateLimit   int      `json:"failChallengeRateLimit"` // failed challenge attempts per IP
	SuspiciousThreshold      int      `json:"suspiciousThreshold"`    // base suspicion level (0-4)
	BlockedFingerprints      []string `json:"blockedFingerprints"`    // fingerprints to block immediately
	AllowedFingerprints      []string `json:"allowedFingerprints"`    // fingerprints to always allow
}

type ChallengeSettings struct {
	CookieChallenge  *CookieChallenge  `json:"cookieChallenge,omitempty"`
	JSChallenge      *JSChallenge      `json:"jsChallenge,omitempty"`
	CaptchaChallenge *CaptchaChallenge `json:"captchaChallenge,omitempty"`
	// Offloading: автоматическая блокировка повторных нарушителей на kernel level
	AutoOffloading *AutoOffloading `json:"autoOffloading,omitempty"`
}

type AutoOffloading struct {
	Enabled           bool `json:"enabled"`           // Включить автоматический offloading в iptables
	FailureThreshold  int  `json:"failureThreshold"`  // Количество неудачных попыток (default: 5)
	TimeWindowSeconds int  `json:"timeWindowSeconds"` // Временное окно в секундах (default: 10)
	BanDurationMinutes int `json:"banDurationMinutes"` // Длительность бана в минутах (default: 60)
}

type CookieChallenge struct {
	Enabled bool `json:"enabled"`
	TTL     int  `json:"ttl"` // seconds
}

type JSChallenge struct {
	Enabled    bool `json:"enabled"`
	Difficulty int  `json:"difficulty"` // PoW difficulty (number of leading zeros)
	TTL        int  `json:"ttl"`        // seconds
}

type CaptchaChallenge struct {
	Enabled bool `json:"enabled"`
	TTL     int  `json:"ttl"` // seconds
}

type CustomFirewallRule struct {
	Name       string `json:"name"`
	Expression string `json:"expression"` // filter expression (e.g., "ip.country == 'CN' && http.user_agent contains 'bot'")
	Action     string `json:"action"`     // "+1", "-1", "3", "block", "allow"
	Enabled    bool   `json:"enabled"`
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
	GeoCode string   `json:"geoCode,omitempty"` // Agent's country code for D-Agent-ID header
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
