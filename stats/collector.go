package stats

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/defenra/agent/firewall"
	"github.com/defenra/agent/proxy"
)

type ResourceStats struct {
	mu                 sync.RWMutex
	InboundBytes       int64
	OutboundBytes      int64
	Requests           int64
	TotalResponseTime  int64
	Errors             int64
	BlockedRequests    int64
	RateLimitBlocks    int64
	FirewallBlocks     int64
	L4Blocks           int64
}

type StatisticsCollector struct {
	mu          sync.RWMutex
	proxyStats  map[string]*ResourceStats
	domainStats map[string]*ResourceStats
	httpStats   *proxy.HTTPStats
	httpsStats  *proxy.HTTPStats
	firewallStats firewall.FirewallStats
	client      *http.Client
	coreURL     string
	agentID     string
	agentKey    string
}

var globalCollector *StatisticsCollector
var globalCollectorOnce sync.Once

func GetCollector() *StatisticsCollector {
	globalCollectorOnce.Do(func() {
		globalCollector = &StatisticsCollector{
			proxyStats:  make(map[string]*ResourceStats),
			domainStats: make(map[string]*ResourceStats),
			client: &http.Client{
				Timeout: 30 * time.Second,
			},
		}
	})
	return globalCollector
}

func (sc *StatisticsCollector) SetConfig(coreURL, agentID, agentKey string) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.coreURL = coreURL
	sc.agentID = agentID
	sc.agentKey = agentKey
}

func (sc *StatisticsCollector) SetHTTPStats(stats proxy.HTTPStats) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.httpStats = &stats
}

func (sc *StatisticsCollector) SetHTTPSStats(stats proxy.HTTPStats) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.httpsStats = &stats
}

func (sc *StatisticsCollector) UpdateFirewallStats() {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.firewallStats = firewall.GetStats()
}

type StatisticsPayload struct {
	AgentID        string `json:"agentId"`
	ResourceType   string `json:"resourceType"`
	ResourceID     string `json:"resourceId"`
	InboundBytes   int64  `json:"inboundBytes"`
	OutboundBytes  int64  `json:"outboundBytes"`
	Requests       int64  `json:"requests"`
	ResponseTimeMs int64  `json:"responseTimeMs"`
	Errors         int64  `json:"errors"`
	BlockedRequests int64 `json:"blockedRequests,omitempty"`
	RateLimitBlocks int64 `json:"rateLimitBlocks,omitempty"`
	FirewallBlocks  int64 `json:"firewallBlocks,omitempty"`
	L4Blocks        int64 `json:"l4Blocks,omitempty"`
}

func (sc *StatisticsCollector) SendStatistics() {
	sc.mu.Lock()
	
	if sc.coreURL == "" || sc.agentID == "" || sc.agentKey == "" {
		sc.mu.Unlock()
		return
	}

	// собираем статистику из всех модулей
	sc.UpdateFirewallStats()

	sc.mu.Unlock()

	// получаем актуальную статистику из proxy модулей
	httpStats := proxy.GetHTTPStats()
	httpsStats := proxy.GetHTTPSStats()
	firewallStats := firewall.GetStats()

	// отправляем статистику по доменам (HTTP/HTTPS трафик)
	sc.sendDomainStatistics(httpStats, httpsStats, firewallStats)

	log.Printf("[Stats] Statistics sent to Core")
}

func (sc *StatisticsCollector) sendDomainStatistics(httpStats, httpsStats proxy.HTTPStats, firewallStats firewall.FirewallStats) {
	// объединяем HTTP и HTTPS статистику
	totalRequests := httpStats.TotalRequests + httpsStats.TotalRequests
	totalBlocked := httpStats.BlockedRequests + httpsStats.BlockedRequests
	totalRateLimit := httpStats.RateLimitBlocks + httpsStats.RateLimitBlocks
	totalFirewall := httpStats.FirewallBlocks + httpsStats.FirewallBlocks

	if totalRequests == 0 && firewallStats.L4Blocks == 0 {
		return
	}

	// отправляем общую статистику для всех доменов
	// в будущем можно добавить сбор по отдельным доменам
	payload := StatisticsPayload{
		AgentID:         sc.agentID,
		ResourceType:    "domain",
		ResourceID:      "all",
		InboundBytes:    0,
		OutboundBytes:   0,
		Requests:        int64(totalRequests),
		ResponseTimeMs:  0,
		Errors:          int64(httpStats.ProxyErrors + httpsStats.ProxyErrors),
		BlockedRequests: int64(totalBlocked),
		RateLimitBlocks: int64(totalRateLimit),
		FirewallBlocks:  int64(totalFirewall),
		L4Blocks:        int64(firewallStats.L4Blocks),
	}

	sc.sendPayload(payload)
}


func (sc *StatisticsCollector) sendPayload(payload StatisticsPayload) {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	sc.sendPayloadUnsafe(payload)
}

func (sc *StatisticsCollector) sendPayloadUnsafe(payload StatisticsPayload) {
	data, err := json.Marshal(payload)
	if err != nil {
		log.Printf("[Stats] Error marshaling payload: %v", err)
		return
	}

	req, err := http.NewRequest("POST", sc.coreURL+"/api/statistics", bytes.NewBuffer(data))
	if err != nil {
		log.Printf("[Stats] Error creating request: %v", err)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+sc.agentKey)

	resp, err := sc.client.Do(req)
	if err != nil {
		log.Printf("[Stats] Error sending statistics: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("[Stats] Error response (status %d) for resource %s/%s", resp.StatusCode, payload.ResourceType, payload.ResourceID)
		return
	}
}
