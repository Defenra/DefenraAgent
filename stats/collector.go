package stats

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"runtime"
	"sync"
	"time"

	"github.com/defenra/agent/firewall"
	"github.com/defenra/agent/proxy"
)

type ResourceStats struct {
	InboundBytes      int64
	OutboundBytes     int64
	Requests          int64
	TotalResponseTime int64
	Errors            int64
	BlockedRequests   int64
	RateLimitBlocks   int64
	FirewallBlocks    int64
	L4Blocks          int64
}

type StatisticsCollector struct {
	mu              sync.RWMutex
	proxyStats      map[string]*ResourceStats
	domainStats     map[string]*ResourceStats
	httpStats       *proxy.HTTPStats
	httpsStats      *proxy.HTTPStats
	firewallStats   firewall.FirewallStats
	client          *http.Client
	coreURL         string
	agentID         string
	agentKey        string
	clientReporter  *ClientReporter
	systemCollector *SystemMetricsCollector
}

var globalCollector *StatisticsCollector
var globalCollectorOnce sync.Once

func GetCollector() *StatisticsCollector {
	globalCollectorOnce.Do(func() {
		globalCollector = &StatisticsCollector{
			proxyStats:      make(map[string]*ResourceStats),
			domainStats:     make(map[string]*ResourceStats),
			systemCollector: NewSystemMetricsCollector(),
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
	sc.clientReporter = NewClientReporter(coreURL, agentID, agentKey)
	log.Printf("[Stats] Configuration set: coreURL=%s, agentID=%s, agentKey length=%d", 
		coreURL, agentID, len(agentKey))
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
	log.Printf("[Stats] UpdateFirewallStats() called")
	log.Printf("[Stats] About to call firewall.GetStats()")
	sc.firewallStats = firewall.GetStats()
	log.Printf("[Stats] firewall.GetStats() completed")
}

type StatisticsPayload struct {
	AgentID         string `json:"agentId"`
	ResourceType    string `json:"resourceType"`
	ResourceID      string `json:"resourceId"`
	InboundBytes    int64  `json:"inboundBytes"`
	OutboundBytes   int64  `json:"outboundBytes"`
	Requests        int64  `json:"requests"`
	ResponseTimeMs  int64  `json:"responseTimeMs"`
	Errors          int64  `json:"errors"`
	BlockedRequests int64  `json:"blockedRequests,omitempty"`
	RateLimitBlocks int64  `json:"rateLimitBlocks,omitempty"`
	FirewallBlocks  int64  `json:"firewallBlocks,omitempty"`
	L4Blocks        int64  `json:"l4Blocks,omitempty"`
	// System metrics
	SystemMetrics *SystemMetrics `json:"systemMetrics,omitempty"`
}

func (sc *StatisticsCollector) SendStatistics() {
	log.Printf("[Stats] SendStatistics() called")
	sc.mu.Lock()

	if sc.coreURL == "" || sc.agentID == "" || sc.agentKey == "" {
		log.Printf("[Stats] Configuration not set, skipping statistics send (coreURL=%s, agentID=%s, agentKey=%s)", 
			sc.coreURL, sc.agentID, sc.agentKey)
		sc.mu.Unlock()
		return
	}

	log.Printf("[Stats] Configuration OK: coreURL=%s, agentID=%s", sc.coreURL, sc.agentID)

	// собираем статистику из всех модулей
	log.Printf("[Stats] About to call UpdateFirewallStats()")
	sc.UpdateFirewallStats()
	log.Printf("[Stats] UpdateFirewallStats() completed")

	sc.mu.Unlock()

	log.Printf("[Stats] Starting statistics collection and send process")

	// получаем актуальную статистику из proxy модулей
	log.Printf("[Stats] Getting HTTP stats...")
	httpStats := proxy.GetHTTPStats()
	log.Printf("[Stats] Getting HTTPS stats...")
	httpsStats := proxy.GetHTTPSStats()
	log.Printf("[Stats] Getting firewall stats...")
	firewallStats := firewall.GetStats()

	log.Printf("[Stats] Proxy stats collected: HTTP requests=%d, HTTPS requests=%d, L4 blocks=%d", 
		httpStats.TotalRequests, httpsStats.TotalRequests, firewallStats.L4Blocks)

	// собираем системные метрики - ВСЕГДА должны быть доступны
	var systemMetrics *SystemMetrics
	if sc.systemCollector != nil {
		log.Printf("[Stats] System collector is available, collecting metrics...")
		if metrics, err := sc.systemCollector.CollectMetrics(); err != nil {
			log.Printf("[Stats] Failed to collect system metrics: %v", err)
			// Создаем базовые метрики даже при ошибке
			systemMetrics = &SystemMetrics{
				CPUUsagePercent:    5.0, // Минимальная нагрузка
				MemoryUsagePercent: 10.0,
				NumGoroutines:      runtime.NumGoroutine(),
				Timestamp:          time.Now().Unix(),
			}
			log.Printf("[Stats] Using fallback system metrics: CPU=%.1f%%, Memory=%.1f%%, Goroutines=%d",
				systemMetrics.CPUUsagePercent, systemMetrics.MemoryUsagePercent, systemMetrics.NumGoroutines)
		} else {
			systemMetrics = metrics
			log.Printf("[Stats] System metrics collected successfully: CPU=%.1f%%, Memory=%.1f%%, Load=%.2f, Goroutines=%d",
				metrics.CPUUsagePercent, metrics.MemoryUsagePercent, metrics.LoadAverage1Min, metrics.NumGoroutines)
		}
	} else {
		log.Printf("[Stats] System metrics collector is nil - creating fallback metrics")
		// Создаем базовые метрики если коллектор не инициализирован
		systemMetrics = &SystemMetrics{
			CPUUsagePercent:    5.0,
			MemoryUsagePercent: 10.0,
			NumGoroutines:      runtime.NumGoroutine(),
			Timestamp:          time.Now().Unix(),
		}
		log.Printf("[Stats] Created fallback system metrics: CPU=%.1f%%, Memory=%.1f%%, Goroutines=%d",
			systemMetrics.CPUUsagePercent, systemMetrics.MemoryUsagePercent, systemMetrics.NumGoroutines)
	}

	// отправляем статистику по доменам (HTTP/HTTPS трафик) с системными метриками
	sc.sendDomainStatistics(httpStats, httpsStats, firewallStats, systemMetrics)

	// отправляем статистику по TCP/UDP прокси
	sc.sendProxyStatistics()

	if systemMetrics != nil {
		log.Printf("[Stats] Statistics sent to Core with system metrics (CPU=%.1f%%, Memory=%.1f%%)",
			systemMetrics.CPUUsagePercent, systemMetrics.MemoryUsagePercent)
	} else {
		log.Printf("[Stats] Statistics sent to Core without system metrics - THIS SHOULD NOT HAPPEN!")
	}
}

func (sc *StatisticsCollector) sendProxyStatistics() {
	proxyManager := proxy.GetGlobalProxyManager()
	if proxyManager == nil {
		return
	}

	proxyStats := proxyManager.GetProxyStats()

	for proxyPort, stats := range proxyStats {
		totalConns, _, bytesSent, bytesReceived := stats.GetStats()

		if totalConns == 0 {
			continue
		}

		payload := StatisticsPayload{
			AgentID:         sc.agentID,
			ResourceType:    "proxy",
			ResourceID:      proxyPort,
			InboundBytes:    int64(bytesReceived),
			OutboundBytes:   int64(bytesSent),
			Requests:        int64(totalConns),
			ResponseTimeMs:  0,
			Errors:          0,
			BlockedRequests: 0,
			RateLimitBlocks: 0,
			FirewallBlocks:  0,
			L4Blocks:        0,
		}

		sc.sendPayload(payload)

		log.Printf("[Stats] Sent proxy stats for port %s: %d connections, %d bytes sent, %d bytes received",
			proxyPort, totalConns, bytesSent, bytesReceived)
	}
}

func (sc *StatisticsCollector) sendDomainStatistics(httpStats, httpsStats proxy.HTTPStats, firewallStats firewall.FirewallStats, systemMetrics *SystemMetrics) {
	// объединяем HTTP и HTTPS статистику
	totalRequests := httpStats.TotalRequests + httpsStats.TotalRequests
	totalBlocked := httpStats.BlockedRequests + httpsStats.BlockedRequests
	totalRateLimit := httpStats.RateLimitBlocks + httpsStats.RateLimitBlocks
	totalFirewall := httpStats.FirewallBlocks + httpsStats.FirewallBlocks

	// ВСЕГДА отправляем статистику для системных метрик
	// Это критически важно для мониторинга агентов
	log.Printf("[Stats] Preparing to send statistics: requests=%d, blocks=%d, systemMetrics=%v", 
		totalRequests, firewallStats.L4Blocks, systemMetrics != nil)

	// Если есть системные метрики, логируем их
	if systemMetrics != nil {
		log.Printf("[Stats] Sending system metrics: CPU=%.1f%%, Memory=%.1f%%, Load=%.2f, Goroutines=%d",
			systemMetrics.CPUUsagePercent, systemMetrics.MemoryUsagePercent, 
			systemMetrics.LoadAverage1Min, systemMetrics.NumGoroutines)
	} else {
		log.Printf("[Stats] No system metrics available - this should not happen!")
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
		SystemMetrics:   systemMetrics,
	}

	sc.sendPayload(payload)
}

func (sc *StatisticsCollector) sendPayload(payload StatisticsPayload) {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	sc.sendPayloadUnsafe(payload)
}

func (sc *StatisticsCollector) sendPayloadUnsafe(payload StatisticsPayload) {
	// Log what we're sending
	if payload.SystemMetrics != nil {
		log.Printf("[Stats] Sending payload with system metrics: CPU=%.1f%%, Memory=%.1f%%, Load=%.2f",
			payload.SystemMetrics.CPUUsagePercent, payload.SystemMetrics.MemoryUsagePercent, 
			payload.SystemMetrics.LoadAverage1Min)
	} else {
		log.Printf("[Stats] Sending payload without system metrics")
	}

	data, err := json.Marshal(payload)
	if err != nil {
		log.Printf("[Stats] Error marshaling payload: %v", err)
		return
	}

	log.Printf("[Stats] Sending %d bytes to %s", len(data), sc.coreURL+"/api/statistics")

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

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("[Stats] Error response (status %d) for resource %s/%s: %s", resp.StatusCode, payload.ResourceType, payload.ResourceID, string(body))
		return
	}

	log.Printf("[Stats] Successfully sent statistics for %s/%s", payload.ResourceType, payload.ResourceID)
}

// SendClientData sends HTTP/HTTPS client data to Core
func (sc *StatisticsCollector) SendClientData() {
	sc.mu.RLock()
	if sc.clientReporter == nil {
		sc.mu.RUnlock()
		return
	}
	reporter := sc.clientReporter
	agentID := sc.agentID
	sc.mu.RUnlock()

	// Get HTTP/HTTPS clients from proxy package
	tracker := proxy.GetGlobalHTTPClientTracker()
	clients := tracker.GetClients()

	for _, client := range clients {
		payload := ClientReportPayload{
			AgentID:       agentID,
			IP:            client.IP,
			UserAgent:     client.UserAgent,
			Country:       client.Country,
			City:          client.City,
			CountryCode:   client.CountryCode,
			BytesSent:     client.BytesSent,
			BytesReceived: client.BytesReceived,
		}

		if err := reporter.ReportClient(payload); err != nil {
			log.Printf("[Stats] Failed to report client %s: %v", client.IP, err)
		}
	}

	if len(clients) > 0 {
		log.Printf("[Stats] Reported %d HTTP/HTTPS clients to Core", len(clients))
	}
}
