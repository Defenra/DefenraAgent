package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

const (
	metricsReportInterval = 60 * time.Second
	maxPendingClients     = 500
	maxPendingLogs        = 500
	logsPerSend           = 100
)

// ResourceStats tracks traffic statistics per resource (proxy or domain)
type ResourceStats struct {
	InboundBytes      int64
	OutboundBytes     int64
	Requests          int64
	TotalResponseTime int64
	Errors            int64
}

// ClientInfo represents a client connection
type ClientInfo struct {
	IP          string                 `json:"ip"`
	AgentID     string                 `json:"agentId"`
	UserAgent   string                 `json:"userAgent,omitempty"`
	Country     string                 `json:"country,omitempty"`
	City        string                 `json:"city,omitempty"`
	CountryCode string                 `json:"countryCode,omitempty"`
}

// LogEntry represents a log message
type LogEntry struct {
	AgentID  string                 `json:"agentId"`
	Level    string                 `json:"level"` // info, warning, error
	Message  string                 `json:"message"`
	Details  string                 `json:"details,omitempty"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// StatisticsPayload for sending to Core
type StatisticsPayload struct {
	AgentID        string `json:"agentId"`
	ResourceType   string `json:"resourceType"` // "proxy" or "domain"
	ResourceID     string `json:"resourceId"`
	InboundBytes   int64  `json:"inboundBytes"`
	OutboundBytes  int64  `json:"outboundBytes"`
	Requests       int64  `json:"requests"`
	ResponseTimeMs int64  `json:"responseTimeMs"`
	Errors         int64  `json:"errors"`
}

// MetricsCollector collects and reports metrics to Core
type MetricsCollector struct {
	coreURL string
	agentID string
	
	// Queues with mutexes
	pendingClients []ClientInfo
	clientsMutex   sync.Mutex
	
	pendingLogs []LogEntry
	logsMutex   sync.Mutex
	
	// Statistics maps
	proxyStats  sync.Map // map[string]*ResourceStats
	domainStats sync.Map // map[string]*ResourceStats
	
	stopChan chan struct{}
}

// NewMetricsCollector creates a new metrics collector
func NewMetricsCollector(coreURL, agentID string) *MetricsCollector {
	mc := &MetricsCollector{
		coreURL:  coreURL,
		agentID:  agentID,
		stopChan: make(chan struct{}),
	}
	
	// Start reporting goroutine
	go mc.reportingLoop()
	
	return mc
}

// Stop stops the metrics collector
func (mc *MetricsCollector) Stop() {
	close(mc.stopChan)
}

// reportingLoop periodically sends metrics to Core
func (mc *MetricsCollector) reportingLoop() {
	ticker := time.NewTicker(metricsReportInterval)
	defer ticker.Stop()
	
	log.Printf("[Metrics] Reporting loop started, interval: %v", metricsReportInterval)
	
	for {
		select {
		case <-ticker.C:
			log.Printf("[Metrics] Sending metrics to Core...")
			mc.sendAllMetrics()
			log.Printf("[Metrics] Metrics sent successfully")
		case <-mc.stopChan:
			log.Printf("[Metrics] Reporting loop stopped")
			return
		}
	}
}

// sendAllMetrics sends all pending metrics to Core
func (mc *MetricsCollector) sendAllMetrics() {
	// Send in order: clients -> statistics -> logs
	mc.sendClients()
	mc.sendStatistics()
	mc.sendLogs()
}

// AddClient adds a client to the pending queue
func (mc *MetricsCollector) AddClient(ip, userAgent, country, city, countryCode string) {
	mc.clientsMutex.Lock()
	defer mc.clientsMutex.Unlock()
	
	mc.pendingClients = append(mc.pendingClients, ClientInfo{
		IP:          ip,
		UserAgent:   userAgent,
		Country:     country,
		City:        city,
		CountryCode: countryCode,
	})
	
	// Limit queue size
	if len(mc.pendingClients) > maxPendingClients {
		mc.pendingClients = mc.pendingClients[1:]
	}
}

// AddLog adds a log entry to the pending queue
func (mc *MetricsCollector) AddLog(level, message, details string, metadata map[string]interface{}) {
	mc.logsMutex.Lock()
	defer mc.logsMutex.Unlock()
	
	mc.pendingLogs = append(mc.pendingLogs, LogEntry{
		Level:    level,
		Message:  message,
		Details:  details,
		Metadata: metadata,
	})
	
	// Limit queue size
	if len(mc.pendingLogs) > maxPendingLogs {
		mc.pendingLogs = mc.pendingLogs[1:]
	}
}

// TrackProxyTraffic records traffic statistics for a proxy
func (mc *MetricsCollector) TrackProxyTraffic(proxyID string, inbound, outbound int64) {
	mc.trackTraffic(&mc.proxyStats, proxyID, inbound, outbound)
}

// TrackProxyRequest records a request for a proxy
func (mc *MetricsCollector) TrackProxyRequest(proxyID string, responseTime time.Duration) {
	mc.trackRequest(&mc.proxyStats, proxyID, responseTime)
}

// TrackProxyError records an error for a proxy
func (mc *MetricsCollector) TrackProxyError(proxyID string) {
	mc.trackError(&mc.proxyStats, proxyID)
}

// TrackDomainTraffic records traffic statistics for a domain
func (mc *MetricsCollector) TrackDomainTraffic(domainID string, inbound, outbound int64) {
	mc.trackTraffic(&mc.domainStats, domainID, inbound, outbound)
}

// TrackDomainRequest records a request for a domain
func (mc *MetricsCollector) TrackDomainRequest(domainID string, responseTime time.Duration) {
	mc.trackRequest(&mc.domainStats, domainID, responseTime)
}

// TrackDomainError records an error for a domain
func (mc *MetricsCollector) TrackDomainError(domainID string) {
	mc.trackError(&mc.domainStats, domainID)
}

// Internal helper methods
func (mc *MetricsCollector) trackTraffic(statsMap *sync.Map, resourceID string, inbound, outbound int64) {
	val, _ := statsMap.LoadOrStore(resourceID, &ResourceStats{})
	stats := val.(*ResourceStats)
	
	atomic.AddInt64(&stats.InboundBytes, inbound)
	atomic.AddInt64(&stats.OutboundBytes, outbound)
}

func (mc *MetricsCollector) trackRequest(statsMap *sync.Map, resourceID string, responseTime time.Duration) {
	val, _ := statsMap.LoadOrStore(resourceID, &ResourceStats{})
	stats := val.(*ResourceStats)
	
	atomic.AddInt64(&stats.Requests, 1)
	atomic.AddInt64(&stats.TotalResponseTime, responseTime.Milliseconds())
}

func (mc *MetricsCollector) trackError(statsMap *sync.Map, resourceID string) {
	val, _ := statsMap.LoadOrStore(resourceID, &ResourceStats{})
	stats := val.(*ResourceStats)
	
	atomic.AddInt64(&stats.Errors, 1)
}

// sendClients sends pending clients to Core
func (mc *MetricsCollector) sendClients() {
	mc.clientsMutex.Lock()
	if len(mc.pendingClients) == 0 {
		mc.clientsMutex.Unlock()
		log.Printf("[Metrics] No pending clients to send")
		return
	}
	
	clients := make([]ClientInfo, len(mc.pendingClients))
	copy(clients, mc.pendingClients)
	mc.pendingClients = nil
	mc.clientsMutex.Unlock()
	
	log.Printf("[Metrics] Sending %d clients to Core", len(clients))
	
	successCount := 0
	for _, client := range clients {
		client.AgentID = mc.agentID
		data, err := json.Marshal(client)
		if err != nil {
			log.Printf("[Metrics] Failed to marshal client: %v", err)
			continue
		}
		
		req, err := http.NewRequest("POST", mc.coreURL+"/api/clients", bytes.NewBuffer(data))
		if err != nil {
			log.Printf("[Metrics] Failed to create client request: %v", err)
			continue
		}
		
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+mc.agentID)
		
		httpClient := &http.Client{Timeout: 10 * time.Second}
		resp, err := httpClient.Do(req)
		if err != nil {
			// Return to queue on error
			mc.clientsMutex.Lock()
			mc.pendingClients = append(mc.pendingClients, client)
			mc.clientsMutex.Unlock()
			log.Printf("[Metrics] Failed to send client: %v", err)
			continue
		}
		
		if resp.StatusCode != 200 {
			bodyBytes, _ := io.ReadAll(resp.Body)
			log.Printf("[Metrics] Client API returned status %d: %s", resp.StatusCode, string(bodyBytes))
			resp.Body.Close()
			continue
		}
		
		resp.Body.Close()
		successCount++
	}
	
	log.Printf("[Metrics] Successfully sent %d/%d clients", successCount, len(clients))
}

// sendStatistics sends aggregated statistics to Core
func (mc *MetricsCollector) sendStatistics() {
	log.Printf("[Metrics] Collecting statistics...")
	
	proxyCount := 0
	domainCount := 0
	
	// Send proxy statistics
	mc.proxyStats.Range(func(key, value interface{}) bool {
		proxyCount++
		proxyID := key.(string)
		stats := value.(*ResourceStats)
		
		requests := atomic.LoadInt64(&stats.Requests)
		if requests == 0 {
			return true // Skip empty stats
		}
		
		inbound := atomic.SwapInt64(&stats.InboundBytes, 0)
		outbound := atomic.SwapInt64(&stats.OutboundBytes, 0)
		reqCount := atomic.SwapInt64(&stats.Requests, 0)
		totalTime := atomic.SwapInt64(&stats.TotalResponseTime, 0)
		errors := atomic.SwapInt64(&stats.Errors, 0)
		
		avgResponseTime := int64(0)
		if reqCount > 0 {
			avgResponseTime = totalTime / reqCount
		}
		
		payload := StatisticsPayload{
			AgentID:        mc.agentID,
			ResourceType:   "proxy",
			ResourceID:     proxyID,
			InboundBytes:   inbound,
			OutboundBytes:  outbound,
			Requests:       reqCount,
			ResponseTimeMs: avgResponseTime,
			Errors:         errors,
		}
		
		mc.sendSingleStatistic(payload)
		return true
	})
	
	log.Printf("[Metrics] Sent %d proxy statistics", proxyCount)
	
	// Send domain statistics
	mc.domainStats.Range(func(key, value interface{}) bool {
		domainCount++
		domainID := key.(string)
		stats := value.(*ResourceStats)
		
		requests := atomic.LoadInt64(&stats.Requests)
		if requests == 0 {
			return true // Skip empty stats
		}
		
		inbound := atomic.SwapInt64(&stats.InboundBytes, 0)
		outbound := atomic.SwapInt64(&stats.OutboundBytes, 0)
		reqCount := atomic.SwapInt64(&stats.Requests, 0)
		totalTime := atomic.SwapInt64(&stats.TotalResponseTime, 0)
		errors := atomic.SwapInt64(&stats.Errors, 0)
		
		avgResponseTime := int64(0)
		if reqCount > 0 {
			avgResponseTime = totalTime / reqCount
		}
		
		payload := StatisticsPayload{
			AgentID:        mc.agentID,
			ResourceType:   "domain",
			ResourceID:     domainID,
			InboundBytes:   inbound,
			OutboundBytes:  outbound,
			Requests:       reqCount,
			ResponseTimeMs: avgResponseTime,
			Errors:         errors,
		}
		
		mc.sendSingleStatistic(payload)
		return true
	})
	
	log.Printf("[Metrics] Sent %d domain statistics", domainCount)
}

func (mc *MetricsCollector) sendSingleStatistic(payload StatisticsPayload) {
	data, err := json.Marshal(payload)
	if err != nil {
		log.Printf("[Metrics] Failed to marshal statistics: %v", err)
		return
	}
	
	req, err := http.NewRequest("POST", mc.coreURL+"/api/statistics", bytes.NewBuffer(data))
	if err != nil {
		log.Printf("[Metrics] Failed to create request: %v", err)
		return
	}
	
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+mc.agentID)
	
	log.Printf("[Metrics] Sending statistic to %s (resourceType: %s, resourceId: %s, requests: %d)", 
		mc.coreURL+"/api/statistics", payload.ResourceType, payload.ResourceID, payload.Requests)
	
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[Metrics] Failed to send statistics: %v", err)
		return
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != 200 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		log.Printf("[Metrics] Statistics API returned status %d: %s", resp.StatusCode, string(bodyBytes))
		return
	}
	
	log.Printf("[Metrics] Statistic sent successfully (status: %d)", resp.StatusCode)
}

// sendLogs sends pending logs to Core
func (mc *MetricsCollector) sendLogs() {
	mc.logsMutex.Lock()
	
	limit := logsPerSend
	if len(mc.pendingLogs) < limit {
		limit = len(mc.pendingLogs)
	}
	
	if limit == 0 {
		mc.logsMutex.Unlock()
		log.Printf("[Metrics] No pending logs to send")
		return
	}
	
	logsToSend := make([]LogEntry, limit)
	copy(logsToSend, mc.pendingLogs[:limit])
	mc.pendingLogs = mc.pendingLogs[limit:]
	
	mc.logsMutex.Unlock()
	
	log.Printf("[Metrics] Sending %d logs to Core", len(logsToSend))
	
	successCount := 0
	for i, logEntry := range logsToSend {
		logEntry.AgentID = mc.agentID
		data, err := json.Marshal(logEntry)
		if err != nil {
			log.Printf("[Metrics] Failed to marshal log: %v", err)
			continue
		}
		
		req, err := http.NewRequest("POST", mc.coreURL+"/api/logs", bytes.NewBuffer(data))
		if err != nil {
			log.Printf("[Metrics] Failed to create log request: %v", err)
			continue
		}
		
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+mc.agentID)
		
		httpClient := &http.Client{Timeout: 10 * time.Second}
		resp, err := httpClient.Do(req)
		if err != nil || (resp != nil && resp.StatusCode != 200) {
			// Return unsent logs to queue
			mc.logsMutex.Lock()
			mc.pendingLogs = append(logsToSend[i:], mc.pendingLogs...)
			mc.logsMutex.Unlock()
			
			if resp != nil {
				bodyBytes, _ := io.ReadAll(resp.Body)
				log.Printf("[Metrics] Logs API returned status %d: %s", resp.StatusCode, string(bodyBytes))
				resp.Body.Close()
			} else {
				log.Printf("[Metrics] Failed to send log: %v", err)
			}
			break
		}
		
		resp.Body.Close()
		successCount++
	}
	
	log.Printf("[Metrics] Successfully sent %d/%d logs", successCount, len(logsToSend))
}
