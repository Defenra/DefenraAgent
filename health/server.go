.package health

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"runtime"
	"time"

	"github.com/defenra/agent/config"
	"github.com/defenra/agent/firewall"
	"github.com/defenra/agent/stats"
)

type HealthServer struct {
	configMgr       *config.ConfigManager
	startTime       time.Time
	systemCollector *stats.SystemMetricsCollector
}

var globalFirewallMgr *firewall.IPTablesManager

func SetFirewallManager(mgr *firewall.IPTablesManager) {
	globalFirewallMgr = mgr
}

type HealthResponse struct {
	Status        string    `json:"status"`
	Uptime        string    `json:"uptime"`
	LastPoll      string    `json:"last_poll"`
	DomainsLoaded int       `json:"domains_loaded"`
	ProxiesActive int       `json:"proxies_active"`
	MemoryUsage   string    `json:"memory_usage"`
	Timestamp     time.Time `json:"timestamp"`
}

type StatsResponse struct {
	Config        ConfigStats          `json:"config"`
	Runtime       RuntimeStats         `json:"runtime"`
	Firewall      FirewallStats        `json:"firewall"`
	SystemMetrics *stats.SystemMetrics `json:"systemMetrics,omitempty"`
}

type ConfigStats struct {
	TotalPolls    uint64    `json:"total_polls"`
	FailedPolls   uint64    `json:"failed_polls"`
	LastPollTime  time.Time `json:"last_poll_time"`
	DomainsLoaded int       `json:"domains_loaded"`
	ProxiesActive int       `json:"proxies_active"`
}

type RuntimeStats struct {
	Uptime       string `json:"uptime"`
	MemoryAlloc  string `json:"memory_alloc"`
	MemorySys    string `json:"memory_sys"`
	NumGoroutine int    `json:"num_goroutine"`
	NumCPU       int    `json:"num_cpu"`
}

type FirewallStats struct {
	TotalBans             uint64 `json:"total_bans"`
	ActiveBans            uint64 `json:"active_bans"`
	L4Blocks              uint64 `json:"l4_blocks"`
	TCPFlagBlocks         uint64 `json:"tcp_flag_blocks"`
	RateLimitBlocks       uint64 `json:"rate_limit_blocks"`
	ConnectionLimitBlocks uint64 `json:"connection_limit_blocks"`
}

func StartHealthCheck(configMgr *config.ConfigManager) {
	server := &HealthServer{
		configMgr:       configMgr,
		startTime:       time.Now(),
		systemCollector: stats.NewSystemMetricsCollector(),
	}

	http.HandleFunc("/health", server.handleHealth)
	http.HandleFunc("/stats", server.handleStats)
	http.HandleFunc("/banned-ips", server.handleBannedIPs)
	http.HandleFunc("/clients", server.handleClients)

	log.Println("[Health] Starting health check server on :8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Printf("[Health] Failed to start server: %v", err)
	}
}

func (h *HealthServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	stats := h.configMgr.GetStats()

	response := HealthResponse{
		Status:        "healthy",
		Uptime:        formatDuration(time.Since(h.startTime)),
		LastPoll:      stats.LastPollTime.Format(time.RFC3339),
		DomainsLoaded: stats.DomainsLoaded,
		ProxiesActive: stats.ProxiesActive,
		MemoryUsage:   formatBytes(getMemoryUsage()),
		Timestamp:     time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("[Health] Error encoding response: %v", err)
	}
}

func (h *HealthServer) handleStats(w http.ResponseWriter, r *http.Request) {
	configStats := h.configMgr.GetStats()

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	firewallStats := firewall.GetStats()

	// Collect system metrics
	var systemMetrics *stats.SystemMetrics
	if h.systemCollector != nil {
		if metrics, err := h.systemCollector.CollectMetrics(); err != nil {
			log.Printf("[Health] Failed to collect system metrics: %v", err)
		} else {
			systemMetrics = metrics
		}
	}

	response := StatsResponse{
		Config: ConfigStats{
			TotalPolls:    configStats.TotalPolls,
			FailedPolls:   configStats.FailedPolls,
			LastPollTime:  configStats.LastPollTime,
			DomainsLoaded: configStats.DomainsLoaded,
			ProxiesActive: configStats.ProxiesActive,
		},
		Runtime: RuntimeStats{
			Uptime:       formatDuration(time.Since(h.startTime)),
			MemoryAlloc:  formatBytes(m.Alloc),
			MemorySys:    formatBytes(m.Sys),
			NumGoroutine: runtime.NumGoroutine(),
			NumCPU:       runtime.NumCPU(),
		},
		Firewall: FirewallStats{
			TotalBans:             firewallStats.TotalBans,
			ActiveBans:            firewallStats.ActiveBans,
			L4Blocks:              firewallStats.L4Blocks,
			TCPFlagBlocks:         firewallStats.TCPFlagBlocks,
			RateLimitBlocks:       firewallStats.RateLimitBlocks,
			ConnectionLimitBlocks: firewallStats.ConnectionLimitBlocks,
		},
		SystemMetrics: systemMetrics,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("[Health] Error encoding response: %v", err)
	}
}

func getMemoryUsage() uint64 {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.Alloc
}

func formatBytes(bytes uint64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := uint64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute
	d -= m * time.Minute
	s := d / time.Second

	if h > 0 {
		return fmt.Sprintf("%dh%dm%ds", h, m, s)
	}
	if m > 0 {
		return fmt.Sprintf("%dm%ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}

type BannedIPsResponse struct {
	BannedIPs []BannedIPInfo `json:"banned_ips"`
}

type BannedIPInfo struct {
	IP        string    `json:"ip"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (h *HealthServer) handleBannedIPs(w http.ResponseWriter, r *http.Request) {
	if globalFirewallMgr == nil {
		http.Error(w, "Firewall manager not available", http.StatusServiceUnavailable)
		return
	}

	bannedIPsInfo := globalFirewallMgr.GetBannedIPsInfo()

	response := BannedIPsResponse{
		BannedIPs: make([]BannedIPInfo, 0, len(bannedIPsInfo)),
	}

	for _, ipInfo := range bannedIPsInfo {
		response.BannedIPs = append(response.BannedIPs, BannedIPInfo{
			IP:        ipInfo.IP,
			ExpiresAt: ipInfo.ExpiresAt,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("[Health] Error encoding banned IPs response: %v", err)
	}
}

type ClientsResponse struct {
	Clients []ClientInfo `json:"clients"`
	Total   int          `json:"total"`
}

type ClientInfo struct {
	IP            string `json:"ip"`
	ConnectedAt   string `json:"connected_at"`
	LastActivity  string `json:"last_activity"`
	Duration      string `json:"duration"`
	BytesSent     uint64 `json:"bytes_sent"`
	BytesReceived uint64 `json:"bytes_received"`
	TotalBytes    uint64 `json:"total_bytes"`
	ProxyID       string `json:"proxy_id"`
	ProxyPort     int    `json:"proxy_port"`
}

func (h *HealthServer) handleClients(w http.ResponseWriter, r *http.Request) {
	// Получаем параметр port если указан (для TCP/UDP прокси)
	portFilter := r.URL.Query().Get("port")
	// Получаем параметр domain если указан (для HTTP/HTTPS)
	domainFilter := r.URL.Query().Get("domain")

	var clients []ClientInfo

	if portFilter != "" {
		// TCP/UDP proxy clients
		clients = getActiveClients(portFilter)
	} else if domainFilter != "" {
		// HTTP/HTTPS clients for specific domain
		clients = GetHTTPClientsByDomain(domainFilter)
	} else {
		// All HTTP/HTTPS clients
		clients = GetAllHTTPClients()
	}

	response := ClientsResponse{
		Clients: clients,
		Total:   len(clients),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("[Health] Error encoding clients response: %v", err)
	}
}
