package health

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"runtime"
	"time"

	"github.com/defenra/agent/config"
)

type HealthServer struct {
	configMgr *config.ConfigManager
	startTime time.Time
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
	Config  ConfigStats  `json:"config"`
	Runtime RuntimeStats `json:"runtime"`
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

func StartHealthCheck(configMgr *config.ConfigManager) {
	server := &HealthServer{
		configMgr: configMgr,
		startTime: time.Now(),
	}

	http.HandleFunc("/health", server.handleHealth)
	http.HandleFunc("/stats", server.handleStats)

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
	json.NewEncoder(w).Encode(response)
}

func (h *HealthServer) handleStats(w http.ResponseWriter, r *http.Request) {
	stats := h.configMgr.GetStats()

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	response := StatsResponse{
		Config: ConfigStats{
			TotalPolls:    stats.TotalPolls,
			FailedPolls:   stats.FailedPolls,
			LastPollTime:  stats.LastPollTime,
			DomainsLoaded: stats.DomainsLoaded,
			ProxiesActive: stats.ProxiesActive,
		},
		Runtime: RuntimeStats{
			Uptime:       formatDuration(time.Since(h.startTime)),
			MemoryAlloc:  formatBytes(m.Alloc),
			MemorySys:    formatBytes(m.Sys),
			NumGoroutine: runtime.NumGoroutine(),
			NumCPU:       runtime.NumCPU(),
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
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
