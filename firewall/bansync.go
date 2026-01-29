package firewall

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"sync"
	"time"
)

// BanSyncManager handles synchronization of IP bans across agents
type BanSyncManager struct {
	mu              sync.RWMutex
	coreURL         string
	agentKey        string
	client          *http.Client
	lastSyncTime    time.Time
	pendingBans     []BanReport
	iptablesManager *IPTablesManager
	stopChan        chan struct{}
}

// BanReport represents a ban to be reported to Core
type BanReport struct {
	IP          string    `json:"ip"`
	Reason      string    `json:"reason"`
	BannedAt    time.Time `json:"bannedAt"`
	ExpiresAt   time.Time `json:"expiresAt"`
	IsPermanent bool      `json:"isPermanent"`
	IsCIDR      bool      `json:"isCIDR"`
}

// GlobalBan represents a ban received from Core
type GlobalBan struct {
	IP          string    `json:"ip"`
	Reason      string    `json:"reason"`
	BannedAt    time.Time `json:"bannedAt"`
	ExpiresAt   time.Time `json:"expiresAt"`
	IsPermanent bool      `json:"isPermanent"`
	IsCIDR      bool      `json:"isCIDR"`
}

// BanSyncRequest is the payload sent to Core
type BanSyncRequest struct {
	NewBans      []BanReport `json:"newBans"`
	LastSyncTime string      `json:"lastSyncTime,omitempty"`
}

// BanSyncResponse is the response from Core
type BanSyncResponse struct {
	Success    bool        `json:"success"`
	GlobalBans []GlobalBan `json:"globalBans"`
	Stats      struct {
		TotalActiveBans int `json:"totalActiveBans"`
		NewBansReceived int `json:"newBansReceived"`
		BansSent        int `json:"bansSent"`
	} `json:"stats"`
}

var globalBanSyncManager *BanSyncManager
var globalBanSyncOnce sync.Once

// GetBanSyncManager returns the global ban sync manager instance
func GetBanSyncManager() *BanSyncManager {
	globalBanSyncOnce.Do(func() {
		globalBanSyncManager = &BanSyncManager{
			client: &http.Client{
				Timeout: 30 * time.Second,
			},
			pendingBans:     make([]BanReport, 0),
			iptablesManager: GetIPTablesManager(),
			stopChan:        make(chan struct{}),
		}
	})
	return globalBanSyncManager
}

// SetConfig configures the ban sync manager
func (bsm *BanSyncManager) SetConfig(coreURL, agentKey string) {
	bsm.mu.Lock()
	defer bsm.mu.Unlock()
	bsm.coreURL = coreURL
	bsm.agentKey = agentKey
	log.Printf("[BanSync] Configuration set: coreURL=%s", coreURL)
}

// StartSync starts the ban synchronization loop (every 30 seconds)
func (bsm *BanSyncManager) StartSync() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	// Initial sync after 5 seconds
	time.Sleep(5 * time.Second)
	bsm.Sync()

	for {
		select {
		case <-ticker.C:
			bsm.Sync()
		case <-bsm.stopChan:
			return
		}
	}
}

// ReportBan adds a ban to the pending queue for synchronization
func (bsm *BanSyncManager) ReportBan(ip, reason string, expiresAt time.Time, isPermanent, isCIDR bool) {
	bsm.mu.Lock()
	defer bsm.mu.Unlock()

	ban := BanReport{
		IP:          ip,
		Reason:      reason,
		BannedAt:    time.Now(),
		ExpiresAt:   expiresAt,
		IsPermanent: isPermanent,
		IsCIDR:      isCIDR,
	}

	bsm.pendingBans = append(bsm.pendingBans, ban)
	log.Printf("[BanSync] Queued ban for sync: %s (reason: %s, expires: %v)", ip, reason, expiresAt)
}

// Sync performs ban synchronization with Core
func (bsm *BanSyncManager) Sync() {
	bsm.mu.Lock()
	if bsm.coreURL == "" || bsm.agentKey == "" {
		bsm.mu.Unlock()
		return
	}

	// Get pending bans and clear the queue
	pendingBans := make([]BanReport, len(bsm.pendingBans))
	copy(pendingBans, bsm.pendingBans)
	bsm.pendingBans = make([]BanReport, 0)

	lastSyncTime := bsm.lastSyncTime
	coreURL := bsm.coreURL
	agentKey := bsm.agentKey
	bsm.mu.Unlock()

	// Prepare request
	request := BanSyncRequest{
		NewBans: pendingBans,
	}

	if !lastSyncTime.IsZero() {
		request.LastSyncTime = lastSyncTime.Format(time.RFC3339)
	}

	// Send request to Core
	data, err := json.Marshal(request)
	if err != nil {
		log.Printf("[BanSync] Error marshaling request: %v", err)
		return
	}

	req, err := http.NewRequest("POST", coreURL+"/api/agent/ban-sync", bytes.NewBuffer(data))
	if err != nil {
		log.Printf("[BanSync] Error creating request: %v", err)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+agentKey)

	resp, err := bsm.client.Do(req)
	if err != nil {
		log.Printf("[BanSync] Error sending request: %v", err)
		// Re-queue pending bans on failure
		bsm.mu.Lock()
		bsm.pendingBans = append(pendingBans, bsm.pendingBans...)
		bsm.mu.Unlock()
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("[BanSync] Error response (status %d): %s", resp.StatusCode, string(body))
		// Re-queue pending bans on failure
		bsm.mu.Lock()
		bsm.pendingBans = append(pendingBans, bsm.pendingBans...)
		bsm.mu.Unlock()
		return
	}

	// Parse response
	var response BanSyncResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		log.Printf("[BanSync] Error decoding response: %v", err)
		return
	}

	// Update last sync time
	bsm.mu.Lock()
	bsm.lastSyncTime = time.Now()
	bsm.mu.Unlock()

	// Apply global bans from other agents
	if len(response.GlobalBans) > 0 {
		bsm.applyGlobalBans(response.GlobalBans)
	}

	log.Printf("[BanSync] Sync complete: sent %d bans, received %d bans, total active: %d",
		response.Stats.NewBansReceived, response.Stats.BansSent, response.Stats.TotalActiveBans)
}

// applyGlobalBans applies bans received from Core to local ipset
func (bsm *BanSyncManager) applyGlobalBans(bans []GlobalBan) {
	appliedCount := 0
	skippedCount := 0

	for _, ban := range bans {
		// Check if already banned
		if bsm.iptablesManager.IsBanned(ban.IP) {
			skippedCount++
			continue
		}

		// Calculate remaining duration
		now := time.Now()
		if ban.ExpiresAt.Before(now) {
			// Ban already expired, skip
			skippedCount++
			continue
		}

		duration := ban.ExpiresAt.Sub(now)

		// Apply ban WITHOUT reporting back to Core (prevents infinite loop)
		// reportToSync = false means this ban came from Core, don't send it back
		var err error
		if ban.IsCIDR {
			err = bsm.iptablesManager.BanIPRangeWithSync(ban.IP, duration, ban.Reason+" (global)", false)
		} else if ban.IsPermanent {
			err = bsm.iptablesManager.AddToPermanentBlacklistWithSync(ban.IP, ban.Reason+" (global)", false)
		} else {
			err = bsm.iptablesManager.BanIPWithSync(ban.IP, duration, ban.Reason+" (global)", false)
		}

		if err != nil {
			log.Printf("[BanSync] Failed to apply global ban for %s: %v", ban.IP, err)
		} else {
			appliedCount++
		}
	}

	if appliedCount > 0 || skippedCount > 0 {
		log.Printf("[BanSync] Applied %d global bans, skipped %d (already banned or expired)",
			appliedCount, skippedCount)
	}
}

// Stop stops the ban sync manager
func (bsm *BanSyncManager) Stop() {
	close(bsm.stopChan)
}
