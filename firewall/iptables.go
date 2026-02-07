package firewall

import (
	"fmt"
	"log"
	"os/exec"
	"strconv"
	"sync"
	"time"
)

type IPTablesManager struct {
	mu            sync.RWMutex
	bannedIPs     map[string]time.Time
	useIPSet      bool // Use ipset instead of individual iptables rules
	blacklistSet  string
	tempbanSet    string
	cidrSet       string
	checkInterval time.Duration
	stopChan      chan struct{}
}

var globalIPTablesManager *IPTablesManager
var globalIPTablesOnce sync.Once

func GetIPTablesManager() *IPTablesManager {
	globalIPTablesOnce.Do(func() {
		manager := &IPTablesManager{
			bannedIPs:     make(map[string]time.Time),
			blacklistSet:  "defenra-blacklist",
			tempbanSet:    "defenra-tempban",
			cidrSet:       "defenra-cidr",
			checkInterval: 60 * time.Second,
			stopChan:      make(chan struct{}),
		}

		// Check if ipset is available
		if err := exec.Command("ipset", "list").Run(); err == nil {
			manager.useIPSet = true
			log.Printf("[Firewall] ipset detected, using ipset for IP blocking (O(1) lookup)")

			// Ensure ipset sets exist (created by quick-install.sh or setup-ipset.sh)
			// We don't create them here to avoid conflicts
		} else {
			manager.useIPSet = false
			log.Printf("[Firewall] ipset not available, falling back to iptables rules (O(n) lookup)")

			// Create iptables chain for fallback
			chainName := "DEFENRA_BLOCK"
			if err := manager.ensureChainLegacy(chainName); err != nil {
				log.Printf("[Firewall] Warning: failed to create iptables chain: %v", err)
				log.Printf("[Firewall] Continuing without iptables support (may require root)")
			}
		}

		go manager.cleanupExpired()
		globalIPTablesManager = manager
	})
	return globalIPTablesManager
}

func NewIPTablesManager() *IPTablesManager {
	return GetIPTablesManager()
}

// ensureChainLegacy creates iptables chain for legacy mode (without ipset)
func (m *IPTablesManager) ensureChainLegacy(chainName string) error {
	// Check if chain exists
	cmd := exec.Command("iptables", "-t", "filter", "-L", chainName)
	if err := cmd.Run(); err == nil {
		return nil
	}

	// Create chain
	cmd = exec.Command("iptables", "-t", "filter", "-N", chainName)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to create chain: %w", err)
	}

	// Add jump rule to INPUT
	cmd = exec.Command("iptables", "-t", "filter", "-C", "INPUT", "-j", chainName)
	if err := cmd.Run(); err != nil {
		cmd = exec.Command("iptables", "-t", "filter", "-I", "INPUT", "1", "-j", chainName)
		if err := cmd.Run(); err != nil {
			log.Printf("[Firewall] Warning: failed to add INPUT rule: %v", err)
		}
	}

	log.Printf("[Firewall] Created iptables chain: %s", chainName)
	return nil
}

func (m *IPTablesManager) BanIP(ip string, duration time.Duration, reason string) error {
	return m.BanIPWithSync(ip, duration, reason, true)
}

// BanIPWithSync bans an IP with optional sync reporting
// reportToSync: if true, report ban to Core for distribution to other agents
// if false, skip reporting (used when applying global bans from Core)
func (m *IPTablesManager) BanIPWithSync(ip string, duration time.Duration, reason string, reportToSync bool) error {
	if duration <= 0 {
		duration = 24 * time.Hour
	}

	if reason == "" {
		reason = "Unknown"
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	expiresAt := time.Now().Add(duration)
	m.bannedIPs[ip] = expiresAt

	// Only report to sync if this is a local ban (not from global sync)
	// This prevents infinite loop: local ban -> Core -> other agents -> Core -> ...
	if reportToSync {
		banSync := GetBanSyncManager()
		banSync.ReportBan(ip, reason, expiresAt, false, false)
	}

	if m.useIPSet {
		// Use ipset (O(1) lookup, efficient for millions of IPs)
		return m.banIPWithIPSet(ip, duration, reason)
	} else {
		// Fallback to iptables rules (O(n) lookup, slow with many IPs)
		return m.banIPWithIPTables(ip, reason)
	}
}

func (m *IPTablesManager) banIPWithIPSet(ip string, duration time.Duration, reason string) error {
	timeout := int(duration.Seconds())
	// Format: "Reason: TLS flood | Banned at 2026-01-28T20:27:17Z"
	comment := fmt.Sprintf("Reason: %s | Banned at %s", reason, time.Now().Format(time.RFC3339))

	// Check if IP is already in set
	cmd := exec.Command("ipset", "test", m.tempbanSet, ip)
	if err := cmd.Run(); err == nil {
		// Already banned, update timeout and reason
		log.Printf("[Firewall] IP %s already in ipset, updating timeout and reason", ip)
	}

	// Add to temporary ban set with timeout
	cmd = exec.Command("ipset", "add", m.tempbanSet, ip,
		"timeout", strconv.Itoa(timeout),
		"comment", comment,
		"-exist") // -exist flag updates existing entry instead of failing

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add IP %s to ipset: %w", ip, err)
	}

	IncTotalBans()
	IncActiveBans()

	log.Printf("[Firewall] Banned IP %s for %v (ipset) - Reason: %s", ip, duration, reason)
	return nil
}

func (m *IPTablesManager) banIPWithIPTables(ip string, reason string) error {
	chainName := "DEFENRA_BLOCK"

	// Check if rule already exists
	cmd := exec.Command("iptables", "-t", "filter", "-C", chainName, "-s", ip, "-j", "DROP")
	if err := cmd.Run(); err == nil {
		log.Printf("[Firewall] IP %s already banned (iptables)", ip)
		return nil
	}

	// Add blocking rule
	cmd = exec.Command("iptables", "-t", "filter", "-A", chainName, "-s", ip, "-j", "DROP")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to ban IP %s: %w", ip, err)
	}

	IncTotalBans()
	IncActiveBans()

	log.Printf("[Firewall] Banned IP %s (iptables) - Reason: %s", ip, reason)
	return nil
}

func (m *IPTablesManager) UnbanIP(ip string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.bannedIPs, ip)
	DecActiveBans()

	if m.useIPSet {
		return m.unbanIPWithIPSet(ip)
	} else {
		return m.unbanIPWithIPTables(ip)
	}
}

func (m *IPTablesManager) unbanIPWithIPSet(ip string) error {
	// Remove from both sets (permanent and temporary)
	// We ignore errors here because the IP might not be in one of the sets
	_ = exec.Command("ipset", "del", m.blacklistSet, ip).Run()
	_ = exec.Command("ipset", "del", m.tempbanSet, ip).Run()

	log.Printf("[Firewall] Unbanned IP %s (ipset)", ip)
	return nil
}

func (m *IPTablesManager) unbanIPWithIPTables(ip string) error {
	chainName := "DEFENRA_BLOCK"

	// Remove rule
	cmd := exec.Command("iptables", "-t", "filter", "-D", chainName, "-s", ip, "-j", "DROP")
	if err := cmd.Run(); err != nil {
		log.Printf("[Firewall] Warning: failed to remove rule for %s (may not exist): %v", ip, err)
		return nil
	}

	log.Printf("[Firewall] Unbanned IP %s (iptables)", ip)
	return nil
}

func (m *IPTablesManager) IsBanned(ip string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// If using ipset, check ipset ONLY (not in-memory cache)
	// This ensures we check the actual kernel state, not our local cache
	// In-memory cache is only used for fallback mode (no ipset)
	if m.useIPSet {
		// Check permanent blacklist
		cmd := exec.Command("ipset", "test", m.blacklistSet, ip)
		if cmd.Run() == nil {
			return true
		}

		// Check temporary ban list
		cmd = exec.Command("ipset", "test", m.tempbanSet, ip)
		return cmd.Run() == nil
	}

	// Fallback mode (no ipset): check in-memory cache
	expiresAt, exists := m.bannedIPs[ip]
	return exists && time.Now().Before(expiresAt)
}

// GetAllBannedIPs returns all currently banned IPs from in-memory cache
// Note: This only works for fallback mode (no ipset). For ipset mode,
// this returns the in-memory cache which may not include all IPs from ipset.
func (m *IPTablesManager) GetAllBannedIPs() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	ips := make([]string, 0, len(m.bannedIPs))
	now := time.Now()

	for ip, expiresAt := range m.bannedIPs {
		if now.Before(expiresAt) {
			ips = append(ips, ip)
		}
	}

	return ips
}

func (m *IPTablesManager) cleanupExpired() {
	ticker := time.NewTicker(m.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.mu.Lock()
			now := time.Now()
			var expired []string

			for ip, expiresAt := range m.bannedIPs {
				if now.After(expiresAt) {
					expired = append(expired, ip)
				}
			}

			m.mu.Unlock()

			// Note: ipset handles expiration automatically via timeout
			// We only need to clean up in-memory cache and legacy iptables rules
			if !m.useIPSet {
				for _, ip := range expired {
					if err := m.UnbanIP(ip); err != nil {
						log.Printf("[Firewall] Warning: failed to unban expired IP %s: %v", ip, err)
					}
				}
			} else {
				// Just clean up in-memory cache for ipset mode
				m.mu.Lock()
				for _, ip := range expired {
					delete(m.bannedIPs, ip)
				}
				m.mu.Unlock()
			}

			if len(expired) > 0 {
				log.Printf("[Firewall] Cleaned up %d expired bans from cache", len(expired))
			}

		case <-m.stopChan:
			return
		}
	}
}

func (m *IPTablesManager) GetBannedIPs() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var ips []string
	now := time.Now()

	for ip, expiresAt := range m.bannedIPs {
		if now.Before(expiresAt) {
			ips = append(ips, ip)
		}
	}

	return ips
}

func (m *IPTablesManager) GetBannedIPsInfo() []BannedIPInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []BannedIPInfo
	now := time.Now()

	for ip, expiresAt := range m.bannedIPs {
		if now.Before(expiresAt) {
			result = append(result, BannedIPInfo{
				IP:        ip,
				ExpiresAt: expiresAt,
			})
		}
	}

	return result
}

type BannedIPInfo struct {
	IP        string
	ExpiresAt time.Time
}

func (m *IPTablesManager) Stop() {
	close(m.stopChan)
}

// BanIPRange blocks IP range (CIDR)
func (m *IPTablesManager) BanIPRange(cidr string, duration time.Duration, reason string) error {
	return m.BanIPRangeWithSync(cidr, duration, reason, true)
}

// BanIPRangeWithSync blocks IP range with optional sync reporting
func (m *IPTablesManager) BanIPRangeWithSync(cidr string, duration time.Duration, reason string, reportToSync bool) error {
	if duration <= 0 {
		duration = 24 * time.Hour
	}

	if reason == "" {
		reason = "CIDR ban"
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	expiresAt := time.Now().Add(duration)

	// Only report to sync if this is a local ban
	if reportToSync {
		banSync := GetBanSyncManager()
		banSync.ReportBan(cidr, reason, expiresAt, false, true)
	}

	if m.useIPSet {
		return m.banIPRangeWithIPSet(cidr, duration, reason)
	} else {
		return m.banIPRangeWithIPTables(cidr, reason)
	}
}

func (m *IPTablesManager) banIPRangeWithIPSet(cidr string, duration time.Duration, reason string) error {
	timeout := int(duration.Seconds())
	comment := fmt.Sprintf("Reason: %s | Banned at %s", reason, time.Now().Format(time.RFC3339))

	// Add to CIDR set
	cmd := exec.Command("ipset", "add", m.cidrSet, cidr,
		"timeout", strconv.Itoa(timeout),
		"comment", comment,
		"-exist")

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add CIDR %s to ipset: %w", cidr, err)
	}

	log.Printf("[Firewall] Banned CIDR %s for %v (ipset) - Reason: %s", cidr, duration, reason)
	return nil
}

func (m *IPTablesManager) banIPRangeWithIPTables(cidr string, reason string) error {
	chainName := "DEFENRA_BLOCK"

	// Check if rule already exists
	cmd := exec.Command("iptables", "-t", "filter", "-C", chainName, "-s", cidr, "-j", "DROP")
	if err := cmd.Run(); err == nil {
		log.Printf("[Firewall] CIDR %s already banned (iptables)", cidr)
		return nil
	}

	// Add blocking rule
	cmd = exec.Command("iptables", "-t", "filter", "-A", chainName, "-s", cidr, "-j", "DROP")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to ban CIDR %s: %w", cidr, err)
	}

	log.Printf("[Firewall] Banned CIDR %s (iptables) - Reason: %s", cidr, reason)
	return nil
}

// AddToPermanentBlacklist adds IP to permanent blacklist (no timeout)
func (m *IPTablesManager) AddToPermanentBlacklist(ip string, reason string) error {
	return m.AddToPermanentBlacklistWithSync(ip, reason, true)
}

// AddToPermanentBlacklistWithSync adds IP to permanent blacklist with optional sync reporting
func (m *IPTablesManager) AddToPermanentBlacklistWithSync(ip string, reason string, reportToSync bool) error {
	if !m.useIPSet {
		log.Printf("[Firewall] Permanent blacklist requires ipset, falling back to 24h ban")
		return m.BanIPWithSync(ip, 24*time.Hour, reason, reportToSync)
	}

	if reason == "" {
		reason = "Permanent ban"
	}

	// Only report to sync if this is a local ban
	if reportToSync {
		banSync := GetBanSyncManager()
		expiresAt := time.Now().Add(100 * 365 * 24 * time.Hour)
		banSync.ReportBan(ip, reason, expiresAt, true, false)
	}

	comment := fmt.Sprintf("Reason: %s | Banned at %s", reason, time.Now().Format(time.RFC3339))

	cmd := exec.Command("ipset", "add", m.blacklistSet, ip,
		"comment", comment,
		"-exist")

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add IP %s to permanent blacklist: %w", ip, err)
	}

	log.Printf("[Firewall] Added IP %s to permanent blacklist - Reason: %s", ip, reason)
	return nil
}

// IsUsingIPSet returns true if ipset is being used
func (m *IPTablesManager) IsUsingIPSet() bool {
	return m.useIPSet
}
