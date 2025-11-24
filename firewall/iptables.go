package firewall

import (
	"fmt"
	"log"
	"os/exec"
	"sync"
	"time"
)

type IPTablesManager struct {
	mu            sync.RWMutex
	bannedIPs     map[string]time.Time
	chainName     string
	checkInterval time.Duration
	stopChan      chan struct{}
}

var globalIPTablesManager *IPTablesManager
var globalIPTablesOnce sync.Once

func GetIPTablesManager() *IPTablesManager {
	globalIPTablesOnce.Do(func() {
		chainName := "DEFENRA_BLOCK"
		manager := &IPTablesManager{
			bannedIPs:     make(map[string]time.Time),
			chainName:     chainName,
			checkInterval: 60 * time.Second,
			stopChan:      make(chan struct{}),
		}

		// создаем цепочку iptables если её нет
		if err := manager.ensureChain(); err != nil {
			log.Printf("[Firewall] Warning: failed to create iptables chain: %v", err)
			log.Printf("[Firewall] Continuing without iptables support (may require root)")
		} else {
			go manager.cleanupExpired()
		}

		globalIPTablesManager = manager
	})
	return globalIPTablesManager
}

func NewIPTablesManager() *IPTablesManager {
	return GetIPTablesManager()
}

func (m *IPTablesManager) ensureChain() error {
	// проверяем существует ли цепочка
	cmd := exec.Command("iptables", "-t", "filter", "-L", m.chainName)
	if err := cmd.Run(); err == nil {
		return nil
	}

	// создаем цепочку
	cmd = exec.Command("iptables", "-t", "filter", "-N", m.chainName)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to create chain: %w", err)
	}

	// добавляем правило для перехода в цепочку
	cmd = exec.Command("iptables", "-t", "filter", "-C", "INPUT", "-j", m.chainName)
	if err := cmd.Run(); err != nil {
		cmd = exec.Command("iptables", "-t", "filter", "-I", "INPUT", "1", "-j", m.chainName)
		if err := cmd.Run(); err != nil {
			log.Printf("[Firewall] Warning: failed to add INPUT rule: %v", err)
		}
	}

	log.Printf("[Firewall] Created iptables chain: %s", m.chainName)
	return nil
}

func (m *IPTablesManager) BanIP(ip string, duration time.Duration) error {
	if duration <= 0 {
		duration = 24 * time.Hour
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	expiresAt := time.Now().Add(duration)
	m.bannedIPs[ip] = expiresAt

	// проверяем нет ли уже правила
	cmd := exec.Command("iptables", "-t", "filter", "-C", m.chainName, "-s", ip, "-j", "DROP")
	if err := cmd.Run(); err == nil {
		log.Printf("[Firewall] IP %s already banned", ip)
		return nil
	}

	// добавляем правило блокировки
	cmd = exec.Command("iptables", "-t", "filter", "-A", m.chainName, "-s", ip, "-j", "DROP")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to ban IP %s: %w", ip, err)
	}

	IncTotalBans()
	IncActiveBans()

	log.Printf("[Firewall] Banned IP %s for %v", ip, duration)
	return nil
}

func (m *IPTablesManager) UnbanIP(ip string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.bannedIPs, ip)
	DecActiveBans()

	// удаляем правило
	cmd := exec.Command("iptables", "-t", "filter", "-D", m.chainName, "-s", ip, "-j", "DROP")
	if err := cmd.Run(); err != nil {
		log.Printf("[Firewall] Warning: failed to remove rule for %s (may not exist): %v", ip, err)
		return nil
	}

	log.Printf("[Firewall] Unbanned IP %s", ip)
	return nil
}

func (m *IPTablesManager) IsBanned(ip string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	expiresAt, exists := m.bannedIPs[ip]
	if !exists {
		return false
	}

	if time.Now().After(expiresAt) {
		return false
	}

	return true
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

			for _, ip := range expired {
				if err := m.UnbanIP(ip); err != nil {
					log.Printf("[Firewall] Warning: failed to unban expired IP %s: %v", ip, err)
				}
			}

			if len(expired) > 0 {
				log.Printf("[Firewall] Cleaned up %d expired bans", len(expired))
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

// BanIPRange блокирует диапазон IP (CIDR)
func (m *IPTablesManager) BanIPRange(cidr string, duration time.Duration) error {
	if duration <= 0 {
		duration = 24 * time.Hour
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// проверяем нет ли уже правила
	cmd := exec.Command("iptables", "-t", "filter", "-C", m.chainName, "-s", cidr, "-j", "DROP")
	if err := cmd.Run(); err == nil {
		log.Printf("[Firewall] CIDR %s already banned", cidr)
		return nil
	}

	// добавляем правило блокировки
	cmd = exec.Command("iptables", "-t", "filter", "-A", m.chainName, "-s", cidr, "-j", "DROP")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to ban CIDR %s: %w", cidr, err)
	}

	log.Printf("[Firewall] Banned CIDR %s for %v", cidr, duration)
	return nil
}