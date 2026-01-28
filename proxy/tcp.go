package proxy

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/defenra/agent/config"
	"github.com/defenra/agent/firewall"
)

type ProxyManager struct {
	configMgr     *config.ConfigManager
	activeProxies map[int]*TCPProxy
	mu            sync.RWMutex
	stopChan      chan struct{}
	l4Protection  *firewall.L4Protection
	firewallMgr   *firewall.IPTablesManager
}

type TCPProxy struct {
	config       config.Proxy
	listener     net.Listener
	stopChan     chan struct{}
	stats        *ProxyStats
	proxyManager *ProxyManager
	clients      *ClientTracker
}

type ProxyStats struct {
	TotalConnections  uint64
	ActiveConnections uint64
	BytesSent         uint64
	BytesReceived     uint64
	mu                sync.RWMutex
}

func (ps *ProxyStats) GetStats() (totalConns, activeConns, bytesSent, bytesReceived uint64) {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	return ps.TotalConnections, ps.ActiveConnections, ps.BytesSent, ps.BytesReceived
}

type ClientConnection struct {
	IP            string
	ConnectedAt   time.Time
	LastActivity  time.Time
	BytesSent     uint64
	BytesReceived uint64
	ProxyID       string
	ProxyPort     int
}

type ClientTracker struct {
	mu      sync.RWMutex
	clients map[string]*ClientConnection // key: IP address
}

func NewClientTracker() *ClientTracker {
	return &ClientTracker{
		clients: make(map[string]*ClientConnection),
	}
}

func (ct *ClientTracker) AddClient(ip string, proxyID string, proxyPort int) {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	ct.clients[ip] = &ClientConnection{
		IP:           ip,
		ConnectedAt:  time.Now(),
		LastActivity: time.Now(),
		ProxyID:      proxyID,
		ProxyPort:    proxyPort,
	}
}

func (ct *ClientTracker) UpdateTraffic(ip string, sent, received uint64) {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	if client, exists := ct.clients[ip]; exists {
		atomic.AddUint64(&client.BytesSent, sent)
		atomic.AddUint64(&client.BytesReceived, received)
		client.LastActivity = time.Now()
	}
}

func (ct *ClientTracker) RemoveClient(ip string) {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	delete(ct.clients, ip)
}

func (ct *ClientTracker) GetClients() []*ClientConnection {
	ct.mu.RLock()
	defer ct.mu.RUnlock()

	clients := make([]*ClientConnection, 0, len(ct.clients))
	for _, client := range ct.clients {
		// копируем данные для безопасности
		clientCopy := &ClientConnection{
			IP:            client.IP,
			ConnectedAt:   client.ConnectedAt,
			LastActivity:  client.LastActivity,
			BytesSent:     atomic.LoadUint64(&client.BytesSent),
			BytesReceived: atomic.LoadUint64(&client.BytesReceived),
			ProxyID:       client.ProxyID,
			ProxyPort:     client.ProxyPort,
		}
		clients = append(clients, clientCopy)
	}
	return clients
}

var globalClientTracker *ClientTracker
var globalClientTrackerOnce sync.Once

func GetGlobalClientTracker() *ClientTracker {
	globalClientTrackerOnce.Do(func() {
		globalClientTracker = NewClientTracker()
	})
	return globalClientTracker
}

func StartProxyManager(configMgr *config.ConfigManager) {
	l4Protection := firewall.NewL4Protection(100, 1000, 60*time.Second)
	firewallMgr := firewall.GetIPTablesManager()
	// Note: SetFirewallManager will be called from main.go to avoid circular imports

	manager := &ProxyManager{
		configMgr:     configMgr,
		activeProxies: make(map[int]*TCPProxy),
		stopChan:      make(chan struct{}),
		l4Protection:  l4Protection,
		firewallMgr:   firewallMgr,
	}

	globalProxyManager = manager

	go manager.watchProxies()

	<-manager.stopChan
}

func (pm *ProxyManager) watchProxies() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	pm.updateProxies()

	for {
		select {
		case <-ticker.C:
			pm.updateProxies()
		case <-pm.stopChan:
			return
		}
	}
}

func (pm *ProxyManager) updateProxies() {
	proxies := pm.configMgr.GetProxies()

	currentPorts := make(map[int]bool)
	enabledPorts := make(map[int]bool)

	// собираем список активных и включенных прокси
	for _, proxy := range proxies {
		currentPorts[proxy.ListenPort] = true
		if proxy.Enabled {
			enabledPorts[proxy.ListenPort] = true
		}
	}

	// запускаем новые включенные прокси
	for _, proxy := range proxies {
		if !proxy.Enabled {
			continue
		}

		pm.mu.RLock()
		_, exists := pm.activeProxies[proxy.ListenPort]
		pm.mu.RUnlock()

		if !exists {
			pm.startProxy(proxy)
		}
	}

	// останавливаем прокси, которые были отключены или удалены
	pm.mu.Lock()
	for port, proxy := range pm.activeProxies {
		if !currentPorts[port] || !enabledPorts[port] {
			log.Printf("[Proxy] Stopping proxy on port %d (removed or disabled)", port)
			proxy.Stop()
			delete(pm.activeProxies, port)
		}
	}
	pm.mu.Unlock()
}

func (pm *ProxyManager) startProxy(proxyConfig config.Proxy) {
	// Skip if protocol is empty or invalid
	if proxyConfig.Protocol == "" {
		log.Printf("[Proxy] Skipping proxy with empty protocol: %s (port: %d)", proxyConfig.Name, proxyConfig.ListenPort)
		return
	}

	// Skip if proxy is disabled
	if !proxyConfig.Enabled {
		log.Printf("[Proxy] Skipping disabled proxy: %s (port: %d)", proxyConfig.Name, proxyConfig.ListenPort)
		return
	}

	switch proxyConfig.Protocol {
	case "tcp":
		pm.startTCPProxy(proxyConfig)
	case "udp":
		pm.startUDPProxy(proxyConfig)
	default:
		log.Printf("[Proxy] Unknown protocol '%s' for proxy: %s (port: %d)", proxyConfig.Protocol, proxyConfig.Name, proxyConfig.ListenPort)
	}
}

func (pm *ProxyManager) startTCPProxy(proxyConfig config.Proxy) {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", proxyConfig.ListenPort))
	if err != nil {
		log.Printf("[TCP Proxy] Failed to start on port %d: %v", proxyConfig.ListenPort, err)
		return
	}

	proxy := &TCPProxy{
		config:       proxyConfig,
		listener:     listener,
		stopChan:     make(chan struct{}),
		stats:        &ProxyStats{},
		proxyManager: pm,
		clients:      GetGlobalClientTracker(),
	}

	pm.mu.Lock()
	pm.activeProxies[proxyConfig.ListenPort] = proxy
	pm.mu.Unlock()

	log.Printf("[TCP Proxy] Started: %s on :%d → %s:%d",
		proxyConfig.Name, proxyConfig.ListenPort, proxyConfig.TargetHost, proxyConfig.TargetPort)

	go proxy.Accept()
}

func (pm *ProxyManager) GetProxyStats() map[string]*ProxyStats {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	stats := make(map[string]*ProxyStats)
	for port, proxy := range pm.activeProxies {
		stats[fmt.Sprintf("%d", port)] = proxy.stats
	}
	return stats
}

var globalProxyManager *ProxyManager

func GetGlobalProxyManager() *ProxyManager {
	return globalProxyManager
}

func (p *TCPProxy) Accept() {
	for {
		select {
		case <-p.stopChan:
			return
		default:
		}

		conn, err := p.listener.Accept()
		if err != nil {
			select {
			case <-p.stopChan:
				return
			default:
				log.Printf("[TCP Proxy] Accept error: %v", err)
				continue
			}
		}

		p.stats.mu.Lock()
		p.stats.TotalConnections++
		p.stats.ActiveConnections++
		p.stats.mu.Unlock()

		go p.handleConnection(conn)
	}
}

func (p *TCPProxy) handleConnection(clientConn net.Conn) {
	startTime := time.Now()
	clientIP := extractIP(clientConn.RemoteAddr())

	// добавляем клиента в трекер
	p.clients.AddClient(clientIP, p.config.ID, p.config.ListenPort)

	defer clientConn.Close()
	defer func() {
		p.stats.mu.Lock()
		p.stats.ActiveConnections--
		p.stats.mu.Unlock()

		// удаляем клиента из трекера после отключения
		p.clients.RemoveClient(clientIP)

		duration := time.Since(startTime)
		log.Printf("[TCP Proxy] Connection closed: %s (duration: %v)", clientIP, duration)
	}()

	// проверка iptables банов
	if p.proxyManager != nil && p.proxyManager.firewallMgr != nil {
		if p.proxyManager.firewallMgr.IsBanned(clientIP) {
			log.Printf("[TCP Proxy] Connection blocked: IP %s is banned", clientIP)
			return
		}
	}

	// L4 защита - проверка лимита соединений и rate limit
	if p.proxyManager != nil && p.proxyManager.l4Protection != nil {
		allowed, reason := p.proxyManager.l4Protection.CheckConnection(clientIP)
		if !allowed {
			log.Printf("[TCP Proxy] Connection blocked: %s", reason)
			// блокируем через iptables
			if p.proxyManager.firewallMgr != nil {
				if err := p.proxyManager.firewallMgr.BanIP(clientIP, 1*time.Hour, "TCP connection limit exceeded"); err != nil {
					log.Printf("[TCP Proxy] Failed to ban IP %s: %v", clientIP, err)
				}
			}
			return
		}
		defer p.proxyManager.l4Protection.ReleaseConnection(clientIP)

		allowed, reason = p.proxyManager.l4Protection.CheckRateLimit(clientIP)
		if !allowed {
			log.Printf("[TCP Proxy] Rate limit exceeded: %s", reason)
			if p.proxyManager.firewallMgr != nil {
				if err := p.proxyManager.firewallMgr.BanIP(clientIP, 1*time.Hour, "TCP rate limit exceeded"); err != nil {
					log.Printf("[TCP Proxy] Failed to ban IP %s: %v", clientIP, err)
				}
			}
			return
		}
	}

	// используем net.JoinHostPort для правильной обработки IPv6
	targetAddr := net.JoinHostPort(p.config.TargetHost, fmt.Sprintf("%d", p.config.TargetPort))
	targetConn, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
	if err != nil {
		log.Printf("[TCP Proxy] Failed to connect to backend %s: %v", targetAddr, err)
		return
	}
	defer targetConn.Close()

	// отправляем PROXY protocol v2 если включен
	if p.config.ProxyProtocol {
		if err := sendProxyProtocolV2(targetConn, clientConn); err != nil {
			log.Printf("[TCP Proxy] Failed to send PROXY protocol: %v", err)
			return
		}
	}

	done := make(chan struct{}, 2)
	var bytesSent, bytesReceived uint64

	go func() {
		n, _ := io.Copy(targetConn, clientConn)
		atomic.AddUint64(&bytesReceived, uint64(n))
		p.stats.mu.Lock()
		p.stats.BytesReceived += uint64(n)
		p.stats.mu.Unlock()
		done <- struct{}{}
	}()

	go func() {
		n, _ := io.Copy(clientConn, targetConn)
		atomic.AddUint64(&bytesSent, uint64(n))
		p.stats.mu.Lock()
		p.stats.BytesSent += uint64(n)
		p.stats.mu.Unlock()
		done <- struct{}{}
	}()

	<-done

	// обновляем трафик клиента
	p.clients.UpdateTraffic(clientIP, bytesSent, bytesReceived)
}

// sendProxyProtocolV2 отправляет PROXY protocol v2 header перед данными клиента
func sendProxyProtocolV2(targetConn net.Conn, clientConn net.Conn) error {
	clientAddr := clientConn.RemoteAddr()
	proxyAddr := clientConn.LocalAddr()

	clientTCPAddr, ok := clientAddr.(*net.TCPAddr)
	if !ok {
		return fmt.Errorf("client address is not TCPAddr")
	}

	proxyTCPAddr, ok := proxyAddr.(*net.TCPAddr)
	if !ok {
		return fmt.Errorf("proxy address is not TCPAddr")
	}

	// signature для PROXY protocol v2
	signature := []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}

	// version (4 bits) + command (4 bits)
	// version = 2, command = PROXY (0x1)
	versionCommand := byte(0x21)

	var family byte
	var addrLen int
	var srcAddr, dstAddr []byte

	// определяем IPv4 или IPv6
	if clientTCPAddr.IP.To4() != nil && proxyTCPAddr.IP.To4() != nil {
		// IPv4
		family = 0x11 // IPv4 + TCP
		addrLen = 12  // 4 (src) + 4 (dst) + 2 (src port) + 2 (dst port)
		srcAddr = clientTCPAddr.IP.To4()
		dstAddr = proxyTCPAddr.IP.To4()
	} else if clientTCPAddr.IP.To16() != nil && proxyTCPAddr.IP.To16() != nil {
		// IPv6
		family = 0x21 // IPv6 + TCP
		addrLen = 36  // 16 (src) + 16 (dst) + 2 (src port) + 2 (dst port)
		srcAddr = clientTCPAddr.IP.To16()
		dstAddr = proxyTCPAddr.IP.To16()
	} else {
		// UNSPEC (если адреса не совпадают по типу)
		family = 0x00
		addrLen = 0
	}

	// длина адресных данных (2 байта, big-endian)
	lengthBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(lengthBytes, uint16(addrLen))

	// собираем PROXY protocol header
	header := make([]byte, 0, 16+addrLen)
	header = append(header, signature...)
	header = append(header, versionCommand)
	header = append(header, family)
	header = append(header, lengthBytes...)

	if addrLen > 0 {
		header = append(header, srcAddr...)
		header = append(header, dstAddr...)

		// порты (2 байта каждый, big-endian)
		srcPort := make([]byte, 2)
		dstPort := make([]byte, 2)
		binary.BigEndian.PutUint16(srcPort, uint16(clientTCPAddr.Port))
		binary.BigEndian.PutUint16(dstPort, uint16(proxyTCPAddr.Port))
		header = append(header, srcPort...)
		header = append(header, dstPort...)
	}

	// отправляем header
	if _, err := targetConn.Write(header); err != nil {
		return fmt.Errorf("failed to write PROXY protocol header: %w", err)
	}

	return nil
}

func extractIP(addr net.Addr) string {
	addrStr := addr.String()
	if idx := strings.LastIndex(addrStr, ":"); idx != -1 {
		return addrStr[:idx]
	}
	return addrStr
}

func (p *TCPProxy) Stop() {
	close(p.stopChan)
	if p.listener != nil {
		p.listener.Close()
	}
}

func (pm *ProxyManager) startUDPProxy(proxyConfig config.Proxy) {
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", proxyConfig.ListenPort))
	if err != nil {
		log.Printf("[UDP Proxy] Failed to resolve address: %v", err)
		return
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Printf("[UDP Proxy] Failed to start on port %d: %v", proxyConfig.ListenPort, err)
		return
	}

	log.Printf("[UDP Proxy] Started: %s on :%d → %s:%d",
		proxyConfig.Name, proxyConfig.ListenPort, proxyConfig.TargetHost, proxyConfig.TargetPort)

	go handleUDPProxy(conn, proxyConfig)
}

func handleUDPProxy(conn *net.UDPConn, proxyConfig config.Proxy) {
	defer conn.Close()

	buffer := make([]byte, 65535)

	for {
		n, clientAddr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			log.Printf("[UDP Proxy] Read error: %v", err)
			continue
		}

		go forwardUDP(conn, clientAddr, buffer[:n], proxyConfig)
	}
}

func forwardUDP(serverConn *net.UDPConn, clientAddr *net.UDPAddr, data []byte, proxyConfig config.Proxy) {
	targetAddr, err := net.ResolveUDPAddr("udp",
		fmt.Sprintf("%s:%d", proxyConfig.TargetHost, proxyConfig.TargetPort))
	if err != nil {
		return
	}

	targetConn, err := net.DialUDP("udp", nil, targetAddr)
	if err != nil {
		return
	}
	defer targetConn.Close()

	_, err = targetConn.Write(data)
	if err != nil {
		return
	}

	responseBuffer := make([]byte, 65535)
	if err := targetConn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return
	}
	n, err := targetConn.Read(responseBuffer)
	if err != nil {
		return
	}

	if _, err := serverConn.WriteToUDP(responseBuffer[:n], clientAddr); err != nil {
		log.Printf("[UDP Proxy] Error writing response: %v", err)
	}
}
