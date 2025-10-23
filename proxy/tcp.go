package proxy

import (
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/defenra/agent/config"
)

type ProxyManager struct {
	configMgr     *config.ConfigManager
	activeProxies map[int]*TCPProxy
	mu            sync.RWMutex
	stopChan      chan struct{}
}

type TCPProxy struct {
	config   config.Proxy
	listener net.Listener
	stopChan chan struct{}
	stats    *ProxyStats
}

type ProxyStats struct {
	TotalConnections  uint64
	ActiveConnections uint64
	BytesSent         uint64
	BytesReceived     uint64
	mu                sync.RWMutex
}

func StartProxyManager(configMgr *config.ConfigManager) {
	manager := &ProxyManager{
		configMgr:     configMgr,
		activeProxies: make(map[int]*TCPProxy),
		stopChan:      make(chan struct{}),
	}

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
	for _, proxy := range proxies {
		currentPorts[proxy.ListenPort] = true

		pm.mu.RLock()
		_, exists := pm.activeProxies[proxy.ListenPort]
		pm.mu.RUnlock()

		if !exists {
			pm.startProxy(proxy)
		}
	}

	pm.mu.Lock()
	for port, proxy := range pm.activeProxies {
		if !currentPorts[port] {
			log.Printf("[Proxy] Stopping proxy on port %d", port)
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
		config:   proxyConfig,
		listener: listener,
		stopChan: make(chan struct{}),
		stats:    &ProxyStats{},
	}

	pm.mu.Lock()
	pm.activeProxies[proxyConfig.ListenPort] = proxy
	pm.mu.Unlock()

	log.Printf("[TCP Proxy] Started: %s on :%d → %s:%d",
		proxyConfig.Name, proxyConfig.ListenPort, proxyConfig.TargetHost, proxyConfig.TargetPort)

	go proxy.Accept()
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
	defer clientConn.Close()
	defer func() {
		p.stats.mu.Lock()
		p.stats.ActiveConnections--
		p.stats.mu.Unlock()
	}()

	targetAddr := fmt.Sprintf("%s:%d", p.config.TargetHost, p.config.TargetPort)
	targetConn, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
	if err != nil {
		log.Printf("[TCP Proxy] Failed to connect to backend %s: %v", targetAddr, err)
		return
	}
	defer targetConn.Close()

	done := make(chan struct{}, 2)

	go func() {
		n, _ := io.Copy(targetConn, clientConn)
		p.stats.mu.Lock()
		p.stats.BytesReceived += uint64(n)
		p.stats.mu.Unlock()
		done <- struct{}{}
	}()

	go func() {
		n, _ := io.Copy(clientConn, targetConn)
		p.stats.mu.Lock()
		p.stats.BytesSent += uint64(n)
		p.stats.mu.Unlock()
		done <- struct{}{}
	}()

	<-done
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
