package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/defenra/agent/config"
	"github.com/defenra/agent/dns"
	"github.com/defenra/agent/health"
	"github.com/defenra/agent/proxy"
	"github.com/defenra/agent/stats"
)

func main() {
	log.Println("Starting Defenra Agent...")

	agentID := os.Getenv("AGENT_ID")
	agentKey := os.Getenv("AGENT_KEY")
	coreURL := os.Getenv("CORE_URL")

	if agentID == "" || agentKey == "" || coreURL == "" {
		log.Fatal("Missing required environment variables: AGENT_ID, AGENT_KEY, CORE_URL")
	}

	pollingInterval := getEnvInt("POLLING_INTERVAL", 60)

	log.Printf("Agent ID: %s", agentID)
	log.Printf("Core URL: %s", coreURL)
	log.Printf("Polling Interval: %d seconds", pollingInterval)

	configMgr := config.NewConfigManager(coreURL, agentID, agentKey)

	go configMgr.StartPolling(time.Duration(pollingInterval) * time.Second)

	log.Println("Waiting for initial configuration...")
	time.Sleep(2 * time.Second)

	log.Println("Starting DNS Server on :53...")
	go dns.StartDNSServer(configMgr)

	log.Println("Starting HTTP Proxy on :80...")
	go proxy.StartHTTPProxy(configMgr)

	log.Println("Starting HTTPS Proxy on :443...")
	go proxy.StartHTTPSProxy(configMgr)

	log.Println("Starting TCP/UDP Proxy Manager...")
	go proxy.StartProxyManager(configMgr)

	log.Println("Starting Health Check on :8080...")
	go health.StartHealthCheck(configMgr)

	// настраиваем статистику коллектор
	statsCollector := stats.GetCollector()
	statsCollector.SetConfig(coreURL, agentID, agentKey)

	// запускаем отправку статистики каждые 5 минут
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			statsCollector.SendStatistics()
		}
	}()

	log.Println("Defenra Agent started successfully")

	select {}
}

func getEnvInt(key string, defaultVal int) int {
	val := os.Getenv(key)
	if val == "" {
		return defaultVal
	}
	var result int
	if _, err := fmt.Sscanf(val, "%d", &result); err != nil {
		return defaultVal
	}
	return result
}
