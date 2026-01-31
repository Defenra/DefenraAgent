package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/defenra/agent/config"
	"github.com/defenra/agent/dns"
	"github.com/defenra/agent/firewall"
	"github.com/defenra/agent/health"
	"github.com/defenra/agent/proxy"
	"github.com/defenra/agent/stats"
	"github.com/defenra/agent/updater"
	"github.com/defenra/agent/utils"
)

func main() {
	// Handle CLI commands
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version", "--version", "-v":
			printVersion()
			return
		case "update":
			handleUpdate()
			return
		case "check-update":
			handleCheckUpdate()
			return
		case "help", "--help", "-h":
			printHelp()
			return
		}
	}

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

	// Set agent ID for challenge pages (used in D-Agent-ID header format: GEO+ID[:8])
	challengeMgr := firewall.GetChallengeManager()
	challengeMgr.SetAgentID(agentID)

	// Set up connection limit updater callback
	configMgr.SetConnectionLimitUpdater(func(maxConnPerIP int) {
		connLimiter := firewall.GetConnectionLimiter()
		connLimiter.UpdateLimits(maxConnPerIP)
	})

	utils.SafeGo(func() {
		configMgr.StartPolling(time.Duration(pollingInterval) * time.Second)
	}, "ConfigPolling")

	log.Println("Waiting for initial configuration...")
	time.Sleep(2 * time.Second)

	log.Println("Starting DNS Server on :53...")
	utils.SafeGo(func() {
		dns.StartDNSServer(configMgr)
	}, "DNSServer")

	log.Println("Starting HTTP Proxy on :80...")
	utils.SafeGo(func() {
		proxy.StartHTTPProxy(configMgr)
	}, "HTTPProxy")

	log.Println("Starting HTTPS Proxy on :443...")
	utils.SafeGo(func() {
		proxy.StartHTTPSProxy(configMgr)
	}, "HTTPSProxy")

	log.Println("Starting TCP/UDP Proxy Manager...")
	utils.SafeGo(func() {
		proxy.StartProxyManager(configMgr)
	}, "ProxyManager")

	// Initialize firewall manager for health checks (avoid circular imports)
	firewallMgr := firewall.GetIPTablesManager()
	health.SetFirewallManager(firewallMgr)

	log.Println("Starting Health Check on :8080...")
	utils.SafeGo(func() {
		health.StartHealthCheck(configMgr)
	}, "HealthCheck")

	// Initialize HTTP client provider for health checks
	proxy.InitHTTPClientProvider()

	// Initialize agent discovery for anycast routing
	log.Println("Starting Agent Discovery...")
	agentDiscovery := proxy.GetAgentDiscovery(coreURL, agentKey)
	_ = agentDiscovery // Discovery starts automatically

	// Initialize ban synchronization manager
	log.Println("[BanSync] Initializing ban synchronization...")
	banSyncManager := firewall.GetBanSyncManager()
	banSyncManager.SetConfig(coreURL, agentKey)
	log.Println("[BanSync] Starting ban sync (every 30 seconds)...")
	utils.SafeGo(func() {
		banSyncManager.StartSync()
	}, "BanSync")

	// настраиваем статистику коллектор ПЕРЕД запуском горутин
	log.Println("[Stats] Initializing statistics collector...")
	statsCollector := stats.GetCollector()
	log.Println("[Stats] Got collector instance")
	statsCollector.SetConfig(coreURL, agentID, agentKey)
	log.Printf("[Stats] Statistics collector configured with coreURL=%s, agentID=%s", coreURL, agentID)

	// Тестируем сразу отправку статистики
	log.Println("[Stats] Testing immediate statistics send...")
	statsCollector.SendStatistics()

	// запускаем отправку статистики каждые 2 минуты (более частая отправка)
	utils.SafeGo(func() {
		ticker := time.NewTicker(2 * time.Minute)
		defer ticker.Stop()

		// Небольшая задержка чтобы все сервисы запустились
		time.Sleep(3 * time.Second)

		// Отправляем статистику сразу при запуске
		log.Println("[Stats] Sending initial statistics...")
		statsCollector.SendStatistics()

		for range ticker.C {
			log.Println("[Stats] Sending periodic statistics...")
			statsCollector.SendStatistics()
		}
	}, "StatsCollector")

	// запускаем отправку данных о клиентах каждые 1 минуту (более частая отправка)
	utils.SafeGo(func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()

		// Небольшая задержка чтобы все сервисы запустились
		time.Sleep(5 * time.Second)

		// Отправляем данные о клиентах сразу при запуске
		log.Println("[Stats] Sending initial client data...")
		statsCollector.SendClientData()

		for range ticker.C {
			log.Println("[Stats] Sending periodic client data...")
			statsCollector.SendClientData()
		}
	}, "ClientDataCollector")

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

func printVersion() {
	fmt.Printf("Defenra Agent\n")
	fmt.Printf("Version:    %s\n", Version)
	fmt.Printf("Build Date: %s\n", BuildDate)
	fmt.Printf("Git Commit: %s\n", GitCommit)
	fmt.Printf("Go Version: %s\n", "go1.21+")
	fmt.Printf("OS/Arch:    %s/%s\n", "linux", "amd64")
}

func printHelp() {
	fmt.Println("Defenra Agent - Distributed DDoS Protection & GeoDNS Platform")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  defenra-agent                Start the agent (requires env vars)")
	fmt.Println("  defenra-agent version        Show version information")
	fmt.Println("  defenra-agent update         Update to the latest version")
	fmt.Println("  defenra-agent check-update   Check if update is available")
	fmt.Println("  defenra-agent help           Show this help message")
	fmt.Println()
	fmt.Println("Environment Variables:")
	fmt.Println("  AGENT_ID          Agent identifier (required)")
	fmt.Println("  AGENT_KEY         Agent authentication key (required)")
	fmt.Println("  CORE_URL          Core API URL (required)")
	fmt.Println("  POLLING_INTERVAL  Config polling interval in seconds (default: 60)")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  # Check for updates")
	fmt.Println("  defenra-agent check-update")
	fmt.Println()
	fmt.Println("  # Update to latest version")
	fmt.Println("  sudo defenra-agent update")
	fmt.Println()
	fmt.Println("Documentation: https://github.com/Defenra/DefenraAgent")
}

func handleUpdate() {
	fmt.Println("🔍 Checking for updates...")
	fmt.Printf("Current version: %s\n\n", Version)

	if err := updater.PerformUpdate(Version); err != nil {
		fmt.Fprintf(os.Stderr, "❌ Update failed: %v\n", err)
		os.Exit(1)
	}
}

func handleCheckUpdate() {
	fmt.Println("🔍 Checking for updates...")
	fmt.Printf("Current version: %s\n", Version)

	hasUpdate, latestVersion, err := updater.CheckForUpdate(Version)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Failed to check for updates: %v\n", err)
		os.Exit(1)
	}

	if hasUpdate {
		fmt.Printf("✨ New version available: %s\n", latestVersion)
		fmt.Println("\nTo update, run:")
		fmt.Println("  sudo defenra-agent update")
	} else {
		fmt.Printf("✓ You are running the latest version: %s\n", Version)
	}
}
