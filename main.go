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
	"github.com/defenra/agent/updater"
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

	// регистрируем ClientTracker в health server
	health.SetClientTracker(proxy.GetGlobalClientTracker())

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
