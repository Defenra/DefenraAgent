package health

import (
	"log"
	"os"
	"strconv"
	"time"

	"github.com/coreos/go-systemd/v22/daemon"
)

// SystemdWatchdog manages systemd watchdog notifications
// to prevent systemd from killing the agent when it appears unresponsive
type SystemdWatchdog struct {
	interval time.Duration
	stopChan chan struct{}
}

// NewSystemdWatchdog creates a new watchdog notifier
// It automatically detects the watchdog interval from systemd environment
func NewSystemdWatchdog() *SystemdWatchdog {
	interval := getWatchdogInterval()
	return &SystemdWatchdog{
		interval: interval,
		stopChan: make(chan struct{}),
	}
}

// Start begins sending periodic watchdog notifications to systemd
// This keeps the service alive during long operations like HTTP polling
func (w *SystemdWatchdog) Start() {
	if w.interval == 0 {
		log.Println("[SystemdWatchdog] Watchdog not enabled (no WATCHDOG_USEC env var)")
		return
	}

	// Send notification at half the watchdog interval to be safe
	tickerInterval := w.interval / 2
	if tickerInterval < time.Second {
		tickerInterval = time.Second
	}

	log.Printf("[SystemdWatchdog] Starting watchdog notifications every %v (watchdog timeout: %v)",
		tickerInterval, w.interval)

	ticker := time.NewTicker(tickerInterval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				w.notify()
			case <-w.stopChan:
				log.Println("[SystemdWatchdog] Stopping watchdog notifications")
				return
			}
		}
	}()
}

// Stop stops the watchdog notifications
func (w *SystemdWatchdog) Stop() {
	close(w.stopChan)
}

// notify sends a watchdog notification to systemd
func (w *SystemdWatchdog) notify() {
	if _, err := daemon.SdNotify(false, daemon.SdNotifyWatchdog); err != nil {
		log.Printf("[SystemdWatchdog] Failed to notify systemd: %v", err)
	}
}

// getWatchdogInterval reads the watchdog timeout from systemd environment
// Returns 0 if watchdog is not configured
func getWatchdogInterval() time.Duration {
	// Check if running under systemd with watchdog enabled
	watchdogUsec := os.Getenv("WATCHDOG_USEC")
	if watchdogUsec == "" {
		return 0
	}

	usec, err := strconv.ParseInt(watchdogUsec, 10, 64)
	if err != nil {
		log.Printf("[SystemdWatchdog] Invalid WATCHDOG_USEC value: %s", watchdogUsec)
		return 0
	}

	return time.Duration(usec) * time.Microsecond
}

// NotifyReady sends a ready notification to systemd
// Call this when the agent has fully started and is ready to serve requests
func NotifyReady() {
	if supported, err := daemon.SdNotify(false, daemon.SdNotifyReady); err != nil {
		log.Printf("[SystemdWatchdog] Failed to send ready notification: %v", err)
	} else if supported {
		log.Println("[SystemdWatchdog] Sent READY notification to systemd")
	}
}

// NotifyStopping sends a stopping notification to systemd
// Call this when the agent is about to shut down gracefully
func NotifyStopping() {
	if supported, err := daemon.SdNotify(false, daemon.SdNotifyStopping); err != nil {
		log.Printf("[SystemdWatchdog] Failed to send stopping notification: %v", err)
	} else if supported {
		log.Println("[SystemdWatchdog] Sent STOPPING notification to systemd")
	}
}
