package stats

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// SystemMetrics represents system performance metrics
type SystemMetrics struct {
	CPUUsagePercent    float64 `json:"cpuUsagePercent"`
	MemoryUsagePercent float64 `json:"memoryUsagePercent"`
	MemoryUsedBytes    uint64  `json:"memoryUsedBytes"`
	MemoryTotalBytes   uint64  `json:"memoryTotalBytes"`
	DiskReadBytesPS    uint64  `json:"diskReadBytesPS"`
	DiskWriteBytesPS   uint64  `json:"diskWriteBytesPS"`
	NetworkRxBytesPS   uint64  `json:"networkRxBytesPS"`
	NetworkTxBytesPS   uint64  `json:"networkTxBytesPS"`
	LoadAverage1Min    float64 `json:"loadAverage1Min"`
	LoadAverage5Min    float64 `json:"loadAverage5Min"`
	LoadAverage15Min   float64 `json:"loadAverage15Min"`
	NumGoroutines      int     `json:"numGoroutines"`
	Timestamp          int64   `json:"timestamp"`
}

// SystemMetricsCollector collects system performance metrics
type SystemMetricsCollector struct {
	lastCPUStats     *cpuStats
	lastDiskStats    *diskStats
	lastNetworkStats *networkStats
	lastCollectTime  time.Time
}

type cpuStats struct {
	user    uint64
	nice    uint64
	system  uint64
	idle    uint64
	iowait  uint64
	irq     uint64
	softirq uint64
	steal   uint64
}

type diskStats struct {
	readBytes  uint64
	writeBytes uint64
}

type networkStats struct {
	rxBytes uint64
	txBytes uint64
}

// NewSystemMetricsCollector creates a new system metrics collector
func NewSystemMetricsCollector() *SystemMetricsCollector {
	return &SystemMetricsCollector{}
}

// CollectMetrics collects current system metrics
func (smc *SystemMetricsCollector) CollectMetrics() (*SystemMetrics, error) {
	now := time.Now()

	metrics := &SystemMetrics{
		NumGoroutines: runtime.NumGoroutine(),
		Timestamp:     now.Unix(),
	}

	// Collect memory metrics
	if err := smc.collectMemoryMetrics(metrics); err != nil {
		return nil, fmt.Errorf("failed to collect memory metrics: %w", err)
	}

	// Collect CPU metrics (requires previous measurement for percentage calculation)
	if err := smc.collectCPUMetrics(metrics, now); err != nil {
		return nil, fmt.Errorf("failed to collect CPU metrics: %w", err)
	}

	// Collect disk I/O metrics
	if err := smc.collectDiskMetrics(metrics, now); err != nil {
		return nil, fmt.Errorf("failed to collect disk metrics: %w", err)
	}

	// Collect network I/O metrics
	if err := smc.collectNetworkMetrics(metrics, now); err != nil {
		return nil, fmt.Errorf("failed to collect network metrics: %w", err)
	}

	// Collect load average (Linux/Unix only)
	if err := smc.collectLoadAverage(metrics); err != nil {
		// Load average is not critical, just log and continue
		// On Windows this will fail, which is expected
	}

	smc.lastCollectTime = now
	return metrics, nil
}

func (smc *SystemMetricsCollector) collectMemoryMetrics(metrics *SystemMetrics) error {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	// Use Go runtime memory stats as base
	metrics.MemoryUsedBytes = m.Alloc

	// Try to get system memory info
	if runtime.GOOS == "linux" {
		if total, used, err := getLinuxMemoryInfo(); err == nil {
			metrics.MemoryTotalBytes = total
			metrics.MemoryUsedBytes = used
			if total > 0 {
				metrics.MemoryUsagePercent = float64(used) / float64(total) * 100
			}
		} else {
			// Fallback to runtime stats
			metrics.MemoryTotalBytes = m.Sys
			if m.Sys > 0 {
				metrics.MemoryUsagePercent = float64(m.Alloc) / float64(m.Sys) * 100
			}
		}
	} else {
		// For non-Linux systems, use runtime stats
		metrics.MemoryTotalBytes = m.Sys
		if m.Sys > 0 {
			metrics.MemoryUsagePercent = float64(m.Alloc) / float64(m.Sys) * 100
		}
	}

	return nil
}

func (smc *SystemMetricsCollector) collectCPUMetrics(metrics *SystemMetrics, now time.Time) error {
	if runtime.GOOS != "linux" {
		// For non-Linux systems, we can't easily get CPU usage
		// Set to 0 to indicate unavailable
		metrics.CPUUsagePercent = 0
		return nil
	}

	currentStats, err := getLinuxCPUStats()
	if err != nil {
		return err
	}

	// Calculate CPU usage percentage if we have previous stats
	if smc.lastCPUStats != nil && !smc.lastCollectTime.IsZero() {
		timeDelta := now.Sub(smc.lastCollectTime).Seconds()
		if timeDelta > 0 {
			metrics.CPUUsagePercent = calculateCPUUsage(smc.lastCPUStats, currentStats)
		}
	}

	smc.lastCPUStats = currentStats
	return nil
}

func (smc *SystemMetricsCollector) collectDiskMetrics(metrics *SystemMetrics, now time.Time) error {
	if runtime.GOOS != "linux" {
		// For non-Linux systems, set to 0
		metrics.DiskReadBytesPS = 0
		metrics.DiskWriteBytesPS = 0
		return nil
	}

	currentStats, err := getLinuxDiskStats()
	if err != nil {
		return err
	}

	// Calculate per-second rates if we have previous stats
	if smc.lastDiskStats != nil && !smc.lastCollectTime.IsZero() {
		timeDelta := now.Sub(smc.lastCollectTime).Seconds()
		if timeDelta > 0 {
			readDelta := currentStats.readBytes - smc.lastDiskStats.readBytes
			writeDelta := currentStats.writeBytes - smc.lastDiskStats.writeBytes

			metrics.DiskReadBytesPS = uint64(float64(readDelta) / timeDelta)
			metrics.DiskWriteBytesPS = uint64(float64(writeDelta) / timeDelta)
		}
	}

	smc.lastDiskStats = currentStats
	return nil
}

func (smc *SystemMetricsCollector) collectNetworkMetrics(metrics *SystemMetrics, now time.Time) error {
	if runtime.GOOS != "linux" {
		// For non-Linux systems, set to 0
		metrics.NetworkRxBytesPS = 0
		metrics.NetworkTxBytesPS = 0
		return nil
	}

	currentStats, err := getLinuxNetworkStats()
	if err != nil {
		return err
	}

	// Calculate per-second rates if we have previous stats
	if smc.lastNetworkStats != nil && !smc.lastCollectTime.IsZero() {
		timeDelta := now.Sub(smc.lastCollectTime).Seconds()
		if timeDelta > 0 {
			rxDelta := currentStats.rxBytes - smc.lastNetworkStats.rxBytes
			txDelta := currentStats.txBytes - smc.lastNetworkStats.txBytes

			metrics.NetworkRxBytesPS = uint64(float64(rxDelta) / timeDelta)
			metrics.NetworkTxBytesPS = uint64(float64(txDelta) / timeDelta)
		}
	}

	smc.lastNetworkStats = currentStats
	return nil
}

func (smc *SystemMetricsCollector) collectLoadAverage(metrics *SystemMetrics) error {
	if runtime.GOOS != "linux" {
		// For non-Linux systems, set to 0
		metrics.LoadAverage1Min = 0
		metrics.LoadAverage5Min = 0
		metrics.LoadAverage15Min = 0
		return nil
	}

	load1, load5, load15, err := getLinuxLoadAverage()
	if err != nil {
		return err
	}

	metrics.LoadAverage1Min = load1
	metrics.LoadAverage5Min = load5
	metrics.LoadAverage15Min = load15
	return nil
}

// Linux-specific functions

func getLinuxMemoryInfo() (total, used uint64, err error) {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0, err
	}
	defer file.Close()

	var memTotal, memFree, buffers, cached uint64
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		value, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}

		// Convert from KB to bytes
		value *= 1024

		switch fields[0] {
		case "MemTotal:":
			memTotal = value
		case "MemFree:":
			memFree = value
		case "Buffers:":
			buffers = value
		case "Cached:":
			cached = value
		}
	}

	if memTotal == 0 {
		return 0, 0, fmt.Errorf("could not parse MemTotal from /proc/meminfo")
	}

	// Used memory = Total - Free - Buffers - Cached
	used = memTotal - memFree - buffers - cached
	return memTotal, used, nil
}

func getLinuxCPUStats() (*cpuStats, error) {
	file, err := os.Open("/proc/stat")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if !scanner.Scan() {
		return nil, fmt.Errorf("could not read first line from /proc/stat")
	}

	line := scanner.Text()
	fields := strings.Fields(line)
	if len(fields) < 8 || fields[0] != "cpu" {
		return nil, fmt.Errorf("invalid CPU stats format in /proc/stat")
	}

	stats := &cpuStats{}
	var err2 error

	if stats.user, err2 = strconv.ParseUint(fields[1], 10, 64); err2 != nil {
		return nil, err2
	}
	if stats.nice, err2 = strconv.ParseUint(fields[2], 10, 64); err2 != nil {
		return nil, err2
	}
	if stats.system, err2 = strconv.ParseUint(fields[3], 10, 64); err2 != nil {
		return nil, err2
	}
	if stats.idle, err2 = strconv.ParseUint(fields[4], 10, 64); err2 != nil {
		return nil, err2
	}
	if stats.iowait, err2 = strconv.ParseUint(fields[5], 10, 64); err2 != nil {
		return nil, err2
	}
	if stats.irq, err2 = strconv.ParseUint(fields[6], 10, 64); err2 != nil {
		return nil, err2
	}
	if stats.softirq, err2 = strconv.ParseUint(fields[7], 10, 64); err2 != nil {
		return nil, err2
	}
	if len(fields) > 8 {
		if stats.steal, err2 = strconv.ParseUint(fields[8], 10, 64); err2 != nil {
			return nil, err2
		}
	}

	return stats, nil
}

func calculateCPUUsage(prev, curr *cpuStats) float64 {
	prevTotal := prev.user + prev.nice + prev.system + prev.idle + prev.iowait + prev.irq + prev.softirq + prev.steal
	currTotal := curr.user + curr.nice + curr.system + curr.idle + curr.iowait + curr.irq + curr.softirq + curr.steal

	prevIdle := prev.idle + prev.iowait
	currIdle := curr.idle + curr.iowait

	totalDelta := currTotal - prevTotal
	idleDelta := currIdle - prevIdle

	if totalDelta == 0 {
		return 0
	}

	return float64(totalDelta-idleDelta) / float64(totalDelta) * 100
}

func getLinuxDiskStats() (*diskStats, error) {
	file, err := os.Open("/proc/diskstats")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	stats := &diskStats{}
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 14 {
			continue
		}

		// Skip loop devices and ram devices
		deviceName := fields[2]
		if strings.HasPrefix(deviceName, "loop") || strings.HasPrefix(deviceName, "ram") {
			continue
		}

		// Read sectors (field 5) and write sectors (field 9)
		// Each sector is 512 bytes
		readSectors, err1 := strconv.ParseUint(fields[5], 10, 64)
		writeSectors, err2 := strconv.ParseUint(fields[9], 10, 64)

		if err1 == nil && err2 == nil {
			stats.readBytes += readSectors * 512
			stats.writeBytes += writeSectors * 512
		}
	}

	return stats, nil
}

func getLinuxNetworkStats() (*networkStats, error) {
	file, err := os.Open("/proc/net/dev")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	stats := &networkStats{}
	scanner := bufio.NewScanner(file)

	// Skip header lines
	scanner.Scan()
	scanner.Scan()

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 17 {
			continue
		}

		// Skip loopback interface
		interfaceName := strings.TrimSuffix(fields[0], ":")
		if interfaceName == "lo" {
			continue
		}

		// RX bytes (field 1) and TX bytes (field 9)
		rxBytes, err1 := strconv.ParseUint(fields[1], 10, 64)
		txBytes, err2 := strconv.ParseUint(fields[9], 10, 64)

		if err1 == nil && err2 == nil {
			stats.rxBytes += rxBytes
			stats.txBytes += txBytes
		}
	}

	return stats, nil
}

func getLinuxLoadAverage() (load1, load5, load15 float64, err error) {
	file, err := os.Open("/proc/loadavg")
	if err != nil {
		return 0, 0, 0, err
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return 0, 0, 0, err
	}

	fields := strings.Fields(string(data))
	if len(fields) < 3 {
		return 0, 0, 0, fmt.Errorf("invalid format in /proc/loadavg")
	}

	load1, err = strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0, 0, 0, err
	}

	load5, err = strconv.ParseFloat(fields[1], 64)
	if err != nil {
		return 0, 0, 0, err
	}

	load15, err = strconv.ParseFloat(fields[2], 64)
	if err != nil {
		return 0, 0, 0, err
	}

	return load1, load5, load15, nil
}
