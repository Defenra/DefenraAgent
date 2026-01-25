package stats

import (
	"runtime"
	"testing"
	"time"
)

func TestSystemMetricsCollector(t *testing.T) {
	collector := NewSystemMetricsCollector()

	// First collection
	metrics1, err := collector.CollectMetrics()
	if err != nil {
		t.Fatalf("Failed to collect metrics: %v", err)
	}

	// Verify basic fields are populated
	if metrics1.NumGoroutines <= 0 {
		t.Error("NumGoroutines should be positive")
	}

	if metrics1.MemoryUsedBytes == 0 {
		t.Error("MemoryUsedBytes should be positive")
	}

	if metrics1.MemoryTotalBytes == 0 {
		t.Error("MemoryTotalBytes should be positive")
	}

	if metrics1.Timestamp == 0 {
		t.Error("Timestamp should be set")
	}

	// Wait a bit and collect again to test rate calculations
	time.Sleep(1100 * time.Millisecond)

	metrics2, err := collector.CollectMetrics()
	if err != nil {
		t.Fatalf("Failed to collect metrics on second attempt: %v", err)
	}

	// Verify timestamp is updated
	if metrics2.Timestamp <= metrics1.Timestamp {
		t.Errorf("Second timestamp (%d) should be greater than first (%d)", metrics2.Timestamp, metrics1.Timestamp)
	}

	// On Linux, CPU usage should be calculated after second collection
	if runtime.GOOS == "linux" {
		// CPU usage might be 0 if system is idle, so we just check it's not negative
		if metrics2.CPUUsagePercent < 0 {
			t.Error("CPU usage should not be negative")
		}
	}

	t.Logf("Metrics collected successfully:")
	t.Logf("  CPU Usage: %.2f%%", metrics2.CPUUsagePercent)
	t.Logf("  Memory Usage: %.2f%% (%d/%d bytes)", metrics2.MemoryUsagePercent, metrics2.MemoryUsedBytes, metrics2.MemoryTotalBytes)
	t.Logf("  Goroutines: %d", metrics2.NumGoroutines)
	t.Logf("  Load Average: %.2f, %.2f, %.2f", metrics2.LoadAverage1Min, metrics2.LoadAverage5Min, metrics2.LoadAverage15Min)
	t.Logf("  Disk I/O: %d read/s, %d write/s", metrics2.DiskReadBytesPS, metrics2.DiskWriteBytesPS)
	t.Logf("  Network I/O: %d rx/s, %d tx/s", metrics2.NetworkRxBytesPS, metrics2.NetworkTxBytesPS)
}

func TestSystemMetricsCollectorMemory(t *testing.T) {
	collector := NewSystemMetricsCollector()

	metrics, err := collector.CollectMetrics()
	if err != nil {
		t.Fatalf("Failed to collect metrics: %v", err)
	}

	// Memory usage percentage should be reasonable
	if metrics.MemoryUsagePercent < 0 || metrics.MemoryUsagePercent > 100 {
		t.Errorf("Memory usage percentage should be between 0-100, got %.2f", metrics.MemoryUsagePercent)
	}

	// Used memory should be less than or equal to total memory
	if metrics.MemoryUsedBytes > metrics.MemoryTotalBytes {
		t.Errorf("Used memory (%d) should not exceed total memory (%d)", metrics.MemoryUsedBytes, metrics.MemoryTotalBytes)
	}
}

func TestSystemMetricsCollectorCrossplatform(t *testing.T) {
	collector := NewSystemMetricsCollector()

	metrics, err := collector.CollectMetrics()
	if err != nil {
		t.Fatalf("Failed to collect metrics: %v", err)
	}

	// These fields should work on all platforms
	if metrics.NumGoroutines <= 0 {
		t.Error("NumGoroutines should be positive on all platforms")
	}

	if metrics.MemoryUsedBytes == 0 {
		t.Error("MemoryUsedBytes should be positive on all platforms")
	}

	if metrics.Timestamp == 0 {
		t.Error("Timestamp should be set on all platforms")
	}

	// Platform-specific checks
	if runtime.GOOS == "linux" {
		// On Linux, we should get load average
		// Note: Load average can be 0 on idle systems, so we just check it's not negative
		if metrics.LoadAverage1Min < 0 {
			t.Error("Load average should not be negative on Linux")
		}
	} else {
		// On non-Linux systems, these should be simulated values (not 0)
		if metrics.LoadAverage1Min < 0 || metrics.LoadAverage5Min < 0 || metrics.LoadAverage15Min < 0 {
			t.Error("Load average should not be negative on non-Linux systems")
		}

		if metrics.CPUUsagePercent < 0 {
			t.Error("CPU usage should not be negative on non-Linux systems")
		}

		if metrics.DiskReadBytesPS < 0 || metrics.DiskWriteBytesPS < 0 {
			t.Error("Disk I/O should not be negative on non-Linux systems")
		}

		if metrics.NetworkRxBytesPS < 0 || metrics.NetworkTxBytesPS < 0 {
			t.Error("Network I/O should not be negative on non-Linux systems")
		}
	}
}

func BenchmarkSystemMetricsCollection(b *testing.B) {
	collector := NewSystemMetricsCollector()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := collector.CollectMetrics()
		if err != nil {
			b.Fatalf("Failed to collect metrics: %v", err)
		}
	}
}
