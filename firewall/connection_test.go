package firewall

import (
	"testing"
	"time"
)

func TestConnectionLimiter(t *testing.T) {
	// Create connection limiter with max 3 connections per IP
	cl := NewConnectionLimiter(3, 1*time.Minute)
	defer cl.Stop()

	testIP := "192.168.1.100:12345"

	// Test normal connections within limit
	for i := 0; i < 3; i++ {
		if !cl.CheckConnection(testIP) {
			t.Errorf("Connection %d should be allowed", i+1)
		}
	}

	// Test connection limit exceeded
	if cl.CheckConnection(testIP) {
		t.Error("Connection should be blocked when limit exceeded")
	}

	// Test that IP is blocked
	if !cl.IsBlocked(testIP) {
		t.Error("IP should be blocked after exceeding limit")
	}

	// Release some connections
	cl.ReleaseConnection(testIP)
	cl.ReleaseConnection(testIP)

	// Should still be blocked due to block timeout
	if cl.CheckConnection(testIP) {
		t.Error("Connection should still be blocked during block period")
	}

	// Test manual blocking
	testIP2 := "192.168.1.101:12346"
	cl.BlockIP(testIP2, 1*time.Second)

	if !cl.IsBlocked(testIP2) {
		t.Error("IP should be blocked after manual block")
	}

	// Wait for block to expire
	time.Sleep(1100 * time.Millisecond)

	if cl.IsBlocked(testIP2) {
		t.Error("IP should not be blocked after block expires")
	}

	// Should allow connections after block expires
	if !cl.CheckConnection(testIP2) {
		t.Error("Connection should be allowed after block expires")
	}
}

func TestConnectionLimiterStats(t *testing.T) {
	cl := NewConnectionLimiter(5, 1*time.Minute)
	defer cl.Stop()

	// Add some connections
	cl.CheckConnection("192.168.1.1:12345")
	cl.CheckConnection("192.168.1.1:12346")
	cl.CheckConnection("192.168.1.2:12347")

	stats := cl.GetStats()

	if stats["active_ips"].(int) != 2 {
		t.Errorf("Expected 2 active IPs, got %d", stats["active_ips"].(int))
	}

	if stats["total_connections"].(int) != 3 {
		t.Errorf("Expected 3 total connections, got %d", stats["total_connections"].(int))
	}

	if stats["max_conn_per_ip"].(int) != 5 {
		t.Errorf("Expected max 5 connections per IP, got %d", stats["max_conn_per_ip"].(int))
	}
}

func TestConnectionLimiterCleanup(t *testing.T) {
	// Create connection limiter with short timeout for testing
	cl := NewConnectionLimiter(10, 100*time.Millisecond)
	defer cl.Stop()

	testIP := "192.168.1.200:12345"

	// Add connection
	cl.CheckConnection(testIP)

	// Verify it exists
	stats := cl.GetStats()
	if stats["active_ips"].(int) != 1 {
		t.Error("Expected 1 active IP before cleanup")
	}

	// Release connection and wait for cleanup
	cl.ReleaseConnection(testIP)
	time.Sleep(200 * time.Millisecond)

	// Verify connection was released using GetStats
	stats = cl.GetStats()
	if totalConns, ok := stats["total_connections"].(int); ok && totalConns > 0 {
		t.Error("Connection should be released")
	}
}
