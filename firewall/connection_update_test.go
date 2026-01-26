package firewall

import (
	"testing"
	"time"
)

func TestConnectionLimiterUpdateLimits(t *testing.T) {
	// Create connection limiter with initial limit of 5
	cl := NewConnectionLimiter(5, 1*time.Minute)
	defer cl.Stop()

	// Verify initial limit
	if cl.GetCurrentLimit() != 5 {
		t.Errorf("Expected initial limit 5, got %d", cl.GetCurrentLimit())
	}

	// Test connections with initial limit
	for i := 0; i < 5; i++ {
		if !cl.CheckConnection("192.168.1.100:12345") {
			t.Errorf("Connection %d should be allowed with limit 5", i+1)
		}
	}

	// 6th connection should be blocked
	if cl.CheckConnection("192.168.1.100:12346") {
		t.Error("6th connection should be blocked with limit 5")
	}

	// Release all connections
	for i := 0; i < 5; i++ {
		cl.ReleaseConnection("192.168.1.100:12345")
	}

	// Update limit to 10
	cl.UpdateLimits(10)

	// Verify limit was updated
	if cl.GetCurrentLimit() != 10 {
		t.Errorf("Expected updated limit 10, got %d", cl.GetCurrentLimit())
	}

	// Test connections with new limit
	for i := 0; i < 10; i++ {
		if !cl.CheckConnection("192.168.1.101:12345") {
			t.Errorf("Connection %d should be allowed with limit 10", i+1)
		}
	}

	// 11th connection should be blocked
	if cl.CheckConnection("192.168.1.101:12346") {
		t.Error("11th connection should be blocked with limit 10")
	}

	// Update limit to 2 (lower than current)
	cl.UpdateLimits(2)

	// Verify limit was updated
	if cl.GetCurrentLimit() != 2 {
		t.Errorf("Expected updated limit 2, got %d", cl.GetCurrentLimit())
	}

	// Release all connections for new test
	for i := 0; i < 10; i++ {
		cl.ReleaseConnection("192.168.1.101:12345")
	}

	// Test connections with lower limit
	for i := 0; i < 2; i++ {
		if !cl.CheckConnection("192.168.1.102:12345") {
			t.Errorf("Connection %d should be allowed with limit 2", i+1)
		}
	}

	// 3rd connection should be blocked
	if cl.CheckConnection("192.168.1.102:12346") {
		t.Error("3rd connection should be blocked with limit 2")
	}
}
