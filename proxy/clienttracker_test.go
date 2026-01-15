package proxy

import (
	"testing"
	"time"
)

func TestHTTPClientTracker(t *testing.T) {
	tracker := &HTTPClientTracker{
		clients: make(map[string]*HTTPClientConnection),
		geoIP:   NewGeoIPService(),
	}

	t.Run("track new client", func(t *testing.T) {
		tracker.TrackRequest("192.168.1.1", "Mozilla/5.0", "example.com", 100, 200)

		clients := tracker.GetClients()
		if len(clients) != 1 {
			t.Fatalf("expected 1 client, got %d", len(clients))
		}

		client := clients[0]
		if client.IP != "192.168.1.1" {
			t.Errorf("expected IP 192.168.1.1, got %s", client.IP)
		}
		if client.BytesSent != 100 {
			t.Errorf("expected BytesSent 100, got %d", client.BytesSent)
		}
		if client.BytesReceived != 200 {
			t.Errorf("expected BytesReceived 200, got %d", client.BytesReceived)
		}
		if client.Domain != "example.com" {
			t.Errorf("expected domain example.com, got %s", client.Domain)
		}
	})

	t.Run("update existing client", func(t *testing.T) {
		tracker.TrackRequest("192.168.1.1", "Mozilla/5.0", "example.com", 50, 100)

		clients := tracker.GetClients()
		if len(clients) != 1 {
			t.Fatalf("expected 1 client, got %d", len(clients))
		}

		client := clients[0]
		if client.BytesSent != 150 { // 100 + 50
			t.Errorf("expected BytesSent 150, got %d", client.BytesSent)
		}
		if client.BytesReceived != 300 { // 200 + 100
			t.Errorf("expected BytesReceived 300, got %d", client.BytesReceived)
		}
	})

	t.Run("filter by domain", func(t *testing.T) {
		tracker.TrackRequest("192.168.1.2", "Mozilla/5.0", "test.com", 100, 200)

		allClients := tracker.GetClients()
		if len(allClients) != 2 {
			t.Fatalf("expected 2 clients total, got %d", len(allClients))
		}

		exampleClients := tracker.GetClientsByDomain("example.com")
		if len(exampleClients) != 1 {
			t.Fatalf("expected 1 client for example.com, got %d", len(exampleClients))
		}

		testClients := tracker.GetClientsByDomain("test.com")
		if len(testClients) != 1 {
			t.Fatalf("expected 1 client for test.com, got %d", len(testClients))
		}
	})

	t.Run("cleanup inactive clients", func(t *testing.T) {
		// Add a client with old LastActivity
		oldClient := &HTTPClientConnection{
			IP:           "192.168.1.99",
			ConnectedAt:  time.Now().Add(-2 * time.Hour),
			LastActivity: time.Now().Add(-1 * time.Hour),
			Domain:       "old.com",
		}
		tracker.clients["192.168.1.99"] = oldClient

		// Run cleanup
		tracker.cleanup()

		// Old client should be removed
		if _, exists := tracker.clients["192.168.1.99"]; exists {
			t.Error("expected old client to be removed")
		}

		// Recent clients should remain
		if _, exists := tracker.clients["192.168.1.1"]; !exists {
			t.Error("expected recent client to remain")
		}
	})
}

func TestGeoIPService(t *testing.T) {
	service := NewGeoIPService()

	t.Run("lookup public IP", func(t *testing.T) {
		// Use a known public IP (Google DNS)
		info, err := service.Lookup("8.8.8.8")
		if err != nil {
			t.Skipf("GeoIP lookup failed (may be rate limited or offline): %v", err)
		}

		if info.Country == "" {
			t.Error("expected country to be set")
		}
		if info.CountryCode == "" {
			t.Error("expected country code to be set")
		}

		t.Logf("GeoIP result: %s, %s (%s)", info.City, info.Country, info.CountryCode)
	})

	t.Run("cache works", func(t *testing.T) {
		// First lookup
		info1, err1 := service.Lookup("1.1.1.1")
		if err1 != nil {
			t.Skipf("GeoIP lookup failed: %v", err1)
		}

		// Second lookup should use cache
		info2, err2 := service.Lookup("1.1.1.1")
		if err2 != nil {
			t.Fatalf("cached lookup failed: %v", err2)
		}

		if info1.Country != info2.Country {
			t.Error("cached result differs from original")
		}

		// Check cache was used (CachedAt should be the same)
		if info1.CachedAt != info2.CachedAt {
			t.Error("expected cache to be used")
		}
	})
}
