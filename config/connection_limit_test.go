package config

import (
	"testing"
)

func TestConfigManagerConnectionLimitCallback(t *testing.T) {
	cm := NewConfigManager("http://test.com", "test-agent", "test-key")

	// Track callback calls
	var callbackCalled bool
	var receivedLimit int

	// Set up callback
	cm.SetConnectionLimitUpdater(func(limit int) {
		callbackCalled = true
		receivedLimit = limit
	})

	// Create test domains with different connection limits
	cm.config.Domains = []Domain{
		{
			Domain: "example1.com",
			HTTPProxy: HTTPProxy{
				AntiDDoS: &AntiDDoS{
					Slowloris: &Slowloris{
						MaxConnections: 500,
					},
				},
			},
		},
		{
			Domain: "example2.com",
			HTTPProxy: HTTPProxy{
				AntiDDoS: &AntiDDoS{
					Slowloris: &Slowloris{
						MaxConnections: 1000, // This should be the highest
					},
				},
			},
		},
		{
			Domain: "example3.com",
			HTTPProxy: HTTPProxy{
				AntiDDoS: &AntiDDoS{
					Slowloris: &Slowloris{
						MaxConnections: 200,
					},
				},
			},
		},
	}

	// Call updateConnectionLimits
	cm.updateConnectionLimits()

	// Verify callback was called with the highest limit
	if !callbackCalled {
		t.Error("Connection limit callback was not called")
	}

	if receivedLimit != 1000 {
		t.Errorf("Expected callback to receive limit 1000, got %d", receivedLimit)
	}

	// Test with no AntiDDoS config (should use default)
	callbackCalled = false
	receivedLimit = 0

	cm.config.Domains = []Domain{
		{
			Domain:    "example4.com",
			HTTPProxy: HTTPProxy{
				// No AntiDDoS config
			},
		},
	}

	cm.updateConnectionLimits()

	if !callbackCalled {
		t.Error("Connection limit callback was not called for default case")
	}

	if receivedLimit != 100 { // Default minimum
		t.Errorf("Expected callback to receive default limit 100, got %d", receivedLimit)
	}

	// Test with nil Slowloris config
	callbackCalled = false
	receivedLimit = 0

	cm.config.Domains = []Domain{
		{
			Domain: "example5.com",
			HTTPProxy: HTTPProxy{
				AntiDDoS: &AntiDDoS{
					// No Slowloris config
				},
			},
		},
	}

	cm.updateConnectionLimits()

	if !callbackCalled {
		t.Error("Connection limit callback was not called for nil Slowloris case")
	}

	if receivedLimit != 100 { // Default minimum
		t.Errorf("Expected callback to receive default limit 100, got %d", receivedLimit)
	}
}
