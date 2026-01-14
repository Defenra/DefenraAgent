package proxy

import (
	"crypto/tls"
	"net/http"
	"testing"
)

func TestCreateHTTPClient_EncryptionModes(t *testing.T) {
	tests := []struct {
		name           string
		encryptionMode string
		wantInsecure   *bool // nil means no TLS config expected
	}{
		{
			name:           "off mode - no TLS",
			encryptionMode: "off",
			wantInsecure:   nil,
		},
		{
			name:           "flexible mode - no TLS",
			encryptionMode: "flexible",
			wantInsecure:   nil,
		},
		{
			name:           "full mode - insecure TLS",
			encryptionMode: "full",
			wantInsecure:   boolPtr(true),
		},
		{
			name:           "full_strict mode - secure TLS",
			encryptionMode: "full_strict",
			wantInsecure:   boolPtr(false),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := createHTTPClient(tt.encryptionMode)

			if client == nil {
				t.Fatal("createHTTPClient returned nil")
			}

			if client.Timeout == 0 {
				t.Error("Client timeout not set")
			}

			if tt.wantInsecure == nil {
				// No TLS config expected (off/flexible modes)
				if transport, ok := client.Transport.(*http.Transport); ok {
					if transport.TLSClientConfig != nil {
						t.Errorf("Expected no TLS config for mode %s, but got one", tt.encryptionMode)
					}
				}
			} else {
				// TLS config expected (full/full_strict modes)
				transport, ok := client.Transport.(*http.Transport)
				if !ok {
					t.Fatal("Expected http.Transport")
				}

				if transport.TLSClientConfig == nil {
					t.Fatal("Expected TLS config but got nil")
				}

				if transport.TLSClientConfig.InsecureSkipVerify != *tt.wantInsecure {
					t.Errorf("InsecureSkipVerify = %v, want %v",
						transport.TLSClientConfig.InsecureSkipVerify, *tt.wantInsecure)
				}
			}
		})
	}
}

func TestCreateHTTPClient_Timeout(t *testing.T) {
	client := createHTTPClient("full_strict")

	if client.Timeout == 0 {
		t.Error("Client timeout should be set")
	}

	if client.CheckRedirect == nil {
		t.Error("CheckRedirect should be set")
	}

	// Test that CheckRedirect returns ErrUseLastResponse
	err := client.CheckRedirect(nil, nil)
	if err != http.ErrUseLastResponse {
		t.Errorf("CheckRedirect should return ErrUseLastResponse, got %v", err)
	}
}

func TestCreateHTTPClient_TLSVersions(t *testing.T) {
	client := createHTTPClient("full_strict")

	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("Expected http.Transport")
	}

	if transport.TLSClientConfig == nil {
		t.Fatal("Expected TLS config")
	}

	// Verify that we're not setting a minimum TLS version (use Go defaults)
	if transport.TLSClientConfig.MinVersion != 0 && transport.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		t.Errorf("TLS version too low: %d", transport.TLSClientConfig.MinVersion)
	}
}

func boolPtr(b bool) *bool {
	return &b
}
