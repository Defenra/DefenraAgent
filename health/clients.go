package health

import (
	"time"
)

// ClientConnection represents a client connection (used by TCP proxy)
type ClientConnection struct {
	IP            string
	ConnectedAt   time.Time
	LastActivity  time.Time
	BytesSent     uint64
	BytesReceived uint64
	ProxyID       string
	ProxyPort     int
}

// HTTPClientProvider is an interface for getting HTTP/HTTPS clients
type HTTPClientProvider interface {
	GetAllClients() []HTTPClientInfo
	GetClientsByDomain(domain string) []HTTPClientInfo
}

// HTTPClientInfo represents an HTTP/HTTPS client
type HTTPClientInfo struct {
	IP            string
	ConnectedAt   time.Time
	LastActivity  time.Time
	BytesSent     uint64
	BytesReceived uint64
	Country       string
	City          string
	CountryCode   string
	UserAgent     string
	Domain        string
}

var httpClientProvider HTTPClientProvider

// SetHTTPClientProvider sets the HTTP client provider
func SetHTTPClientProvider(provider HTTPClientProvider) {
	httpClientProvider = provider
}

// GetAllHTTPClients returns all HTTP/HTTPS clients
func GetAllHTTPClients() []ClientInfo {
	if httpClientProvider == nil {
		return []ClientInfo{}
	}

	httpClients := httpClientProvider.GetAllClients()
	clients := make([]ClientInfo, 0, len(httpClients))

	for _, hc := range httpClients {
		duration := time.Since(hc.ConnectedAt)
		clients = append(clients, ClientInfo{
			IP:            hc.IP,
			ConnectedAt:   hc.ConnectedAt.Format(time.RFC3339),
			LastActivity:  hc.LastActivity.Format(time.RFC3339),
			Duration:      formatDuration(duration),
			BytesSent:     hc.BytesSent,
			BytesReceived: hc.BytesReceived,
			TotalBytes:    hc.BytesSent + hc.BytesReceived,
			ProxyID:       hc.Domain,
			ProxyPort:     0, // Not applicable for HTTP/HTTPS
		})
	}

	return clients
}

// GetHTTPClientsByDomain returns HTTP/HTTPS clients for a specific domain
func GetHTTPClientsByDomain(domain string) []ClientInfo {
	if httpClientProvider == nil {
		return []ClientInfo{}
	}

	httpClients := httpClientProvider.GetClientsByDomain(domain)
	clients := make([]ClientInfo, 0, len(httpClients))

	for _, hc := range httpClients {
		duration := time.Since(hc.ConnectedAt)
		clients = append(clients, ClientInfo{
			IP:            hc.IP,
			ConnectedAt:   hc.ConnectedAt.Format(time.RFC3339),
			LastActivity:  hc.LastActivity.Format(time.RFC3339),
			Duration:      formatDuration(duration),
			BytesSent:     hc.BytesSent,
			BytesReceived: hc.BytesReceived,
			TotalBytes:    hc.BytesSent + hc.BytesReceived,
			ProxyID:       hc.Domain,
			ProxyPort:     0,
		})
	}

	return clients
}

// getActiveClients returns TCP/UDP proxy clients
func getActiveClients(portFilter string) []ClientInfo {
	// This will be implemented by proxy package
	// For now, return empty list
	return []ClientInfo{}
}
