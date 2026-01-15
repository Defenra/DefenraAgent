package health

import (
	"fmt"
	"time"

	"github.com/defenra/agent/proxy"
)

// GetAllHTTPClients returns all HTTP/HTTPS clients
func GetAllHTTPClients() []ClientInfo {
	provider := proxy.GetHTTPClientProvider()
	if provider == nil {
		return []ClientInfo{}
	}

	httpClients := provider.GetAllClients()
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
	provider := proxy.GetHTTPClientProvider()
	if provider == nil {
		return []ClientInfo{}
	}

	httpClients := provider.GetClientsByDomain(domain)
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
	tracker := proxy.GetGlobalClientTracker()
	if tracker == nil {
		return []ClientInfo{}
	}

	clients := tracker.GetClients()
	result := make([]ClientInfo, 0, len(clients))

	for _, client := range clients {
		// Filter by port if specified
		if portFilter != "" && fmt.Sprintf("%d", client.ProxyPort) != portFilter {
			continue
		}

		duration := time.Since(client.ConnectedAt)
		result = append(result, ClientInfo{
			IP:            client.IP,
			ConnectedAt:   client.ConnectedAt.Format(time.RFC3339),
			LastActivity:  client.LastActivity.Format(time.RFC3339),
			Duration:      formatDuration(duration),
			BytesSent:     client.BytesSent,
			BytesReceived: client.BytesReceived,
			TotalBytes:    client.BytesSent + client.BytesReceived,
			ProxyID:       client.ProxyID,
			ProxyPort:     client.ProxyPort,
		})
	}

	return result
}
