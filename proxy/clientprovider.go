package proxy

import (
	"github.com/defenra/agent/health"
)

// HTTPClientTrackerAdapter adapts HTTPClientTracker to health.HTTPClientProvider interface
type HTTPClientTrackerAdapter struct {
	tracker *HTTPClientTracker
}

// NewHTTPClientTrackerAdapter creates a new adapter
func NewHTTPClientTrackerAdapter(tracker *HTTPClientTracker) *HTTPClientTrackerAdapter {
	return &HTTPClientTrackerAdapter{
		tracker: tracker,
	}
}

// GetAllClients implements health.HTTPClientProvider
func (a *HTTPClientTrackerAdapter) GetAllClients() []health.HTTPClientInfo {
	clients := a.tracker.GetClients()
	result := make([]health.HTTPClientInfo, 0, len(clients))

	for _, c := range clients {
		result = append(result, health.HTTPClientInfo{
			IP:            c.IP,
			ConnectedAt:   c.ConnectedAt,
			LastActivity:  c.LastActivity,
			BytesSent:     c.BytesSent,
			BytesReceived: c.BytesReceived,
			Country:       c.Country,
			City:          c.City,
			CountryCode:   c.CountryCode,
			UserAgent:     c.UserAgent,
			Domain:        c.Domain,
		})
	}

	return result
}

// GetClientsByDomain implements health.HTTPClientProvider
func (a *HTTPClientTrackerAdapter) GetClientsByDomain(domain string) []health.HTTPClientInfo {
	clients := a.tracker.GetClientsByDomain(domain)
	result := make([]health.HTTPClientInfo, 0, len(clients))

	for _, c := range clients {
		result = append(result, health.HTTPClientInfo{
			IP:            c.IP,
			ConnectedAt:   c.ConnectedAt,
			LastActivity:  c.LastActivity,
			BytesSent:     c.BytesSent,
			BytesReceived: c.BytesReceived,
			Country:       c.Country,
			City:          c.City,
			CountryCode:   c.CountryCode,
			UserAgent:     c.UserAgent,
			Domain:        c.Domain,
		})
	}

	return result
}

// InitHTTPClientProvider initializes the HTTP client provider for health checks
func InitHTTPClientProvider() {
	tracker := GetGlobalHTTPClientTracker()
	adapter := NewHTTPClientTrackerAdapter(tracker)
	health.SetHTTPClientProvider(adapter)
}
