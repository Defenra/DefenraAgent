package proxy

// HTTPClientTrackerAdapter adapts HTTPClientTracker to HTTPClientProvider interface
type HTTPClientTrackerAdapter struct {
	tracker *HTTPClientTracker
}

// NewHTTPClientTrackerAdapter creates a new adapter
func NewHTTPClientTrackerAdapter(tracker *HTTPClientTracker) *HTTPClientTrackerAdapter {
	return &HTTPClientTrackerAdapter{
		tracker: tracker,
	}
}

// GetAllClients implements HTTPClientProvider
func (a *HTTPClientTrackerAdapter) GetAllClients() []HTTPClientInfo {
	clients := a.tracker.GetClients()
	result := make([]HTTPClientInfo, 0, len(clients))

	for _, c := range clients {
		result = append(result, HTTPClientInfo{
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

// GetClientsByDomain implements HTTPClientProvider
func (a *HTTPClientTrackerAdapter) GetClientsByDomain(domain string) []HTTPClientInfo {
	clients := a.tracker.GetClientsByDomain(domain)
	result := make([]HTTPClientInfo, 0, len(clients))

	for _, c := range clients {
		result = append(result, HTTPClientInfo{
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

var httpClientProvider HTTPClientProvider

// SetHTTPClientProvider sets the HTTP client provider
func SetHTTPClientProvider(provider HTTPClientProvider) {
	httpClientProvider = provider
}

// GetHTTPClientProvider returns the current HTTP client provider
func GetHTTPClientProvider() HTTPClientProvider {
	return httpClientProvider
}

// InitHTTPClientProvider initializes the HTTP client provider
func InitHTTPClientProvider() {
	tracker := GetGlobalHTTPClientTracker()
	adapter := NewHTTPClientTrackerAdapter(tracker)
	SetHTTPClientProvider(adapter)
}
