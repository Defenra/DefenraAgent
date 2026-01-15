package proxy

import (
	"time"
)

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
