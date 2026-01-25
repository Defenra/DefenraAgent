package dns

import (
	"net"
	"testing"

	"github.com/defenra/agent/config"
	"github.com/miekg/dns"
)

// MockConfigManager for testing
type MockConfigManager struct {
	domains map[string]*config.Domain
	agentIP string
}

func NewMockConfigManager() *MockConfigManager {
	return &MockConfigManager{
		domains: make(map[string]*config.Domain),
		agentIP: "94.159.110.227", // Test agent IP
	}
}

func (m *MockConfigManager) GetDomain(domain string) *config.Domain {
	return m.domains[domain]
}

func (m *MockConfigManager) AddDomain(domain *config.Domain) {
	m.domains[domain.Domain] = domain
}

func (m *MockConfigManager) GetAgentIP() string {
	return m.agentIP
}

func TestCNAMEFlattening(t *testing.T) {
	tests := []struct {
		name           string
		domain         *config.Domain
		queryName      string
		queryType      uint16
		expectedAnswer bool
		expectedIP     string
		expectedCNAME  string
	}{
		{
			name: "CNAME with HTTPProxyEnabled should return A record with agent IP",
			domain: &config.Domain{
				Domain: "example.com",
				DNSRecords: []config.DNSRecord{
					{
						Type:             "CNAME",
						Name:             "www",
						Value:            "example.com",
						TTL:              300,
						HTTPProxyEnabled: true,
					},
				},
				GeoDNSMap: map[string]string{},
			},
			queryName:      "www.example.com",
			queryType:      dns.TypeA,
			expectedAnswer: true,
			expectedIP:     "94.159.110.227", // Agent IP
		},
		{
			name: "CNAME without HTTPProxyEnabled should return CNAME record",
			domain: &config.Domain{
				Domain: "example.com",
				DNSRecords: []config.DNSRecord{
					{
						Type:             "CNAME",
						Name:             "www",
						Value:            "example.com",
						TTL:              300,
						HTTPProxyEnabled: false,
					},
				},
				GeoDNSMap: map[string]string{},
			},
			queryName:      "www.example.com",
			queryType:      dns.TypeA,
			expectedAnswer: true,
			expectedCNAME:  "example.com.",
		},
		{
			name: "CNAME with HTTPProxyEnabled and GeoDNS should use GeoDNS IP",
			domain: &config.Domain{
				Domain: "example.com",
				DNSRecords: []config.DNSRecord{
					{
						Type:             "CNAME",
						Name:             "www",
						Value:            "example.com",
						TTL:              300,
						HTTPProxyEnabled: true,
					},
				},
				GeoDNSMap: map[string]string{
					"default": "1.2.3.4",
					"us":      "5.6.7.8",
				},
			},
			queryName:      "www.example.com",
			queryType:      dns.TypeA,
			expectedAnswer: true,
			expectedIP:     "1.2.3.4", // GeoDNS default IP
		},
		{
			name: "CNAME query (not A) should return CNAME even with HTTPProxyEnabled",
			domain: &config.Domain{
				Domain: "example.com",
				DNSRecords: []config.DNSRecord{
					{
						Type:             "CNAME",
						Name:             "www",
						Value:            "example.com",
						TTL:              300,
						HTTPProxyEnabled: true,
					},
				},
				GeoDNSMap: map[string]string{},
			},
			queryName:      "www.example.com",
			queryType:      dns.TypeCNAME,
			expectedAnswer: true,
			expectedCNAME:  "example.com.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock config manager
			configMgr := NewMockConfigManager()
			configMgr.AddDomain(tt.domain)

			// Create DNS server
			server := &DNSServer{
				configMgr: configMgr,
				geoIP:     nil, // No GeoIP for testing
				cache:     NewDNSCache(100),
				stats:     &DNSStats{},
			}

			// Create DNS query
			msg := new(dns.Msg)
			msg.SetQuestion(dns.Fqdn(tt.queryName), tt.queryType)

			// Create mock response writer
			mockWriter := &MockResponseWriter{}

			// Handle the request
			server.handleDNSRequest(mockWriter, msg)

			// Check response
			if !tt.expectedAnswer {
				if len(mockWriter.response.Answer) != 0 {
					t.Errorf("Expected no answer, got %d answers", len(mockWriter.response.Answer))
				}
				return
			}

			if len(mockWriter.response.Answer) == 0 {
				t.Errorf("Expected answer, got no answers")
				return
			}

			// Check first answer
			answer := mockWriter.response.Answer[0]

			if tt.expectedIP != "" {
				// Expecting A record
				if aRecord, ok := answer.(*dns.A); ok {
					if aRecord.A.String() != tt.expectedIP {
						t.Errorf("Expected IP %s, got %s", tt.expectedIP, aRecord.A.String())
					}
				} else {
					t.Errorf("Expected A record, got %T", answer)
				}
			}

			if tt.expectedCNAME != "" {
				// Expecting CNAME record
				if cnameRecord, ok := answer.(*dns.CNAME); ok {
					if cnameRecord.Target != tt.expectedCNAME {
						t.Errorf("Expected CNAME %s, got %s", tt.expectedCNAME, cnameRecord.Target)
					}
				} else {
					t.Errorf("Expected CNAME record, got %T", answer)
				}
			}
		})
	}
}

// MockResponseWriter for testing
type MockResponseWriter struct {
	response *dns.Msg
	addr     net.Addr
}

func (m *MockResponseWriter) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53}
}

func (m *MockResponseWriter) RemoteAddr() net.Addr {
	if m.addr != nil {
		return m.addr
	}
	return &net.UDPAddr{IP: net.ParseIP("192.168.1.100"), Port: 12345}
}

func (m *MockResponseWriter) WriteMsg(msg *dns.Msg) error {
	m.response = msg
	return nil
}

func (m *MockResponseWriter) Write([]byte) (int, error) {
	return 0, nil
}

func (m *MockResponseWriter) Close() error {
	return nil
}

func (m *MockResponseWriter) TsigStatus() error {
	return nil
}

func (m *MockResponseWriter) TsigTimersOnly(bool) {}

func (m *MockResponseWriter) Hijack() {}
