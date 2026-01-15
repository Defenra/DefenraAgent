package stats

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"time"
)

// ClientReportPayload represents client data to send to Core
type ClientReportPayload struct {
	AgentID       string `json:"agentId"`
	IP            string `json:"ip"`
	UserAgent     string `json:"userAgent"`
	Country       string `json:"country"`
	City          string `json:"city"`
	CountryCode   string `json:"countryCode"`
	BytesSent     uint64 `json:"bytesSent"`
	BytesReceived uint64 `json:"bytesReceived"`
}

// ClientReporter reports client data to Core
type ClientReporter struct {
	coreURL  string
	agentID  string
	agentKey string
	client   *http.Client
}

// NewClientReporter creates a new client reporter
func NewClientReporter(coreURL, agentID, agentKey string) *ClientReporter {
	return &ClientReporter{
		coreURL:  coreURL,
		agentID:  agentID,
		agentKey: agentKey,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// ReportClient sends client data to Core
func (cr *ClientReporter) ReportClient(payload ClientReportPayload) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", cr.coreURL+"/api/clients", bytes.NewBuffer(data))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cr.agentKey)

	resp, err := cr.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		log.Printf("[ClientReporter] Error response (status %d) for client %s", resp.StatusCode, payload.IP)
		return nil // Don't fail on individual client errors
	}

	return nil
}
