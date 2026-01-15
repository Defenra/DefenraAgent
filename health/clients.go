package health

import (
	"strconv"
	"time"
)

// ClientConnection представляет информацию о подключенном клиенте
type ClientConnection struct {
	IP            string
	ConnectedAt   time.Time
	LastActivity  time.Time
	BytesSent     uint64
	BytesReceived uint64
	ProxyID       string
	ProxyPort     int
}

// ClientTrackerInterface определяет интерфейс для получения клиентов
type ClientTrackerInterface interface {
	GetClients() []*ClientConnection
}

var globalClientTracker ClientTrackerInterface

// SetClientTracker устанавливает глобальный трекер клиентов
func SetClientTracker(tracker ClientTrackerInterface) {
	globalClientTracker = tracker
}

// getActiveClients получает список активных клиентов из ClientTracker
func getActiveClients(portFilter string) []ClientInfo {
	if globalClientTracker == nil {
		return []ClientInfo{}
	}

	clients := globalClientTracker.GetClients()
	result := make([]ClientInfo, 0, len(clients))

	for _, client := range clients {
		// Фильтруем по порту если указан
		if portFilter != "" {
			filterPort, err := strconv.Atoi(portFilter)
			if err == nil && client.ProxyPort != filterPort {
				continue
			}
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
