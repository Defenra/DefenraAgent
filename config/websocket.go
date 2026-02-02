package config

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/gorilla/websocket"
)

// WebSocketMessage represents a message from the server
type WebSocketMessage struct {
	Type      string          `json:"type"`
	Timestamp int64           `json:"timestamp"`
	Data      json.RawMessage `json:"data"`
}

// WebSocketConfig represents the config sent via WebSocket
type WebSocketConfig struct {
	AgentId string              `json:"agentId"`
	Domains []Domain            `json:"domains"`
	Proxies []Proxy             `json:"proxies"`
	Agents  []FallbackAgentInfo `json:"agents"` // All agents for coordinate-based fallback
	GeoCode string              `json:"geoCode,omitempty"`
	Bans    []BanInfo           `json:"bans"`
	Hash    int                 `json:"hash,omitempty"` // Config version hash
}

// BanInfo represents ban information
type BanInfo struct {
	IP          string    `json:"ip"`
	Reason      string    `json:"reason"`
	BannedAt    time.Time `json:"bannedAt"`
	ExpiresAt   time.Time `json:"expiresAt"`
	IsPermanent bool      `json:"isPermanent"`
	IsCIDR      bool      `json:"isCIDR"`
}

// WebSocketClient manages WebSocket connection to Core
type WebSocketClient struct {
	agentId           string
	agentKey          string
	coreURL           string
	conn              *websocket.Conn
	config            *Config
	ctx               context.Context
	cancel            context.CancelFunc
	onConfig          func(*Config)
	onBan             func(BanInfo)
	isRunning         bool
	reconnectInterval time.Duration
}

// NewWebSocketClient creates a new WebSocket client
func NewWebSocketClient(agentId, agentKey, coreURL string, onConfig func(*Config), onBan func(BanInfo)) *WebSocketClient {
	ctx, cancel := context.WithCancel(context.Background())
	return &WebSocketClient{
		agentId:           agentId,
		agentKey:          agentKey,
		coreURL:           coreURL,
		ctx:               ctx,
		cancel:            cancel,
		onConfig:          onConfig,
		onBan:             onBan,
		reconnectInterval: 5 * time.Second,
	}
}

// Start connects to WebSocket and starts listening
func (w *WebSocketClient) Start() error {
	if w.isRunning {
		return fmt.Errorf("WebSocket client already running")
	}

	w.isRunning = true
	go w.connectionManager()
	return nil
}

// Stop closes the WebSocket connection
func (w *WebSocketClient) Stop() {
	w.cancel()
	if w.conn != nil {
		w.conn.Close()
	}
	w.isRunning = false
}

// connectionManager handles connection lifecycle with reconnection
func (w *WebSocketClient) connectionManager() {
	for {
		select {
		case <-w.ctx.Done():
			return
		default:
			if err := w.connect(); err != nil {
				log.Printf("[WebSocket] Connection failed: %v, retrying in %v...", err, w.reconnectInterval)
				time.Sleep(w.reconnectInterval)
				continue
			}

			// Connection successful, handle messages
			if err := w.handleMessages(); err != nil {
				log.Printf("[WebSocket] Connection lost: %v, reconnecting...", err)
				time.Sleep(w.reconnectInterval)
			}
		}
	}
}

// connect establishes WebSocket connection
func (w *WebSocketClient) connect() error {
	u, err := url.Parse(w.coreURL)
	if err != nil {
		return fmt.Errorf("invalid core URL: %w", err)
	}

	// Convert HTTP to WS
	if u.Scheme == "https" {
		u.Scheme = "wss"
	} else {
		u.Scheme = "ws"
	}

	// Add query parameters
	q := u.Query()
	q.Set("agentId", w.agentId)
	q.Set("agentKey", w.agentKey)
	u.RawQuery = q.Encode()

	// Change path to WebSocket endpoint
	u.Path = "/api/agent/ws"

	log.Printf("[WebSocket] Connecting to %s", u.String())

	dialer := websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
	}

	conn, resp, err := dialer.Dial(u.String(), http.Header{})
	if err != nil {
		if resp != nil {
			return fmt.Errorf("WebSocket handshake failed (status %d): %w", resp.StatusCode, err)
		}
		return fmt.Errorf("WebSocket dial failed: %w", err)
	}

	w.conn = conn
	log.Printf("[WebSocket] Connected successfully")
	return nil
}

// handleMessages processes incoming WebSocket messages
func (w *WebSocketClient) handleMessages() error {
	defer func() {
		if w.conn != nil {
			w.conn.Close()
			w.conn = nil
		}
	}()

	// Start ping handler
	go w.pingHandler()

	for {
		select {
		case <-w.ctx.Done():
			return nil
		default:
			_, message, err := w.conn.ReadMessage()
			if err != nil {
				return fmt.Errorf("read error: %w", err)
			}

			if err := w.processMessage(message); err != nil {
				log.Printf("[WebSocket] Error processing message: %v", err)
			}
		}
	}
}

// processMessage handles different message types
func (w *WebSocketClient) processMessage(data []byte) error {
	var msg WebSocketMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		return fmt.Errorf("unmarshal error: %w", err)
	}

	switch msg.Type {
	case "config":
		var config WebSocketConfig
		if err := json.Unmarshal(msg.Data, &config); err != nil {
			return fmt.Errorf("unmarshal config error: %w", err)
		}

		// Convert WebSocketConfig to Config
		cfg := w.convertConfig(&config)

		log.Printf("[WebSocket] Received config update with %d domains and %d bans",
			len(config.Domains), len(config.Bans))

		if w.onConfig != nil {
			w.onConfig(cfg)
		}

	case "ban_sync":
		var banSync struct {
			Bans  []BanInfo `json:"bans"`
			Total int       `json:"total"`
		}
		if err := json.Unmarshal(msg.Data, &banSync); err != nil {
			return fmt.Errorf("unmarshal ban_sync error: %w", err)
		}

		log.Printf("[WebSocket] Received ban sync with %d bans", banSync.Total)

		// Forward to ban handler if set
		if w.onBan != nil {
			for _, ban := range banSync.Bans {
				w.onBan(ban)
			}
		}

	case "ban":
		var ban BanInfo
		if err := json.Unmarshal(msg.Data, &ban); err != nil {
			return fmt.Errorf("unmarshal ban error: %w", err)
		}

		log.Printf("[WebSocket] Received new ban for IP: %s", ban.IP)

		if w.onBan != nil {
			w.onBan(ban)
		}

	case "ping":
		// Respond with pong
		w.sendMessage(map[string]string{"type": "pong"})

	default:
		log.Printf("[WebSocket] Unknown message type: %s", msg.Type)
	}

	return nil
}

// pingHandler sends periodic pings to keep connection alive
func (w *WebSocketClient) pingHandler() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-w.ctx.Done():
			return
		case <-ticker.C:
			if w.conn == nil {
				return
			}
			if err := w.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				log.Printf("[WebSocket] Ping failed: %v", err)
				return
			}
		}
	}
}

// sendMessage sends a message to the server
func (w *WebSocketClient) sendMessage(data interface{}) error {
	if w.conn == nil {
		return fmt.Errorf("not connected")
	}

	msg, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshal error: %w", err)
	}

	return w.conn.WriteMessage(websocket.TextMessage, msg)
}

// convertConfig converts WebSocketConfig to Config
func (w *WebSocketClient) convertConfig(wsConfig *WebSocketConfig) *Config {
	config := &Config{
		Domains:    wsConfig.Domains,
		Proxies:    wsConfig.Proxies,
		Agents:     wsConfig.Agents, // All agents for coordinate-based fallback
		LastUpdate: time.Now(),
	}

	return config
}

// IsConnected returns true if WebSocket is connected
func (w *WebSocketClient) IsConnected() bool {
	return w.conn != nil && w.isRunning
}

// IsRunning returns true if client is running
func (w *WebSocketClient) IsRunning() bool {
	return w.isRunning
}

// ReportStats sends statistics to server via WebSocket or falls back to HTTP
func (w *WebSocketClient) ReportStats(stats interface{}) error {
	if w.IsConnected() {
		// Send via WebSocket
		return w.sendMessage(map[string]interface{}{
			"type": "stats",
			"data": stats,
		})
	}
	// Fallback: stats will be sent via HTTP polling
	return fmt.Errorf("WebSocket not connected, use HTTP fallback")
}
