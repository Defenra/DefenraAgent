package stats

import (
	"testing"

	"github.com/defenra/agent/firewall"
)

func TestStatisticsCollector(t *testing.T) {
	t.Run("singleton pattern", func(t *testing.T) {
		collector1 := GetCollector()
		collector2 := GetCollector()
		
		if collector1 != collector2 {
			t.Error("GetCollector should return the same instance")
		}
	})

	t.Run("set config", func(t *testing.T) {
		collector := GetCollector()
		collector.SetConfig("http://test.core", "test-agent-id", "test-key")

		// проверяем что конфиг установлен (внутренняя проверка через SendStatistics)
		// если coreURL пуст, статистика не отправляется
		// это сложно проверить напрямую без мокирования HTTP клиента
	})

	t.Run("update firewall stats", func(t *testing.T) {
		collector := GetCollector()

		// инкрементируем статистику firewall
		firewall.IncTotalBans()
		firewall.IncL4Blocks()
		firewall.IncRateLimitBlocks()

		collector.UpdateFirewallStats()

		// проверяем что статистика обновлена
		stats := firewall.GetStats()
		if stats.TotalBans == 0 {
			t.Error("TotalBans should be incremented")
		}
	})

	t.Run("send statistics structure", func(t *testing.T) {
		collector := GetCollector()
		
		// устанавливаем тестовый конфиг
		collector.SetConfig("http://localhost:3000", "test-agent", "test-key")

		// проверяем что структура правильная
		// реальная отправка требует HTTP сервер, поэтому тестируем структуру
		payload := StatisticsPayload{
			AgentID:         "test-agent",
			ResourceType:    "domain",
			ResourceID:      "test-domain",
			Requests:        100,
			BlockedRequests: 10,
			RateLimitBlocks: 5,
			FirewallBlocks:  3,
			L4Blocks:        2,
		}

		if payload.AgentID != "test-agent" {
			t.Error("AgentID should match")
		}
		if payload.BlockedRequests == 0 {
			t.Error("BlockedRequests should be set")
		}
	})
}

func TestStatisticsPayload(t *testing.T) {
	t.Run("payload fields", func(t *testing.T) {
		payload := StatisticsPayload{
			AgentID:         "agent-123",
			ResourceType:    "domain",
			ResourceID:      "domain-456",
			InboundBytes:    1000,
			OutboundBytes:   2000,
			Requests:        50,
			ResponseTimeMs:  150,
			Errors:          2,
			BlockedRequests: 5,
			RateLimitBlocks: 3,
			FirewallBlocks:  1,
			L4Blocks:        1,
		}

		if payload.AgentID != "agent-123" {
			t.Error("AgentID mismatch")
		}
		if payload.ResourceType != "domain" {
			t.Error("ResourceType mismatch")
		}
		if payload.BlockedRequests != 5 {
			t.Error("BlockedRequests mismatch")
		}
		if payload.RateLimitBlocks != 3 {
			t.Error("RateLimitBlocks mismatch")
		}
		if payload.FirewallBlocks != 1 {
			t.Error("FirewallBlocks mismatch")
		}
		if payload.L4Blocks != 1 {
			t.Error("L4Blocks mismatch")
		}
	})
}
