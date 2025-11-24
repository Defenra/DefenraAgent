package firewall

import (
	"sync"
	"testing"
)

func TestFirewallStats(t *testing.T) {
	ResetStats()

	t.Run("inc total bans", func(t *testing.T) {
		IncTotalBans()
		stats := GetStats()
		if stats.TotalBans != 1 {
			t.Errorf("expected TotalBans=1, got %d", stats.TotalBans)
		}
	})

	t.Run("inc active bans", func(t *testing.T) {
		IncActiveBans()
		stats := GetStats()
		if stats.ActiveBans != 1 {
			t.Errorf("expected ActiveBans=1, got %d", stats.ActiveBans)
		}
	})

	t.Run("dec active bans", func(t *testing.T) {
		// инкрементируем перед декрементом
		IncActiveBans()
		IncActiveBans()
		DecActiveBans()
		stats := GetStats()
		// после 2 inc и 1 dec должно быть 1
		if stats.ActiveBans == 0 {
			t.Errorf("expected ActiveBans=1 after inc/dec, got %d", stats.ActiveBans)
		}
	})

	t.Run("inc l4 blocks", func(t *testing.T) {
		IncL4Blocks()
		stats := GetStats()
		if stats.L4Blocks != 1 {
			t.Errorf("expected L4Blocks=1, got %d", stats.L4Blocks)
		}
	})

	t.Run("inc tcp flag blocks", func(t *testing.T) {
		IncTCPFlagBlocks()
		stats := GetStats()
		if stats.TCPFlagBlocks != 1 {
			t.Errorf("expected TCPFlagBlocks=1, got %d", stats.TCPFlagBlocks)
		}
	})

	t.Run("inc rate limit blocks", func(t *testing.T) {
		IncRateLimitBlocks()
		stats := GetStats()
		if stats.RateLimitBlocks != 1 {
			t.Errorf("expected RateLimitBlocks=1, got %d", stats.RateLimitBlocks)
		}
	})

	t.Run("inc connection limit blocks", func(t *testing.T) {
		IncConnectionLimitBlocks()
		stats := GetStats()
		if stats.ConnectionLimitBlocks != 1 {
			t.Errorf("expected ConnectionLimitBlocks=1, got %d", stats.ConnectionLimitBlocks)
		}
	})

	t.Run("concurrent increments", func(t *testing.T) {
		ResetStats()
		var wg sync.WaitGroup
		iterations := 100

		for i := 0; i < iterations; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				IncTotalBans()
				IncActiveBans()
				IncL4Blocks()
				IncRateLimitBlocks()
			}()
		}

		wg.Wait()

		stats := GetStats()
		if stats.TotalBans != uint64(iterations) {
			t.Errorf("expected TotalBans=%d, got %d", iterations, stats.TotalBans)
		}
		if stats.ActiveBans != uint64(iterations) {
			t.Errorf("expected ActiveBans=%d, got %d", iterations, stats.ActiveBans)
		}
	})

	t.Run("reset stats", func(t *testing.T) {
		ResetStats()
		stats := GetStats()
		if stats.TotalBans != 0 || stats.ActiveBans != 0 || stats.L4Blocks != 0 {
			t.Errorf("expected all stats to be 0 after reset")
		}
	})
}
