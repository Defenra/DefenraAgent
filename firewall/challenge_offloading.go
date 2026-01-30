package firewall

import (
	"log"
	"sync"
	"time"
)

// ChallengeOffloadingTracker отслеживает неудачные попытки прохождения challenge
// и автоматически переносит повторных нарушителей в iptables (L7 → L3 offloading)
type ChallengeOffloadingTracker struct {
	mu                 sync.RWMutex
	failures           map[string]*challengeFailureInfo
	trustedIPs         map[string]time.Time // IP → время последнего успешного challenge
	enabled            bool
	failureThreshold   int           // Количество неудачных попыток
	timeWindow         time.Duration // Временное окно
	banDuration        time.Duration // Длительность бана
	trustedWindow      time.Duration // Окно доверия для прошедших challenge (grace period)
	cleanupInterval    time.Duration
	stopChan           chan struct{}
	totalOffloaded     uint64 // Статистика: сколько IP отправлено в iptables
	totalFailuresCount uint64 // Статистика: общее количество failures
}

type challengeFailureInfo struct {
	count       int
	firstFail   time.Time
	lastFail    time.Time
	offloaded   bool // Уже отправлен в iptables
	offloadedAt time.Time
}

var globalChallengeOffloadingTracker *ChallengeOffloadingTracker
var globalChallengeOffloadingTrackerOnce sync.Once

// GetChallengeOffloadingTracker возвращает глобальный tracker
func GetChallengeOffloadingTracker() *ChallengeOffloadingTracker {
	globalChallengeOffloadingTrackerOnce.Do(func() {
		tracker := &ChallengeOffloadingTracker{
			failures:         make(map[string]*challengeFailureInfo),
			trustedIPs:       make(map[string]time.Time),
			enabled:          true,             // По умолчанию включен
			failureThreshold: 5,                // 5 неудачных попыток
			timeWindow:       10 * time.Second, // За 10 секунд
			banDuration:      60 * time.Minute, // Бан на 60 минут
			trustedWindow:    5 * time.Minute,  // Grace period для доверенных: 5 минут
			cleanupInterval:  60 * time.Second, // Очистка каждую минуту
			stopChan:         make(chan struct{}),
		}
		go tracker.cleanup()
		globalChallengeOffloadingTracker = tracker
	})
	return globalChallengeOffloadingTracker
}

// UpdateConfig обновляет настройки offloading из конфигурации домена
func (t *ChallengeOffloadingTracker) UpdateConfig(enabled bool, threshold int, windowSeconds int, banMinutes int) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.enabled = enabled

	if threshold > 0 {
		t.failureThreshold = threshold
	}

	if windowSeconds > 0 {
		t.timeWindow = time.Duration(windowSeconds) * time.Second
	}

	if banMinutes > 0 {
		t.banDuration = time.Duration(banMinutes) * time.Minute
	}

	log.Printf("[Challenge-Offloading] Config updated: enabled=%v, threshold=%d, window=%v, ban=%v",
		t.enabled, t.failureThreshold, t.timeWindow, t.banDuration)
}

// RecordFailure записывает неудачную попытку прохождения challenge
// Возвращает true, если IP должен быть отправлен в iptables (offloaded)
func (t *ChallengeOffloadingTracker) RecordFailure(ip string, challengeType string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.enabled {
		return false
	}

	// Проверяем grace period для доверенных пользователей
	// Если IP успешно проходил challenge в последние 5 минут,
	// не увеличиваем счетчик failures (это параллельные запросы ресурсов)
	if lastSuccess, exists := t.trustedIPs[ip]; exists {
		if time.Since(lastSuccess) < t.trustedWindow {
			log.Printf("[Challenge-Offloading] IP %s has active grace period (last success: %v ago), ignoring failure for %s challenge",
				ip, time.Since(lastSuccess), challengeType)
			return false
		}
		// Окно доверия истекло, удаляем запись
		delete(t.trustedIPs, ip)
	}

	t.totalFailuresCount++

	now := time.Now()
	info, exists := t.failures[ip]

	if !exists {
		// Первая неудачная попытка
		t.failures[ip] = &challengeFailureInfo{
			count:     1,
			firstFail: now,
			lastFail:  now,
			offloaded: false,
		}
		return false
	}

	// Проверяем, не истекло ли временное окно
	if now.Sub(info.firstFail) > t.timeWindow {
		// Окно истекло, сбрасываем счетчик
		info.count = 1
		info.firstFail = now
		info.lastFail = now
		return false
	}

	// Увеличиваем счетчик
	info.count++
	info.lastFail = now

	// Проверяем порог
	if info.count >= t.failureThreshold && !info.offloaded {
		// Превышен порог - отправляем в iptables
		info.offloaded = true
		info.offloadedAt = now
		t.totalOffloaded++

		log.Printf("[Challenge-Offloading] IP %s exceeded threshold (%d failures in %v) - offloading to iptables for %v",
			ip, info.count, t.timeWindow, t.banDuration)

		// Отправляем в iptables
		firewallMgr := GetIPTablesManager()
		if firewallMgr != nil {
			go func() {
				if err := firewallMgr.BanIP(ip, t.banDuration, "Challenge offloading (repeated failures)"); err != nil {
					log.Printf("[Challenge-Offloading] Failed to ban IP %s: %v", ip, err)
				} else {
					log.Printf("[Challenge-Offloading] Successfully offloaded IP %s to kernel-level blocking", ip)
				}
			}()
		}

		return true
	}

	return false
}

// IsOffloaded проверяет, был ли IP уже отправлен в iptables
func (t *ChallengeOffloadingTracker) IsOffloaded(ip string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()

	info, exists := t.failures[ip]
	if !exists {
		return false
	}

	return info.offloaded
}

// cleanup периодически очищает старые записи
func (t *ChallengeOffloadingTracker) cleanup() {
	ticker := time.NewTicker(t.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			t.mu.Lock()
			now := time.Now()
			var toDelete []string
			var trustedDeleted int

			for ip, info := range t.failures {
				// Удаляем записи старше banDuration (если offloaded)
				if info.offloaded && now.Sub(info.offloadedAt) > t.banDuration {
					toDelete = append(toDelete, ip)
				}

				// Удаляем неактивные записи (не offloaded и старше 5 минут)
				if !info.offloaded && now.Sub(info.lastFail) > 5*time.Minute {
					toDelete = append(toDelete, ip)
				}
			}

			for _, ip := range toDelete {
				delete(t.failures, ip)
			}

			// Очищаем устаревшие записи trustedIPs (старше trustedWindow)
			for ip, lastSuccess := range t.trustedIPs {
				if now.Sub(lastSuccess) > t.trustedWindow {
					delete(t.trustedIPs, ip)
					trustedDeleted++
				}
			}

			if len(toDelete) > 0 || trustedDeleted > 0 {
				log.Printf("[Challenge-Offloading] Cleaned up %d failure entries, %d trusted entries",
					len(toDelete), trustedDeleted)
			}

			t.mu.Unlock()

		case <-t.stopChan:
			return
		}
	}
}

// GetStats возвращает статистику offloading
func (t *ChallengeOffloadingTracker) GetStats() map[string]interface{} {
	t.mu.RLock()
	defer t.mu.RUnlock()

	offloadedCount := 0
	activeCount := 0

	for _, info := range t.failures {
		if info.offloaded {
			offloadedCount++
		} else {
			activeCount++
		}
	}

	return map[string]interface{}{
		"enabled":                t.enabled,
		"total_tracked":          len(t.failures),
		"offloaded_ips":          offloadedCount,
		"active_ips":             activeCount,
		"trusted_ips":            len(t.trustedIPs),
		"trusted_window_minutes": int(t.trustedWindow.Minutes()),
		"total_offloaded":        t.totalOffloaded,
		"total_failures":         t.totalFailuresCount,
		"failure_threshold":      t.failureThreshold,
		"time_window_seconds":    int(t.timeWindow.Seconds()),
		"ban_duration_minutes":   int(t.banDuration.Minutes()),
	}
}

// Stop останавливает cleanup goroutine
func (t *ChallengeOffloadingTracker) Stop() {
	close(t.stopChan)
}

// ResetIP сбрасывает счетчик для IP (используется при успешном прохождении challenge)
func (t *ChallengeOffloadingTracker) ResetIP(ip string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	delete(t.failures, ip)
}

// RecordSuccess записывает успешное прохождение challenge для IP
// Это активирует grace period для доверенных пользователей
func (t *ChallengeOffloadingTracker) RecordSuccess(ip string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Удаляем из failures если есть
	delete(t.failures, ip)

	// Записываем время успешного challenge
	t.trustedIPs[ip] = time.Now()

	log.Printf("[Challenge-Offloading] IP %s successfully completed challenge, grace period activated for %v",
		ip, t.trustedWindow)
}

// IsInGracePeriod проверяет, находится ли IP в grace period (недавно прошел challenge)
func (t *ChallengeOffloadingTracker) IsInGracePeriod(ip string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if lastSuccess, exists := t.trustedIPs[ip]; exists {
		if time.Since(lastSuccess) < t.trustedWindow {
			return true
		}
	}
	return false
}
