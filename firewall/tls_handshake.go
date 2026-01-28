package firewall

import (
	"crypto/tls"
	"errors"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

// HandshakeRateLimiter отслеживает скорость TLS handshake с каждого IP
// Защита от атак типа "быстрое подключение-отключение" (velocity attack)
type HandshakeRateLimiter struct {
	mu            sync.RWMutex
	handshakes    map[string]*handshakeCounter
	maxRate       int           // Максимум handshake в секунду
	burstSize     int           // Размер burst (кратковременный всплеск)
	cleanInterval time.Duration // Интервал очистки старых записей
	stopChan      chan struct{}
}

type handshakeCounter struct {
	count       int
	windowStart time.Time
	blocked     bool
	blockUntil  time.Time
}

var globalHandshakeLimiter *HandshakeRateLimiter
var globalHandshakeLimiterOnce sync.Once

// GetHandshakeRateLimiter возвращает глобальный rate limiter для TLS handshake
func GetHandshakeRateLimiter() *HandshakeRateLimiter {
	globalHandshakeLimiterOnce.Do(func() {
		limiter := &HandshakeRateLimiter{
			handshakes:    make(map[string]*handshakeCounter),
			maxRate:       15,               // 15 handshake/sec (легитимный браузер делает 1-3)
			burstSize:     20,               // Burst до 20 (для CDN/load balancer)
			cleanInterval: 60 * time.Second, // Очистка каждую минуту
			stopChan:      make(chan struct{}),
		}
		go limiter.cleanup()
		globalHandshakeLimiter = limiter
	})
	return globalHandshakeLimiter
}

// AllowHandshake проверяет, разрешен ли handshake для данного IP
func (h *HandshakeRateLimiter) AllowHandshake(ip string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()

	now := time.Now()
	counter, exists := h.handshakes[ip]

	if !exists {
		// Первый handshake от этого IP
		h.handshakes[ip] = &handshakeCounter{
			count:       1,
			windowStart: now,
			blocked:     false,
		}
		return true
	}

	// Проверяем, не заблокирован ли IP
	if counter.blocked {
		if now.Before(counter.blockUntil) {
			// Всё ещё заблокирован
			return false
		}
		// Блокировка истекла, сбрасываем
		counter.blocked = false
		counter.count = 1
		counter.windowStart = now
		return true
	}

	// Проверяем временное окно (1 секунда)
	windowDuration := now.Sub(counter.windowStart)
	if windowDuration > time.Second {
		// Новое окно, сбрасываем счетчик
		counter.count = 1
		counter.windowStart = now
		return true
	}

	// Увеличиваем счетчик
	counter.count++

	// Проверяем лимит
	if counter.count > h.burstSize {
		// Превышен burst limit - блокируем на 5 минут
		counter.blocked = true
		counter.blockUntil = now.Add(5 * time.Minute)
		log.Printf("[TLS-Handshake] IP %s blocked for 5 minutes (handshake flood: %d/sec)", ip, counter.count)

		// Добавляем в iptables для kernel-level блокировки
		firewallMgr := GetIPTablesManager()
		if firewallMgr != nil {
			go func() {
				if err := firewallMgr.BanIP(ip, 5*time.Minute, "TLS handshake flood"); err != nil {
					log.Printf("[TLS-Handshake] Failed to ban IP %s: %v", ip, err)
				}
			}()
		}

		return false
	}

	if counter.count > h.maxRate {
		// Превышен rate limit, но в пределах burst
		log.Printf("[TLS-Handshake] IP %s exceeding rate limit (%d/%d handshakes/sec)",
			ip, counter.count, h.maxRate)
		return false
	}

	return true
}

// cleanup периодически очищает старые записи
func (h *HandshakeRateLimiter) cleanup() {
	ticker := time.NewTicker(h.cleanInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			h.mu.Lock()
			now := time.Now()
			var toDelete []string

			for ip, counter := range h.handshakes {
				// Удаляем записи старше 5 минут (если не заблокированы)
				if !counter.blocked && now.Sub(counter.windowStart) > 5*time.Minute {
					toDelete = append(toDelete, ip)
				}
				// Удаляем разблокированные записи
				if counter.blocked && now.After(counter.blockUntil) {
					toDelete = append(toDelete, ip)
				}
			}

			for _, ip := range toDelete {
				delete(h.handshakes, ip)
			}

			if len(toDelete) > 0 {
				log.Printf("[TLS-Handshake] Cleaned up %d old entries", len(toDelete))
			}

			h.mu.Unlock()

		case <-h.stopChan:
			return
		}
	}
}

// GetStats возвращает статистику rate limiter
func (h *HandshakeRateLimiter) GetStats() map[string]interface{} {
	h.mu.RLock()
	defer h.mu.RUnlock()

	blockedCount := 0
	activeCount := 0

	for _, counter := range h.handshakes {
		if counter.blocked {
			blockedCount++
		} else {
			activeCount++
		}
	}

	return map[string]interface{}{
		"total_tracked": len(h.handshakes),
		"blocked_ips":   blockedCount,
		"active_ips":    activeCount,
		"max_rate":      h.maxRate,
		"burst_size":    h.burstSize,
	}
}

// Stop останавливает cleanup goroutine
func (h *HandshakeRateLimiter) Stop() {
	close(h.stopChan)
}

// ValidateSNI проверяет, является ли SNI валидным для данного агента
// Блокирует пустые SNI и SNI, не соответствующие настроенным доменам
func ValidateSNI(serverName string, configuredDomains []string) error {
	// Проверка 1: Пустой SNI
	if serverName == "" {
		return errors.New("empty SNI")
	}

	// Проверка 2: SNI не должен быть IP-адресом
	if net.ParseIP(serverName) != nil {
		return errors.New("SNI is IP address")
	}

	// Проверка 3: SNI должен быть в списке настроенных доменов
	if len(configuredDomains) == 0 {
		// Если домены не настроены, пропускаем проверку
		// getCertificate сам решит, есть ли сертификат для этого домена
		return nil
	}

	// Нормализуем serverName (lowercase для сравнения)
	serverNameLower := strings.ToLower(serverName)

	for _, domain := range configuredDomains {
		domainLower := strings.ToLower(domain)

		// Точное совпадение (case-insensitive)
		if serverNameLower == domainLower {
			return nil
		}

		// Wildcard совпадение (*.example.com)
		if strings.HasPrefix(domainLower, "*.") {
			baseDomain := domainLower[2:] // Убираем "*."
			if strings.HasSuffix(serverNameLower, "."+baseDomain) || serverNameLower == baseDomain {
				return nil
			}
		}

		// Subdomain совпадение (example.com покрывает *.example.com)
		if strings.HasSuffix(serverNameLower, "."+domainLower) {
			return nil
		}
	}

	return errors.New("SNI not in configured domains")
}

// ExtractIPFromAddr извлекает IP из net.Addr
func ExtractIPFromAddr(addr net.Addr) string {
	if addr == nil {
		return ""
	}

	// Для TCP адресов формат: "ip:port"
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		// Если не удалось распарсить, возвращаем как есть
		return addr.String()
	}

	return host
}

// GetConfigForClientWrapper создает обертку для GetConfigForClient с защитой
// Это главная точка входа для Fortress Edition
func GetConfigForClientWrapper(
	baseConfig *tls.Config,
	configuredDomains []string,
	getCertificateFunc func(*tls.ClientHelloInfo) (*tls.Certificate, error),
) func(*tls.ClientHelloInfo) (*tls.Config, error) {

	handshakeLimiter := GetHandshakeRateLimiter()
	firewallMgr := GetIPTablesManager()

	return func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		ip := ExtractIPFromAddr(hello.Conn.RemoteAddr())

		// === FORTRESS LAYER 1: SNI Validation (Cheap Check) ===
		// Отсекаем сканеры и боты без валидного SNI
		if err := ValidateSNI(hello.ServerName, configuredDomains); err != nil {
			// Логируем с указанием настроенных доменов для отладки
			log.Printf("[TLS-Fortress] Blocked handshake from %s: %v (SNI: %s, configured domains: %d)",
				ip, err, hello.ServerName, len(configuredDomains))

			// ВАЖНО: НЕ банить сразу - возможно домен есть, но не в списке
			// getCertificate сам решит, есть ли сертификат
			// Банить только явные атаки (пустой SNI, IP-адрес)
			if err.Error() == "empty SNI" || err.Error() == "SNI is IP address" {
				// Это явная атака - банить
				if firewallMgr != nil {
					go func() {
						if err := firewallMgr.BanIP(ip, 1*time.Hour, "Invalid SNI (empty or IP address)"); err != nil {
							log.Printf("[TLS-Fortress] Failed to ban IP %s: %v", ip, err)
						}
					}()
				}
			} else {
				// "SNI not in configured domains" - возможно домен есть, но не синхронизирован
				// Логируем для отладки, но не банить
				log.Printf("[TLS-Fortress] SNI %s not in configured domains list, but allowing getCertificate to decide", hello.ServerName)
				// Продолжаем - getCertificate вернет ошибку, если сертификата нет
				return nil, nil
			}

			return nil, errors.New("invalid SNI")
		}

		// === FORTRESS LAYER 2: Handshake Rate Limiting (Velocity Check) ===
		// Защита от быстрых подключений-отключений
		if !handshakeLimiter.AllowHandshake(ip) {
			log.Printf("[TLS-Fortress] Blocked handshake from %s: rate limit exceeded", ip)

			// IP уже заблокирован в iptables внутри AllowHandshake
			return nil, errors.New("handshake rate limit exceeded")
		}

		// === FORTRESS LAYER 3: TLS Fingerprinting (JA3/JA4) ===
		// Анализ TLS fingerprint для обнаружения ботов
		tlsFingerprint := ExtractTLSFingerprint(hello)
		if tlsFingerprint != "" {
			// Проверяем fingerprint против базы известных ботнетов
			if IsKnownBotFingerprint(tlsFingerprint) {
				log.Printf("[TLS-Fortress] Blocked handshake from %s: known bot fingerprint %s",
					ip, tlsFingerprint)

				if firewallMgr != nil {
					go func() {
						if err := firewallMgr.BanIP(ip, 24*time.Hour, "Malicious TLS fingerprint"); err != nil {
							log.Printf("[TLS-Fortress] Failed to ban IP %s: %v", ip, err)
						}
					}()
				}

				return nil, errors.New("malicious TLS fingerprint")
			}

			// Сохраняем fingerprint для последующего анализа
			remoteAddr := hello.Conn.RemoteAddr().String()
			StoreTLSFingerprint(remoteAddr, tlsFingerprint)
		}

		// Все проверки пройдены - возвращаем базовую конфигурацию
		// GetCertificate будет вызван автоматически из baseConfig
		return nil, nil
	}
}

// IsKnownBotFingerprint проверяет, является ли fingerprint известным ботом
func IsKnownBotFingerprint(fingerprint string) bool {
	// Получаем базу известных bot fingerprints
	botFingerprints := GetBotFingerprints()

	if description, exists := botFingerprints[fingerprint]; exists {
		log.Printf("[TLS-Fortress] Detected bot fingerprint: %s (%s)", fingerprint, description)
		return true
	}

	return false
}
