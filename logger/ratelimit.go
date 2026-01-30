package logger

import (
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"
)

// RateLimitedLogger ограничивает частоту логирования для предотвращения spam в journald
type RateLimitedLogger struct {
	mu          sync.RWMutex
	counters    map[string]*logCounter
	sampleRate  int           // Логировать 1 из N событий при высокой нагрузке
	minInterval time.Duration // Минимальный интервал между логами одного типа
}

type logCounter struct {
	count      uint64
	lastLog    time.Time
	totalCount uint64 // Общее количество событий для агрегации
}

var (
	globalLogger *RateLimitedLogger
	once         sync.Once
)

// GetRateLimitedLogger возвращает singleton rate-limited logger
func GetRateLimitedLogger() *RateLimitedLogger {
	once.Do(func() {
		globalLogger = &RateLimitedLogger{
			counters:    make(map[string]*logCounter),
			sampleRate:  100,             // По умолчанию 1 из 100
			minInterval: 1 * time.Second, // Минимум 1 лог в секунду на тип
		}
	})
	return globalLogger
}

// SetSampleRate устанавливает частоту семплирования (1 из N)
func (rl *RateLimitedLogger) SetSampleRate(rate int) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.sampleRate = rate
}

// SetMinInterval устанавливает минимальный интервал между логами
func (rl *RateLimitedLogger) SetMinInterval(interval time.Duration) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.minInterval = interval
}

// Printf логирует с rate limiting
func (rl *RateLimitedLogger) Printf(format string, v ...interface{}) {
	rl.logWithLimit(format, v...)
}

// PrintfLimited логирует с rate limiting по ключу
func (rl *RateLimitedLogger) PrintfLimited(key string, format string, v ...interface{}) {
	rl.mu.Lock()
	counter, exists := rl.counters[key]
	if !exists {
		counter = &logCounter{}
		rl.counters[key] = counter
	}

	now := time.Now()
	atomic.AddUint64(&counter.count, 1)
	atomic.AddUint64(&counter.totalCount, 1)

	// Проверяем, нужно ли логировать
	shouldLog := false
	count := atomic.LoadUint64(&counter.count)

	if count >= uint64(rl.sampleRate) {
		shouldLog = true
		atomic.StoreUint64(&counter.count, 0)
		counter.lastLog = now
	} else if now.Sub(counter.lastLog) > rl.minInterval && counter.lastLog.IsZero() {
		// Первый лог или прошло больше minInterval
		shouldLog = true
		counter.lastLog = now
	}

	total := atomic.LoadUint64(&counter.totalCount)
	rl.mu.Unlock()

	if shouldLog {
		if total > 1 {
			log.Printf("[AGGREGATED] %s (+%d events) %s", key, total, fmt.Sprintf(format, v...))
		} else {
			log.Printf("[%s] %s", key, fmt.Sprintf(format, v...))
		}
		// Сбрасываем счетчик после логирования
		atomic.StoreUint64(&counter.totalCount, 0)
	}
}

// PrintfCritical всегда логирует (для критических ошибок)
func (rl *RateLimitedLogger) PrintfCritical(format string, v ...interface{}) {
	log.Printf("[CRITICAL] "+format, v...)
}

// logWithLimit внутренний метод для rate limiting
func (rl *RateLimitedLogger) logWithLimit(format string, v ...interface{}) {
	// Извлекаем префикс из формата для определения типа
	var key string
	if len(format) > 10 && format[0] == '[' {
		// Ищем закрывающую скобку
		end := 0
		for i := 1; i < len(format) && i < 20; i++ {
			if format[i] == ']' {
				end = i
				break
			}
		}
		if end > 0 {
			key = format[1:end]
		}
	}

	if key == "" {
		// Если не удалось определить ключ, логируем как есть
		log.Printf(format, v...)
		return
	}

	rl.PrintfLimited(key, format[len(key)+3:], v...) // +3 для "] "
}

// GetStats возвращает статистику логирования
func (rl *RateLimitedLogger) GetStats() map[string]uint64 {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	stats := make(map[string]uint64)
	for key, counter := range rl.counters {
		stats[key] = atomic.LoadUint64(&counter.totalCount)
	}
	return stats
}

// ResetStats сбрасывает статистику
func (rl *RateLimitedLogger) ResetStats() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	for _, counter := range rl.counters {
		atomic.StoreUint64(&counter.totalCount, 0)
		atomic.StoreUint64(&counter.count, 0)
	}
}

// Debug логирует только если DEBUG=true
func Debug(format string, v ...interface{}) {
	// В production debug логи отключены
	// Можно добавить проверку env var если нужно
}
