package firewall

import (
	"log"
	"net"
	"sync/atomic"
)

// FirewallListener оборачивает net.Listener и фильтрует соединения на уровне TCP (L4)
// ДО того, как начнется TLS handshake. Это критично для защиты от TLS Flood атак.
type FirewallListener struct {
	net.Listener
	maxConns      int64
	currentConns  int64
	rejectedConns uint64
}

// NewFirewallListener создает защищенный listener с ограничением соединений
func NewFirewallListener(inner net.Listener, maxConns int64) *FirewallListener {
	return &FirewallListener{
		Listener:     inner,
		maxConns:     maxConns,
		currentConns: 0,
	}
}

// Accept принимает новое соединение с проверками безопасности ДО TLS handshake
func (l *FirewallListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}

		remoteIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())

		// === КРИТИЧЕСКАЯ ПРОВЕРКА #1: Глобальный лимит соединений ===
		// Защита от исчерпания ресурсов (file descriptors, memory)
		currentConns := atomic.LoadInt64(&l.currentConns)
		if l.maxConns > 0 && currentConns >= l.maxConns {
			conn.Close()
			atomic.AddUint64(&l.rejectedConns, 1)
			// Не логируем каждое отклонение - слишком много спама
			if atomic.LoadUint64(&l.rejectedConns)%1000 == 0 {
				log.Printf("[FIREWALL] Global connection limit reached (%d/%d), rejected %d connections",
					currentConns, l.maxConns, atomic.LoadUint64(&l.rejectedConns))
			}
			continue // Пробуем принять следующее соединение
		}

		// === КРИТИЧЕСКАЯ ПРОВЕРКА #2: IP в черном списке (iptables) ===
		// Проверяем ДО TLS handshake - экономим CPU на криптографии
		firewallMgr := GetIPTablesManager()
		if firewallMgr != nil && firewallMgr.IsBanned(remoteIP) {
			conn.Close()
			atomic.AddUint64(&l.rejectedConns, 1)
			// Не логируем каждую блокировку - слишком много спама
			continue
		}

		// === КРИТИЧЕСКАЯ ПРОВЕРКА #3: Connection Limiter (per-IP) ===
		// Проверяем лимит соединений на IP ДО TLS handshake
		connLimiter := GetConnectionLimiter()
		if connLimiter.IsBlocked(conn.RemoteAddr().String()) {
			conn.Close()
			atomic.AddUint64(&l.rejectedConns, 1)
			continue
		}

		// Соединение прошло все проверки - оборачиваем в TrackedConn для учета
		atomic.AddInt64(&l.currentConns, 1)
		return &TrackedConn{
			Conn:     conn,
			listener: l,
		}, nil
	}
}

// GetStats возвращает статистику listener
func (l *FirewallListener) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"current_connections":  atomic.LoadInt64(&l.currentConns),
		"max_connections":      l.maxConns,
		"rejected_connections": atomic.LoadUint64(&l.rejectedConns),
	}
}

// TrackedConn оборачивает net.Conn для отслеживания закрытия соединения
type TrackedConn struct {
	net.Conn
	listener *FirewallListener
	closed   int32
}

// Close закрывает соединение и уменьшает счетчик активных соединений
func (c *TrackedConn) Close() error {
	// Используем atomic для защиты от двойного Close()
	if atomic.CompareAndSwapInt32(&c.closed, 0, 1) {
		atomic.AddInt64(&c.listener.currentConns, -1)
	}
	return c.Conn.Close()
}

// IsIPAllowed проверяет, разрешен ли IP (используется в других местах)
func IsIPAllowed(ip string) bool {
	// Проверка в iptables
	firewallMgr := GetIPTablesManager()
	if firewallMgr != nil && firewallMgr.IsBanned(ip) {
		return false
	}

	// Проверка в connection limiter
	connLimiter := GetConnectionLimiter()
	if connLimiter.IsBlocked(ip) {
		return false
	}

	return true
}
