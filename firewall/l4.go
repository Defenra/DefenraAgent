package firewall

import (
	"encoding/binary"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

type L4Protection struct {
	mu               sync.RWMutex
	connectionLimits map[string]*connectionTracker
	maxConnsPerIP    int
	rateLimitPerIP   int
	rateWindow       time.Duration
	suspiciousFlags  map[string]int64
	stopChan         chan struct{}
}

type connectionTracker struct {
	count      int64
	lastAccess time.Time
	rateCount  int64
	rateReset  time.Time
}

type TCPFlags struct {
	FIN bool
	SYN bool
	RST bool
	PSH bool
	ACK bool
	URG bool
	ECE bool
	CWR bool
}

func NewL4Protection(maxConnsPerIP int, rateLimitPerIP int, rateWindow time.Duration) *L4Protection {
	prot := &L4Protection{
		connectionLimits: make(map[string]*connectionTracker),
		maxConnsPerIP:    maxConnsPerIP,
		rateLimitPerIP:   rateLimitPerIP,
		rateWindow:       rateWindow,
		suspiciousFlags:  make(map[string]int64),
		stopChan:         make(chan struct{}),
	}

	go prot.cleanup()
	return prot
}

func (l4 *L4Protection) CheckConnection(ip string) (bool, string) {
	l4.mu.Lock()
	defer l4.mu.Unlock()

	tracker, exists := l4.connectionLimits[ip]
	if !exists {
		tracker = &connectionTracker{
			lastAccess: time.Now(),
			rateReset:  time.Now(),
		}
		l4.connectionLimits[ip] = tracker
	}

	// проверка лимита одновременных соединений
	if int(atomic.LoadInt64(&tracker.count)) >= l4.maxConnsPerIP {
		IncConnectionLimitBlocks()
		return false, fmt.Sprintf("connection limit exceeded (%d)", l4.maxConnsPerIP)
	}

	atomic.AddInt64(&tracker.count, 1)
	tracker.lastAccess = time.Now()

	return true, ""
}

func (l4 *L4Protection) ReleaseConnection(ip string) {
	l4.mu.Lock()
	defer l4.mu.Unlock()

	tracker, exists := l4.connectionLimits[ip]
	if !exists {
		return
	}

	if atomic.AddInt64(&tracker.count, -1) < 0 {
		atomic.StoreInt64(&tracker.count, 0)
	}
}

func (l4 *L4Protection) CheckRateLimit(ip string) (bool, string) {
	l4.mu.Lock()
	defer l4.mu.Unlock()

	tracker, exists := l4.connectionLimits[ip]
	if !exists {
		tracker = &connectionTracker{
			rateReset: time.Now(),
		}
		l4.connectionLimits[ip] = tracker
	}

	// сброс счетчика если окно истекло
	if time.Since(tracker.rateReset) > l4.rateWindow {
		atomic.StoreInt64(&tracker.rateCount, 0)
		tracker.rateReset = time.Now()
	}

	currentRate := atomic.AddInt64(&tracker.rateCount, 1)
	if int(currentRate) > l4.rateLimitPerIP {
		IncRateLimitBlocks()
		return false, fmt.Sprintf("rate limit exceeded (%d/%v)", l4.rateLimitPerIP, l4.rateWindow)
	}

	return true, ""
}

func (l4 *L4Protection) AnalyzeTCPPacket(srcIP string, data []byte) (bool, string) {
	if len(data) < 20 {
		return true, ""
	}

	// парсим TCP header
	flags := data[13]

	tcpFlags := TCPFlags{
		FIN: (flags & 0x01) != 0,
		SYN: (flags & 0x02) != 0,
		RST: (flags & 0x04) != 0,
		PSH: (flags & 0x08) != 0,
		ACK: (flags & 0x10) != 0,
		URG: (flags & 0x20) != 0,
		ECE: (flags & 0x40) != 0,
		CWR: (flags & 0x80) != 0,
	}

	// проверяем подозрительные комбинации флагов
	suspicious := false
	reason := ""

	// SYN flood - только SYN без ACK
	if tcpFlags.SYN && !tcpFlags.ACK {
		if !tcpFlags.FIN && !tcpFlags.RST {
			suspicious = true
			reason = "suspicious SYN packet"
		}
	}

	// Xmas scan - FIN + URG + PSH
	if tcpFlags.FIN && tcpFlags.URG && tcpFlags.PSH && !tcpFlags.SYN && !tcpFlags.ACK {
		suspicious = true
		reason = "xmas scan detected"
	}

	// NULL scan - все флаги выключены
	if !tcpFlags.FIN && !tcpFlags.SYN && !tcpFlags.RST && !tcpFlags.PSH && !tcpFlags.ACK && !tcpFlags.URG {
		suspicious = true
		reason = "null scan detected"
	}

	// FIN scan - только FIN
	if tcpFlags.FIN && !tcpFlags.SYN && !tcpFlags.ACK && !tcpFlags.RST {
		suspicious = true
		reason = "fin scan detected"
	}

	if suspicious {
		l4.mu.Lock()
		l4.suspiciousFlags[srcIP]++
		count := l4.suspiciousFlags[srcIP]
		l4.mu.Unlock()

		if count >= 10 {
			IncTCPFlagBlocks()
			return false, fmt.Sprintf("%s (count: %d)", reason, count)
		}
	}

	return true, ""
}

func (l4 *L4Protection) GetConnectionCount(ip string) int {
	l4.mu.RLock()
	defer l4.mu.RUnlock()

	tracker, exists := l4.connectionLimits[ip]
	if !exists {
		return 0
	}

	return int(atomic.LoadInt64(&tracker.count))
}

func (l4 *L4Protection) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			l4.mu.Lock()
			now := time.Now()
			var toRemove []string

			for ip, tracker := range l4.connectionLimits {
				if now.Sub(tracker.lastAccess) > 10*time.Minute {
					if atomic.LoadInt64(&tracker.count) == 0 {
						toRemove = append(toRemove, ip)
					}
				}
			}

			for _, ip := range toRemove {
				delete(l4.connectionLimits, ip)
			}

			l4.mu.Unlock()

		case <-l4.stopChan:
			return
		}
	}
}

func (l4 *L4Protection) Stop() {
	close(l4.stopChan)
}

// ParseTCPHeader парсит TCP заголовок из raw пакета
func ParseTCPHeader(data []byte) (srcPort, dstPort uint16, flags TCPFlags, seqNum, ackNum uint32, err error) {
	if len(data) < 20 {
		return 0, 0, TCPFlags{}, 0, 0, fmt.Errorf("packet too short")
	}

	srcPort = binary.BigEndian.Uint16(data[0:2])
	dstPort = binary.BigEndian.Uint16(data[2:4])
	seqNum = binary.BigEndian.Uint32(data[4:8])
	ackNum = binary.BigEndian.Uint32(data[8:12])
	flagsByte := data[13]

	flags = TCPFlags{
		FIN: (flagsByte & 0x01) != 0,
		SYN: (flagsByte & 0x02) != 0,
		RST: (flagsByte & 0x04) != 0,
		PSH: (flagsByte & 0x08) != 0,
		ACK: (flagsByte & 0x10) != 0,
		URG: (flagsByte & 0x20) != 0,
		ECE: (flagsByte & 0x40) != 0,
		CWR: (flagsByte & 0x80) != 0,
	}

	return
}
