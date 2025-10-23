package dns

import (
	"log"
	"net"
	"strings"
	"sync/atomic"

	"github.com/defenra/agent/config"
	"github.com/miekg/dns"
)

type DNSServer struct {
	configMgr *config.ConfigManager
	geoIP     *GeoIPService
	cache     *DNSCache
	stats     *DNSStats
}

type DNSStats struct {
	TotalQueries  uint64
	CacheHits     uint64
	CacheMisses   uint64
	GeoDNSQueries uint64
	NXDomain      uint64
}

func StartDNSServer(configMgr *config.ConfigManager) {
	geoIP, err := NewGeoIPService("GeoLite2-City.mmdb")
	if err != nil {
		log.Printf("[DNS] Warning: GeoIP service not available: %v", err)
		log.Println("[DNS] GeoDNS will use fallback logic")
	}

	server := &DNSServer{
		configMgr: configMgr,
		geoIP:     geoIP,
		cache:     NewDNSCache(10000),
		stats:     &DNSStats{},
	}

	dns.HandleFunc(".", server.handleDNSRequest)

	udpServer := &dns.Server{Addr: ":53", Net: "udp"}
	tcpServer := &dns.Server{Addr: ":53", Net: "tcp"}

	go func() {
		log.Println("[DNS] Starting UDP server on :53")
		if err := udpServer.ListenAndServe(); err != nil {
			log.Fatalf("[DNS] Failed to start UDP server: %v", err)
		}
	}()

	go func() {
		log.Println("[DNS] Starting TCP server on :53")
		if err := tcpServer.ListenAndServe(); err != nil {
			log.Fatalf("[DNS] Failed to start TCP server: %v", err)
		}
	}()
}

func (s *DNSServer) handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	atomic.AddUint64(&s.stats.TotalQueries, 1)

	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true

	if len(r.Question) == 0 {
		w.WriteMsg(msg)
		return
	}

	question := r.Question[0]
	domain := cleanDomain(question.Name)
	qtype := question.Qtype

	log.Printf("[DNS] Query: %s %s from %s", domain, dns.TypeToString[qtype], w.RemoteAddr())

	clientIP := extractClientIP(w.RemoteAddr())

	domainConfig := s.configMgr.GetDomain(domain)
	if domainConfig == nil {
		log.Printf("[DNS] Domain not found: %s", domain)
		atomic.AddUint64(&s.stats.NXDomain, 1)
		s.sendNXDOMAIN(w, r)
		return
	}

	if qtype == dns.TypeA && len(domainConfig.GeoDNSMap) > 0 {
		atomic.AddUint64(&s.stats.GeoDNSQueries, 1)
		s.handleGeoDNSQuery(w, r, domainConfig, clientIP)
		return
	}

	s.handleRegularDNSQuery(w, r, domainConfig)
}

func (s *DNSServer) handleGeoDNSQuery(w dns.ResponseWriter, r *dns.Msg, domainConfig *config.Domain, clientIP string) {
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true

	clientLocation := "default"
	if s.geoIP != nil {
		clientLocation = s.geoIP.GetLocation(clientIP)
	}

	log.Printf("[DNS] GeoDNS Query: %s from %s (location: %s)", domainConfig.Domain, clientIP, clientLocation)

	agentIP := findBestAgentIP(domainConfig.GeoDNSMap, clientLocation)
	if agentIP == "" {
		log.Printf("[DNS] No agent IP found for location: %s", clientLocation)
		s.sendNXDOMAIN(w, r)
		return
	}

	log.Printf("[DNS] GeoDNS Response: %s → %s", domainConfig.Domain, agentIP)

	msg.Answer = append(msg.Answer, &dns.A{
		Hdr: dns.RR_Header{
			Name:   r.Question[0].Name,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    60,
		},
		A: net.ParseIP(agentIP),
	})

	w.WriteMsg(msg)
}

func (s *DNSServer) handleRegularDNSQuery(w dns.ResponseWriter, r *dns.Msg, domainConfig *config.Domain) {
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true

	question := r.Question[0]
	qtype := question.Qtype
	queryName := cleanDomain(question.Name)

	for _, record := range domainConfig.DNSRecords {
		recordName := record.Name
		if recordName == "@" {
			recordName = domainConfig.Domain
		} else if !strings.HasSuffix(recordName, ".") {
			recordName = recordName + "." + domainConfig.Domain
		}

		if recordName != queryName {
			continue
		}

		switch qtype {
		case dns.TypeA:
			if record.Type == "A" {
				msg.Answer = append(msg.Answer, &dns.A{
					Hdr: dns.RR_Header{
						Name:   question.Name,
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    record.TTL,
					},
					A: net.ParseIP(record.Value),
				})
			}

		case dns.TypeAAAA:
			if record.Type == "AAAA" {
				msg.Answer = append(msg.Answer, &dns.AAAA{
					Hdr: dns.RR_Header{
						Name:   question.Name,
						Rrtype: dns.TypeAAAA,
						Class:  dns.ClassINET,
						Ttl:    record.TTL,
					},
					AAAA: net.ParseIP(record.Value),
				})
			}

		case dns.TypeCNAME:
			if record.Type == "CNAME" {
				msg.Answer = append(msg.Answer, &dns.CNAME{
					Hdr: dns.RR_Header{
						Name:   question.Name,
						Rrtype: dns.TypeCNAME,
						Class:  dns.ClassINET,
						Ttl:    record.TTL,
					},
					Target: dns.Fqdn(record.Value),
				})
			}

		case dns.TypeMX:
			if record.Type == "MX" {
				msg.Answer = append(msg.Answer, &dns.MX{
					Hdr: dns.RR_Header{
						Name:   question.Name,
						Rrtype: dns.TypeMX,
						Class:  dns.ClassINET,
						Ttl:    record.TTL,
					},
					Preference: record.Priority,
					Mx:         dns.Fqdn(record.Value),
				})
			}

		case dns.TypeTXT:
			if record.Type == "TXT" {
				msg.Answer = append(msg.Answer, &dns.TXT{
					Hdr: dns.RR_Header{
						Name:   question.Name,
						Rrtype: dns.TypeTXT,
						Class:  dns.ClassINET,
						Ttl:    record.TTL,
					},
					Txt: []string{record.Value},
				})
			}
		}
	}

	if len(msg.Answer) == 0 {
		atomic.AddUint64(&s.stats.NXDomain, 1)
		msg.Rcode = dns.RcodeNameError
	}

	w.WriteMsg(msg)
}

func (s *DNSServer) sendNXDOMAIN(w dns.ResponseWriter, r *dns.Msg) {
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Rcode = dns.RcodeNameError
	w.WriteMsg(msg)
}

func cleanDomain(domain string) string {
	domain = strings.TrimSuffix(domain, ".")
	return strings.ToLower(domain)
}

func extractClientIP(addr net.Addr) string {
	switch v := addr.(type) {
	case *net.UDPAddr:
		return v.IP.String()
	case *net.TCPAddr:
		return v.IP.String()
	default:
		return ""
	}
}

func findBestAgentIP(geoDNSMap map[string]string, clientLocation string) string {
	if ip, ok := geoDNSMap[clientLocation]; ok {
		return ip
	}

	fallbackMap := map[string][]string{
		"us": {"north-america", "south-america", "europe"},
		"ca": {"north-america", "us", "europe"},
		"mx": {"north-america", "south-america", "us"},
		"br": {"south-america", "north-america", "europe"},
		"gb": {"europe", "africa", "north-america"},
		"de": {"europe", "africa", "asia"},
		"fr": {"europe", "africa", "asia"},
		"ru": {"europe", "asia", "africa"},
		"cn": {"asia", "oceania", "europe"},
		"jp": {"asia", "oceania", "north-america"},
		"in": {"asia", "europe", "africa"},
		"au": {"oceania", "asia", "north-america"},
		"za": {"africa", "europe", "asia"},
	}

	if fallbacks, ok := fallbackMap[clientLocation]; ok {
		for _, fallback := range fallbacks {
			if ip, ok := geoDNSMap[fallback]; ok {
				return ip
			}
		}
	}

	if ip, ok := geoDNSMap["default"]; ok {
		return ip
	}

	for _, ip := range geoDNSMap {
		return ip
	}

	return ""
}

func (s *DNSServer) GetStats() DNSStats {
	return DNSStats{
		TotalQueries:  atomic.LoadUint64(&s.stats.TotalQueries),
		CacheHits:     atomic.LoadUint64(&s.stats.CacheHits),
		CacheMisses:   atomic.LoadUint64(&s.stats.CacheMisses),
		GeoDNSQueries: atomic.LoadUint64(&s.stats.GeoDNSQueries),
		NXDomain:      atomic.LoadUint64(&s.stats.NXDomain),
	}
}
