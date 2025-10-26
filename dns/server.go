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
		if err := w.WriteMsg(msg); err != nil {
			log.Printf("[DNS] Error writing response: %v", err)
		}
		return
	}

	question := r.Question[0]
	domain := cleanDomain(question.Name)
	qtype := question.Qtype

	log.Printf("[DNS] Query: %s %s from %s", domain, dns.TypeToString[qtype], w.RemoteAddr())

	clientIP := extractClientIP(w.RemoteAddr())

	// Try to find exact domain match first
	domainConfig := s.configMgr.GetDomain(domain)
	
	// If not found, try to find parent domain (for subdomains like _acme-challenge.example.com)
	if domainConfig == nil {
		parentDomain := extractParentDomain(domain)
		if parentDomain != "" {
			domainConfig = s.configMgr.GetDomain(parentDomain)
			log.Printf("[DNS] Exact match not found for %s, trying parent domain: %s", domain, parentDomain)
		}
	}
	
	if domainConfig == nil {
		log.Printf("[DNS] Domain not found: %s", domain)
		atomic.AddUint64(&s.stats.NXDomain, 1)
		s.sendNXDOMAIN(w, r)
		return
	}

	// Use GeoDNS if we have GeoDNS map and this is an A query for the main domain
	queryName := cleanDomain(question.Name)
	if qtype == dns.TypeA && len(domainConfig.GeoDNSMap) > 0 && queryName == domainConfig.Domain {
		atomic.AddUint64(&s.stats.GeoDNSQueries, 1)
		log.Printf("[DNS] Using GeoDNS for %s (map size: %d)", domain, len(domainConfig.GeoDNSMap))
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
		detectedLocation := s.geoIP.GetLocation(clientIP)
		if detectedLocation != "" {
			clientLocation = detectedLocation
			log.Printf("[DNS] Client %s detected as location: %s", clientIP, clientLocation)
		}
	}

	log.Printf("[DNS] GeoDNS Query: %s from %s (location: %s)", domainConfig.Domain, clientIP, clientLocation)
	log.Printf("[DNS] GeoDNS Map: %+v", domainConfig.GeoDNSMap)

	agentIP := findBestAgentIP(domainConfig.GeoDNSMap, clientLocation)
	if agentIP == "" {
		log.Printf("[DNS] No agent IP found in GeoDNS map for location: %s", clientLocation)

		// Fallback to first A record
		for _, record := range domainConfig.DNSRecords {
			if record.Type == "A" {
				agentIP = record.Value
				log.Printf("[DNS] Falling back to A record: %s", agentIP)
				break
			}
		}

		if agentIP == "" {
			log.Printf("[DNS] No A records available for fallback")
			s.sendNXDOMAIN(w, r)
			return
		}
	}

	log.Printf("[DNS] GeoDNS Response: %s (location: %s) → %s", domainConfig.Domain, clientLocation, agentIP)

	// Validate IP before creating response
	parsedIP := net.ParseIP(agentIP)
	if parsedIP == nil {
		log.Printf("[DNS] ERROR: Invalid IP address in GeoDNS response: %s", agentIP)
		s.sendNXDOMAIN(w, r)
		return
	}

	msg.Answer = append(msg.Answer, &dns.A{
		Hdr: dns.RR_Header{
			Name:   r.Question[0].Name,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    60,
		},
		A: parsedIP,
	})

	if err := w.WriteMsg(msg); err != nil {
		log.Printf("[DNS] Error writing response: %v", err)
	}
}

func (s *DNSServer) handleRegularDNSQuery(w dns.ResponseWriter, r *dns.Msg, domainConfig *config.Domain) {
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true

	question := r.Question[0]
	qtype := question.Qtype
	queryName := cleanDomain(question.Name)

	log.Printf("[DNS] Regular query for %s (type: %s), have %d DNS records",
		queryName, dns.TypeToString[qtype], len(domainConfig.DNSRecords))

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

	if err := w.WriteMsg(msg); err != nil {
		log.Printf("[DNS] Error writing response: %v", err)
	}
}

func (s *DNSServer) sendNXDOMAIN(w dns.ResponseWriter, r *dns.Msg) {
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Rcode = dns.RcodeNameError
	if err := w.WriteMsg(msg); err != nil {
		log.Printf("[DNS] Error writing NXDOMAIN response: %v", err)
	}
}

func cleanDomain(domain string) string {
	domain = strings.TrimSuffix(domain, ".")
	return strings.ToLower(domain)
}

func extractParentDomain(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) <= 2 {
		return ""
	}
	// Return the last two parts (e.g., "_daun.defenra.cc" -> "defenra.cc")
	return strings.Join(parts[len(parts)-2:], ".")
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
	// Try exact match first
	if ip, ok := geoDNSMap[clientLocation]; ok {
		return ip
	}

	// Try fallback locations
	fallbackMap := map[string][]string{
		"us": {"ca", "mx", "gb", "de"},
		"ca": {"us", "mx", "gb", "de"},
		"mx": {"us", "ca", "br", "cl"},
		"br": {"ar", "cl", "us", "mx"},
		"ar": {"br", "cl", "mx", "us"},
		"cl": {"ar", "br", "mx", "us"},
		"co": {"br", "ar", "mx", "cl"},
		"gb": {"de", "fr", "nl", "us"},
		"de": {"nl", "fr", "gb", "pl"},
		"fr": {"de", "gb", "es", "it"},
		"it": {"fr", "de", "es", "tr"},
		"es": {"fr", "it", "br", "mx"},
		"nl": {"de", "gb", "fr", "pl"},
		"pl": {"de", "ua", "ru", "nl"},
		"ua": {"pl", "ru", "tr", "de"},
		"ru": {"ua", "pl", "kz", "cn"},
		"cn": {"jp", "kr", "sg", "in"},
		"jp": {"kr", "cn", "sg", "au"},
		"kr": {"jp", "cn", "sg", "au"},
		"in": {"sg", "th", "id", "ae"},
		"id": {"sg", "th", "au", "in"},
		"th": {"sg", "id", "in", "cn"},
		"sg": {"id", "th", "in", "au"},
		"au": {"nz", "sg", "id", "jp"},
		"nz": {"au", "sg", "id", "jp"},
		"za": {"eg", "ng", "ae", "gb"},
		"eg": {"ae", "tr", "za", "ng"},
		"ng": {"za", "eg", "br", "fr"},
		"ae": {"ir", "tr", "in", "eg"},
		"tr": {"ae", "ir", "eg", "it"},
		"ir": {"ae", "tr", "kz", "in"},
		"kz": {"ru", "cn", "ir", "tr"},
	}

	if fallbacks, ok := fallbackMap[clientLocation]; ok {
		for _, fallback := range fallbacks {
			if ip, ok := geoDNSMap[fallback]; ok {
				log.Printf("[GeoDNS] No exact match for '%s', using fallback '%s' -> %s", clientLocation, fallback, ip)
				return ip
			}
		}
	}

	// Use default if available
	if ip, ok := geoDNSMap["default"]; ok {
		log.Printf("[GeoDNS] No match for '%s', using default -> %s", clientLocation, ip)
		return ip
	}

	// Return any available IP as last resort
	for location, ip := range geoDNSMap {
		log.Printf("[GeoDNS] No default available, using any available location '%s' -> %s", location, ip)
		return ip
	}

	log.Printf("[GeoDNS] No agent IPs available in GeoDNS map")
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
