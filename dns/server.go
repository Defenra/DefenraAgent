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
	configMgr ConfigManagerInterface
	geoIP     *GeoIPService
	cache     *DNSCache
	stats     *DNSStats
}

// ConfigManagerInterface defines the interface for config manager
type ConfigManagerInterface interface {
	GetDomain(domain string) *config.Domain
	GetAgentIP() string
	GetAgents() []config.FallbackAgentInfo
}

type DNSStats struct {
	TotalQueries  uint64
	CacheHits     uint64
	CacheMisses   uint64
	GeoDNSQueries uint64
	NXDomain      uint64
}

func StartDNSServer(configMgr ConfigManagerInterface) {
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

	// Try to use new GeoDNS agent pools first (with load balancing)
	if len(domainConfig.GeoDNSAgentPools) > 0 {
		agentPool, ok := domainConfig.GeoDNSAgentPools[clientLocation]
		if !ok || len(agentPool) == 0 {
			// Try default pool
			agentPool, ok = domainConfig.GeoDNSAgentPools["default"]
		}

		if ok && len(agentPool) > 0 {
			// Select agent using weighted round-robin
			selectedAgent := selectAgentByWeight(agentPool, clientIP)
			log.Printf("[DNS] GeoDNS Pool Response: %s (location: %s) → %s (load: %.1f%%, weight: %d, pool size: %d)",
				domainConfig.Domain, clientLocation, selectedAgent.IP, selectedAgent.LoadScore, selectedAgent.Weight, len(agentPool))

			parsedIP := net.ParseIP(selectedAgent.IP)
			if parsedIP == nil {
				log.Printf("[DNS] ERROR: Invalid IP address in GeoDNS pool: %s", selectedAgent.IP)
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
			return
		}
	}

	// Fallback to old GeoDNS map (single agent per location)
	log.Printf("[DNS] GeoDNS Map: %+v", domainConfig.GeoDNSMap)
	if len(domainConfig.GeoDnsFallbackMap) > 0 {
		log.Printf("[DNS] GeoDNS Fallback Map: %+v", domainConfig.GeoDnsFallbackMap)
	}

	// Get agents list for coordinate-based fallback
	allAgents := s.configMgr.GetAgents()
	agentIP := findBestAgentIP(domainConfig.GeoDNSMap, domainConfig.GeoDnsFallbackMap, clientLocation, domainConfig.HTTPProxy.Enabled, allAgents)
	if agentIP == "" {
		log.Printf("[DNS] No agent IP found for location: %s (HTTP Proxy: %v)", clientLocation, domainConfig.HTTPProxy.Enabled)
		s.sendNXDOMAIN(w, r)
		return
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

	// сначала ищем CNAME записи для точного совпадения или поддомена
	var cnameRecord *config.DNSRecord
	for _, record := range domainConfig.DNSRecords {
		if record.Type != "CNAME" {
			continue
		}

		recordName := record.Name
		// обработка @ как корневого домена
		if recordName == "@" || recordName == "" {
			recordName = domainConfig.Domain
		} else {
			// если запись относительная (без точки), добавляем домен
			if !strings.HasSuffix(recordName, ".") && !strings.Contains(recordName, ".") {
				// это поддомен нашего домена
				recordName = recordName + "." + domainConfig.Domain
			} else if !strings.HasSuffix(recordName, ".") {
				// проверяем является ли это поддоменом нашего домена
				if strings.HasSuffix(recordName, domainConfig.Domain) {
					// это наш поддомен
				} else {
					// возможно это полное имя, приводим к FQDN
					recordName = dns.Fqdn(recordName)
				}
			}
		}

		// нормализуем для сравнения
		recordNameClean := cleanDomain(recordName)
		queryNameClean := cleanDomain(queryName)

		// проверяем точное совпадение
		if recordNameClean == queryNameClean {
			cnameRecord = &record
			break
		}
	}

	// если найден CNAME, проверяем нужно ли применить CNAME Flattening
	if cnameRecord != nil {
		// CNAME Flattening: если CNAME запись имеет HTTPProxyEnabled и запрашивается A запись,
		// возвращаем A запись с IP агента вместо CNAME (как у Cloudflare)
		if cnameRecord.HTTPProxyEnabled && qtype == dns.TypeA {
			log.Printf("[DNS] CNAME Flattening: %s has HTTP proxy enabled, returning A record with agent IP instead of CNAME", cnameRecord.Value)

			// Get client IP for agent selection
			clientIP := extractClientIP(w.RemoteAddr())

			// Try to find best agent IP using GeoDNS logic if available
			var agentIP string
			if len(domainConfig.GeoDNSMap) > 0 {
				clientLocation := "default"
				if s.geoIP != nil {
					detectedLocation := s.geoIP.GetLocation(clientIP)
					if detectedLocation != "" {
						clientLocation = detectedLocation
					}
				}
				// Get agents list for coordinate-based fallback
				allAgents := s.configMgr.GetAgents()
				agentIP = findBestAgentIP(domainConfig.GeoDNSMap, domainConfig.GeoDnsFallbackMap, clientLocation, cnameRecord.HTTPProxyEnabled, allAgents)
				log.Printf("[DNS] CNAME Flattening: Using GeoDNS agent selection: %s (location: %s) → %s", queryName, clientLocation, agentIP)
			}

			// If no GeoDNS map or no agent found, try to get agent IP from config
			if agentIP == "" {
				// Get agent's own IP address
				agentIP = s.configMgr.GetAgentIP()
				if agentIP == "" {
					log.Printf("[DNS] CNAME Flattening: CRITICAL - No agent IP available for proxied domain. Refusing to leak CNAME target.")
					return
				} else {
					log.Printf("[DNS] CNAME Flattening: Using agent's own IP: %s → %s", queryName, agentIP)
				}
			}

			// If we have agent IP, return A record instead of CNAME
			if agentIP != "" {
				parsedAgentIP := net.ParseIP(agentIP)
				if parsedAgentIP != nil {
					msg.Answer = append(msg.Answer, &dns.A{
						Hdr: dns.RR_Header{
							Name:   question.Name,
							Rrtype: dns.TypeA,
							Class:  dns.ClassINET,
							Ttl:    cnameRecord.TTL,
						},
						A: parsedAgentIP,
					})

					if err := w.WriteMsg(msg); err != nil {
						log.Printf("[DNS] Error writing CNAME flattened response: %v", err)
					}
					return
				} else {
					log.Printf("[DNS] CNAME Flattening: Invalid agent IP address: %s. Refusing to leak CNAME target.", agentIP)
					return
				}
			}
		}

		// Regular CNAME processing (no flattening needed or flattening failed)
		targetDomain := cnameRecord.Value
		// приводим к FQDN формату
		targetFQDN := dns.Fqdn(targetDomain)

		msg.Answer = append(msg.Answer, &dns.CNAME{
			Hdr: dns.RR_Header{
				Name:   question.Name,
				Rrtype: dns.TypeCNAME,
				Class:  dns.ClassINET,
				Ttl:    cnameRecord.TTL,
			},
			Target: targetFQDN,
		})

		// если запрашивается A/AAAA, пытаемся разрешить целевой домен CNAME
		if qtype == dns.TypeA || qtype == dns.TypeAAAA {
			targetDomainClean := cleanDomain(targetFQDN)

			// сначала проверяем есть ли A/AAAA записи для целевого домена в наших записях
			foundInRecords := false
			for _, record := range domainConfig.DNSRecords {
				recordName := record.Name
				if recordName == "@" {
					recordName = domainConfig.Domain
				} else if !strings.HasSuffix(recordName, ".") {
					recordName = recordName + "." + domainConfig.Domain
				}

				// проверяем совпадение с целевым доменом CNAME (может быть поддомен)
				if recordName == targetDomainClean {
					if qtype == dns.TypeA && record.Type == "A" {
						ip := net.ParseIP(record.Value)
						if ip != nil {
							msg.Answer = append(msg.Answer, &dns.A{
								Hdr: dns.RR_Header{
									Name:   targetFQDN,
									Rrtype: dns.TypeA,
									Class:  dns.ClassINET,
									Ttl:    record.TTL,
								},
								A: ip,
							})
							foundInRecords = true
						}
					} else if qtype == dns.TypeAAAA && record.Type == "AAAA" {
						ip := net.ParseIP(record.Value)
						if ip != nil {
							msg.Answer = append(msg.Answer, &dns.AAAA{
								Hdr: dns.RR_Header{
									Name:   targetFQDN,
									Rrtype: dns.TypeAAAA,
									Class:  dns.ClassINET,
									Ttl:    record.TTL,
								},
								AAAA: ip,
							})
							foundInRecords = true
						}
					}
				}
			}

			// если не нашли в наших записях, проверяем не является ли целевой домен внешним
			if !foundInRecords {
				// если целевой домен заканчивается не на наш домен - это внешний CNAME
				if !strings.HasSuffix(targetDomainClean, domainConfig.Domain) {
					log.Printf("[DNS] CNAME points to external domain %s, returning CNAME only", targetDomainClean)
					// для внешних доменов просто возвращаем CNAME, рекурсивный резолвер клиента сам разрешит
				} else {
					// это поддомен нашего домена, но записи нет - возвращаем только CNAME
					log.Printf("[DNS] CNAME target %s not found in records", targetDomainClean)
				}
			}
		}

		if err := w.WriteMsg(msg); err != nil {
			log.Printf("[DNS] Error writing response: %v", err)
		}
		return
	}

	// обычная обработка записей (A, AAAA, MX, TXT)
	for _, record := range domainConfig.DNSRecords {
		recordName := record.Name
		if recordName == "@" {
			recordName = domainConfig.Domain
		} else if !strings.HasSuffix(recordName, ".") {
			recordName = recordName + "." + domainConfig.Domain
		}

		// поддерживаем поддомены - если запрашивается поддомен, проверяем точное совпадение
		if recordName != queryName {
			// для поддоменов также проверяем совпадение без проверки корневого домена
			continue
		}

		switch qtype {
		case dns.TypeA:
			if record.Type == "A" {
				ip := net.ParseIP(record.Value)
				if ip == nil {
					log.Printf("[DNS] Invalid IP address in A record: %s", record.Value)
					continue
				}

				// Check if this record has HTTP proxy enabled
				if record.HTTPProxyEnabled {
					log.Printf("[DNS] A record %s has HTTP proxy enabled, returning agent IP instead of origin IP", record.Value)

					// Get client IP for agent selection
					clientIP := extractClientIP(w.RemoteAddr())

					// Try to find best agent IP using GeoDNS logic if available
					var agentIP string
					if len(domainConfig.GeoDNSMap) > 0 {
						clientLocation := "default"
						if s.geoIP != nil {
							detectedLocation := s.geoIP.GetLocation(clientIP)
							if detectedLocation != "" {
								clientLocation = detectedLocation
							}
						}
						// Get agents list for coordinate-based fallback
						allAgents := s.configMgr.GetAgents()
						agentIP = findBestAgentIP(domainConfig.GeoDNSMap, domainConfig.GeoDnsFallbackMap, clientLocation, record.HTTPProxyEnabled, allAgents)
						log.Printf("[DNS] Using GeoDNS agent selection for proxied record: %s (location: %s) → %s", queryName, clientLocation, agentIP)
					}

					// If no GeoDNS map or no agent found, try to get agent IP from config
					if agentIP == "" {
						// Get agent's own IP address
						agentIP = s.configMgr.GetAgentIP()
						if agentIP == "" {
							log.Printf("[DNS] CRITICAL: HTTPProxyEnabled but no Agent IP available. Refusing to leak Origin IP.")
							continue
						} else {
							log.Printf("[DNS] Using agent's own IP for proxied record: %s → %s", queryName, agentIP)
						}
					}

					// Parse and validate agent IP
					parsedAgentIP := net.ParseIP(agentIP)
					if parsedAgentIP == nil {
						log.Printf("[DNS] CRITICAL: Invalid agent IP address: %s. Refusing to leak Origin IP.", agentIP)
						continue
					}

					msg.Answer = append(msg.Answer, &dns.A{
						Hdr: dns.RR_Header{
							Name:   question.Name,
							Rrtype: dns.TypeA,
							Class:  dns.ClassINET,
							Ttl:    record.TTL,
						},
						A: parsedAgentIP,
					})
				} else {
					// Regular A record without proxy - return original IP
					msg.Answer = append(msg.Answer, &dns.A{
						Hdr: dns.RR_Header{
							Name:   question.Name,
							Rrtype: dns.TypeA,
							Class:  dns.ClassINET,
							Ttl:    record.TTL,
						},
						A: ip,
					})
				}
			}

		case dns.TypeAAAA:
			if record.Type == "AAAA" {
				ip := net.ParseIP(record.Value)
				if ip == nil {
					log.Printf("[DNS] Invalid IP address in AAAA record: %s", record.Value)
					continue
				}
				msg.Answer = append(msg.Answer, &dns.AAAA{
					Hdr: dns.RR_Header{
						Name:   question.Name,
						Rrtype: dns.TypeAAAA,
						Class:  dns.ClassINET,
						Ttl:    record.TTL,
					},
					AAAA: ip,
				})
			}

		case dns.TypeCNAME:
			if record.Type == "CNAME" {
				targetDomain := record.Value
				if !strings.HasSuffix(targetDomain, ".") {
					targetDomain = targetDomain + "."
				}
				msg.Answer = append(msg.Answer, &dns.CNAME{
					Hdr: dns.RR_Header{
						Name:   question.Name,
						Rrtype: dns.TypeCNAME,
						Class:  dns.ClassINET,
						Ttl:    record.TTL,
					},
					Target: dns.Fqdn(targetDomain),
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

func findBestAgentIP(geoDNSMap map[string]string, fallbackMap map[string]string, clientLocation string, httpProxyEnabled bool, allAgents []config.FallbackAgentInfo) string {
	// Try exact match first
	if ip, ok := geoDNSMap[clientLocation]; ok {
		return ip
	}

	// Try Core-provided fallback map (country -> nearest agent)
	if fallbackMap != nil {
		if ip, ok := fallbackMap[clientLocation]; ok {
			log.Printf("[GeoDNS] Using Core fallback map: '%s' -> %s", clientLocation, ip)
			return ip
		}
	}

	// If no exact match and no Core fallback, use coordinate-based fallback with all agents
	if len(allAgents) > 0 {
		clientCoords, ok := LOCATION_COORDINATES[clientLocation]
		if ok {
			var nearestAgent string
			var minDistance float64 = -1

			for _, agent := range allAgents {
				agentCountryCode := strings.ToLower(agent.CountryCode)
				if agentCountryCode == "" {
					continue
				}

				// Check political restrictions
				if isRoutingRestricted(clientLocation, agentCountryCode) {
					continue
				}

				agentCoords, ok := LOCATION_COORDINATES[agentCountryCode]
				if !ok {
					continue
				}

				dist := calculateHaversineDistance(
					clientCoords.Lat, clientCoords.Lon,
					agentCoords.Lat, agentCoords.Lon,
				)

				if minDistance == -1 || dist < minDistance {
					minDistance = dist
					nearestAgent = agent.AgentIp
				}
			}

			if nearestAgent != "" {
				log.Printf("[GeoDNS] No exact match for '%s', using nearest agent: %s (distance: %.0f km)",
					clientLocation, nearestAgent, minDistance)
				return nearestAgent
			}
		}
	}

	// When HTTP proxy is enabled and no match found
	if httpProxyEnabled {
		log.Printf("[GeoDNS] No agent available for location '%s' - returning NXDOMAIN", clientLocation)
		return ""
	}

	// HTTP proxy disabled - can use default (origin IP)
	if ip, ok := geoDNSMap["default"]; ok {
		log.Printf("[GeoDNS] No agent match for '%s', using default/origin -> %s", clientLocation, ip)
		return ip
	}

	// DO NOT fall back to random agents. Strict routing required.
	log.Printf("[GeoDNS] No IPs available in GeoDNS map for location '%s'", clientLocation)
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

// selectAgentByWeight selects an agent from pool using weighted round-robin
// based on client IP for consistent distribution
func selectAgentByWeight(pool []config.GeoDNSAgentInfo, clientIP string) config.GeoDNSAgentInfo {
	if len(pool) == 0 {
		return config.GeoDNSAgentInfo{}
	}

	if len(pool) == 1 {
		return pool[0]
	}

	// Calculate total weight
	totalWeight := 0
	for _, agent := range pool {
		totalWeight += agent.Weight
	}

	if totalWeight == 0 {
		// All agents have zero weight - use simple round-robin
		// Hash client IP to get consistent selection
		hash := hashFNV1a(clientIP)
		return pool[int(hash)%len(pool)]
	}

	// Use client IP hash for consistent selection (same client → same agent)
	// This provides sticky sessions while distributing load
	hash := hashFNV1a(clientIP)
	selection := int(hash % uint32(totalWeight))

	// Select agent based on weight
	currentWeight := 0
	for _, agent := range pool {
		currentWeight += agent.Weight
		if selection < currentWeight {
			return agent
		}
	}

	// Fallback (should never reach here)
	return pool[0]
}

// hashFNV1a creates a robust hash from string using FNV-1a algorithm
func hashFNV1a(s string) uint32 {
	const offset32 = 2166136261
	const prime32 = 16777619
	hash := uint32(offset32)
	for i := 0; i < len(s); i++ {
		hash ^= uint32(s[i])
		hash *= prime32
	}
	return hash
}
