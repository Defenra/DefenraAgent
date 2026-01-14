package dns

import (
	"log"
	"net"
	"strings"
	"sync"

	"github.com/oschwald/geoip2-golang"
)

type GeoIPService struct {
	db    *geoip2.Reader
	cache map[string]string
	mu    sync.RWMutex
}

func NewGeoIPService(dbPath string) (*GeoIPService, error) {
	db, err := geoip2.Open(dbPath)
	if err != nil {
		return nil, err
	}

	return &GeoIPService{
		db:    db,
		cache: make(map[string]string),
	}, nil
}

func (g *GeoIPService) GetLocation(ip string) string {
	g.mu.RLock()
	if loc, ok := g.cache[ip]; ok {
		g.mu.RUnlock()
		return loc
	}
	g.mu.RUnlock()

	location := g.lookupLocation(ip)

	g.mu.Lock()
	g.cache[ip] = location
	g.mu.Unlock()

	return location
}

func (g *GeoIPService) lookupLocation(ip string) string {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return "default"
	}

	record, err := g.db.City(parsedIP)
	if err != nil {
		return "default"
	}

	countryCode := strings.ToLower(record.Country.IsoCode)

	// Return country code directly - routing is handled by GeoDNS map from API
	if countryCode != "" {
		return countryCode
	}

	// Fallback to continent for unknown countries
	continent := strings.ToLower(record.Continent.Code)

	continentMap := map[string]string{
		"eu": "de", // Europe -> Germany
		"na": "us", // North America -> USA
		"sa": "br", // South America -> Brazil
		"as": "sg", // Asia -> Singapore
		"oc": "au", // Oceania -> Australia
		"af": "za", // Africa -> South Africa
	}

	if location, ok := continentMap[continent]; ok {
		log.Printf("[GeoIP] Country %s (continent: %s) not in map, using fallback: %s", countryCode, continent, location)
		return location
	}

	log.Printf("[GeoIP] Could not determine location for IP %s (country: %s, continent: %s)", ip, countryCode, continent)
	return "default"
}

func (g *GeoIPService) Close() error {
	if g.db != nil {
		return g.db.Close()
	}
	return nil
}
