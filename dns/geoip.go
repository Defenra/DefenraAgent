package dns

import (
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

	countryMap := map[string]string{
		"us": "us",
		"ca": "ca",
		"mx": "mx",
		"br": "br",
		"ar": "ar",
		"cl": "cl",
		"co": "co",
		"gb": "gb",
		"de": "de",
		"fr": "fr",
		"it": "it",
		"es": "es",
		"nl": "nl",
		"pl": "pl",
		"ua": "ua",
		"ru": "ru",
		"cn": "cn",
		"jp": "jp",
		"kr": "kr",
		"in": "in",
		"id": "id",
		"th": "th",
		"sg": "sg",
		"au": "au",
		"nz": "nz",
		"za": "za",
		"eg": "eg",
		"ng": "ng",
		"ae": "ae",
		"tr": "tr",
		"ir": "ir",
		"kz": "kz",
	}

	if location, ok := countryMap[countryCode]; ok {
		return location
	}

	return "default"
}

func (g *GeoIPService) Close() error {
	if g.db != nil {
		return g.db.Close()
	}
	return nil
}
