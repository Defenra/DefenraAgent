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
	if countryCode == "" {
		return "default"
	}

	// ISO 3166-1 alpha-2 country codes mapping
	// Primary countries with dedicated agents
	// Fallback to geographically closest primary country
	countryMap := map[string]string{
		// North America
		"us": "us", // United States
		"ca": "ca", // Canada
		"mx": "mx", // Mexico
		"ag": "us", // Antigua and Barbuda
		"ai": "us", // Anguilla
		"aw": "us", // Aruba
		"bb": "us", // Barbados
		"bl": "us", // Saint Barthélemy
		"bm": "us", // Bermuda
		"bq": "us", // Caribbean Netherlands
		"bs": "us", // Bahamas
		"bz": "mx", // Belize
		"cr": "mx", // Costa Rica
		"cu": "mx", // Cuba
		"cw": "us", // Curaçao
		"dm": "us", // Dominica
		"do": "us", // Dominican Republic
		"gd": "us", // Grenada
		"gl": "ca", // Greenland
		"gp": "us", // Guadeloupe
		"gt": "mx", // Guatemala
		"hn": "mx", // Honduras
		"ht": "us", // Haiti
		"jm": "us", // Jamaica
		"kn": "us", // Saint Kitts and Nevis
		"ky": "us", // Cayman Islands
		"lc": "us", // Saint Lucia
		"mf": "us", // Saint Martin
		"mq": "us", // Martinique
		"ms": "us", // Montserrat
		"ni": "mx", // Nicaragua
		"pa": "mx", // Panama
		"pm": "ca", // Saint Pierre and Miquelon
		"pr": "us", // Puerto Rico
		"sv": "mx", // El Salvador
		"sx": "us", // Sint Maarten
		"tc": "us", // Turks and Caicos Islands
		"tt": "us", // Trinidad and Tobago
		"vc": "us", // Saint Vincent and the Grenadines
		"vg": "us", // British Virgin Islands
		"vi": "us", // U.S. Virgin Islands
		
		// South America
		"ar": "ar", // Argentina
		"br": "br", // Brazil
		"cl": "cl", // Chile
		"co": "co", // Colombia
		"bo": "br", // Bolivia
		"ec": "co", // Ecuador
		"fk": "ar", // Falkland Islands
		"gf": "br", // French Guiana
		"gy": "br", // Guyana
		"pe": "co", // Peru
		"py": "br", // Paraguay
		"sr": "br", // Suriname
		"uy": "ar", // Uruguay
		"ve": "co", // Venezuela
		
		// Western Europe
		"gb": "gb", // United Kingdom
		"de": "de", // Germany
		"fr": "fr", // France
		"es": "es", // Spain
		"it": "it", // Italy
		"nl": "nl", // Netherlands
		"ad": "es", // Andorra
		"at": "de", // Austria
		"ax": "de", // Åland Islands
		"be": "nl", // Belgium
		"ch": "de", // Switzerland
		"fo": "de", // Faroe Islands
		"gg": "gb", // Guernsey
		"gi": "es", // Gibraltar
		"ie": "gb", // Ireland
		"im": "gb", // Isle of Man
		"is": "gb", // Iceland
		"je": "gb", // Jersey
		"li": "de", // Liechtenstein
		"lu": "de", // Luxembourg
		"mc": "fr", // Monaco
		"pt": "es", // Portugal
		"sm": "it", // San Marino
		"va": "it", // Vatican City
		
		// Eastern Europe
		"pl": "pl", // Poland
		"ua": "ua", // Ukraine
		"ru": "ru", // Russia
		"al": "it", // Albania
		"ba": "de", // Bosnia and Herzegovina
		"bg": "tr", // Bulgaria
		"by": "ru", // Belarus
		"cz": "de", // Czech Republic
		"ee": "pl", // Estonia
		"gr": "it", // Greece
		"hr": "it", // Croatia
		"hu": "de", // Hungary
		"lt": "pl", // Lithuania
		"lv": "pl", // Latvia
		"md": "ua", // Moldova
		"me": "it", // Montenegro
		"mk": "it", // North Macedonia
		"ro": "tr", // Romania
		"rs": "de", // Serbia
		"si": "it", // Slovenia
		"sk": "de", // Slovakia
		"xk": "de", // Kosovo
		
		// Northern Europe
		"dk": "de", // Denmark
		"fi": "de", // Finland
		"no": "de", // Norway
		"se": "de", // Sweden
		"sj": "de", // Svalbard and Jan Mayen
		
		// Middle East & Turkey
		"tr": "tr", // Turkey
		"ae": "ae", // United Arab Emirates
		"ir": "ir", // Iran
		"am": "tr", // Armenia
		"az": "tr", // Azerbaijan
		"bh": "ae", // Bahrain
		"cy": "tr", // Cyprus
		"ge": "tr", // Georgia
		"il": "tr", // Israel
		"iq": "ae", // Iraq
		"jo": "ae", // Jordan
		"kw": "ae", // Kuwait
		"lb": "ae", // Lebanon
		"om": "ae", // Oman
		"ps": "ae", // Palestine
		"qa": "ae", // Qatar
		"sa": "ae", // Saudi Arabia
		"sy": "ae", // Syria
		"ye": "ae", // Yemen
		
		// Central Asia
		"kz": "kz", // Kazakhstan
		"af": "kz", // Afghanistan
		"kg": "kz", // Kyrgyzstan
		"tj": "kz", // Tajikistan
		"tm": "kz", // Turkmenistan
		"uz": "kz", // Uzbekistan
		
		// South Asia
		"in": "in", // India
		"bd": "in", // Bangladesh
		"bt": "in", // Bhutan
		"lk": "in", // Sri Lanka
		"mv": "in", // Maldives
		"np": "in", // Nepal
		"pk": "in", // Pakistan
		
		// East Asia
		"cn": "cn", // China
		"jp": "jp", // Japan
		"kr": "kr", // South Korea
		"hk": "cn", // Hong Kong
		"kp": "cn", // North Korea
		"mo": "cn", // Macau
		"mn": "cn", // Mongolia
		"tw": "jp", // Taiwan
		
		// Southeast Asia
		"id": "id", // Indonesia
		"th": "th", // Thailand
		"sg": "sg", // Singapore
		"bn": "sg", // Brunei
		"kh": "th", // Cambodia
		"la": "th", // Laos
		"mm": "th", // Myanmar
		"my": "sg", // Malaysia
		"ph": "sg", // Philippines
		"tl": "id", // Timor-Leste
		"vn": "sg", // Vietnam
		
		// Oceania
		"au": "au", // Australia
		"nz": "nz", // New Zealand
		"as": "au", // American Samoa
		"cc": "au", // Cocos Islands
		"ck": "nz", // Cook Islands
		"cx": "au", // Christmas Island
		"fj": "au", // Fiji
		"fm": "au", // Micronesia
		"gu": "au", // Guam
		"ki": "au", // Kiribati
		"mh": "au", // Marshall Islands
		"mp": "au", // Northern Mariana Islands
		"nc": "au", // New Caledonia
		"nf": "au", // Norfolk Island
		"nr": "au", // Nauru
		"nu": "nz", // Niue
		"pf": "au", // French Polynesia
		"pg": "au", // Papua New Guinea
		"pw": "au", // Palau
		"sb": "au", // Solomon Islands
		"tk": "nz", // Tokelau
		"to": "nz", // Tonga
		"tv": "au", // Tuvalu
		"vu": "au", // Vanuatu
		"wf": "au", // Wallis and Futuna
		"ws": "nz", // Samoa
		
		// North Africa
		"eg": "eg", // Egypt
		"dz": "eg", // Algeria
		"eh": "eg", // Western Sahara
		"ly": "eg", // Libya
		"ma": "eg", // Morocco
		"sd": "eg", // Sudan
		"ss": "eg", // South Sudan
		"tn": "eg", // Tunisia
		
		// West Africa
		"ng": "ng", // Nigeria
		"bf": "ng", // Burkina Faso
		"bj": "ng", // Benin
		"ci": "ng", // Ivory Coast
		"cv": "ng", // Cape Verde
		"gh": "ng", // Ghana
		"gm": "ng", // Gambia
		"gn": "ng", // Guinea
		"gw": "ng", // Guinea-Bissau
		"lr": "ng", // Liberia
		"ml": "ng", // Mali
		"mr": "eg", // Mauritania
		"ne": "ng", // Niger
		"sh": "ng", // Saint Helena
		"sl": "ng", // Sierra Leone
		"sn": "ng", // Senegal
		"tg": "ng", // Togo
		
		// East Africa
		"ke": "za", // Kenya
		"bi": "za", // Burundi
		"dj": "eg", // Djibouti
		"er": "eg", // Eritrea
		"et": "eg", // Ethiopia
		"io": "za", // British Indian Ocean Territory
		"km": "za", // Comoros
		"mg": "za", // Madagascar
		"mu": "za", // Mauritius
		"mw": "za", // Malawi
		"mz": "za", // Mozambique
		"re": "za", // Réunion
		"rw": "za", // Rwanda
		"sc": "za", // Seychelles
		"so": "eg", // Somalia
		"tz": "za", // Tanzania
		"ug": "za", // Uganda
		"yt": "za", // Mayotte
		"zm": "za", // Zambia
		"zw": "za", // Zimbabwe
		
		// Central & Southern Africa
		"za": "za", // South Africa
		"ao": "za", // Angola
		"bw": "za", // Botswana
		"cd": "za", // DR Congo
		"cf": "za", // Central African Republic
		"cg": "za", // Congo
		"cm": "ng", // Cameroon
		"ga": "za", // Gabon
		"gq": "ng", // Equatorial Guinea
		"ls": "za", // Lesotho
		"na": "za", // Namibia
		"st": "ng", // São Tomé and Príncipe
		"sz": "za", // Eswatini
		"td": "eg", // Chad
		
		// Antarctica & Special
		"aq": "au", // Antarctica
	}

	if location, ok := countryMap[countryCode]; ok {
		return location
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
