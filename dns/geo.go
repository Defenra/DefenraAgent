package dns

import "math"

// Coordinates for countries
type Coordinates struct {
	Lat float64
	Lon float64
}

// LOCATION_COORDINATES contains coordinates for all countries to enable
// coordinate-based fallback for GeoDNS when no exact agent match exists
var LOCATION_COORDINATES = map[string]Coordinates{
	// North America
	"us": {Lat: 37.0902, Lon: -95.7129},  // United States
	"ca": {Lat: 56.1304, Lon: -106.3468}, // Canada
	"mx": {Lat: 23.6345, Lon: -102.5528}, // Mexico

	// Europe
	"de": {Lat: 51.1657, Lon: 10.4515}, // Germany
	"fr": {Lat: 46.2276, Lon: 2.2137},  // France
	"gb": {Lat: 55.3781, Lon: -3.4360}, // United Kingdom
	"it": {Lat: 41.8719, Lon: 12.5674}, // Italy
	"es": {Lat: 40.4637, Lon: -3.7492}, // Spain
	"nl": {Lat: 52.1326, Lon: 5.2913},  // Netherlands
	"be": {Lat: 50.8503, Lon: 4.3517},  // Belgium
	"ch": {Lat: 46.8182, Lon: 8.2275},  // Switzerland
	"at": {Lat: 47.5162, Lon: 14.5501}, // Austria
	"pl": {Lat: 51.9194, Lon: 19.1451}, // Poland
	"cz": {Lat: 49.8175, Lon: 15.4730}, // Czech Republic
	"se": {Lat: 60.1282, Lon: 18.6435}, // Sweden
	"no": {Lat: 60.4720, Lon: 8.4689},  // Norway
	"dk": {Lat: 56.2639, Lon: 9.5018},  // Denmark
	"fi": {Lat: 61.9241, Lon: 25.7482}, // Finland
	"ie": {Lat: 53.1424, Lon: -7.6921}, // Ireland
	"pt": {Lat: 39.3999, Lon: -8.2245}, // Portugal
	"gr": {Lat: 39.0742, Lon: 21.8243}, // Greece
	"hu": {Lat: 47.1625, Lon: 19.5033}, // Hungary
	"ro": {Lat: 45.9432, Lon: 24.9668}, // Romania
	"bg": {Lat: 42.7339, Lon: 25.4858}, // Bulgaria
	"sk": {Lat: 48.6690, Lon: 19.6990}, // Slovakia
	"hr": {Lat: 45.1000, Lon: 15.2000}, // Croatia
	"si": {Lat: 46.1512, Lon: 14.9955}, // Slovenia
	"lt": {Lat: 55.1694, Lon: 23.8813}, // Lithuania
	"lv": {Lat: 56.8796, Lon: 24.6032}, // Latvia
	"ee": {Lat: 58.5953, Lon: 25.0136}, // Estonia
	"lu": {Lat: 49.8153, Lon: 6.1296},  // Luxembourg
	"mt": {Lat: 35.9375, Lon: 14.3754}, // Malta
	"cy": {Lat: 35.1264, Lon: 33.4299}, // Cyprus

	// Eastern Europe / CIS
	"ru": {Lat: 61.5240, Lon: 105.3188}, // Russia
	"ua": {Lat: 48.3794, Lon: 31.1656},  // Ukraine
	"by": {Lat: 53.7098, Lon: 27.9534},  // Belarus
	"kz": {Lat: 48.0196, Lon: 66.9237},  // Kazakhstan
	"md": {Lat: 47.4116, Lon: 28.3699},  // Moldova
	"az": {Lat: 40.1431, Lon: 47.5769},  // Azerbaijan
	"am": {Lat: 40.0691, Lon: 45.0382},  // Armenia
	"ge": {Lat: 42.3154, Lon: 43.3569},  // Georgia
	"uz": {Lat: 41.3775, Lon: 64.5853},  // Uzbekistan
	"kg": {Lat: 41.2044, Lon: 74.7661},  // Kyrgyzstan
	"tj": {Lat: 38.8610, Lon: 71.2761},  // Tajikistan
	"tm": {Lat: 38.9697, Lon: 59.5563},  // Turkmenistan

	// Asia
	"jp": {Lat: 36.2048, Lon: 138.2529}, // Japan
	"hk": {Lat: 22.3193, Lon: 114.1694}, // Hong Kong
	"sg": {Lat: 1.3521, Lon: 103.8198},  // Singapore
	"cn": {Lat: 35.8617, Lon: 104.1954}, // China
	"kr": {Lat: 35.9078, Lon: 127.7669}, // South Korea
	"tw": {Lat: 23.6978, Lon: 120.9605}, // Taiwan
	"in": {Lat: 20.5937, Lon: 78.9629},  // India
	"id": {Lat: -0.7893, Lon: 113.9213}, // Indonesia
	"th": {Lat: 15.8700, Lon: 100.9925}, // Thailand
	"vn": {Lat: 14.0583, Lon: 108.2772}, // Vietnam
	"my": {Lat: 4.2105, Lon: 101.9758},  // Malaysia
	"ph": {Lat: 12.8797, Lon: 121.7740}, // Philippines
	"pk": {Lat: 30.3753, Lon: 69.3451},  // Pakistan
	"bd": {Lat: 23.6850, Lon: 90.3563},  // Bangladesh
	"lk": {Lat: 7.8731, Lon: 80.7718},   // Sri Lanka
	"np": {Lat: 28.3949, Lon: 84.1240},  // Nepal
	"mm": {Lat: 21.9162, Lon: 95.9560},  // Myanmar
	"kh": {Lat: 12.5657, Lon: 104.9910}, // Cambodia
	"la": {Lat: 19.8563, Lon: 102.4955}, // Laos
	"mn": {Lat: 46.8625, Lon: 103.8467}, // Mongolia

	// Middle East
	"tr": {Lat: 38.9637, Lon: 35.2433}, // Turkey
	"ir": {Lat: 32.4279, Lon: 53.6880}, // Iran
	"sa": {Lat: 23.8859, Lon: 45.0792}, // Saudi Arabia
	"ae": {Lat: 23.4241, Lon: 53.8478}, // UAE
	"il": {Lat: 31.0461, Lon: 34.8516}, // Israel
	"jo": {Lat: 30.5852, Lon: 36.2384}, // Jordan
	"lb": {Lat: 33.8547, Lon: 35.8623}, // Lebanon
	"iq": {Lat: 33.2232, Lon: 43.6793}, // Iraq
	"sy": {Lat: 34.8021, Lon: 38.9968}, // Syria
	"om": {Lat: 21.4735, Lon: 55.9754}, // Oman
	"qa": {Lat: 25.3548, Lon: 51.1839}, // Qatar
	"bh": {Lat: 25.9304, Lon: 50.6378}, // Bahrain
	"kw": {Lat: 29.3117, Lon: 47.4818}, // Kuwait

	// Oceania
	"au": {Lat: -25.2744, Lon: 133.7751}, // Australia
	"nz": {Lat: -40.9006, Lon: 174.8860}, // New Zealand

	// South America
	"br": {Lat: -14.2350, Lon: -51.9253}, // Brazil
	"ar": {Lat: -38.4161, Lon: -63.6167}, // Argentina
	"cl": {Lat: -35.6751, Lon: -71.5430}, // Chile
	"co": {Lat: 4.5709, Lon: -74.2973},   // Colombia
	"pe": {Lat: -9.1900, Lon: -75.0152},  // Peru
	"ve": {Lat: 6.4238, Lon: -66.5897},   // Venezuela
	"ec": {Lat: -1.8312, Lon: -78.1834},  // Ecuador
	"bo": {Lat: -16.2902, Lon: -63.5887}, // Bolivia
	"py": {Lat: -23.4425, Lon: -58.4438}, // Paraguay
	"uy": {Lat: -32.5228, Lon: -55.7658}, // Uruguay
	"gy": {Lat: 4.8604, Lon: -58.9302},   // Guyana
	"sr": {Lat: 3.9193, Lon: -56.0278},   // Suriname

	// Africa
	"za": {Lat: -30.5595, Lon: 22.9375}, // South Africa
	"eg": {Lat: 26.0975, Lon: 30.0444},  // Egypt
	"ng": {Lat: 9.0820, Lon: 8.6753},    // Nigeria
	"ke": {Lat: -0.0236, Lon: 37.9062},  // Kenya
	"et": {Lat: 9.1450, Lon: 40.4897},   // Ethiopia
	"tz": {Lat: -6.3690, Lon: 34.8888},  // Tanzania
	"gh": {Lat: 7.9465, Lon: -1.0232},   // Ghana
	"mz": {Lat: -18.6657, Lon: 35.5296}, // Mozambique
	"mg": {Lat: -18.7669, Lon: 46.8691}, // Madagascar
	"cm": {Lat: 7.3697, Lon: 12.3547},   // Cameroon
	"ci": {Lat: 7.5400, Lon: -5.5471},   // Ivory Coast
	"ne": {Lat: 17.6078, Lon: 8.0817},   // Niger
	"sn": {Lat: 14.4974, Lon: -14.4524}, // Senegal
	"ml": {Lat: 17.5707, Lon: -3.9962},  // Mali
	"bf": {Lat: 12.2383, Lon: -1.5616},  // Burkina Faso
	"rw": {Lat: -1.9403, Lon: 29.8739},  // Rwanda
	"so": {Lat: 5.1521, Lon: 46.1996},   // Somalia
	"ss": {Lat: 6.8770, Lon: 31.3070},   // South Sudan
	"sd": {Lat: 12.8628, Lon: 30.2176},  // Sudan
	"ug": {Lat: 1.3733, Lon: 32.2903},   // Uganda
	"zm": {Lat: -13.1339, Lon: 27.8493}, // Zambia
	"zw": {Lat: -19.0154, Lon: 29.1549}, // Zimbabwe
	"bw": {Lat: -22.3285, Lon: 24.6849}, // Botswana
	"na": {Lat: -22.9576, Lon: 18.4904}, // Namibia
	"ao": {Lat: -11.2027, Lon: 17.8739}, // Angola
	"cd": {Lat: -4.0383, Lon: 21.7587},  // DR Congo
	"cg": {Lat: -0.2280, Lon: 15.8277},  // Congo
	"ga": {Lat: -0.8037, Lon: 11.6094},  // Gabon
	"gq": {Lat: 1.6508, Lon: 10.2679},   // Equatorial Guinea
	"st": {Lat: 0.1864, Lon: 6.6131},    // Sao Tome and Principe
	"bi": {Lat: -3.3731, Lon: 29.9189},  // Burundi
	"dj": {Lat: 11.8251, Lon: 42.5903},  // Djibouti
	"er": {Lat: 15.1794, Lon: 39.7823},  // Eritrea
	"ls": {Lat: -29.6100, Lon: 28.2336}, // Lesotho
	"sz": {Lat: -26.5225, Lon: 31.4659}, // Eswatini
	"mu": {Lat: -20.3484, Lon: 57.5522}, // Mauritius
	"km": {Lat: -11.8750, Lon: 43.8722}, // Comoros
	"sc": {Lat: -4.6796, Lon: 55.4920},  // Seychelles
	"cv": {Lat: 16.5388, Lon: -23.0418}, // Cape Verde

	// Central America & Caribbean
	"gt": {Lat: 15.7835, Lon: -90.2308}, // Guatemala
	"hn": {Lat: 15.2000, Lon: -86.2419}, // Honduras
	"sv": {Lat: 13.7942, Lon: -88.8965}, // El Salvador
	"ni": {Lat: 12.8654, Lon: -85.2072}, // Nicaragua
	"cr": {Lat: 9.7489, Lon: -83.7534},  // Costa Rica
	"pa": {Lat: 8.5380, Lon: -80.7821},  // Panama
	"cu": {Lat: 21.5218, Lon: -77.7812}, // Cuba
	"jm": {Lat: 18.1096, Lon: -77.2975}, // Jamaica
	"ht": {Lat: 18.9712, Lon: -72.2852}, // Haiti
	"do": {Lat: 18.7357, Lon: -70.1627}, // Dominican Republic
	"tt": {Lat: 10.6918, Lon: -61.2225}, // Trinidad and Tobago
	"bb": {Lat: 13.1939, Lon: -59.5432}, // Barbados
	"bs": {Lat: 25.0343, Lon: -77.3963}, // Bahamas
	"bz": {Lat: 17.1899, Lon: -88.4976}, // Belize
}

// isRoutingRestricted checks political routing restrictions
func isRoutingRestricted(from, to string) bool {
	// UA cannot route to RU or BY
	if from == "ua" && (to == "ru" || to == "by") {
		return true
	}
	// RU cannot route to UA
	if from == "ru" && to == "ua" {
		return true
	}
	return false
}

// calculateHaversineDistance calculates distance between two points on Earth
func calculateHaversineDistance(lat1, lon1, lat2, lon2 float64) float64 {
	const R = 6371 // Earth radius in km

	lat1Rad := lat1 * math.Pi / 180
	lat2Rad := lat2 * math.Pi / 180
	deltaLat := (lat2 - lat1) * math.Pi / 180
	deltaLon := (lon2 - lon1) * math.Pi / 180

	a := math.Sin(deltaLat/2)*math.Sin(deltaLat/2) +
		math.Cos(lat1Rad)*math.Cos(lat2Rad)*
			math.Sin(deltaLon/2)*math.Sin(deltaLon/2)
	c := 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))

	return R * c
}
