package dns

import "math"

// Coordinates for countries
type Coordinates struct {
	Lat float64
	Lon float64
}

var LOCATION_COORDINATES = map[string]Coordinates{
	"us": {Lat: 37.0902, Lon: -95.7129},
	"de": {Lat: 51.1657, Lon: 10.4515},
	"cz": {Lat: 49.8175, Lon: 15.4730},
	"ru": {Lat: 61.5240, Lon: 105.3188},
	"kz": {Lat: 48.0196, Lon: 66.9237},
	"ua": {Lat: 48.3794, Lon: 31.1656},
	"by": {Lat: 53.7098, Lon: 27.9534},
	"pl": {Lat: 51.9194, Lon: 19.1451},
	"gb": {Lat: 55.3781, Lon: -3.4360},
	"fr": {Lat: 46.2276, Lon: 2.2137},
	"it": {Lat: 41.8719, Lon: 12.5674},
	"es": {Lat: 40.4637, Lon: -3.7492},
	"nl": {Lat: 52.1326, Lon: 5.2913},
	"jp": {Lat: 36.2048, Lon: 138.2529},
	"hk": {Lat: 22.3193, Lon: 114.1694},
	"sg": {Lat: 1.3521, Lon: 103.8198},
	"au": {Lat: -25.2744, Lon: 133.7751},
	"br": {Lat: -14.2350, Lon: -51.9253},
	"in": {Lat: 20.5937, Lon: 78.9629},
	"tr": {Lat: 38.9637, Lon: 35.2433},
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
