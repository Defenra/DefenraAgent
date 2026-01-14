package proxy

import (
	"fmt"
	"log"
	"net/http"
	"regexp"
	"sort"
	"strings"

	"github.com/defenra/agent/config"
)

type PageRuleMatch struct {
	Rule     *config.PageRule
	Priority int
}

// MatchPageRules находит все подходящие Page Rules для данного URL
func MatchPageRules(rules []config.PageRule, requestURL string) []*config.PageRule {
	var matches []*PageRuleMatch

	for i := range rules {
		rule := &rules[i]
		if !rule.Enabled {
			continue
		}

		if matchesPattern(rule.URLPattern, requestURL) {
			matches = append(matches, &PageRuleMatch{
				Rule:     rule,
				Priority: rule.Priority,
			})
		}
	}

	// Сортируем по приоритету (меньше = выше приоритет)
	sort.Slice(matches, func(i, j int) bool {
		return matches[i].Priority < matches[j].Priority
	})

	// Возвращаем только правила
	result := make([]*config.PageRule, len(matches))
	for i, match := range matches {
		result[i] = match.Rule
	}

	return result
}

// matchesPattern проверяет соответствие URL паттерну
// Поддерживает wildcards: * (любые символы), ? (один символ)
func matchesPattern(pattern, url string) bool {
	// Преобразуем wildcard паттерн в regex
	// * -> .*
	// ? -> .
	regexPattern := regexp.QuoteMeta(pattern)
	regexPattern = strings.ReplaceAll(regexPattern, `\*`, ".*")
	regexPattern = strings.ReplaceAll(regexPattern, `\?`, ".")
	regexPattern = "^" + regexPattern + "$"

	matched, err := regexp.MatchString(regexPattern, url)
	if err != nil {
		log.Printf("[PageRules] Error matching pattern %s: %v", pattern, err)
		return false
	}

	return matched
}

// ApplyPageRules применяет Page Rules к запросу
// Возвращает true если запрос должен быть обработан специальным образом (redirect, block, etc)
func ApplyPageRules(w http.ResponseWriter, r *http.Request, rules []*config.PageRule, domainConfig *config.Domain) (handled bool, skipSecurity bool, skipRateLimit bool, customBackend string) {
	if len(rules) == 0 {
		return false, false, false, ""
	}

	for _, rule := range rules {
		actions := rule.Actions

		// Always Use HTTPS
		if actions.AlwaysUseHTTPS != nil && *actions.AlwaysUseHTTPS {
			if r.TLS == nil && r.Header.Get("X-Forwarded-Proto") != "https" {
				httpsURL := "https://" + r.Host + r.RequestURI
				http.Redirect(w, r, httpsURL, http.StatusMovedPermanently)
				return true, false, false, ""
			}
		}

		// Forwarding URL (Redirect)
		if actions.ForwardingURL != nil && actions.ForwardingURL.URL != "" {
			http.Redirect(w, r, actions.ForwardingURL.URL, actions.ForwardingURL.StatusCode)
			return true, false, false, ""
		}

		// Custom Headers
		if actions.CustomHeaders != nil {
			for key, value := range actions.CustomHeaders {
				w.Header().Set(key, value)
			}
		}

		// Cache Control Headers
		if actions.BrowserCacheTTL != nil {
			w.Header().Set("Cache-Control", formatCacheControl(*actions.BrowserCacheTTL))
		}

		// Security Headers based on Security Level
		if actions.SecurityLevel != "" {
			applySecurityHeaders(w, actions.SecurityLevel)
		}

		// Disable Security (bypass WAF)
		if actions.DisableSecurity != nil && *actions.DisableSecurity {
			skipSecurity = true
		}

		// Disable Rate Limiting
		if actions.DisableRateLimiting != nil && *actions.DisableRateLimiting {
			skipRateLimit = true
		}

		// Resolve Override (change backend)
		if actions.ResolveOverride != "" {
			customBackend = actions.ResolveOverride
		}

		// IP Geolocation Header
		if actions.IPGeolocationHeader != nil && *actions.IPGeolocationHeader {
			// Добавляем заголовок с информацией о геолокации клиента
			// В реальной реализации здесь должен быть lookup GeoIP
			clientIP := getClientIP(r)
			w.Header().Set("CF-IPCountry", "XX") // Placeholder
			w.Header().Set("X-Client-IP", clientIP)
		}
	}

	return false, skipSecurity, skipRateLimit, customBackend
}

func formatCacheControl(ttl int) string {
	if ttl <= 0 {
		return "no-cache, no-store, must-revalidate"
	}
	return fmt.Sprintf("public, max-age=%d", ttl)
}

func applySecurityHeaders(w http.ResponseWriter, level string) {
	switch level {
	case "off", "essentially_off":
		// Минимальные заголовки безопасности
		return
	case "low":
		w.Header().Set("X-Content-Type-Options", "nosniff")
	case "medium":
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
	case "high", "under_attack":
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	}
}
