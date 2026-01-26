package firewall

import (
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
)

type RuleEngine struct {
	rules []CompiledRule
}

type CompiledRule struct {
	Name       string
	Expression string
	Action     string
	Enabled    bool
	Filter     *ExpressionFilter
}

type ExpressionFilter struct {
	expression string
}

type RequestContext struct {
	ClientIP       string
	Country        string
	ASN            string
	BrowserType    string
	BotType        string
	TLSFingerprint string
	RequestCount   int
	ChallengeCount int
	Host           string
	Method         string
	URL            string
	Path           string
	Query          string
	UserAgent      string
	Headers        map[string]string
	SuspicionLevel int
	IsCloudflare   bool
	IsAttack       bool
	RequestsPerSec int
}

func NewRuleEngine() *RuleEngine {
	return &RuleEngine{
		rules: make([]CompiledRule, 0),
	}
}

func (re *RuleEngine) AddRule(name, expression, action string, enabled bool) error {
	filter, err := NewExpressionFilter(expression)
	if err != nil {
		return fmt.Errorf("failed to compile rule '%s': %v", name, err)
	}

	rule := CompiledRule{
		Name:       name,
		Expression: expression,
		Action:     action,
		Enabled:    enabled,
		Filter:     filter,
	}

	re.rules = append(re.rules, rule)
	return nil
}

func (re *RuleEngine) EvaluateRules(ctx *RequestContext, baseSuspicion int) int {
	suspicion := baseSuspicion

	for _, rule := range re.rules {
		if !rule.Enabled {
			continue
		}

		if rule.Filter.Matches(ctx) {
			suspicion = re.applyAction(suspicion, rule.Action)
		}
	}

	return suspicion
}

func (re *RuleEngine) applyAction(currentSuspicion int, action string) int {
	if action == "" {
		return currentSuspicion
	}

	// Handle relative actions (+N, -N)
	if strings.HasPrefix(action, "+") {
		if delta, err := strconv.Atoi(action[1:]); err == nil {
			return currentSuspicion + delta
		}
	} else if strings.HasPrefix(action, "-") {
		if delta, err := strconv.Atoi(action[1:]); err == nil {
			return currentSuspicion - delta
		}
	} else {
		// Handle absolute actions (N, "block", "allow")
		switch action {
		case "block":
			return 999 // Very high suspicion = block
		case "allow":
			return 0 // No suspicion = allow
		default:
			if level, err := strconv.Atoi(action); err == nil {
				return level
			}
		}
	}

	return currentSuspicion
}

// ExpressionFilter implements a simple expression evaluator
func NewExpressionFilter(expression string) (*ExpressionFilter, error) {
	// Validate expression syntax (simplified)
	if expression == "" {
		return nil, fmt.Errorf("empty expression")
	}

	return &ExpressionFilter{
		expression: expression,
	}, nil
}

func (ef *ExpressionFilter) Matches(ctx *RequestContext) bool {
	// Simple expression evaluator
	// In production, use a proper expression parser like govaluate or similar

	expr := strings.ToLower(ef.expression)

	// Replace context variables
	expr = strings.ReplaceAll(expr, "ip.src", fmt.Sprintf("'%s'", ctx.ClientIP))
	expr = strings.ReplaceAll(expr, "ip.address", fmt.Sprintf("'%s'", ctx.ClientIP)) // Alias for ip.src
	expr = strings.ReplaceAll(expr, "ip.country", fmt.Sprintf("'%s'", strings.ToLower(ctx.Country)))
	expr = strings.ReplaceAll(expr, "ip.asn", fmt.Sprintf("'%s'", strings.ToLower(ctx.ASN)))
	expr = strings.ReplaceAll(expr, "ip.engine", fmt.Sprintf("'%s'", strings.ToLower(ctx.BrowserType)))
	expr = strings.ReplaceAll(expr, "ip.bot", fmt.Sprintf("'%s'", strings.ToLower(ctx.BotType)))
	expr = strings.ReplaceAll(expr, "ip.fingerprint", fmt.Sprintf("'%s'", ctx.TLSFingerprint))
	expr = strings.ReplaceAll(expr, "ip.requests", strconv.Itoa(ctx.RequestCount))
	expr = strings.ReplaceAll(expr, "ip.http_requests", strconv.Itoa(ctx.RequestCount))
	expr = strings.ReplaceAll(expr, "ip.challenge_requests", strconv.Itoa(ctx.ChallengeCount))

	expr = strings.ReplaceAll(expr, "http.host", fmt.Sprintf("'%s'", strings.ToLower(ctx.Host)))
	expr = strings.ReplaceAll(expr, "http.method", fmt.Sprintf("'%s'", strings.ToLower(ctx.Method)))
	expr = strings.ReplaceAll(expr, "http.url", fmt.Sprintf("'%s'", strings.ToLower(ctx.URL)))
	expr = strings.ReplaceAll(expr, "http.path", fmt.Sprintf("'%s'", strings.ToLower(ctx.Path)))
	expr = strings.ReplaceAll(expr, "http.query", fmt.Sprintf("'%s'", strings.ToLower(ctx.Query)))
	expr = strings.ReplaceAll(expr, "http.user_agent", fmt.Sprintf("'%s'", strings.ToLower(ctx.UserAgent)))

	expr = strings.ReplaceAll(expr, "proxy.stage", strconv.Itoa(ctx.SuspicionLevel))
	expr = strings.ReplaceAll(expr, "proxy.cloudflare", strconv.FormatBool(ctx.IsCloudflare))
	expr = strings.ReplaceAll(expr, "proxy.attack", strconv.FormatBool(ctx.IsAttack))
	expr = strings.ReplaceAll(expr, "proxy.rps", strconv.Itoa(ctx.RequestsPerSec))

	// Simple expression evaluation
	return ef.evaluateSimpleExpression(expr)
}

func (ef *ExpressionFilter) evaluateSimpleExpression(expr string) bool {
	// Handle common patterns

	// Country checks: ip.country == 'cn'
	if strings.Contains(expr, "==") {
		parts := strings.Split(expr, "==")
		if len(parts) == 2 {
			left := strings.TrimSpace(parts[0])
			right := strings.TrimSpace(parts[1])
			right = strings.Trim(right, "'\"")
			left = strings.Trim(left, "'\"")
			return left == right
		}
	}

	// Contains checks: http.user_agent contains 'bot'
	if strings.Contains(expr, " contains ") {
		parts := strings.Split(expr, " contains ")
		if len(parts) == 2 {
			left := strings.TrimSpace(parts[0])
			right := strings.TrimSpace(parts[1])
			right = strings.Trim(right, "'\"")
			left = strings.Trim(left, "'\"")
			return strings.Contains(left, right)
		}
	}

	// Greater than: ip.requests > 100
	if strings.Contains(expr, " > ") {
		parts := strings.Split(expr, " > ")
		if len(parts) == 2 {
			left := strings.TrimSpace(parts[0])
			right := strings.TrimSpace(parts[1])

			leftVal, err1 := strconv.Atoi(left)
			rightVal, err2 := strconv.Atoi(right)

			if err1 == nil && err2 == nil {
				return leftVal > rightVal
			}
		}
	}

	// Less than: ip.requests < 10
	if strings.Contains(expr, " < ") {
		parts := strings.Split(expr, " < ")
		if len(parts) == 2 {
			left := strings.TrimSpace(parts[0])
			right := strings.TrimSpace(parts[1])

			leftVal, err1 := strconv.Atoi(left)
			rightVal, err2 := strconv.Atoi(right)

			if err1 == nil && err2 == nil {
				return leftVal < rightVal
			}
		}
	}

	// AND conditions: condition1 && condition2
	if strings.Contains(expr, " && ") {
		parts := strings.Split(expr, " && ")
		for _, part := range parts {
			if !ef.evaluateSimpleExpression(strings.TrimSpace(part)) {
				return false
			}
		}
		return true
	}

	// OR conditions: condition1 || condition2
	if strings.Contains(expr, " || ") {
		parts := strings.Split(expr, " || ")
		for _, part := range parts {
			if ef.evaluateSimpleExpression(strings.TrimSpace(part)) {
				return true
			}
		}
		return false
	}

	// Boolean values
	if expr == "true" {
		return true
	}
	if expr == "false" {
		return false
	}

	return false
}

// BuildRequestContext creates a context from HTTP request and additional data
func BuildRequestContext(r *http.Request, clientIP, country, asn, browserType, botType, tlsFingerprint string, requestCount, challengeCount, suspicionLevel, requestsPerSec int, isAttack bool) *RequestContext {
	headers := make(map[string]string)
	for key, values := range r.Header {
		if len(values) > 0 {
			headers[strings.ToLower(key)] = strings.ToLower(values[0])
		}
	}

	return &RequestContext{
		ClientIP:       clientIP,
		Country:        country,
		ASN:            asn,
		BrowserType:    browserType,
		BotType:        botType,
		TLSFingerprint: tlsFingerprint,
		RequestCount:   requestCount,
		ChallengeCount: challengeCount,
		Host:           strings.ToLower(r.Host),
		Method:         strings.ToLower(r.Method),
		URL:            strings.ToLower(r.URL.String()),
		Path:           strings.ToLower(r.URL.Path),
		Query:          strings.ToLower(r.URL.RawQuery),
		UserAgent:      strings.ToLower(r.UserAgent()),
		Headers:        headers,
		SuspicionLevel: suspicionLevel,
		IsCloudflare:   isCloudflareRequest(r),
		IsAttack:       isAttack,
		RequestsPerSec: requestsPerSec,
	}
}

func isCloudflareRequest(r *http.Request) bool {
	// Check for Cloudflare headers
	cfHeaders := []string{
		"CF-Connecting-IP",
		"CF-Ray",
		"CF-Visitor",
		"CF-IPCountry",
	}

	for _, header := range cfHeaders {
		if r.Header.Get(header) != "" {
			return true
		}
	}

	return false
}

// GetGeoInfo gets country and ASN info for an IP (placeholder)
func GetGeoInfo(ip string) (country, asn string) {
	// This should integrate with a GeoIP database
	// For now, return placeholder values

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return "unknown", "unknown"
	}

	// Check for private/local IPs
	if parsedIP.IsPrivate() || parsedIP.IsLoopback() {
		return "local", "local"
	}

	// Placeholder - integrate with MaxMind GeoIP2 or similar
	return "unknown", "unknown"
}

// Example rule configurations
func GetDefaultRules() []CompiledRule {
	rules := []CompiledRule{
		{
			Name:       "Block China",
			Expression: "ip.country == 'cn'",
			Action:     "block",
			Enabled:    false,
		},
		{
			Name:       "Suspicious User Agents",
			Expression: "http.user_agent contains 'bot' || http.user_agent contains 'crawler' || http.user_agent contains 'spider'",
			Action:     "+2",
			Enabled:    true,
		},
		{
			Name:       "High Request Rate",
			Expression: "ip.requests > 100",
			Action:     "+1",
			Enabled:    true,
		},
		{
			Name:       "Admin Path Access",
			Expression: "http.path contains '/admin' || http.path contains '/wp-admin'",
			Action:     "+1",
			Enabled:    true,
		},
		{
			Name:       "Known Good Browsers",
			Expression: "ip.engine == 'chrome' || ip.engine == 'firefox' || ip.engine == 'safari'",
			Action:     "-1",
			Enabled:    true,
		},
	}

	return rules
}
