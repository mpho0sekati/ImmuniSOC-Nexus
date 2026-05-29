package middleware

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"

	"immunisoc-nexus/proxy/internal/opa"
	"immunisoc-nexus/proxy/internal/tcell"
)

// EgressProtection middleware inspects outbound traffic for sensitive data
type EgressProtection struct {
	opaClient    *opa.OpaClient
	dataPatterns []*regexp.Regexp // Using multiple simpler patterns instead of one complex one
	internalIP   *regexp.Regexp
	blockActions []string
	tcellEngine  *tcell.Engine // Reference to T-Cell engine for automatic response
}

// NewEgressProtection creates a new egress protection middleware
func NewEgressProtection() *EgressProtection {
	// Compile multiple simpler regex patterns to avoid complex regex that could cause ReDoS
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)\b\d{3}-?\d{2}-?\d{4}\b`),                                        // SSN pattern
		regexp.MustCompile(`(?i)\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`),            // Email pattern
		regexp.MustCompile(`(?i)\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b`), // Credit card pattern
	}

	return &EgressProtection{
		opaClient:    opa.NewOpaClient(),
		dataPatterns: patterns,
		internalIP:   regexp.MustCompile(`\b(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)\d{1,3}\.\d{1,3}\b`),
		blockActions: []string{
			"BLOCK_EGRESS",
			"QUARANTINE_DATA",
			"LOG_AND_ALERT",
		},
		tcellEngine: nil, // Will be set externally
	}
}

// SetTCellEngine sets the T-Cell engine for automatic response to egress violations
func (ep *EgressProtection) SetTCellEngine(engine *tcell.Engine) {
	ep.tcellEngine = engine
}

// EgressMiddleware implements the egress protection logic
func (ep *EgressProtection) EgressMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Capture the response
		rr := httptest.NewRecorder()
		next.ServeHTTP(rr, r)

		// Get the response body
		responseBody := rr.Body.Bytes()

		// Check if the response should be scanned for sensitive data
		if ep.shouldScanResponse(r, rr) {
			isBlocked, reason := ep.scanForSensitiveData(responseBody)
			if isBlocked {
				log.Printf("Egress protection triggered: %s", reason)
				
				// Trigger T-Cell engine to respond to the egress violation
				if ep.tcellEngine != nil {
					ip := getClientIP(r)
					sessionID := getSessionID(r)
					
					threatDetails := map[string]interface{}{
						"threat_type":       "egress_violation",
						"violation_reason":  reason,
						"request_method":    r.Method,
						"request_path":      r.URL.Path,
						"response_size":     len(responseBody),
					}
					
					// Use High containment level for egress violations
					_, err := ep.tcellEngine.ProcessThreat(ip, sessionID, "", tcell.High, threatDetails)
					if err != nil {
						log.Printf("[EGRESS] Failed to process threat with T-Cell engine: %v", err)
					} else {
						log.Printf("[EGRESS] Egress violation processed by T-Cell engine from IP: %s", ip)
					}
				}
				
				http.Error(w, "Access denied", http.StatusForbidden)
				return
			}
		}

		// Copy the original response to the actual response writer
		for key, values := range rr.Header() {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}
		w.WriteHeader(rr.Code)
		w.Write(responseBody)
	})
}

// scanForSensitiveData checks if the response contains sensitive data
func (ep *EgressProtection) scanForSensitiveData(body []byte) (bool, string) {
	bodyStr := string(body)

	// Check against each pattern separately to avoid complex regex
	for i, pattern := range ep.dataPatterns {
		if pattern.MatchString(bodyStr) {
			return true, fmt.Sprintf("Sensitive data pattern %d detected", i)
		}
	}

	// Additional checks for internal IP addresses
	lines := strings.Split(bodyStr, "\n")
	for lineNum, line := range lines {
		// Check for internal IP addresses
		if ep.internalIP.MatchString(line) {
			log.Printf("Internal IP detected in egress response at line %d", lineNum)
			return true, "Internal network information detected"
		}
	}

	// Additional checks for binary data that might contain sensitive info
	if len(body) > 0 { // Check the entire payload instead of truncating at 1000 bytes
		bodyStr := string(body)
		if strings.Contains(bodyStr, "{") && strings.Count(bodyStr, "{") > 5 { // Likely JSON with many fields
			// Check if it contains common sensitive field names
			sensitiveFields := []string{"password", "token", "secret", "apiKey", "credential", "auth"}
			for _, field := range sensitiveFields {
				if strings.Contains(strings.ToLower(bodyStr), field) {
					log.Printf("Sensitive field '%s' detected in egress payload", field)
					return true, "Sensitive data field detected"
				}
			}
		}
	}

	// Additional check for large payloads with potential sensitive data
	if len(body) > 10000 { // For very large payloads, perform deeper inspection
		// Look for potential data patterns that might indicate sensitive information
		lowerBody := strings.ToLower(bodyStr)
		if strings.Contains(lowerBody, "ssn") || strings.Contains(lowerBody, "passport") ||
			strings.Contains(lowerBody, "credit") || strings.Contains(lowerBody, "account") {
			log.Printf("Potential sensitive data pattern detected in large payload (%d bytes)", len(body))
			return true, "Heuristic sensitive data detection triggered"
		}
	}

	return false, ""
}

// shouldBlockEgress checks if egress should be blocked based on OPA policy
func (ep *EgressProtection) shouldBlockEgress(input map[string]interface{}) (bool, error) {
	// Check if block policy exists and is triggered
	result, err := ep.opaClient.CheckBlockPolicy(map[string]interface{}{
		"destination":         input["destination"],
		"payload":             input["payload"],
		"purpose":             input["purpose"],
		"data_classification": input["data_classification"],
	})
	if err != nil {
		return false, err
	}

	// If the block policy returns true, it means egress should be blocked
	return result, nil
}

// shouldScanResponse determines if a response should be scanned for sensitive data
func (ep *EgressProtection) shouldScanResponse(_ *http.Request, rr *httptest.ResponseRecorder) bool {
	// Only scan responses that are likely to contain data
	contentType := rr.Header().Get("Content-Type")
	if strings.Contains(contentType, "application/json") ||
		strings.Contains(contentType, "text/") ||
		strings.Contains(contentType, "application/xml") {
		return true
	}

	// Don't scan images, binaries, etc.
	return false
}

// copyResponse copies the recorded response to the actual response writer
func copyResponse(w http.ResponseWriter, r *httptest.ResponseRecorder) {
	// Copy headers
	for key, values := range r.Header() {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	// Set status code
	w.WriteHeader(r.Code)

	// Copy body
	_, _ = io.Copy(w, bytes.NewReader(r.Body.Bytes()))
}

// EgressFilter is a simpler function-based middleware for egress protection
func EgressFilter(next http.Handler) http.Handler {
	protection := NewEgressProtection()
	return protection.EgressMiddleware(next)
}

// SanitizeResponse sanitizes sensitive data from responses
func SanitizeResponse(data []byte) []byte {
	// Define patterns to sanitize
	ssnPattern := regexp.MustCompile(`\b(\d{3})-(\d{2})-(\d{4})\b`)
	emailPattern := regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`)
	creditCardPattern := regexp.MustCompile(`\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b`)

	// Sanitize SSNs
	data = ssnPattern.ReplaceAllFunc(data, func(match []byte) []byte {
		return []byte("***-**-****")
	})

	// Sanitize emails
	data = emailPattern.ReplaceAllFunc(data, func(match []byte) []byte {
		parts := bytes.Split(match, []byte("@"))
		if len(parts) == 2 {
			localPart := parts[0]
			domainPart := parts[1]

			if len(localPart) > 2 {
				return append(append(localPart[:2], []byte("***@")...), domainPart...)
			}
		}
		return []byte("***@***.***")
	})

	// Sanitize credit cards
	data = creditCardPattern.ReplaceAllFunc(data, func(match []byte) []byte {
		matchStr := string(match)
		if len(matchStr) >= 4 {
			return []byte("****-****-****-" + matchStr[len(matchStr)-4:])
		}
		return []byte("****-****-****-****")
	})

	return data
}

// truncateString truncates a string to a maximum length
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// getClientIP extracts the client IP from the request
func getClientIP(r *http.Request) string {
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		ips := strings.Split(forwarded, ",")
		return strings.TrimSpace(ips[0])
	}
	
	realIP := r.Header.Get("X-Real-IP")
	if realIP != "" {
		return realIP
	}
	
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
}

// getSessionID extracts session ID from request with validation
func getSessionID(r *http.Request) string {
	sessionCookie, err := r.Cookie("session_id")
	if err == nil && sessionCookie != nil {
		// For simplicity in this context, we'll just return the cookie value
		// In a real implementation, you'd validate the session ID
		return sessionCookie.Value
	}
	
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		// If it's a Bearer token, extract the token part
		if strings.HasPrefix(authHeader, "Bearer ") {
			return strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
		} else {
			// Return the whole header as session identifier
			return authHeader
		}
	}
	
	return "unknown_session"
}
