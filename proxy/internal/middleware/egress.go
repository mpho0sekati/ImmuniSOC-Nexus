package middleware

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"

	"immunisoc-nexus/proxy/internal/opa"
)

// EgressProtection middleware inspects outbound traffic for sensitive data
type EgressProtection struct {
	opaClient    *opa.OpaClient
	dataPattern  *regexp.Regexp
	blockActions []string
}

// NewEgressProtection creates a new egress protection middleware
func NewEgressProtection() *EgressProtection {
	// Compile regex for sensitive data patterns
	pattern := regexp.MustCompile(`(?i)(\b\d{3}-?\d{2}-?\d{4}\b|\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b|\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b)`)
	
	return &EgressProtection{
		opaClient:   opa.NewOpaClient(),
		dataPattern: pattern,
		blockActions: []string{
			"BLOCK_EGRESS",
			"QUARANTINE_DATA",
			"LOG_AND_ALERT",
		},
	}
}

// EgressMiddleware implements the egress protection logic
func (ep *EgressProtection) EgressMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Create a response recorder to capture the response
		recorder := httptest.NewRecorder()
		
		// Process the request with the next handler
		next.ServeHTTP(recorder, r)
		
		// Check if the response contains sensitive data
		responseBody := recorder.Body.String()
		if ep.containsSensitiveData([]byte(responseBody)) {
			// Prepare input for OPA policy evaluation
			input := map[string]interface{}{
				"request_method":      "EGRESS_CHECK",
				"destination":         r.URL.String(),
				"payload":             responseBody,
				"purpose":             r.Header.Get("X-PopIA-Purpose"),
				"data_classification": classifyData(responseBody),
				"is_admin_bypass":     false,
				"audit_log_required":  true,
			}
			
			// Check OPA policy
			allowed, err := ep.opaClient.CheckPolicy(input)
			if err != nil {
				log.Printf("Egress protection OPA error: %v", err)
				// Fail closed - if policy check fails, block the response
				http.Error(w, "Egress policy check failed", http.StatusForbidden)
				return
			}
			
			if !allowed {
				log.Printf("Egress protection blocked response to: %s", r.URL.Path)
				
				// Check for blocking directives from policy
				blockInput := map[string]interface{}{
					"destination":         r.URL.String(),
					"payload":             responseBody,
					"purpose":             r.Header.Get("X-PopIA-Purpose"),
					"data_classification": classifyData(responseBody),
				}
				
				shouldBlock, err := ep.shouldBlockEgress(blockInput)
				if err != nil {
					log.Printf("Egress block check error: %v", err)
				}
				
				if shouldBlock {
					// Return a safe response instead of the original
					http.Error(w, "Response contains sensitive data and is blocked by egress policy", http.StatusForbidden)
					return
				}
			}
		}
		
		// Copy the original response to the actual response writer
		copyResponse(w, recorder)
	})
}

// containsSensitiveData checks if the data contains sensitive information
func (ep *EgressProtection) containsSensitiveData(data []byte) bool {
	return ep.dataPattern.Match(data)
}

// shouldBlockEgress checks if egress should be blocked based on OPA policy
func (ep *EgressProtection) shouldBlockEgress(input map[string]interface{}) (bool, error) {
	// Prepare the request for the block policy check
	blockInput := map[string]interface{}{
		"input": map[string]interface{}{
			"destination":         input["destination"],
			"payload":             input["payload"],
			"purpose":             input["purpose"],
			"data_classification": input["data_classification"],
		},
	}

	// Check if block policy exists and is triggered
	result, err := ep.opaClient.CheckPolicy(blockInput)
	if err != nil {
		return false, err
	}
	
	// If the block policy returns true, it means egress should be blocked
	return result, nil
}

// classifyData classifies data based on content
func classifyData(data string) string {
	if len(data) > 10000 { // Large data sets might be critical
		return "CRITICAL"
	}
	
	if strings.Contains(strings.ToLower(data), "confidential") ||
	   strings.Contains(strings.ToLower(data), "private") ||
	   strings.Contains(strings.ToLower(data), "restricted") {
		return "CRITICAL"
	}
	
	// Check for sensitive patterns
	if matched, _ := regexp.MatchString(`(?i)(ssn|social\s+security|credit\s+card|password|api\s+key|secret|token)`, data); matched {
		return "CRITICAL"
	}
	
	return "STANDARD"
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

// ScanAndBlockEgress scans response bodies for sensitive data and blocks if necessary
func ScanAndBlockEgress(body []byte, destination string, purpose string) (bool, string) {
	// Check for various sensitive data patterns
	scanner := bufio.NewScanner(bytes.NewReader(body))
	lineNum := 0
	
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		
		// Check for sensitive patterns
		if matched, _ := regexp.MatchString(`(?i)(ssn|social\s+security|credit\s+card|password|api\s+key|secret|token|confidential)`, line); matched {
			log.Printf("Sensitive data detected in egress response at line %d: %s", lineNum, truncateString(line, 100))
			return true, fmt.Sprintf("Sensitive data detected at line %d", lineNum)
		}
		
		// Check for actual SSN patterns
		if matched, _ := regexp.MatchString(`\b\d{3}-\d{2}-\d{4}\b`, line); matched {
			log.Printf("SSN pattern detected in egress response at line %d", lineNum)
			return true, fmt.Sprintf("SSN pattern detected at line %d", lineNum)
		}
		
		// Check for email patterns
		if matched, _ := regexp.MatchString(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`, line); matched {
			log.Printf("Email pattern detected in egress response at line %d", lineNum)
			return true, fmt.Sprintf("Email pattern detected at line %d", lineNum)
		}
		
		// Check for internal IP addresses
		if matched, _ := regexp.MatchString(`\b(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)\d{1,3}\.\d{1,3}\b`, line); matched {
			log.Printf("Internal IP detected in egress response at line %d", lineNum)
			return true, fmt.Sprintf("Internal IP detected at line %d", lineNum)
		}
	}
	
	// Additional checks for binary data that might contain sensitive info
	if len(body) > 1000 { // For larger payloads, perform additional checks
		bodyStr := string(body)
		if strings.Contains(bodyStr, "{") && strings.Count(bodyStr, "{") > 5 { // Likely JSON with many fields
			// Check if it contains common sensitive field names
			sensitiveFields := []string{"password", "token", "secret", "apiKey", "credential", "auth"}
			for _, field := range sensitiveFields {
				if strings.Contains(strings.ToLower(bodyStr), field) {
					log.Printf("Sensitive field '%s' detected in large egress payload", field)
					return true, fmt.Sprintf("Sensitive field '%s' detected in large payload", field)
				}
			}
		}
	}
	
	return false, ""
}

// truncateString truncates a string to a maximum length
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}