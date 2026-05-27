package middleware

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	// Header names for authentication
	TimestampHeader = "X-Auth-Timestamp"
	SignatureHeader = "X-Auth-Signature"
	// 30 second validity window for timestamps
	TimestampValidityWindow = 30 * time.Second
	MaxLogLength          = 1000
)

// Threat detection patterns
var TraversalPatterns = []string{
	"../",
	"..\\",
	"%2e%2e%2f",
	"%2e%2e%5c",
	"..%2f",
	"..%5c",
	"....//",
	"....\\\\",
	"..%252f",
	"..%255c",
}

// ApplySecureHeaders injects security headers to enhance protection
func ApplySecureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set X-Frame-Options to prevent clickjacking
		w.Header().Set("X-Frame-Options", "DENY")
		
		// Set X-Content-Type-Options to prevent MIME-type sniffing attacks
		w.Header().Set("X-Content-Type-Options", "nosniff")
		
		// Set Strict-Transport-Security (HSTS) to enforce HTTPS
		maxAge := int64(31536000) // 1 year in seconds
		w.Header().Set("Strict-Transport-Security", "max-age="+strconv.FormatInt(maxAge, 10)+" ; includeSubDomains")
		
		// Call the next handler in the chain
		next.ServeHTTP(w, r)
	})
}

// ApplyAuthentication adds HMAC-based authentication to requests
func ApplyAuthentication(sharedSecret string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Generate timestamp
			timestamp := strconv.FormatInt(time.Now().Unix(), 10)
			r.Header.Set(TimestampHeader, timestamp)
			
			// Generate HMAC signature
			signature, err := GenerateHMACSignature(r, sharedSecret, timestamp)
			if err != nil {
				log.Printf("Authentication error generating signature: %v", err)
				http.Error(w, "Authentication error", http.StatusInternalServerError)
				return
			}
			
			// Add signature to request headers
			r.Header.Set(SignatureHeader, signature)
			
			// Continue with the next handler
			next.ServeHTTP(w, r)
		})
	}
}

// DetectThreats implements passive threat detection
func DetectThreats(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check for directory traversal in URL path and query parameters
		if hasDirectoryTraversal(r.URL.Path) || hasDirectoryTraversal(r.URL.RawQuery) {
			// Log forensic event
			logForensicEvent("Directory traversal detected", r)
			// Return HTTP 451 - Unavailable For Legal Reasons
			http.Error(w, "Unavailable For Legal Reasons - Threat Detected", 451)
			return
		}

		// Check for canary tokens in headers, path, and query
		if hasCanaryToken(r) {
			// Log forensic event
			logForensicEvent("Canary token detected", r)
			// Return HTTP 451 - Unavailable For Legal Reasons
			http.Error(w, "Unavailable For Legal Reasons - Threat Detected", 451)
			return
		}

		// Continue with the next handler if no threats detected
		next.ServeHTTP(w, r)
	})
}

// hasDirectoryTraversal checks if the input contains directory traversal patterns
func hasDirectoryTraversal(input string) bool {
	if input == "" {
		return false
	}

	lowerInput := strings.ToLower(input)
	for _, pattern := range TraversalPatterns {
		if strings.Contains(lowerInput, pattern) {
			return true
		}
	}
	return false
}

// hasCanaryToken checks if the request contains any canary tokens
func hasCanaryToken(r *http.Request) bool {
	// Check in headers
	for name, values := range r.Header {
		headerName := strings.ToLower(name)
		if strings.Contains(headerName, "canary") || strings.Contains(headerName, "honey") {
			return true
		}
		
		for _, value := range values {
			lowerValue := strings.ToLower(value)
			if strings.Contains(lowerValue, "canary-token") ||
				strings.Contains(lowerValue, "honeytoken") ||
				strings.Contains(lowerValue, "tripwire") {
				return true
			}
		}
	}

	// Check in URL path
	pathLower := strings.ToLower(r.URL.Path)
	if strings.Contains(pathLower, "canary-token") ||
		strings.Contains(pathLower, "honeytoken") ||
		strings.Contains(pathLower, "tripwire") {
		return true
	}

	// Check in query parameters
	queryParams, err := url.QueryUnescape(r.URL.RawQuery)
	if err != nil {
		// If we can't decode the query, use it as-is
		queryParams = r.URL.RawQuery
	}
	queryLower := strings.ToLower(queryParams)
	if strings.Contains(queryLower, "canary-token") ||
		strings.Contains(queryLower, "honeytoken") ||
		strings.Contains(queryLower, "tripwire") {
		return true
	}

	return false
}

// GenerateHMACSignature creates a SHA-256 HMAC signature for a request
func GenerateHMACSignature(r *http.Request, secret, timestamp string) (string, error) {
	// Create the message to sign
	// Format: method|path|timestamp|host
	message := fmt.Sprintf("%s|%s|%s|%s", r.Method, r.URL.Path, timestamp, r.Host)
	
	// Create a new HMAC by defining the hash type and the key (secret)
	h := hmac.New(sha256.New, []byte(secret))
	
	// Write the message to the HMAC
	h.Write([]byte(message))
	
	// Get the final signature
	signature := hex.EncodeToString(h.Sum(nil))
	
	return signature, nil
}

// VerifyHMACSignature verifies a HMAC signature against a request
func VerifyHMACSignature(r *http.Request, secret string) (bool, error) {
	// Get timestamp and signature from headers
	timestampStr := r.Header.Get(TimestampHeader)
	signature := r.Header.Get(SignatureHeader)
	
	if timestampStr == "" || signature == "" {
		return false, fmt.Errorf("missing authentication headers")
	}
	
	// Verify timestamp is within validity window
	timestamp, err := strconv.ParseInt(timestampStr, 10, 64)
	if err != nil {
		return false, fmt.Errorf("invalid timestamp")
	}
	
	currentTime := time.Now().Unix()
	if currentTime-timestamp > int64(TimestampValidityWindow.Seconds()) {
		return false, fmt.Errorf("timestamp too old")
	}
	
	if timestamp-currentTime > int64(TimestampValidityWindow.Seconds()) {
		return false, fmt.Errorf("timestamp too far in the future")
	}
	
	// Generate expected signature
	expectedSig, err := GenerateHMACSignature(r, secret, timestampStr)
	if err != nil {
		return false, err
	}
	
	// Compare signatures using constant-time comparison
	return hmac.Equal([]byte(signature), []byte(expectedSig)), nil
}

// logForensicEvent logs events for forensic analysis in append-only format
func logForensicEvent(eventType string, r *http.Request) {
	// Append-only event logging for forensic ingestion
	logEntry := fmt.Sprintf(
		"[FORENSIC_LOG] %d | %s | %s | %s | %s | %s",
		time.Now().UnixNano()/1000000, // timestamp in milliseconds
		eventType,
		r.RemoteAddr,
		r.URL.Path,
		r.URL.RawQuery,
		r.UserAgent(),
	)
	
	// Limit log entry length to prevent excessive memory usage
	if len(logEntry) > MaxLogLength {
		logEntry = logEntry[:MaxLogLength] + "...[TRUNCATED]"
	}
	
	// In a real implementation, this would write to an append-only log file or database
	// Added error handling for potential print issues
	_, err := fmt.Println(logEntry) // For demonstration purposes
	if err != nil {
		log.Printf("Error writing forensic log: %v", err)
	}
}