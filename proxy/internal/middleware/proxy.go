package middleware

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

const (
	// Header names for authentication
	TimestampHeader = "X-Auth-Timestamp"
	SignatureHeader = "X-Auth-Signature"
	// 30 second validity window for timestamps
	TimestampValidityWindow = 30 * time.Second
)

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