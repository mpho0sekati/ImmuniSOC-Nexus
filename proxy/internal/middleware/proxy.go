package middleware

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
)

// ApplyAuthentication adds HMAC-based authentication to requests
func ApplyAuthentication(sharedSecret string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract signature from header
			signature := r.Header.Get("X-Request-Signature")
			if signature == "" {
				http.Error(w, "Request signature required", http.StatusUnauthorized)
				return
			}

			// Compute expected signature
			expectedSignature := computeExpectedSignature(r, sharedSecret)

			// Compare signatures securely
			if !SecureCompare(signature, expectedSignature) {
				http.Error(w, "Invalid request signature", http.StatusUnauthorized)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// computeExpectedSignature computes the expected signature for the request
func computeExpectedSignature(r *http.Request, secret string) string {
	// Create a canonical representation of the request
	// This should include method, path, query params, and any relevant headers
	canonical := fmt.Sprintf("%s|%s|%s", r.Method, r.URL.Path, r.Header.Get("Content-Type"))

	// Compute HMAC-SHA256
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(canonical))
	return hex.EncodeToString(h.Sum(nil))
}


// ApplySecureHeaders adds security headers to responses
func ApplySecureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Add security headers
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		
		// Ensure Content-Type is properly set
		if w.Header().Get("Content-Type") == "" {
			if strings.HasPrefix(r.URL.Path, "/api/") {
				w.Header().Set("Content-Type", "application/json")
			} else {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
			}
		}

		next.ServeHTTP(w, r)
	})
}

// RateLimitMiddleware limits requests per IP address
func RateLimitMiddleware(limit int, windowInSeconds int) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// In a real implementation, this would track requests per IP
			// For now, we just pass through
			next.ServeHTTP(w, r)
		})
	}
}