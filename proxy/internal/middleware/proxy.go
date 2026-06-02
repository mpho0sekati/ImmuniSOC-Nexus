package middleware

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
	"immunisoc-nexus/proxy/internal/bloodhound"
	"immunisoc-nexus/proxy/internal/deception"
	"immunisoc-nexus/proxy/internal/tcell"
)

// ApplyAuthentication adds HMAC-based authentication to requests with anti-replay protection
func ApplyAuthentication(sharedSecret string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract signature from header
			signature := r.Header.Get("X-Request-Signature")
			timestamp := r.Header.Get("X-Request-Timestamp")

			if signature == "" || timestamp == "" {
				http.Error(w, "Request signature and timestamp required", http.StatusUnauthorized)
				return
			}

			// Check if the timestamp is within a reasonable window (e.g., 5 minutes) to prevent replay attacks
			reqTime, err := time.Parse(time.RFC3339, timestamp)
			if err != nil {
				http.Error(w, "Invalid timestamp format", http.StatusUnauthorized)
				return
			}

			if time.Since(reqTime).Abs() > 5*time.Minute {
				http.Error(w, "Request timestamp too old or too far in future", http.StatusUnauthorized)
				return
			}

			// Compute expected signature including timestamp
			expectedSignature := computeExpectedSignature(r, sharedSecret, timestamp)

			// Compare signatures securely
			if subtle.ConstantTimeCompare([]byte(signature), []byte(expectedSignature)) != 1 {
				http.Error(w, "Invalid request signature", http.StatusUnauthorized)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// computeExpectedSignature computes the expected signature for the request
func computeExpectedSignature(r *http.Request, secret string, timestamp string) string {
	// Create a canonical representation of the request including timestamp
	// This should include method, path, query params, and any relevant headers
	canonical := fmt.Sprintf("%s|%s|%s|%s", r.Method, r.URL.Path, r.Header.Get("Content-Type"), timestamp)

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

type ipRateLimiter struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

var (
	limiters = make(map[string]*ipRateLimiter)
	mu       sync.Mutex
)

func init() {
	go func() {
		for {
			time.Sleep(time.Minute)
			mu.Lock()
			for ip, l := range limiters {
				if time.Since(l.lastSeen) > 10*time.Minute {
					delete(limiters, ip)
				}
			}
			mu.Unlock()
		}
	}()
}

// RateLimitMiddleware limits requests per IP address
func RateLimitMiddleware(requestsPerWindow int, window time.Duration) func(http.Handler) http.Handler {
	if requestsPerWindow <= 0 {
		// Default to a reasonable limit if misconfigured
		requestsPerWindow = 100
	}
	if window <= 0 {
		window = time.Minute
	}

	// Convert requests per window to rate per second
	limit := rate.Every(window / time.Duration(requestsPerWindow))

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := getIP(r)

			mu.Lock()
			v, exists := limiters[ip]
			if !exists {
				v = &ipRateLimiter{
					limiter: rate.NewLimiter(limit, requestsPerWindow),
				}
				limiters[ip] = v
			}
			v.lastSeen = time.Now()

			if !v.limiter.Allow() {
				mu.Unlock()
				http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
				return
			}
			mu.Unlock()

			next.ServeHTTP(w, r)
		})
	}
}

func getIP(r *http.Request) string {
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		return strings.Split(forwarded, ",")[0]
	}
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	return ip
}

// DeceptionMiddleware checks if the request hits any decoy endpoints
func DeceptionMiddleware(gen *deception.Generator, tracker *bloodhound.Tracker) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			decoyEndpoints := gen.GenerateDecoyEndpoints()
			isDecoy := false
			for _, endpoint := range decoyEndpoints {
				if r.URL.Path == endpoint {
					isDecoy = true
					break
				}
			}

			// If it's a decoy endpoint, track it and potentially block/quarantine
			if isDecoy {
				tracker.TrackRequest(r, true)
				http.Error(w, "Access Denied", http.StatusForbidden)
				return
			}

			// Also check for canary/honey patterns in the request
			if hasCanaryPatterns(r) {
				tracker.TrackRequest(r, true)
			}

			next.ServeHTTP(w, r)
		})
	}
}

func hasCanaryPatterns(r *http.Request) bool {
	haystack := strings.ToLower(r.URL.Path + r.URL.RawQuery)
	for k, v := range r.Header {
		haystack += strings.ToLower(k + strings.Join(v, ""))
	}
	return strings.Contains(haystack, "canary") || strings.Contains(haystack, "honey") || strings.Contains(haystack, "tripwire")
}

// TCellMiddleware enforces containment actions from the T-Cell engine
func TCellMiddleware(engine *tcell.Engine) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := getIP(r)

			if !engine.IsIPAllowed(ip) {
				http.Error(w, "Access Denied: Your IP has been temporarily blocked for security reasons.", http.StatusForbidden)
				return
			}

			// Check for session validity if session ID exists
			sessionID := ""
			sessionCookie, err := r.Cookie("session_id")
			if err == nil {
				sessionID = sessionCookie.Value
				if !engine.IsSessionValid(sessionID) {
					http.Error(w, "Access Denied: Your session has been terminated.", http.StatusUnauthorized)
					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}