package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
	"immunisoc-nexus/proxy/internal/classification"
	"immunisoc-nexus/proxy/internal/middleware"
	"immunisoc-nexus/proxy/internal/opa"
)

const (
	// Shared secret for Proxy-to-Backend authentication
	HandshakeSecretToken = "your-secret-token-here" // In production, load from environment/config
)

// rateLimiterMap stores rate limiters per IP address
var (
	rateLimiterMap = make(map[string]*rate.Limiter)
	mu             sync.Mutex
)

// getRateLimiter retrieves or creates a rate limiter for a given IP
func getRateLimiter(ip string) *rate.Limiter {
	mu.Lock()
	defer mu.Unlock()

	limiter, exists := rateLimiterMap[ip]
	if !exists {
		// Allow 10 requests per second with a burst of 5
		limiter = rate.NewLimiter(rate.Every(100*time.Millisecond), 5)
		rateLimiterMap[ip] = limiter
	}

	return limiter
}

// verbWhitelist middleware checks if the HTTP method is allowed
func verbWhitelist(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only allow GET and POST methods
		if r.Method != http.MethodGet && r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// rateLimit middleware applies rate limiting per client IP
func rateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr
		limiter := getRateLimiter(ip)

		if !limiter.Allow() {
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// detectThreats middleware implements passive threat detection
func detectThreats(next http.Handler) http.Handler {
	return middleware.DetectThreats(next)
}

// authenticateRequest middleware adds HMAC-based authentication
func authenticateRequest(next http.Handler) http.Handler {
	return middleware.ApplyAuthentication(HandshakeSecretToken)(next)
}

// classifyRequest middleware classifies the request based on content
func classifyRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Create a classifier instance
		classifier := &classification.Classifier{}
		
		// Classify the request path
		tier, cleanedPath := classifier.Classify(r.URL.Path)
		
		// Log the classification tier for monitoring
		log.Printf("Request classified with tier: %d, cleaned path: %s", tier, cleanedPath)
		
		// Store the tier in the request context for later use
		// In a real implementation, you'd use context.WithValue to store the tier
		// For now, we'll just continue with the classification
		
		next.ServeHTTP(w, r)
	})
}

// maskSensitiveData implements data minimization by masking non-critical segments
func maskSensitiveData(data string) string {
	// Simple implementation - in a real system this would be more sophisticated
	if len(data) > 10 {
		return data[:3] + "..." + data[len(data)-3:]
	}
	return data
}

// popiaCompliance middleware checks POPIA compliance
func popiaCompliance(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract POPIA-related headers
		purpose := r.Header.Get("X-PopIA-Purpose")
		consent := r.Header.Get("X-PopIA-Consent")
		retentionStr := r.Header.Get("X-PopIA-Retention")
		
		// If no POPIA headers are present, default to safe values
		if purpose == "" {
			purpose = "CUSTOMER_SERVICE" // default safe purpose
		}
		
		consentGiven := consent == "true"
		retentionPeriod := 30 // default retention period in days
		if retentionStr != "" {
			// In a real implementation, you would parse the retention period
			// For now, we'll just use the default
		}
		
		// Perform POPIA compliance check
		allowed, err := opa.CheckPopiaCompliance(purpose, []string{"basic_data"}, consentGiven, retentionPeriod)
		if err != nil {
			log.Printf("POPIA compliance check error: %v", err)
			http.Error(w, "Compliance check failed", http.StatusInternalServerError)
			return
		}
		
		// If POPIA compliance fails, block the request
		if !allowed {
			log.Printf("Request blocked by POPIA compliance: %s %s", r.Method, r.URL.Path)
			http.Error(w, "Request violates POPIA compliance", http.StatusForbidden)
			return
		}
		
		// If compliant, continue processing
		next.ServeHTTP(w, r)
	})
}

// checkOPAPolicy middleware checks the OPA policy decision
func checkOPAPolicy(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Prepare input for OPA policy evaluation
		input := map[string]interface{}{
			"path":   r.URL.Path,
			"method": r.Method,
			"host":   r.Host,
			"ip":     getClientIP(r),
			"purpose": r.Header.Get("X-PopIA-Purpose"), // Include purpose for POPIA checks
		}
		
		// Query OPA for policy decision
		allowed, err := opa.CheckPolicy(input)
		if err != nil {
			log.Printf("OPA policy check error: %v", err)
			http.Error(w, "Policy check failed", http.StatusInternalServerError)
			return
		}
		
		// If OPA denies the request, block it
		if !allowed {
			log.Printf("Request blocked by OPA policy: %s %s", r.Method, r.URL.Path)
			http.Error(w, "Access denied by policy", http.StatusForbidden)
			return
		}
		
		// If allowed, continue processing
		next.ServeHTTP(w, r)
	})
}

// getClientIP extracts the client IP from the request
func getClientIP(r *http.Request) string {
	// Get IP from X-Forwarded-For header if present
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		ips := strings.Split(forwarded, ",")
		return strings.TrimSpace(ips[0])
	}
	
	// Get IP from X-Real-IP header if present
	realIP := r.Header.Get("X-Real-IP")
	if realIP != "" {
		return realIP
	}
	
	// Fallback to RemoteAddr
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
}

// routeToBackend handles routing the request to the backend
func routeToBackend(w http.ResponseWriter, r *http.Request) {
	// Get backend host from environment variable
	backendHost := os.Getenv("BACKEND_HOST")
	if backendHost == "" {
		backendHost = "localhost:8081" // Default fallback
	}
	
	// Parse the backend URL
	backendURL := fmt.Sprintf("http://%s", backendHost)
	target, err := url.Parse(backendURL)
	if err != nil {
		log.Printf("Failed to parse backend URL: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	
	// Create a reverse proxy
	proxy := httputil.NewSingleHostReverseProxy(target)
	
	// Log the routing action
	log.Printf("Routing request to backend: %s", backendURL)
	
	// Serve the request through the proxy
	proxy.ServeHTTP(w, r)
}

func main() {
	// Call the function to "use" the package
	fmt.Println(classification.AnalyzeTraffic())

	// Create a new mux router
	mux := http.NewServeMux()

	// Define a handler that implements the complete flow
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// This handler will be wrapped by all the middleware layers
		routeToBackend(w, r)
	})

	// Apply middleware stack in the specified order:
	// 1. Apply Secure Headers
	// 2. Detect Threats (passive threat detection)
	// 3. Authenticate Request (add HMAC signatures)
	// 4. Check Rate Limiter
	// 5. Classify Request (get Tier)
	// 6. POPIA Compliance Check
	// 7. Query OPA (get decision)
	// 8. Route to backend or Block
	handler := middleware.ApplySecureHeaders(
		detectThreats(
			middleware.ApplyAuthentication(HandshakeSecretToken)(
				rateLimit(
					classifyRequest(
						popiaCompliance(
							checkOPAPolicy(mux),
						),
					),
				),
			),
		),
	)

	// Create a custom server with timeouts
	server := &http.Server{
		Addr:         ":8080",
		Handler:      handler,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	log.Println("Neutrophil Proxy Membrane Initialized.")
	log.Printf("Server starting on %s", server.Addr)

	// Start the server
	log.Fatal(server.ListenAndServe())
}