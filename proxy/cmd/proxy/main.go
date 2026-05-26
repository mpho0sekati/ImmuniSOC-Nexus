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

// checkOPAPolicy middleware checks the OPA policy decision
func checkOPAPolicy(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Prepare input for OPA policy evaluation
		input := map[string]interface{}{
			"path":   r.URL.Path,
			"method": r.Method,
			"host":   r.Host,
			"ip":     getClientIP(r),
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
	// 2. Check Rate Limiter
	// 3. Classify Request (get Tier)
	// 4. Query OPA (get decision)
	// 5. Route to backend or Block
	handler := middleware.ApplySecureHeaders(
		rateLimit(
			classifyRequest(
				checkOPAPolicy(mux),
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