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
	"immunisoc-nexus/proxy/internal/bloodhound"
	"immunisoc-nexus/proxy/internal/classification"
	"immunisoc-nexus/proxy/internal/deception"
	"immunisoc-nexus/proxy/internal/middleware"
	"immunisoc-nexus/proxy/internal/opa"
)

const (
	// Shared secret for Proxy-to-Backend authentication
	HandshakeSecretToken = "your-secret-token-here" // In production, load from environment/config
)

// Global instances for deception and tracking
var (
	deceptionGen *deception.Generator
	bloodTracker *bloodhound.Tracker
)

// rateLimiterMap stores rate limiters per IP address
var (
	rateLimiterMap = make(map[string]*rate.Limiter)
	mu             sync.Mutex
)

// Initialize deception and tracking systems
func init() {
	deceptionGen = deception.NewGenerator("canary")
	bloodTracker = bloodhound.NewTracker()
}

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
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check for directory traversal in URL path and query parameters
		if hasDirectoryTraversal(r.URL.Path) || hasDirectoryTraversal(r.URL.RawQuery) {
			// Log forensic event
			logForensicEvent("Directory traversal detected", r)
			// Track in bloodhound
			bloodTracker.TrackRequest(r, true) // Mark as honeytrap hit
			// Return HTTP 451 - Unavailable For Legal Reasons
			http.Error(w, "Unavailable For Legal Reasons - Threat Detected", 451)
			return
		}

		// Check for canary tokens in headers, path, and query
		if hasCanaryToken(r) {
			// Log forensic event
			logForensicEvent("Canary token detected", r)
			// Track in bloodhound
			bloodTracker.TrackRequest(r, true) // Mark as honeytrap hit
			// Return HTTP 451 - Unavailable For Legal Reasons
			http.Error(w, "Unavailable For Legal Reasons - Threat Detected", 451)
			return
		}

		// Track normal request in bloodhound
		bloodTracker.TrackRequest(r, false)
		
		// Continue with the next handler if no threats detected
		next.ServeHTTP(w, r)
	})
}

// hasDirectoryTraversal checks if the input contains directory traversal patterns
func hasDirectoryTraversal(input string) bool {
	if input == "" {
		return false
	}

	traversalPatterns := []string{
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

	lowerInput := strings.ToLower(input)
	for _, pattern := range traversalPatterns {
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
	queryLower := strings.ToLower(r.URL.RawQuery)
	if strings.Contains(queryLower, "canary-token") ||
		strings.Contains(queryLower, "honeytoken") ||
		strings.Contains(queryLower, "tripwire") {
		return true
	}

	return false
}

// injectDeception middleware adds deception elements to responses
func injectDeception(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if this is a decoy endpoint
		if isDecoyEndpoint(r.URL.Path) {
			// This is a decoy endpoint - log and respond accordingly
			log.Printf("Decoy endpoint accessed: %s from %s", r.URL.Path, r.RemoteAddr)
			bloodTracker.TrackRequest(r, true) // Mark as honeytrap hit
			
			// Generate fake response for decoy endpoint
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `{"status": "success", "message": "Access granted to decoy endpoint", "token": "%s", "timestamp": "%d"}`, 
				generateFakeToken(), time.Now().Unix())
			return
		}
		
		// For normal requests, add subtle deception elements to responses
		next.ServeHTTP(w, r)
	})
}

// isDecoyEndpoint checks if the path is one of our decoy endpoints
func isDecoyEndpoint(path string) bool {
	decoyEndpoints := deceptionGen.GenerateDecoyEndpoints()
	for _, endpoint := range decoyEndpoints {
		if strings.HasPrefix(path, endpoint) {
			return true
		}
	}
	return false
}

// generateFakeToken creates a fake token for decoy responses
func generateFakeToken() string {
	token, err := deceptionGen.GenerateHoneytoken("decoy_response_token", 24)
	if err != nil {
		return "fake_token_error"
	}
	return token.Value
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
		nodes := bloodTracker.GetNodes()
		highRiskPaths := bloodTracker.GetHighRiskPaths()
		
		input := map[string]interface{}{
			"path":            r.URL.Path,
			"method":          r.Method,
			"host":            r.Host,
			"ip":              getClientIP(r),
			"purpose":         r.Header.Get("X-PopIA-Purpose"), // Include purpose for POPIA checks
			"previous_paths":  extractPaths(nodes),
			"risk_score":      calculateRiskScore(highRiskPaths),
			"threat_type":     determineThreatType(highRiskPaths),
			"confidence":      calculateConfidence(highRiskPaths),
			"attack_path_score": calculateAttackPathScore(highRiskPaths),
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

// extractPaths extracts paths from attack nodes
func extractPaths(nodes []*bloodhound.AttackNode) []string {
	paths := make([]string, 0, len(nodes))
	for _, node := range nodes {
		paths = append(paths, node.Path)
	}
	return paths
}

// calculateRiskScore calculates an overall risk score based on high-risk paths
func calculateRiskScore(paths []*bloodhound.AttackPath) float64 {
	if len(paths) == 0 {
		return 0.0
	}
	
	totalScore := 0.0
	for _, path := range paths {
		totalScore += path.Score
	}
	
	return totalScore / float64(len(paths))
}

// determineThreatType determines the primary threat type from attack paths
func determineThreatType(paths []*bloodhound.AttackPath) string {
	if len(paths) == 0 {
		return "none"
	}
	
	// For simplicity, return the threat type of the first path
	// In a real implementation, you'd aggregate threat types
	return paths[0].ThreatType
}

// calculateConfidence calculates the average confidence of attack paths
func calculateConfidence(paths []*bloodhound.AttackPath) float64 {
	if len(paths) == 0 {
		return 0.0
	}
	
	totalConfidence := 0.0
	for _, path := range paths {
		totalConfidence += path.Confidence
	}
	
	return totalConfidence / float64(len(paths))
}

// calculateAttackPathScore calculates the highest attack path score
func calculateAttackPathScore(paths []*bloodhound.AttackPath) float64 {
	if len(paths) == 0 {
		return 0.0
	}
	
	maxScore := 0.0
	for _, path := range paths {
		if path.Score > maxScore {
			maxScore = path.Score
		}
	}
	
	return maxScore
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
	
	// In a real implementation, this would write to an append-only log file or database
	fmt.Println(logEntry) // For demonstration purposes
}

func main() {
	// Initialize deception elements
	log.Println("Initializing deception mesh...")
	
	// Generate some canary records for injection
	userCanary := deceptionGen.GenerateCanaryRecord("user")
	credCanary := deceptionGen.GenerateCanaryRecord("credential")
	dbCanary := deceptionGen.GenerateCanaryRecord("database")
	
	log.Printf("Generated user canary: %+v", userCanary)
	log.Printf("Generated credential canary: %+v", credCanary)
	log.Printf("Generated database canary: %+v", dbCanary)
	
	// Print available decoy endpoints
	decoyEndpoints := deceptionGen.GenerateDecoyEndpoints()
	log.Printf("Configured decoy endpoints: %v", decoyEndpoints)

	// Call the function to "use" the classification package
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
	// 2. Inject Deception Elements
	// 3. Detect Threats (passive threat detection)
	// 4. Authenticate Request (add HMAC signatures)
	// 5. Check Rate Limiter
	// 6. Classify Request (get Tier)
	// 7. POPIA Compliance Check
	// 8. Query OPA (get decision)
	// 9. Route to backend or Block
	handler := middleware.ApplySecureHeaders(
		injectDeception(
			detectThreats(
				authenticateRequest(
					rateLimit(
						classifyRequest(
							popiaCompliance(
								checkOPAPolicy(mux),
							),
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