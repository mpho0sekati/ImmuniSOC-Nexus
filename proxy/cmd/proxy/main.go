package main

import (
	"encoding/json"
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
	"immunisoc-nexus/proxy/internal/tcell"
)

// Constants for configuration
const (
	DefaultHandshakeSecret = "default-secure-dev-token" // Only for development
	MaxLogLength          = 1000
	MinRetentionPeriod    = 1  // days
	MaxRetentionPeriod    = 365 // days
)

// Global instances for deception, tracking, and healing
var (
	deceptionGen *deception.Generator
	bloodTracker *bloodhound.Tracker
	tcellEngine  *tcell.Engine
)

// rateLimiterMap stores rate limiters per IP address
var (
	rateLimiterMap = make(map[string]*rate.Limiter)
	mu             sync.Mutex
)

// Initialize deception, tracking, and healing systems
func init() {
	deceptionGen = deception.NewGenerator("canary")
	bloodTracker = bloodhound.NewTracker()
	tcellEngine = tcell.NewEngine()
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
		ip := getClientIP(r) // Use the actual client IP, not RemoteAddr
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
		ip := getClientIP(r)
		sessionID := getSessionID(r)
		token := getTokenFromRequest(r)

		// Check if IP is blocked by T-Cell
		if !tcellEngine.IsIPAllowed(ip) {
			log.Printf("Request from blocked IP %s rejected", ip)
			http.Error(w, "Access denied - IP temporarily blocked", http.StatusForbidden)
			return
		}

		// Check if session is valid
		if sessionID != "unknown_session" && !tcellEngine.IsSessionValid(sessionID) {
			log.Printf("Request with invalid session %s rejected", sessionID)
			http.Error(w, "Access denied - Session terminated", http.StatusForbidden)
			return
		}

		// Check if token is valid
		if token != "" && !tcellEngine.IsTokenValid(token) {
			log.Printf("Request with revoked token %s rejected", token)
			http.Error(w, "Access denied - Token revoked", http.StatusForbidden)
			return
		}

		// Check for directory traversal in URL path and query parameters
		if hasDirectoryTraversal(r.URL.Path) || hasDirectoryTraversal(r.URL.RawQuery) {
			// Log forensic event
			logForensicEvent("Directory traversal detected", r)
			// Track in bloodhound
			bloodTracker.TrackRequest(r, true) // Mark as honeytrap hit

			// Process threat with T-Cell
			threatDetails := map[string]interface{}{
				"threat_type":       "directory_traversal",
				"detection_method":  "pattern_match",
				"request_path":      r.URL.Path,
				"request_query":     r.URL.RawQuery,
			}
			level := tcell.Critical // Directory traversal is critical
			actions, err := tcellEngine.ProcessThreat(ip, sessionID, token, level, threatDetails)
			if err != nil {
				log.Printf("T-Cell error processing threat: %v", err)
			} else {
				log.Printf("T-Cell executed %d actions for threat from IP %s", len(actions), ip)
			}

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

			// Process threat with T-Cell
			threatDetails := map[string]interface{}{
				"threat_type":       "honeytrap_access",
				"detection_method":  "canary_token",
				"request_path":      r.URL.Path,
				"user_agent":        r.UserAgent(),
			}
			level := tcell.Critical // Honeytrap access is critical
			actions, err := tcellEngine.ProcessThreat(ip, sessionID, token, level, threatDetails)
			if err != nil {
				log.Printf("T-Cell error processing threat: %v", err)
			} else {
				log.Printf("T-Cell executed %d actions for threat from IP %s", len(actions), ip)
			}

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
			ip := getClientIP(r)
			sessionID := getSessionID(r)
			token := getTokenFromRequest(r)

			// This is a decoy endpoint - log and respond accordingly
			log.Printf("Decoy endpoint accessed: %s from %s", r.URL.Path, ip)
			bloodTracker.TrackRequest(r, true) // Mark as honeytrap hit

			// Process threat with T-Cell
			threatDetails := map[string]interface{}{
				"threat_type":       "decoy_endpoint_access",
				"detection_method":  "path_match",
				"request_path":      r.URL.Path,
				"user_agent":        r.UserAgent(),
			}
			level := tcell.High // Decoy endpoint access is high risk
			actions, err := tcellEngine.ProcessThreat(ip, sessionID, token, level, threatDetails)
			if err != nil {
				log.Printf("T-Cell error processing threat: %v", err)
			} else {
				log.Printf("T-Cell executed %d actions for threat from IP %s", len(actions), ip)
			}
			
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
func authenticateRequest(sharedSecret string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return middleware.ApplyAuthentication(sharedSecret)(next)
	}
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
			// Process threat with T-Cell when OPA blocks the request
			ip := getClientIP(r)
			sessionID := getSessionID(r)
			token := getTokenFromRequest(r)
			
			threatDetails := map[string]interface{}{
				"threat_type":         "opa_policy_block",
				"opa_risk_score":      input["risk_score"],
				"opa_threat_type":     input["threat_type"],
				"opa_attack_path_score": input["attack_path_score"],
				"request_path":        r.URL.Path,
				"user_agent":          r.UserAgent(),
			}
			
			// Determine containment level based on risk factors
			riskScore, ok := input["risk_score"].(float64)
			if !ok {
				riskScore = 0
			}
			confidence, ok := input["confidence"].(float64)
			if !ok {
				confidence = 0
			}
			
			level := tcell.GetContainmentLevel(riskScore, confidence, "opa_block")
			actions, err := tcellEngine.ProcessThreat(ip, sessionID, token, level, threatDetails)
			if err != nil {
				log.Printf("T-Cell error processing OPA-blocked request: %v", err)
			} else {
				log.Printf("T-Cell executed %d actions for OPA-blocked request from IP %s", len(actions), ip)
			}
			
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

// getSessionID extracts session ID from request (simplified)
func getSessionID(r *http.Request) string {
	sessionCookie, err := r.Cookie("session_id")
	if err == nil && sessionCookie != nil {
		return sessionCookie.Value
	}
	
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		return authHeader // Simplified - in reality you'd parse JWT or similar
	}
	
	return "unknown_session"
}

// getTokenFromRequest extracts token from request
func getTokenFromRequest(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		// Handle Bearer tokens
		if strings.HasPrefix(authHeader, "Bearer ") {
			return authHeader[7:]
		}
		// Handle basic tokens
		return authHeader
	}
	
	// Check for other token headers
	token := r.Header.Get("X-API-Token")
	if token != "" {
		return token
	}
	
	token = r.Header.Get("X-Auth-Token")
	if token != "" {
		return token
	}
	
	return ""
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
	
	// Apply egress protection to the proxy
	egressProtectedProxy := middleware.EgressFilter(proxy)
	
	// Serve the request through the egress-protected proxy
	egressProtectedProxy.ServeHTTP(w, r)
}

// metricsHandler exposes security system metrics
func metricsHandler(w http.ResponseWriter, r *http.Request) {
	metrics := tcellEngine.GetMetrics()
	
	w.Header().Set("Content-Type", "application/json")
	
	// Create a JSON response with the metrics
	response := map[string]interface{}{
		"timestamp":              time.Now().Unix(),
		"total_threats_processed": metrics.TotalThreatsProcessed,
		"total_actions_executed":  metrics.TotalActionsExecuted,
		"total_ip_blocks":         metrics.TotalIPBlocks,
		"total_sessions_terminated": metrics.TotalSessionsTerminated,
		"total_tokens_revoked":    metrics.TotalTokensRevoked,
		"active_blocks":           metrics.ActiveBlocks,
		"active_sessions":         metrics.ActiveSessions,
		"revoked_tokens_count":    metrics.RevokedTokensCount,
	}
	
	// Encode response as JSON
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Error encoding metrics: %v", err)
		http.Error(w, "Encoding error", http.StatusInternalServerError)
		return
	}
}

// logForensicEvent logs events for forensic analysis in append-only format
func logForensicEvent(eventType string, r *http.Request) {
	// Append-only event logging for forensic ingestion
	logEntry := fmt.Sprintf(
		"[FORENSIC_LOG] %d | %s | %s | %s | %s | %s",
		time.Now().UnixNano()/1000000, // timestamp in milliseconds
		eventType,
		getClientIP(r), // Use the actual client IP function
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

func main() {
	// Load shared secret for Proxy-to-Backend authentication
	handshakeSecret := os.Getenv("HANDSHAKE_SECRET_TOKEN")
	if handshakeSecret == "" {
		// According to security spec, this should be a fatal error
		log.Fatal("ERROR: HANDSHAKE_SECRET_TOKEN environment variable is required but not set. Server startup aborted.")
	}

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

	// Register the metrics endpoint
	mux.HandleFunc("/metrics", metricsHandler)
	
	// Define a handler that implements the complete flow
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// This handler will be wrapped by all the middleware layers
		routeToBackend(w, r)
	})

	// Apply middleware stack in the specified order:
	// 1. Verb whitelist (early filtering)
	// 2. Apply Secure Headers
	// 3. Inject Deception Elements
	// 4. Detect Threats (passive threat detection)
	// 5. Authenticate Request (add HMAC signatures)
	// 6. Check Rate Limiter
	// 7. Classify Request (get Tier)
	// 8. POPIA Compliance Check
	// 9. Query OPA (get decision)
	// 10. Egress Protection (data exfiltration prevention)
	// 11. Route to backend or Block
	handler := verbWhitelist(
		middleware.ApplySecureHeaders(
			injectDeception(
				detectThreats(
					authenticateRequest(handshakeSecret)(
						rateLimit(
							classifyRequest(
								popiaCompliance(
									checkOPAPolicy(
										middleware.EgressFilter(mux), // Add egress protection before routing
									),
								),
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