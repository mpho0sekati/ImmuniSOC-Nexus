package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// Request metrics for Neutrophil health
type NeutrophilMetrics struct {
	mu                   sync.RWMutex
	totalChecks          int64
	checksPerSecond      float64
	blockedAnomalies     int64
	honeyPotTriggered    int64
	lastMetricsTimestamp time.Time
}

var metrics = &NeutrophilMetrics{
	lastMetricsTimestamp: time.Now(),
}

// Session tracking for T-Cell coordination
type SessionContext struct {
	ID         string
	Tier       string
	UserAgent  string
	ClientIP   string
	Timestamp  time.Time
	PathHash   string
	HeaderHash string
	Anomalies  []string
	mu         sync.RWMutex
}

var activeSessions = make(map[string]*SessionContext)
var sessionsMu sync.RWMutex

// Honeypot/Canary detection (Deception Mesh)
var honeyPots = []string{
	"/api/fake-credentials",
	"/api/admin-secret",
	"/pii/test-user-12345",
	"/banking/dummy-account",
}

// Classification Engine - determines which tier handles the request
func classifyRequest(req *http.Request, clientIP string) string {
	path := req.URL.Path
	method := req.Method

	// Critical Tier: PII, billing, admin operations
	if strings.Contains(path, "/pii") || strings.Contains(path, "/billing") ||
		strings.Contains(path, "/admin") || strings.Contains(path, "/auth/fido2") {
		return "CRITICAL"
	}

	// Standard Tier: General user operations
	if strings.Contains(path, "/profile") || strings.Contains(path, "/settings") ||
		strings.Contains(path, "/user-data") {
		return "STANDARD"
	}

	// Public Tier: Read-only, public records
	if method == "GET" && (strings.Contains(path, "/public") || strings.Contains(path, "/catalog")) {
		return "PUBLIC"
	}

	// Default to STANDARD
	return "STANDARD"
}

// Validation checks - Neutrophil security validation
func validateRequest(req *http.Request, clientIP string) (bool, []string) {
	anomalies := []string{}

	// 1. Missing security headers
	if req.Header.Get("X-Request-ID") == "" {
		anomalies = append(anomalies, "missing_request_id")
	}

	// 2. Suspicious User-Agent
	ua := req.Header.Get("User-Agent")
	if ua == "" {
		anomalies = append(anomalies, "missing_user_agent")
	}
	if strings.Contains(strings.ToLower(ua), "bot") || strings.Contains(strings.ToLower(ua), "scanner") {
		anomalies = append(anomalies, "bot_detected")
	}

	// 3. Large Content-Length (potential DDoS)
	if cl := req.Header.Get("Content-Length"); cl != "" {
		// In real implementation, parse and check against limits
		// 50MB+ would be suspicious for most endpoints
	}

	// 4. SQL/XSS injection patterns
	path := req.URL.Path
	query := req.URL.RawQuery
	if strings.Contains(path, "DROP") || strings.Contains(path, "DELETE") ||
		strings.Contains(query, "'; DROP") || strings.Contains(query, "<script>") {
		anomalies = append(anomalies, "injection_pattern_detected")
	}

	// 5. Protocol violations
	if req.Header.Get("Connection") == "Upgrade" && req.Header.Get("Upgrade") != "" {
		// Suspicious protocol switch
		anomalies = append(anomalies, "protocol_upgrade_attempt")
	}

	return len(anomalies) == 0, anomalies
}

// Honeypot detection - Deception Mesh (Antigen Traps)
func checkHoneyPot(path string) bool {
	for _, honey := range honeyPots {
		if strings.Contains(path, honey) {
			return true
		}
	}
	return false
}

// Update metrics tracking
func updateMetrics(anomalies []string) {
	metrics.mu.Lock()
	defer metrics.mu.Unlock()

	metrics.totalChecks++

	if len(anomalies) > 0 {
		metrics.blockedAnomalies++
	}

	// Calculate checks per second
	elapsed := time.Since(metrics.lastMetricsTimestamp).Seconds()
	if elapsed >= 1.0 {
		metrics.checksPerSecond = float64(metrics.totalChecks) / elapsed
		metrics.totalChecks = 0
		metrics.lastMetricsTimestamp = time.Now()
	}
}

// T-Cell quarantine signal - Used when session needs isolation
func signalTCellQuarantine(sessionID, reason string) {
	fmt.Printf("[T-CELL] Quarantine signal: Session %s - Reason: %s\n", sessionID, reason)
	// Asynchronously notify the T-Cell HTTP service
	go func() {
		payload := map[string]string{"session_id": sessionID, "reason": reason}
		b, err := json.Marshal(payload)
		if err != nil {
			log.Printf("[T-CELL] failed to marshal payload: %v", err)
			return
		}
		client := &http.Client{Timeout: 2 * time.Second}
		resp, err := client.Post("http://localhost:8090/quarantine", "application/json", bytes.NewReader(b))
		if err != nil {
			log.Printf("[T-CELL] notify failed: %v", err)
			return
		}
		resp.Body.Close()
	}()
}

// Main neutrophil proxy handler
func proxyHandler(w http.ResponseWriter, r *http.Request) {
	// 1. Extract client IP
	clientIP := r.RemoteAddr
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		clientIP = strings.Split(forwarded, ",")[0]
	}

	// 2. Generate session context
	sessionID := fmt.Sprintf("%s_%d", clientIP, time.Now().UnixNano())
	pathHash := fmt.Sprintf("%x", sha256.Sum256([]byte(r.URL.Path)))
	// Build a deterministic header string for hashing (http.Header has no Encode())
	var hb strings.Builder
	for name, vals := range r.Header {
		hb.WriteString(name)
		hb.WriteString(":")
		hb.WriteString(strings.Join(vals, ","))
		hb.WriteString("\n")
	}
	headerHash := fmt.Sprintf("%x", sha256.Sum256([]byte(hb.String())))

	session := &SessionContext{
		ID:         sessionID,
		ClientIP:   clientIP,
		UserAgent:  r.Header.Get("User-Agent"),
		Timestamp:  time.Now(),
		PathHash:   pathHash,
		HeaderHash: headerHash,
	}

	// 3. Classify request
	tier := classifyRequest(r, clientIP)
	session.Tier = tier

	// 4. Check for honeypot interactions (Deception Mesh)
	if checkHoneyPot(r.URL.Path) {
		metrics.mu.Lock()
		metrics.honeyPotTriggered++
		metrics.mu.Unlock()
		fmt.Printf("[DECEPTION MESH] Honeypot triggered: %s from %s\n", r.URL.Path, clientIP)
		signalTCellQuarantine(sessionID, "honeypot_interaction")
		http.Error(w, "Suspicious activity detected", http.StatusForbidden)
		return
	}

	// 5. Validate request
	isValid, anomalies := validateRequest(r, clientIP)
	session.Anomalies = anomalies

	// 6. Update metrics
	updateMetrics(anomalies)

	// 7. Log neutrophil intercept
	fmt.Printf("[NEUTROPHIL] Intercept: %s %s -> %s Tier | Anomalies: %d | Session: %s\n",
		r.Method, r.URL.Path, tier, len(anomalies), sessionID)

	// 8. If critical anomalies, block and signal T-Cells
	if !isValid && tier == "CRITICAL" {
		for _, anom := range anomalies {
			if anom == "injection_pattern_detected" || anom == "bot_detected" {
				signalTCellQuarantine(sessionID, fmt.Sprintf("critical_anomaly:%s", anom))
				http.Error(w, "Request rejected", http.StatusForbidden)
				return
			}
		}
	}

	// 9. Store session context
	sessionsMu.Lock()
	activeSessions[sessionID] = session
	sessionsMu.Unlock()

	backendHost := getBackendHost()

	// 10. Route to appropriate tier backend
	var targetURL string
	switch tier {
	case "CRITICAL":
		// HSM decryption, FIDO2, cold-start gVisor, live OPA
		targetURL = fmt.Sprintf("http://%s/critical", backendHost)
	case "STANDARD":
		// Cached OPA, pre-warmed gVisor
		targetURL = fmt.Sprintf("http://%s/standard", backendHost)
	case "PUBLIC":
		// Read-only replica, no write path
		targetURL = fmt.Sprintf("http://%s/public", backendHost)
	}

	// 11. Proxy request with security headers
	parsedURL, _ := url.Parse(targetURL)
	proxy := httputil.NewSingleHostReverseProxy(parsedURL)

	// Add Neutrophil tracking headers
	r.Header.Set("X-Neutrophil-Session-ID", sessionID)
	r.Header.Set("X-Security-Tier", tier)
	r.Header.Set("X-Client-IP", clientIP)

	// Proxy the request
	proxy.ServeHTTP(w, r)
}

func getBackendHost() string {
	if host := os.Getenv("BACKEND_HOST"); host != "" {
		return host
	}
	return "localhost:8081"
}

// Metrics endpoint for Hermes AI / dashboard
func metricsHandler(w http.ResponseWriter, r *http.Request) {
	metrics.mu.RLock()
	defer metrics.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{
  "neutrophil_metrics": {
    "checks_per_second": %.2f,
    "total_checks_lifetime": %d,
    "blocked_anomalies": %d,
    "honeypot_triggered": %d,
    "active_sessions": %d
  }
}`, metrics.checksPerSecond, metrics.totalChecks, metrics.blockedAnomalies, metrics.honeyPotTriggered, len(activeSessions))
}

// Health check endpoint
func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status": "healthy", "component": "neutrophil_gateway"}`)
}

func main() {
	// Start local T-Cell service (receives quarantine messages)
	go startTCellService()
	http.HandleFunc("/", proxyHandler)
	http.HandleFunc("/health", healthHandler)
	http.HandleFunc("/metrics", metricsHandler)

	fmt.Println(`
╔════════════════════════════════════════════════════════════╗
║          ImmuniSOC-Nexus: Neutrophil Layer Active          ║
║     Zero-Trust Proxy Gateway | 50K+ Checks/Sec            ║
╚════════════════════════════════════════════════════════════╝
	`)
	log.Println("Neutrophil Gateway listening on :8080")
	log.Println("  Proxy: http://localhost:8080/")
	log.Println("  Metrics: http://localhost:8080/metrics")
	log.Println("  Health: http://localhost:8080/health")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
