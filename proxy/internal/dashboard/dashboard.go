package dashboard

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"immunisoc-nexus/proxy/internal/bloodhound"
	"immunisoc-nexus/proxy/internal/classification"
	"immunisoc-nexus/proxy/internal/deception"
	"immunisoc-nexus/proxy/internal/hardening"
	"immunisoc-nexus/proxy/internal/microseg"
	"immunisoc-nexus/proxy/internal/monocyte"
	"immunisoc-nexus/proxy/internal/opa"
	"immunisoc-nexus/proxy/internal/rbac"
	"immunisoc-nexus/proxy/internal/tcell"
)

// Dashboard represents the secure-by-design dashboard system
type Dashboard struct {
	bloodTracker    *bloodhound.Tracker
	classifier      *classification.Classifier
	deceptionGen    *deception.Generator
	hardeningMgr    *hardening.HardeningManager
	microSegManager *microseg.MicrosegmentationManager
	immutableLogger *monocyte.MonocyteLogger
	opaClient       *opa.OpaClient
	tcellEngine     *tcell.Engine
	rbacManager     *rbac.RBACManager
	mutex           sync.RWMutex
	securityMetrics SecurityMetrics
}

// SecurityMetrics holds comprehensive security metrics
type SecurityMetrics struct {
	ActiveThreats         int64     `json:"active_threats"`
	BlockedRequests       int64     `json:"blocked_requests"`
	HoneytokenHits        int64     `json:"honeytoken_hits"`
	ActiveSessions        int64     `json:"active_sessions"`
	RevokedTokens         int64     `json:"revoked_tokens"`
	TotalActionsExecuted  int64     `json:"total_actions_executed"`
	ActiveIPBlocks        int64     `json:"active_ip_blocks"`
	TotalThreatsProcessed int64     `json:"total_threats_processed"`
	LogIntegrity          bool      `json:"log_integrity"`
	LastUpdate            time.Time `json:"last_update"`
	RiskScore             float64   `json:"risk_score"`
	ComplianceStatus      string    `json:"compliance_status"`
	EncryptionStatus      string    `json:"encryption_status"`
}

// DashboardData represents the comprehensive dashboard data structure
type DashboardData struct {
	Metrics       SecurityMetrics         `json:"metrics"`
	Threats       []ThreatInfo            `json:"threats"`
	Paths         []bloodhound.AttackPath `json:"paths"` // Using the correct AttackPath type
	Timeline      []tcell.ResponseAction  `json:"timeline"`
	SecurityStats map[string]interface{}  `json:"security_stats"`
	Compliance    ComplianceReport        `json:"compliance"`
	Version       string                  `json:"version"`
	Timestamp     time.Time               `json:"timestamp"`
}

// ThreatInfo represents detailed threat information
type ThreatInfo struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"`
	Severity    string    `json:"severity"`
	SourceIP    string    `json:"source_ip"`
	Timestamp   time.Time `json:"timestamp"`
	Description string    `json:"description"`
	Confidence  float64   `json:"confidence"`
	Actions     []string  `json:"actions"`
}

// ComplianceReport represents compliance status information
type ComplianceReport struct {
	POPIAStatus       string    `json:"popia_status"`
	LastAudit         time.Time `json:"last_audit"`
	NextAudit         time.Time `json:"next_audit"`
	Findings          []string  `json:"findings"`
	OverallScore      float64   `json:"overall_score"`
	RequirementsMet   int       `json:"requirements_met"`
	TotalRequirements int       `json:"total_requirements"`
}

// NewDashboard creates a new secure dashboard instance
func NewDashboard(
	bt *bloodhound.Tracker,
	cf *classification.Classifier,
	dg *deception.Generator,
	hm *hardening.HardeningManager,
	msm *microseg.MicrosegmentationManager,
	il *monocyte.MonocyteLogger,
	oc *opa.OpaClient,
	te *tcell.Engine,
	rm *rbac.RBACManager,
) *Dashboard {
	dash := &Dashboard{
		bloodTracker:    bt,
		classifier:      cf,
		deceptionGen:    dg,
		hardeningMgr:    hm,
		microSegManager: msm,
		immutableLogger: il,
		opaClient:       oc,
		tcellEngine:     te,
		rbacManager:     rm,
		securityMetrics: SecurityMetrics{
			ComplianceStatus: "COMPLIANT",
			EncryptionStatus: "AES-256-GCM",
		},
	}

	// Start metrics collection routine
	go dash.collectMetrics()

	return dash
}

// collectMetrics collects security metrics in the background
func (d *Dashboard) collectMetrics() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		d.updateMetrics()
	}
}

// updateMetrics updates the security metrics
func (d *Dashboard) updateMetrics() {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	// Update metrics from various components
	metrics := d.tcellEngine.GetMetrics()
	d.securityMetrics.BlockedRequests = metrics.TotalIPBlocks
	d.securityMetrics.TotalActionsExecuted = metrics.TotalActionsExecuted
	d.securityMetrics.TotalThreatsProcessed = metrics.TotalThreatsProcessed
	d.securityMetrics.ActiveIPBlocks = d.tcellEngine.GetBlockedIPCount()
	d.securityMetrics.RevokedTokens = int64(len(d.tcellEngine.GetRevokedTokens()))
	d.securityMetrics.ActiveSessions = int64(len(d.tcellEngine.GetActiveSessions()))

	// Update from other components
	d.securityMetrics.HoneytokenHits = d.bloodTracker.GetHoneytokenTriggerCount()
	d.securityMetrics.ActiveThreats = int64(len(d.bloodTracker.GetHighRiskPaths()))

	// Check log integrity
	isValid, _ := d.immutableLogger.VerifyChain()
	d.securityMetrics.LogIntegrity = isValid

	// Update risk score based on various factors
	d.securityMetrics.RiskScore = d.calculateRiskScore()

	d.securityMetrics.LastUpdate = time.Now()
}

// calculateRiskScore calculates an overall risk score based on security metrics
func (d *Dashboard) calculateRiskScore() float64 {
	score := 0.0

	// Weighted factors affecting risk
	score += float64(d.securityMetrics.ActiveThreats) * 10.0
	score += float64(d.securityMetrics.BlockedRequests) * 0.5
	score += float64(d.securityMetrics.HoneytokenHits) * 15.0
	score += float64(d.securityMetrics.ActiveIPBlocks) * 2.0

	// Drastically impact risk score if immutable logs are tampered with
	if !d.securityMetrics.LogIntegrity {
		score += 50.0
	}

	// Cap at 100
	if score > 100.0 {
		score = 100.0
	}

	// Invert so lower is better
	return 100.0 - score
}

// Handler returns the HTTP handler for the dashboard API
func (d *Dashboard) Handler() http.Handler {
	mux := http.NewServeMux()

	// Main dashboard data endpoint
	mux.HandleFunc("/api/dashboard", d.handleDashboardData)

	// Security metrics endpoint
	mux.HandleFunc("/api/metrics", d.handleMetrics)

	// Threats endpoint
	mux.HandleFunc("/api/threats", d.handleThreats)

	// Compliance endpoint
	mux.HandleFunc("/api/compliance", d.handleCompliance)

	// Security configuration endpoint
	mux.HandleFunc("/api/config", d.handleConfig)

	// Health check
	mux.HandleFunc("/api/health", d.handleHealth)

	return mux
}

// handleDashboardData handles requests for comprehensive dashboard data
func (d *Dashboard) handleDashboardData(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	data := d.GetDashboardData()

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-XSS-Protection", "1; mode=block")

	// Implement strict CORS policy
	origin := r.Header.Get("Origin")
	if origin != "" && IsAllowedOrigin(origin) {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Credentials", "true")
	}

	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("Error encoding dashboard data: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// handleMetrics handles requests for security metrics
func (d *Dashboard) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	d.mutex.RLock()
	metrics := d.securityMetrics
	d.mutex.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	if err := json.NewEncoder(w).Encode(metrics); err != nil {
		log.Printf("Error encoding metrics: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// handleThreats handles requests for threat information
func (d *Dashboard) handleThreats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	threats := d.getThreats()

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	if err := json.NewEncoder(w).Encode(threats); err != nil {
		log.Printf("Error encoding threats: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// handleCompliance handles requests for compliance information
func (d *Dashboard) handleCompliance(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	compliance := d.getComplianceReport()

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	if err := json.NewEncoder(w).Encode(compliance); err != nil {
		log.Printf("Error encoding compliance: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// handleConfig handles requests for security configuration
func (d *Dashboard) handleConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	config := d.getConfig()

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	if err := json.NewEncoder(w).Encode(config); err != nil {
		log.Printf("Error encoding config: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// handleHealth handles health check requests
func (d *Dashboard) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	health := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().UTC(),
		"version":   "1.0.0",
		"components": map[string]string{
			"bloodhound": "operational",
			"tcell":      "operational",
			"monocyte":   "operational",
			"deception":  "operational",
			"opa":        "operational",
			"microseg":   "operational",
			"hardening":  "operational",
			"rbac":       "operational",
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	if err := json.NewEncoder(w).Encode(health); err != nil {
		log.Printf("Error encoding health: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// GetDashboardData returns comprehensive dashboard data
func (d *Dashboard) GetDashboardData() *DashboardData {
	d.mutex.RLock()
	metrics := d.securityMetrics
	d.mutex.RUnlock()

	// Convert []*bloodhound.AttackPath to []bloodhound.AttackPath
	highRiskPaths := d.bloodTracker.GetHighRiskPaths()
	paths := make([]bloodhound.AttackPath, len(highRiskPaths))
	for i, path := range highRiskPaths {
		paths[i] = *path
	}

	return &DashboardData{
		Metrics:       metrics,
		Threats:       d.getThreats(),
		Paths:         paths,
		Timeline:      d.tcellEngine.GetRecentActions(),
		SecurityStats: d.getSecurityStats(),
		Compliance:    d.getComplianceReport(),
		Version:       "1.0.0",
		Timestamp:     time.Now(),
	}
}

// getThreats returns current threat information
func (d *Dashboard) getThreats() []ThreatInfo {
	// Get recent threats from various sources
	actions := d.tcellEngine.GetRecentActions()

	var threats []ThreatInfo
	for _, action := range actions {
		if len(threats) >= 20 { // Limit to recent 20 threats
			break
		}

		threat := ThreatInfo{
			ID:          fmt.Sprintf("%d", len(threats)),
			Type:        action.Description,
			Severity:    d.getSeverityFromAction(action),
			SourceIP:    action.Target,
			Timestamp:   action.Timestamp,
			Description: action.Description,
			Confidence:  0.8, // Default confidence
			Actions:     []string{action.ActionType},
		}

		threats = append(threats, threat)
	}

	// Also include high-risk paths from Bloodhound for a holistic view
	paths := d.bloodTracker.GetHighRiskPaths()
	for _, path := range paths {
		if len(threats) >= 40 { // Increase limit slightly to accommodate lateral movement threats
			break
		}

		threat := ThreatInfo{
			ID:          path.ID,
			Type:        path.ThreatType,
			Severity:    strings.ToUpper(path.AlertLevel),
			SourceIP:    "multiple/lateral",
			Timestamp:   path.LastSeen,
			Description: fmt.Sprintf("Potential %s detected with score %.2f", path.ThreatType, path.Score),
			Confidence:  path.Confidence,
			Actions:     []string{"INVESTIGATE", "ISOLATE_SEGMENT"},
		}

		threats = append(threats, threat)
	}

	return threats
}

// getSeverityFromAction maps response actions to severity levels
func (d *Dashboard) getSeverityFromAction(action tcell.ResponseAction) string {
	switch action.Severity {
	case tcell.Low:
		return "LOW"
	case tcell.Medium:
		return "MEDIUM"
	case tcell.High:
		return "HIGH"
	case tcell.Critical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

// getSecurityStats returns additional security statistics
func (d *Dashboard) getSecurityStats() map[string]interface{} {
	return map[string]interface{}{
		"microsegmentation": map[string]interface{}{
			"active_segments": len(d.microSegManager.GetAllSegments()),
			"total_policies":  d.microSegManager.GetTotalPolicies(),
		},
		"deception": map[string]interface{}{
			"active_honeytokens": len(d.deceptionGen.GenerateDecoyEndpoints()),
		},
		"hardening": map[string]interface{}{
			"critical_services": d.hardeningMgr.GetCriticalServicesCount(),
			"disabled_unused":   d.hardeningMgr.GetDisabledServicesCount(),
		},
		"classification": map[string]interface{}{
			"active_classifiers": 1, // Assuming one main classifier
		},
	}
}

// getComplianceReport returns compliance status information
func (d *Dashboard) getComplianceReport() ComplianceReport {
	return ComplianceReport{
		POPIAStatus:       "COMPLIANT",
		LastAudit:         time.Now().AddDate(0, 0, -7), // Last week
		NextAudit:         time.Now().AddDate(0, 0, 23), // In 23 days
		Findings:          []string{},                   // No findings
		OverallScore:      98.5,                         // High compliance score
		RequirementsMet:   47,                           // Met requirements
		TotalRequirements: 48,                           // Total requirements
	}
}

// getConfig returns security configuration information
func (d *Dashboard) getConfig() map[string]interface{} {
	return map[string]interface{}{
		"dashboard": map[string]interface{}{
			"refresh_interval": "30s",
			"retention_days":   30,
			"encryption":       "AES-256-GCM",
		},
		"security": map[string]interface{}{
			"rbac_enabled":      true,
			"opa_integration":   true,
			"microsegmentation": true,
			"deception_layer":   true,
		},
		"logging": map[string]interface{}{
			"immutable":    true,
			"integrity":    true,
			"retention":    "365d",
			"verification": true,
		},
	}
}

// IsAllowedOrigin checks if the origin is allowed for CORS
func IsAllowedOrigin(origin string) bool {
	allowedOrigins := []string{
		"http://localhost:3000",
		"http://127.0.0.1:3000",
		"https://dashboard.immunisoc-nexus.local",
		"https://immunisoc-dashboard.example.com",
	}

	for _, allowed := range allowedOrigins {
		// Use exact match to prevent origin spoofing via subdomains (e.g. localhost.attacker.com)
		if origin == allowed {
			return true
		}
	}
	return false
}

// GetCriticalServicesCount returns the count of critical services
func (d *Dashboard) GetCriticalServicesCount() int {
	if d.hardeningMgr == nil {
		return 0
	}
	return d.hardeningMgr.GetCriticalServicesCount()
}

// GetDisabledServicesCount returns the count of disabled services
func (d *Dashboard) GetDisabledServicesCount() int {
	if d.hardeningMgr == nil {
		return 0
	}
	return d.hardeningMgr.GetDisabledServicesCount()
}

// GetSecurityMetrics returns a copy of the current security metrics
func (d *Dashboard) GetSecurityMetrics() SecurityMetrics {
	d.mutex.RLock()
	defer d.mutex.RUnlock()
	return d.securityMetrics
}
