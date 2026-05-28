package bloodhound

import (
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// AttackNode represents a node in the attack path
type AttackNode struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"` // endpoint, credential, session, etc.
	Name        string    `json:"name"`
	Path        string    `json:"path"`
	Timestamp   time.Time `json:"timestamp"`
	SourceIP    string    `json:"source_ip"`
	UserAgent   string    `json:"user_agent"`
	SessionID   string    `json:"session_id"`
	IsHoneytrap bool      `json:"is_honeytrap"`
	Alert       bool      `json:"alert"`
}

// AttackEdge represents a connection between attack nodes
type AttackEdge struct {
	FromNodeID string    `json:"from_node_id"`
	ToNodeID   string    `json:"to_node_id"`
	Timestamp  time.Time `json:"timestamp"`
	Method     string    `json:"method"`
	Alert      bool      `json:"alert"`
}

// AttackPath represents a complete attack path/lateral movement
type AttackPath struct {
	ID           string       `json:"id"`
	StartNode    string       `json:"start_node"`
	EndNode      string       `json:"end_node"`
	Edges        []AttackEdge `json:"edges"`
	AlertLevel   string       `json:"alert_level"` // low, medium, high, critical
	Score        float64      `json:"score"`
	FirstSeen    time.Time    `json:"first_seen"`
	LastSeen     time.Time    `json:"last_seen"`
	IsCompleted  bool         `json:"is_completed"`
	ThreatType   string       `json:"threat_type"` // recon, lateral_movement, privilege_escalation, exfiltration
	Confidence   float64      `json:"confidence"`
}

// Tracker manages attack path tracking and detection
type Tracker struct {
	nodes     map[string]*AttackNode
	paths     map[string]*AttackPath
	edges     []*AttackEdge
	mutex     sync.RWMutex
	alertChan chan *AttackPath
	stopChan  chan struct{}  // Channel to signal shutdown
}

// NewTracker creates a new bloodhound tracker
func NewTracker() *Tracker {
	tracker := &Tracker{
		nodes:     make(map[string]*AttackNode),
		paths:     make(map[string]*AttackPath),
		edges:     make([]*AttackEdge, 0),
		alertChan: make(chan *AttackPath, 100), // Buffered channel for alerts
		stopChan:  make(chan struct{}),         // Channel to signal shutdown
	}
	
	// Start alert processor goroutine
	go tracker.processAlerts()
	
	return tracker
}

// TrackRequest tracks a request and potentially creates attack path nodes
func (t *Tracker) TrackRequest(r *http.Request, isHoneytrap bool) {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	
	nodeID := generateNodeID(r)
	
	// Create attack node
	node := &AttackNode{
		ID:          nodeID,
		Type:        "endpoint_access",
		Name:        fmt.Sprintf("Request to %s", r.URL.Path),
		Path:        r.URL.Path,
		Timestamp:   time.Now(),
		SourceIP:    getClientIP(r),
		UserAgent:   r.UserAgent(),
		SessionID:   getSessionID(r),
		IsHoneytrap: isHoneytrap,
		Alert:       isHoneytrap, // Alert if it's a honeytrap hit
	}
	
	t.nodes[nodeID] = node
	
	// If this is a honeytrap hit, trigger an alert
	if isHoneytrap {
		path := &AttackPath{
			ID:          fmt.Sprintf("path_%d", time.Now().Unix()),
			StartNode:   nodeID,
			EndNode:     nodeID,
			AlertLevel:  "critical",
			Score:       10.0,
			FirstSeen:   time.Now(),
			LastSeen:    time.Now(),
			IsCompleted: true,
			ThreatType:  "honeytrap_access",
			Confidence:  1.0,
		}
		
		t.paths[path.ID] = path
		select {
		case t.alertChan <- path:
		default:
			// Non-blocking send in case channel is full
			fmt.Println("[BLOODHOUND] Alert channel full, dropping alert")
		}
	}
}

// TrackLateralMovement tracks potential lateral movement between nodes
func (t *Tracker) TrackLateralMovement(fromNodeID, toNodeID, method string) {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	
	edge := &AttackEdge{
		FromNodeID: fromNodeID,
		ToNodeID:   toNodeID,
		Timestamp:  time.Now(),
		Method:     method,
		Alert:      false,
	}
	
	t.edges = append(t.edges, edge)
	
	// Check if this constitutes lateral movement worthy of alert
	fromNode, fromOk := t.nodes[fromNodeID]
	toNode, toOk := t.nodes[toNodeID]
	
	if fromOk && toOk && (fromNode.IsHoneytrap || toNode.IsHoneytrap) {
		pathID := fmt.Sprintf("lateral_%s_to_%s", fromNodeID, toNodeID)
		
		attackPath := &AttackPath{
			ID:          pathID,
			StartNode:   fromNodeID,
			EndNode:     toNodeID,
			Edges:       []AttackEdge{*edge},
			AlertLevel:  "high",
			Score:       8.0,
			FirstSeen:   time.Now(),
			LastSeen:    time.Now(),
			IsCompleted: false,
			ThreatType:  "lateral_movement",
			Confidence:  0.8,
		}
		
		t.paths[pathID] = attackPath
		edge.Alert = true
		attackPath.AlertLevel = "critical"
		attackPath.Confidence = 0.95
		attackPath.IsCompleted = true
		
		select {
		case t.alertChan <- attackPath:
		default:
			// Non-blocking send in case channel is full
			fmt.Println("[BLOODHOUND] Alert channel full, dropping alert")
		}
	}
}

// GetAttackPaths returns all tracked attack paths
func (t *Tracker) GetAttackPaths() []*AttackPath {
	t.mutex.RLock()
	defer t.mutex.RUnlock()
	
	paths := make([]*AttackPath, 0, len(t.paths))
	for _, path := range t.paths {
		paths = append(paths, path)
	}
	
	return paths
}

// GetRecentAttacks returns recent attacks within a timeframe
func (t *Tracker) GetRecentAttacks(hours int) []*AttackPath {
	t.mutex.RLock()
	defer t.mutex.RUnlock()
	
	threshold := time.Now().Add(-time.Duration(hours) * time.Hour)
	recentPaths := make([]*AttackPath, 0)
	
	for _, path := range t.paths {
		if path.LastSeen.After(threshold) {
			recentPaths = append(recentPaths, path)
		}
	}
	
	return recentPaths
}

// processAlerts handles alert processing in a separate goroutine
func (t *Tracker) processAlerts() {
	for {
		select {
		case path := <-t.alertChan:
			// In a real implementation, this would send alerts to SIEM, etc.
			fmt.Printf("[BLOODHOUND ALERT] Potential threat detected: %+v\n", path)
		case <-t.stopChan:
			// Close the alert channel and exit the goroutine
			close(t.alertChan)
			return
		}
	}
}

// Shutdown gracefully shuts down the tracker
func (t *Tracker) Shutdown() {
	close(t.stopChan)
}

// generateNodeID creates a unique ID for a request
func generateNodeID(r *http.Request) string {
	return fmt.Sprintf("node_%d_%s", time.Now().UnixNano(), strings.ReplaceAll(r.URL.Path, "/", "_"))
}

// getClientIP extracts the client IP from the request
func getClientIP(r *http.Request) string {
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		ips := strings.Split(forwarded, ",")
		return strings.TrimSpace(ips[0])
	}
	
	realIP := r.Header.Get("X-Real-IP")
	if realIP != "" {
		return realIP
	}
	
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
}

// getSessionID extracts session ID from request with validation
func getSessionID(r *http.Request) string {
	sessionCookie, err := r.Cookie("session_id")
	if err == nil && sessionCookie != nil {
		// Validate session ID format (should be a proper UUID or long random string)
		if isValidSessionID(sessionCookie.Value) {
			return sessionCookie.Value
		}
	}
	
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		// If it's a Bearer token, extract the token part
		if strings.HasPrefix(authHeader, "Bearer ") {
			token := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
			if isValidSessionID(token) {
				return token
			}
		} else {
			// For other auth schemes, validate as well
			if isValidSessionID(authHeader) {
				return authHeader
			}
		}
	}
	
	return "unknown_session"
}

// isValidSessionID validates that a session ID meets security requirements
func isValidSessionID(id string) bool {
	if id == "" || len(id) < 16 {
		return false
	}
	
	// Check if it looks like a UUID
	uuidRegex := regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	if uuidRegex.MatchString(id) {
		return true
	}
	
	// Check if it's a long, random-looking string with good entropy
	// For non-UUID session IDs, check for sufficient randomness
	return hasSufficientEntropy(id)
}

// hasSufficientEntropy checks if a string has enough randomness to be a secure session ID
func hasSufficientEntropy(s string) bool {
	if len(s) < 22 { // Minimum recommended length for session tokens
		return false
	}
	
	// Count character diversity
	charSet := make(map[rune]bool)
	for _, r := range s {
		charSet[r] = true
	}
	
	// Require at least 50% character diversity
	return float64(len(charSet))/float64(len(s)) >= 0.5
}

// GetNodes returns all tracked nodes
func (t *Tracker) GetNodes() []*AttackNode {
	t.mutex.RLock()
	defer t.mutex.RUnlock()
	
	nodes := make([]*AttackNode, 0, len(t.nodes))
	for _, node := range t.nodes {
		nodes = append(nodes, node)
	}
	
	return nodes
}

// GetHighRiskPaths returns paths with high risk scores
func (t *Tracker) GetHighRiskPaths() []*AttackPath {
	t.mutex.RLock()
	defer t.mutex.RUnlock()
	
	highRiskPaths := make([]*AttackPath, 0)
	
	for _, path := range t.paths {
		if path.Score >= 7.0 {
			highRiskPaths = append(highRiskPaths, path)
		}
	}
	
	return highRiskPaths
}

// GetHoneytokenTriggerCount returns the count of honeytoken triggers
func (bt *Tracker) GetHoneytokenTriggerCount() int64 {
	bt.mutex.RLock()
	defer bt.mutex.RUnlock()

	// Count the number of honeytrap hits in the paths
	count := int64(0)
	for _, path := range bt.paths {
		for _, edge := range path.Edges {
			if edge.Alert {
				count++
			}
		}
	}
	return count
}
