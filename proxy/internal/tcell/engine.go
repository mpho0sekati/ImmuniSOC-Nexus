package tcell

import (
	"fmt"
	"sync"
	"time"
)

// ContainmentLevel defines the severity of containment actions
type ContainmentLevel int

const (
	Low ContainmentLevel = iota
	Medium
	High
	Critical
)

// Metrics holds statistics about the engine's operations
type Metrics struct {
	TotalActionsExecuted    int64
	TotalThreatsProcessed   int64
	TotalIPBlocks           int64
	TotalSessionsTerminated int64
	TotalTokensRevoked      int64
	ActiveBlocks            int64
	ActiveSessions          int64
	RevokedTokensCount      int64
	mutex                   sync.RWMutex
}

// Logger handles enhanced logging
type Logger struct {
	enabled bool
}

// SessionManager handles session-related operations
type SessionManager struct {
	sessions map[string]bool // session_id -> active
	mutex    sync.RWMutex
}

// IPBlocker manages temporary IP blocks
type IPBlocker struct {
	blockedIPs map[string]time.Time // ip -> expiration_time
	mutex      sync.RWMutex
}

// TokenRevoker handles token revocation
type TokenRevoker struct {
	revokedTokens map[string]bool // token -> revoked
	mutex         sync.RWMutex
}

// Engine is the main T-Cell Self-Healing Engine
type Engine struct {
	sessionManager *SessionManager
	ipBlocker      *IPBlocker
	tokenRevoker   *TokenRevoker
	logger         *Logger
	mutex          sync.RWMutex
	metrics        *Metrics
	actionHistory  []ResponseAction
}

// NewEngine creates a new T-Cell engine instance
func NewEngine() *Engine {
	engine := &Engine{
		sessionManager: &SessionManager{
			sessions: make(map[string]bool),
		},
		ipBlocker: &IPBlocker{
			blockedIPs: make(map[string]time.Time),
		},
		tokenRevoker: &TokenRevoker{
			revokedTokens: make(map[string]bool),
		},
		logger: &Logger{
			enabled: true,
		},
		metrics:       &Metrics{},
		actionHistory: make([]ResponseAction, 0, 100),
	}

	// Start background cleanup for expired IP blocks
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		for range ticker.C {
			engine.CleanupExpiredBlocks()
		}
	}()

	return engine
}

// ResponseAction represents an automated response action
type ResponseAction struct {
	ActionType     string            `json:"action_type"`
	Target         string            `json:"target"`
	Severity       ContainmentLevel  `json:"severity"`
	Duration       time.Duration     `json:"duration"`
	Timestamp      time.Time         `json:"timestamp"`
	Description    string            `json:"description"`
	AdditionalData map[string]string `json:"additional_data,omitempty"`
}

// ExecuteResponseActions executes automated response actions based on threat assessment
func (e *Engine) ExecuteResponseActions(level ContainmentLevel, targetIP, sessionID, token string, threatDetails map[string]interface{}) ([]ResponseAction, error) {
	var actions []ResponseAction

	switch level {
	case Low:
		// Low level: Enhanced logging only
		action := ResponseAction{
			ActionType:  "enhanced_logging",
			Target:      targetIP,
			Severity:    Low,
			Timestamp:   time.Now(),
			Description: "Enhanced logging activated for low-risk activity",
		}
		actions = append(actions, action)
		e.logger.EnableEnhancedLogging()

	case Medium:
		// Medium level: Enhanced logging + session monitoring
		action1 := ResponseAction{
			ActionType:  "enhanced_logging",
			Target:      targetIP,
			Severity:    Medium,
			Timestamp:   time.Now(),
			Description: "Enhanced logging activated for medium-risk activity",
		}
		actions = append(actions, action1)

		action2 := ResponseAction{
			ActionType:  "session_monitoring",
			Target:      sessionID,
			Severity:    Medium,
			Timestamp:   time.Now(),
			Description: "Increased monitoring on session",
		}
		actions = append(actions, action2)
		e.logger.EnableEnhancedLogging()

	case High:
		// High level: Enhanced logging + temporary IP block (1 hour)
		action1 := ResponseAction{
			ActionType:  "enhanced_logging",
			Target:      targetIP,
			Severity:    High,
			Timestamp:   time.Now(),
			Description: "Enhanced logging activated for high-risk activity",
		}
		actions = append(actions, action1)

		action2 := ResponseAction{
			ActionType:  "temporary_ip_block",
			Target:      targetIP,
			Severity:    High,
			Duration:    1 * time.Hour,
			Timestamp:   time.Now(),
			Description: "Temporary IP block for 1 hour",
		}
		actions = append(actions, action2)
		e.ipBlocker.BlockIP(targetIP, 1*time.Hour)

		action3 := ResponseAction{
			ActionType:  "session_termination",
			Target:      sessionID,
			Severity:    High,
			Timestamp:   time.Now(),
			Description: "Session terminated due to high-risk activity",
		}
		actions = append(actions, action3)
		if sessionID != "unknown_session" && sessionID != "" {
			e.sessionManager.TerminateSession(sessionID)
		}

	case Critical:
		// Critical level: All actions including token revocation and extended blocking
		action1 := ResponseAction{
			ActionType:  "enhanced_logging",
			Target:      targetIP,
			Severity:    Critical,
			Timestamp:   time.Now(),
			Description: "Enhanced logging activated for critical-risk activity",
		}
		actions = append(actions, action1)

		action2 := ResponseAction{
			ActionType:  "temporary_ip_block",
			Target:      targetIP,
			Severity:    Critical,
			Duration:    24 * time.Hour, // Much longer for critical
			Timestamp:   time.Now(),
			Description: "Extended IP block for 24 hours",
		}
		actions = append(actions, action2)
		e.ipBlocker.BlockIP(targetIP, 24*time.Hour)

		action3 := ResponseAction{
			ActionType:  "session_termination",
			Target:      sessionID,
			Severity:    Critical,
			Timestamp:   time.Now(),
			Description: "Session terminated due to critical-risk activity",
		}
		actions = append(actions, action3)
		if sessionID != "unknown_session" && sessionID != "" {
			e.sessionManager.TerminateSession(sessionID)
		}

		if token != "" {
			action4 := ResponseAction{
				ActionType:  "token_revocation",
				Target:      token,
				Severity:    Critical,
				Timestamp:   time.Now(),
				Description: "Token revoked due to critical-risk activity",
			}
			actions = append(actions, action4)
			e.tokenRevoker.RevokeToken(token)
		}

		// Additional critical-specific actions
		action5 := ResponseAction{
			ActionType:  "security_alert",
			Target:      targetIP,
			Severity:    Critical,
			Timestamp:   time.Now(),
			Description: "Security team alerted about critical activity",
			AdditionalData: map[string]string{
				"threat_type":       fmt.Sprintf("%v", threatDetails["threat_type"]),
				"attack_path_score": fmt.Sprintf("%v", threatDetails["attack_path_score"]),
				"confidence":        fmt.Sprintf("%v", threatDetails["confidence"]),
			},
		}
		actions = append(actions, action5)
	}

	// Update metrics
	e.metrics.mutex.Lock()
	e.metrics.TotalActionsExecuted += int64(len(actions))
	for _, action := range actions {
		switch action.ActionType {
		case "temporary_ip_block":
			e.metrics.TotalIPBlocks++
		case "session_termination":
			e.metrics.TotalSessionsTerminated++
		case "token_revocation":
			e.metrics.TotalTokensRevoked++
		}
	}
	e.metrics.mutex.Unlock()

	e.recordActions(actions)

	return actions, nil
}

func (e *Engine) recordActions(actions []ResponseAction) {
	if len(actions) == 0 {
		return
	}

	e.mutex.Lock()
	defer e.mutex.Unlock()

	e.actionHistory = append(e.actionHistory, actions...)
	if len(e.actionHistory) > 100 {
		e.actionHistory = e.actionHistory[len(e.actionHistory)-100:]
	}
}

// TerminateSession terminates a specific session
func (sm *SessionManager) TerminateSession(sessionID string) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	delete(sm.sessions, sessionID)
}

// IsSessionActive checks if a session is still active
func (sm *SessionManager) IsSessionActive(sessionID string) bool {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	active, exists := sm.sessions[sessionID]
	return exists && active
}

// AddSession adds a new session to the manager
func (sm *SessionManager) AddSession(sessionID string) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	sm.sessions[sessionID] = true
}

// RevokeToken revokes a specific token
func (tr *TokenRevoker) RevokeToken(token string) {
	tr.mutex.Lock()
	defer tr.mutex.Unlock()

	tr.revokedTokens[token] = true
}

// IsTokenRevoked checks if a token has been revoked
func (tr *TokenRevoker) IsTokenRevoked(token string) bool {
	tr.mutex.RLock()
	defer tr.mutex.RUnlock()

	revoked, exists := tr.revokedTokens[token]
	return exists && revoked
}

// BlockIP temporarily blocks an IP address
func (ib *IPBlocker) BlockIP(ip string, duration time.Duration) {
	ib.mutex.Lock()
	defer ib.mutex.Unlock()

	expiration := time.Now().Add(duration)
	ib.blockedIPs[ip] = expiration
}

// IsIPBlocked checks if an IP is currently blocked
func (ib *IPBlocker) IsIPBlocked(ip string) bool {
	ib.mutex.RLock()
	defer ib.mutex.RUnlock()

	expiration, exists := ib.blockedIPs[ip]
	if !exists {
		return false
	}

	// Check if block has expired
	if time.Now().After(expiration) {
		// Clean up expired block
		delete(ib.blockedIPs, ip)
		return false
	}

	return true
}

// EnableEnhancedLogging enables enhanced logging
func (l *Logger) EnableEnhancedLogging() {
	l.enabled = true
	fmt.Println("[TCELL] Enhanced logging activated")
}

// DisableEnhancedLogging disables enhanced logging
func (l *Logger) DisableEnhancedLogging() {
	l.enabled = false
	fmt.Println("[TCELL] Enhanced logging deactivated")
}

// IsEnhancedLoggingEnabled checks if enhanced logging is enabled
func (l *Logger) IsEnhancedLoggingEnabled() bool {
	return l.enabled
}

// SetEnhancedLogging enables or disables enhanced logging
func (l *Logger) SetEnhancedLogging(enabled bool) {
	l.enabled = enabled
	if enabled {
		fmt.Println("[TCELL] Enhanced logging activated")
	} else {
		fmt.Println("[TCELL] Enhanced logging deactivated")
	}
}

// ProcessThreat processes a threat and triggers appropriate response actions
func (e *Engine) ProcessThreat(ip, sessionID, token string, threatLevel ContainmentLevel, threatDetails map[string]interface{}) ([]ResponseAction, error) {
	// Update metrics
	e.metrics.mutex.Lock()
	e.metrics.TotalThreatsProcessed++
	e.metrics.mutex.Unlock()

	// Log the threat
	fmt.Printf("[TCELL] Processing threat: IP=%s, Session=%s, Level=%d, Details=%v\n",
		ip, sessionID, threatLevel, threatDetails)

	// Execute response actions based on threat level
	actions, err := e.ExecuteResponseActions(threatLevel, ip, sessionID, token, threatDetails)
	if err != nil {
		return nil, fmt.Errorf("failed to execute response actions: %w", err)
	}

	// Log the executed actions
	for _, action := range actions {
		fmt.Printf("[TCELL] Executed action: %s on %s (Severity: %d)\n",
			action.ActionType, action.Target, action.Severity)
	}

	return actions, nil
}

// GetContainmentLevel maps numeric risk scores to containment levels
func GetContainmentLevel(riskScore, confidence float64, threatType string) ContainmentLevel {
	// Add validation for risk score and confidence
	if riskScore < 0 || riskScore > 10 {
		riskScore = 0 // Default to lowest risk
	}
	if confidence < 0 || confidence > 1 {
		confidence = 0.5 // Default to medium confidence
	}

	// High risk score and high confidence = Critical
	if riskScore >= 8.0 && confidence >= 0.9 {
		return Critical
	}

	// Medium-high risk score = High
	if riskScore >= 7.0 {
		return High
	}

	// Low-medium risk score = Medium
	if riskScore >= 4.0 {
		return Medium
	}

	// Otherwise = Low
	return Low
}

// IsIPAllowed checks if an IP is allowed to proceed (not blocked)
func (e *Engine) IsIPAllowed(ip string) bool {
	return !e.ipBlocker.IsIPBlocked(ip)
}

// IsTokenValid checks if a token is still valid (not revoked)
func (e *Engine) IsTokenValid(token string) bool {
	return !e.tokenRevoker.IsTokenRevoked(token)
}

// IsSessionValid checks if a session is still valid (not terminated)
func (e *Engine) IsSessionValid(sessionID string) bool {
	return e.sessionManager.IsSessionActive(sessionID)
}

// CleanupExpiredBlocks removes expired IP blocks
func (e *Engine) CleanupExpiredBlocks() {
	e.ipBlocker.mutex.Lock()
	defer e.ipBlocker.mutex.Unlock()

	now := time.Now()
	for ip, expiration := range e.ipBlocker.blockedIPs {
		if now.After(expiration) {
			delete(e.ipBlocker.blockedIPs, ip)
		}
	}

	// Update metrics
	e.metrics.mutex.Lock()
	e.metrics.ActiveBlocks = int64(len(e.ipBlocker.blockedIPs))
	e.metrics.mutex.Unlock()
}

// GetBlockedIPs returns a list of currently blocked IPs
func (e *Engine) GetBlockedIPs() []string {
	e.ipBlocker.mutex.RLock()
	defer e.ipBlocker.mutex.RUnlock()

	ips := make([]string, 0, len(e.ipBlocker.blockedIPs))
	for ip := range e.ipBlocker.blockedIPs {
		ips = append(ips, ip)
	}
	return ips
}

// GetRevokedTokens returns a list of currently revoked tokens
func (e *Engine) GetRevokedTokens() []string {
	e.tokenRevoker.mutex.RLock()
	defer e.tokenRevoker.mutex.RUnlock()

	tokens := make([]string, 0, len(e.tokenRevoker.revokedTokens))
	for token := range e.tokenRevoker.revokedTokens {
		tokens = append(tokens, token)
	}
	return tokens
}

// GetActiveSessions returns a list of currently active sessions
func (e *Engine) GetActiveSessions() []string {
	e.sessionManager.mutex.RLock()
	defer e.sessionManager.mutex.RUnlock()

	sessions := make([]string, 0, len(e.sessionManager.sessions))
	for sessionID := range e.sessionManager.sessions {
		sessions = append(sessions, sessionID)
	}
	return sessions
}

// GetStats returns statistics about the engine's state
func (e *Engine) GetStats() map[string]int {
	e.ipBlocker.mutex.RLock()
	blockedIPs := len(e.ipBlocker.blockedIPs)
	e.ipBlocker.mutex.RUnlock()

	e.sessionManager.mutex.RLock()
	activeSessions := len(e.sessionManager.sessions)
	e.sessionManager.mutex.RUnlock()

	e.tokenRevoker.mutex.RLock()
	revokedTokens := len(e.tokenRevoker.revokedTokens)
	e.tokenRevoker.mutex.RUnlock()

	return map[string]int{
		"blocked_ips":     blockedIPs,
		"active_sessions": activeSessions,
		"revoked_tokens":  revokedTokens,
	}
}

// GetMetrics returns detailed metrics about the engine's operations
func (e *Engine) GetMetrics() *Metrics {
	e.metrics.mutex.RLock()
	defer e.metrics.mutex.RUnlock()

	// Update active counts
	stats := e.GetStats()
	e.metrics.ActiveBlocks = int64(stats["blocked_ips"])
	e.metrics.ActiveSessions = int64(stats["active_sessions"])
	e.metrics.RevokedTokensCount = int64(stats["revoked_tokens"])

	// Create a copy of metrics to return
	metricsCopy := &Metrics{
		TotalActionsExecuted:    e.metrics.TotalActionsExecuted,
		TotalThreatsProcessed:   e.metrics.TotalThreatsProcessed,
		TotalIPBlocks:           e.metrics.TotalIPBlocks,
		TotalSessionsTerminated: e.metrics.TotalSessionsTerminated,
		TotalTokensRevoked:      e.metrics.TotalTokensRevoked,
		ActiveBlocks:            e.metrics.ActiveBlocks,
		ActiveSessions:          e.metrics.ActiveSessions,
		RevokedTokensCount:      e.metrics.RevokedTokensCount,
	}

	return metricsCopy
}

// GetRecentActions returns a snapshot of recent response actions for dashboards.
func (e *Engine) GetRecentActions() []ResponseAction {
	e.mutex.RLock()
	defer e.mutex.RUnlock()

	actions := make([]ResponseAction, len(e.actionHistory))
	copy(actions, e.actionHistory)
	return actions
}
