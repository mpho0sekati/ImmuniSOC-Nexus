package tcell

import (
	"testing"
	"time"
)

func TestNewEngine(t *testing.T) {
	engine := NewEngine()
	if engine == nil {
		t.Fatal("Expected engine to be created, got nil")
	}
	
	// Give time for cleanup goroutine to start
	time.Sleep(10 * time.Millisecond)
}

func TestGetContainmentLevel(t *testing.T) {
	tests := []struct {
		name     string
		risk     float64
		conf     float64
		expected ContainmentLevel
	}{
		{"High risk high confidence", 9.0, 0.95, Critical},
		{"High risk low confidence", 9.0, 0.5, High},
		{"Medium risk", 7.0, 0.7, High},
		{"Low medium risk", 5.0, 0.6, Medium},
		{"Low risk", 2.0, 0.5, Low},
		{"Out of bounds risk", 15.0, 0.9, Low}, // Should default to low risk
		{"Out of bounds confidence", 8.0, 1.5, High}, // Should default to medium confidence (0.5) but risk 8.0 gives High
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetContainmentLevel(tt.risk, tt.conf, "test")
			if result != tt.expected {
				t.Errorf("Expected %d, got %d", tt.expected, result)
			}
		})
	}
}

func TestEngineProcessThreat(t *testing.T) {
	engine := NewEngine()
	
	threatDetails := map[string]interface{}{
		"threat_type":       "test",
		"attack_path_score": 8.0,
		"confidence":        0.9,
	}
	
	actions, err := engine.ProcessThreat("192.168.1.1", "session123", "token123", Critical, threatDetails)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	
	if len(actions) == 0 {
		t.Error("Expected at least one action for critical threat")
	}
	
	// Check that metrics were updated
	metrics := engine.GetMetrics()
	if metrics.TotalThreatsProcessed == 0 {
		t.Error("Expected threat count to be incremented")
	}
}

func TestIPBlocking(t *testing.T) {
	engine := NewEngine()
	
	ip := "192.168.1.100"
	
	// Initially should be allowed
	if !engine.IsIPAllowed(ip) {
		t.Error("Expected IP to be allowed initially")
	}
	
	// Block the IP
	engine.ipBlocker.BlockIP(ip, 1*time.Hour)
	
	// Should be blocked now
	if engine.IsIPAllowed(ip) {
		t.Error("Expected IP to be blocked after blocking")
	}
	
	// Check using internal method
	if !engine.ipBlocker.IsIPBlocked(ip) {
		t.Error("Expected IP to be blocked internally")
	}
}

func TestTokenRevocation(t *testing.T) {
	engine := NewEngine()
	
	token := "test-token-123"
	
	// Initially should be valid
	if !engine.IsTokenValid(token) {
		t.Error("Expected token to be valid initially")
	}
	
	// Revoke the token
	engine.tokenRevoker.RevokeToken(token)
	
	// Should be invalid now
	if engine.IsTokenValid(token) {
		t.Error("Expected token to be invalid after revocation")
	}
	
	// Check using internal method
	if !engine.tokenRevoker.IsTokenRevoked(token) {
		t.Error("Expected token to be revoked internally")
	}
}

func TestSessionManagement(t *testing.T) {
	engine := NewEngine()
	
	sessionID := "test-session-456"
	
	// Initially should be invalid
	if engine.IsSessionValid(sessionID) {
		t.Error("Expected session to be invalid initially")
	}
	
	// Add the session
	engine.sessionManager.AddSession(sessionID)
	
	// Should be valid now
	if !engine.IsSessionValid(sessionID) {
		t.Error("Expected session to be valid after adding")
	}
	
	// Terminate the session
	engine.sessionManager.TerminateSession(sessionID)
	
	// Should be invalid again
	if engine.IsSessionValid(sessionID) {
		t.Error("Expected session to be invalid after termination")
	}
}

func TestCleanupExpiredBlocks(t *testing.T) {
	engine := NewEngine()
	
	// This test is tricky since we need expired blocks
	// For now, just call the method to ensure it doesn't panic
	engine.CleanupExpiredBlocks()
}

func TestGetStats(t *testing.T) {
	engine := NewEngine()
	
	// Add some test data
	engine.ipBlocker.BlockIP("192.168.1.200", 1*time.Hour)
	engine.sessionManager.AddSession("test-session-stats")
	engine.tokenRevoker.RevokeToken("test-token-stats")
	
	stats := engine.GetStats()
	
	if stats["blocked_ips"] == 0 {
		t.Error("Expected blocked IPs in stats")
	}
	
	if stats["active_sessions"] == 0 {
		t.Error("Expected active sessions in stats")
	}
	
	if stats["revoked_tokens"] == 0 {
		t.Error("Expected revoked tokens in stats")
	}
}

func TestGetMetrics(t *testing.T) {
	engine := NewEngine()
	
	metrics := engine.GetMetrics()
	
	if metrics == nil {
		t.Fatal("Expected metrics to be returned")
	}
	
	// Process a threat to increment the counter
	engine.ProcessThreat("192.168.1.1", "session1", "token1", Low, map[string]interface{}{})
	
	metrics = engine.GetMetrics()
	
	if metrics.TotalThreatsProcessed == 0 {
		t.Error("Expected threat count to be incremented in metrics")
	}
}