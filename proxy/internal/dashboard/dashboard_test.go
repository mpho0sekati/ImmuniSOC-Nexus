package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
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

func TestDashboardCreation(t *testing.T) {
	bt := bloodhound.NewTracker()
	cf := &classification.Classifier{}
	dg := deception.NewGenerator("test-secret")  // Providing required parameter
	hm := &hardening.HardeningManager{}
	msm := microseg.NewMicrosegmentationManager(func(msg string) {})
	il := monocyte.NewMonocyteLogger("./test.log", "test-secret")
	oc := opa.NewOpaClient()
	te := tcell.NewEngine()
	rm := rbac.NewRBACManager(oc, nil)  // Providing required recertification manager

	dashboard := NewDashboard(bt, cf, dg, hm, msm, il, oc, te, rm)

	if dashboard == nil {
		t.Fatal("Expected dashboard to be created, got nil")
	}
}

func TestDashboardAPIEndpoints(t *testing.T) {
	bt := bloodhound.NewTracker()
	cf := &classification.Classifier{}
	dg := deception.NewGenerator("test-secret")  // Providing required parameter
	hm := &hardening.HardeningManager{}
	msm := microseg.NewMicrosegmentationManager(func(msg string) {})
	il := monocyte.NewMonocyteLogger("./test.log", "test-secret")
	oc := opa.NewOpaClient()
	te := tcell.NewEngine()
	rm := rbac.NewRBACManager(oc, nil)  // Providing required recertification manager

	dashboard := NewDashboard(bt, cf, dg, hm, msm, il, oc, te, rm)
	handler := dashboard.Handler()

	t.Run("Dashboard Data Endpoint", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/dashboard", nil)
		w := httptest.NewRecorder()
		
		handler.ServeHTTP(w, req)
		
		if w.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
		}
		
		if w.Header().Get("Content-Type") != "application/json" {
			t.Errorf("Expected Content-Type application/json, got %s", w.Header().Get("Content-Type"))
		}
		
		var data DashboardData
		if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
			t.Errorf("Failed to unmarshal dashboard data: %v", err)
		}
		
		// Verify structure
		if data.Version == "" {
			t.Error("Expected version to be set")
		}
		
		if data.Metrics.EncryptionStatus == "" {
			t.Error("Expected encryption status to be set")
		}
	})

	t.Run("Metrics Endpoint", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/metrics", nil)
		w := httptest.NewRecorder()
		
		handler.ServeHTTP(w, req)
		
		if w.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
		}
		
		var metrics SecurityMetrics
		if err := json.Unmarshal(w.Body.Bytes(), &metrics); err != nil {
			t.Errorf("Failed to unmarshal metrics: %v", err)
		}
		
		if metrics.EncryptionStatus == "" {
			t.Error("Expected encryption status to be set")
		}
	})

	t.Run("Health Endpoint", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/health", nil)
		w := httptest.NewRecorder()
		
		handler.ServeHTTP(w, req)
		
		if w.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
		}
		
		var health map[string]interface{}
		if err := json.Unmarshal(w.Body.Bytes(), &health); err != nil {
			t.Errorf("Failed to unmarshal health: %v", err)
		}
		
		status, ok := health["status"]
		if !ok || status != "healthy" {
			t.Error("Expected health status to be 'healthy'")
		}
	})

	t.Run("Method Not Allowed", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/metrics", nil)
		w := httptest.NewRecorder()
		
		handler.ServeHTTP(w, req)
		
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("Expected status %d, got %d", http.StatusMethodNotAllowed, w.Code)
		}
	})
}

func TestDashboardMetricsUpdate(t *testing.T) {
	bt := bloodhound.NewTracker()
	cf := &classification.Classifier{}
	dg := deception.NewGenerator("test-secret")  // Providing required parameter
	hm := &hardening.HardeningManager{}
	msm := microseg.NewMicrosegmentationManager(func(msg string) {})
	il := monocyte.NewMonocyteLogger("./test.log", "test-secret")
	oc := opa.NewOpaClient()
	te := tcell.NewEngine()
	rm := rbac.NewRBACManager(oc, nil)  // Providing required recertification manager

	dashboard := NewDashboard(bt, cf, dg, hm, msm, il, oc, te, rm)

	// Simulate some metrics updates
	dashboard.updateMetrics()

	// Verify metrics are populated
	dashboard.mutex.RLock()
	metrics := dashboard.securityMetrics
	dashboard.mutex.RUnlock()

	if metrics.EncryptionStatus == "" {
		t.Error("Expected encryption status to be set after update")
	}

	if metrics.ComplianceStatus == "" {
		t.Error("Expected compliance status to be set after update")
	}

	if metrics.LastUpdate.IsZero() {
		t.Error("Expected last update to be set after update")
	}
}

func TestCalculateRiskScore(t *testing.T) {
	bt := bloodhound.NewTracker()
	cf := &classification.Classifier{}
	dg := deception.NewGenerator("test-secret")  // Providing required parameter
	hm := &hardening.HardeningManager{}
	msm := microseg.NewMicrosegmentationManager(func(msg string) {})
	il := monocyte.NewMonocyteLogger("./test.log", "test-secret")
	oc := opa.NewOpaClient()
	te := tcell.NewEngine()
	rm := rbac.NewRBACManager(oc, nil)  // Providing required recertification manager

	dashboard := NewDashboard(bt, cf, dg, hm, msm, il, oc, te, rm)

	// Test risk score calculation with default metrics
	score := dashboard.calculateRiskScore()

	if score < 0 || score > 100 {
		t.Errorf("Expected risk score between 0-100, got %f", score)
	}

	// Update metrics to have some threats and test again
	dashboard.mutex.Lock()
	dashboard.securityMetrics.ActiveThreats = 5
	dashboard.securityMetrics.BlockedRequests = 10
	dashboard.mutex.Unlock()

	newScore := dashboard.calculateRiskScore()

	if newScore < 0 || newScore > 100 {
		t.Errorf("Expected risk score between 0-100 with threats, got %f", newScore)
	}
}

func TestIsValidOrigin(t *testing.T) {
	tests := []struct {
		name     string
		origin   string
		expected bool
	}{
		{"Valid localhost", "http://localhost:3000", true},
		{"Valid local IP", "http://127.0.0.1:3000", true},
		{"Valid HTTPS", "https://dashboard.immunisoc-nexus.local", true},
		{"Invalid origin", "http://malicious.com", false},
		{"Partial match", "http://localhost:3001", false}, // Should not match localhost:3000
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidOrigin(tt.origin)
			if result != tt.expected {
				t.Errorf("isValidOrigin(%q) = %v, want %v", tt.origin, result, tt.expected)
			}
		})
	}
}

func TestDashboardDataStructure(t *testing.T) {
	bt := bloodhound.NewTracker()
	cf := &classification.Classifier{}
	dg := deception.NewGenerator("test-secret")  // Providing required parameter
	hm := &hardening.HardeningManager{}
	msm := microseg.NewMicrosegmentationManager(func(msg string) {})
	il := monocyte.NewMonocyteLogger("./test.log", "test-secret")
	oc := opa.NewOpaClient()
	te := tcell.NewEngine()
	rm := rbac.NewRBACManager(oc, nil)  // Providing required recertification manager

	dashboard := NewDashboard(bt, cf, dg, hm, msm, il, oc, te, rm)

	data := dashboard.GetDashboardData()  // Changed from getDashboardData to GetDashboardData

	if data == nil {
		t.Fatal("Expected dashboard data to be returned, got nil")
	}

	// Verify all required fields are present
	if data.Version == "" {
		t.Error("Expected version to be set in dashboard data")
	}

	if data.Timestamp.IsZero() {
		t.Error("Expected timestamp to be set in dashboard data")
	}

	if data.Metrics.EncryptionStatus == "" {
		t.Error("Expected encryption status to be set in dashboard data")
	}

	if data.SecurityStats == nil {
		t.Error("Expected security stats to be set in dashboard data")
	}

	if data.Compliance.POPIAStatus == "" {
		t.Error("Expected compliance status to be set in dashboard data")
	}
}

// TestGetDashboardData tests the GetDashboardData method
func TestGetDashboardData(t *testing.T) {
	// Create a mock dashboard with actual implementations
	bt := bloodhound.NewTracker()
	cf := &classification.Classifier{}
	dg := deception.NewGenerator("test-secret")
	hm := &hardening.HardeningManager{}
	msm := microseg.NewMicrosegmentationManager(func(msg string) {})
	il := monocyte.NewMonocyteLogger("./test.log", "test-secret")
	oc := opa.NewOpaClient()
	te := tcell.NewEngine()
	rm := rbac.NewRBACManager(oc, nil)

	dashboard := NewDashboard(
		bt,
		cf,
		dg,
		hm,
		msm,
		il,
		oc,
		te,
		rm,
	)

	// Start collecting metrics in the background
	go dashboard.collectMetrics()

	// Give it a moment to initialize
	time.Sleep(100 * time.Millisecond)

	// Call the public method
	data := dashboard.GetDashboardData()

	// Verify the data is not nil
	if data == nil {
		t.Fatal("Expected dashboard data, got nil")
	}

	// Verify basic fields are populated
	if data.Version != "1.0.0" {
		t.Errorf("Expected version 1.0.0, got %s", data.Version)
	}

	if data.Timestamp.IsZero() {
		t.Error("Expected timestamp to be set")
	}
}
