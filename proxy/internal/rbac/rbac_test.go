package rbac

import (
	"testing"
	"time"

	"immunisoc-nexus/proxy/internal/opa"
)

func TestRBACManager(t *testing.T) {
	// Create a mock OPA client for testing
	mockOPA := &opa.OpaClient{}
	recertMgr := NewRecertificationManager()
	rbacMgr := NewRBACManager(mockOPA, recertMgr)

	t.Run("CreateSession", func(t *testing.T) {
		session, err := rbacMgr.CreateSession("user123", SecurityAnalyst)
		if err != nil {
			t.Fatalf("Failed to create session: %v", err)
		}

		if session.UserID != "user123" {
			t.Errorf("Expected UserID 'user123', got '%s'", session.UserID)
		}

		if session.Role != SecurityAnalyst {
			t.Errorf("Expected Role SecurityAnalyst, got %v", session.Role)
		}
	})

	t.Run("AuthorizationCheck", func(t *testing.T) {
		session, err := rbacMgr.CreateSession("user456", Auditor)
		if err != nil {
			t.Fatalf("Failed to create session: %v", err)
		}

		// Test authorized access
		authorized, err := rbacMgr.IsAuthorized(session.ID, "read", "/metrics", "monitoring")
		if err != nil {
			t.Fatalf("Authorization check failed: %v", err)
		}

		if !authorized {
			t.Error("Expected access to be authorized")
		}

		// Test unauthorized access
		authorized, err = rbacMgr.IsAuthorized(session.ID, "write", "/admin/access", "maintenance")
		if err != nil {
			t.Fatalf("Authorization check failed: %v", err)
		}

		if authorized {
			t.Error("Expected access to be unauthorized")
		}
	})

	t.Run("JITPermissionRequest", func(t *testing.T) {
		session, err := rbacMgr.CreateSession("user789", BusinessUser)
		if err != nil {
			t.Fatalf("Failed to create session: %v", err)
		}

		perm := []Permission{
			{
				Resource:    "/admin/access",
				Actions:     []string{"read", "write"},
				PurposeTags: []string{"incident_response"},
			},
		}

		jitID, err := rbacMgr.RequestJITPermission(session.ID, "manager123", perm, 30*time.Minute, "Incident response required")
		if err != nil {
			t.Fatalf("Failed to request JIT permission: %v", err)
		}

		// Approve the JIT request
		err = rbacMgr.ApproveJITPermission(jitID, "manager123")
		if err != nil {
			t.Fatalf("Failed to approve JIT permission: %v", err)
		}

		// Test access with JIT permissions
		authorized, err := rbacMgr.IsAuthorized(session.ID, "write", "/admin/access", "incident_response")
		if err != nil {
			t.Fatalf("Authorization check failed: %v", err)
		}

		if !authorized {
			t.Error("Expected access to be authorized with JIT permissions")
		}
	})

	t.Run("ExpiredSession", func(t *testing.T) {
		session, err := rbacMgr.CreateSession("user999", SecurityAnalyst)
		if err != nil {
			t.Fatalf("Failed to create session: %v", err)
		}

		// Manually expire the session for testing
		session.ExpiresAt = time.Now().Add(-1 * time.Hour)

		authorized, err := rbacMgr.IsAuthorized(session.ID, "read", "/metrics", "monitoring")
		if err == nil {
			t.Error("Expected error for expired session")
		}

		if authorized {
			t.Error("Expected access to be denied for expired session")
		}
	})
}

func TestRecertificationManager(t *testing.T) {
	recertMgr := NewRecertificationManager()

	t.Run("ScheduleCertification", func(t *testing.T) {
		certID, err := recertMgr.ScheduleCertification("user111", SystemAdministrator, "manager222", 30)
		if err != nil {
			t.Fatalf("Failed to schedule certification: %v", err)
		}

		if certID == "" {
			t.Error("Expected certification ID to be generated")
		}
	})

	t.Run("ApproveCertification", func(t *testing.T) {
		certID, err := recertMgr.ScheduleCertification("user333", IncidentResponder, "manager444", 60)
		if err != nil {
			t.Fatalf("Failed to schedule certification: %v", err)
		}

		err = recertMgr.ApproveCertification(certID, "manager444", "Approved for incident response role")
		if err != nil {
			t.Fatalf("Failed to approve certification: %v", err)
		}

		// Get the certification to verify status
		recertMgr.RLock()
		cert, exists := recertMgr.certifications[certID]
		recertMgr.RUnlock()

		if !exists {
			t.Fatal("Certification not found after approval")
		}

		if cert.Status != Approved {
			t.Errorf("Expected status Approved, got %v", cert.Status)
		}
	})

	t.Run("RejectCertification", func(t *testing.T) {
		certID, err := recertMgr.ScheduleCertification("user555", SystemAdministrator, "manager666", 90)
		if err != nil {
			t.Fatalf("Failed to schedule certification: %v", err)
		}

		err = recertMgr.RejectCertification(certID, "manager666", "User no longer requires admin access")
		if err != nil {
			t.Fatalf("Failed to reject certification: %v", err)
		}

		// Get the certification to verify status
		recertMgr.RLock()
		cert, exists := recertMgr.certifications[certID]
		recertMgr.RUnlock()

		if !exists {
			t.Fatal("Certification not found after rejection")
		}

		if cert.Status != Rejected {
			t.Errorf("Expected status Rejected, got %v", cert.Status)
		}
	})
}
