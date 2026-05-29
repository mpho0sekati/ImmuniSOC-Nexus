package rbac

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"immunisoc-nexus/proxy/internal/opa"
)

// UserRole represents different user roles in the system
type UserRole int

const (
	Auditor UserRole = iota
	SecurityAnalyst
	SystemAdministrator
	IncidentResponder
	BusinessUser
)

// Permission represents specific permissions for each role
type Permission struct {
	Resource    string   // Resource being accessed (e.g., /api/logs, /admin/users)
	Actions     []string // Allowed actions (e.g., ["read", "write", "delete"])
	PurposeTags []string // POPIA purpose tags (e.g., ["analytics", "support", "compliance"])
}

// RoleDefinition defines the permissions for a role
type RoleDefinition struct {
	Role               UserRole
	Name               string
	Permissions        []Permission
	MaxSessionDuration time.Duration // Maximum allowed session duration
}

// JITPermission represents temporary elevated permissions
type JITPermission struct {
	UserID      string
	RequesterID string
	Permissions []Permission
	RequestedAt time.Time
	ExpiresAt   time.Time
	Approved    bool
	ApprovedBy  string
	Reason      string
}

// Session represents a user session with its permissions
type Session struct {
	ID          string
	UserID      string
	Role        UserRole
	Permissions []Permission
	CreatedAt   time.Time
	ExpiresAt   time.Time
	JITApplied  []JITPermission // Currently active JIT permissions
}

// RBACManager manages role-based access control
type RBACManager struct {
	roles          map[UserRole]RoleDefinition
	sessions       map[string]*Session
	jitPermissions map[string]*JITPermission
	recertManager  *RecertificationManager
	opaClient      *opa.OpaClient
	mutex          sync.RWMutex
}

// NewRBACManager creates a new RBAC manager
func NewRBACManager(opaClient *opa.OpaClient, recertMgr *RecertificationManager) *RBACManager {
	manager := &RBACManager{
		roles:          make(map[UserRole]RoleDefinition),
		sessions:       make(map[string]*Session),
		jitPermissions: make(map[string]*JITPermission),
		recertManager:  recertMgr,
		opaClient:      opaClient,
	}

	// Initialize default roles
	manager.initDefaultRoles()

	return manager
}

// initDefaultRoles initializes the default roles and their permissions
func (rm *RBACManager) initDefaultRoles() {
	rm.roles[Auditor] = RoleDefinition{
		Role:               Auditor,
		Name:               "Auditor",
		MaxSessionDuration: 8 * time.Hour,
		Permissions: []Permission{
			{
				Resource:    "/metrics",
				Actions:     []string{"read"},
				PurposeTags: []string{"compliance", "monitoring"},
			},
			{
				Resource:    "/api/paths",
				Actions:     []string{"read"},
				PurposeTags: []string{"compliance", "auditing"},
			},
			{
				Resource:    "/api/timeline",
				Actions:     []string{"read"},
				PurposeTags: []string{"compliance", "auditing"},
			},
			{
				Resource:    "/verify-log",
				Actions:     []string{"read"},
				PurposeTags: []string{"compliance", "forensics"},
			},
			{
				Resource:    "/popia-report",
				Actions:     []string{"read"},
				PurposeTags: []string{"compliance", "popia"},
			},
		},
	}

	rm.roles[SecurityAnalyst] = RoleDefinition{
		Role:               SecurityAnalyst,
		Name:               "Security Analyst",
		MaxSessionDuration: 8 * time.Hour,
		Permissions: []Permission{
			{
				Resource:    "/metrics",
				Actions:     []string{"read"},
				PurposeTags: []string{"monitoring", "analysis"},
			},
			{
				Resource:    "/api/paths",
				Actions:     []string{"read", "analyze"},
				PurposeTags: []string{"analysis", "threat_intel"},
			},
			{
				Resource:    "/api/timeline",
				Actions:     []string{"read", "analyze"},
				PurposeTags: []string{"analysis", "response"},
			},
			{
				Resource:    "/api/threats",
				Actions:     []string{"read", "analyze"},
				PurposeTags: []string{"analysis", "response"},
			},
			{
				Resource:    "/admin/access",
				Actions:     []string{"read"},
				PurposeTags: []string{"analysis", "access_control"},
			},
		},
	}

	rm.roles[SystemAdministrator] = RoleDefinition{
		Role:               SystemAdministrator,
		Name:               "System Administrator",
		MaxSessionDuration: 4 * time.Hour,
		Permissions: []Permission{
			{
				Resource:    "/admin/*",
				Actions:     []string{"read", "write", "delete"},
				PurposeTags: []string{"maintenance", "configuration"},
			},
			{
				Resource:    "/api/*",
				Actions:     []string{"read", "write"},
				PurposeTags: []string{"configuration", "maintenance"},
			},
			{
				Resource:    "/config/*",
				Actions:     []string{"read", "write", "delete"},
				PurposeTags: []string{"configuration", "maintenance"},
			},
		},
	}

	rm.roles[IncidentResponder] = RoleDefinition{
		Role:               IncidentResponder,
		Name:               "Incident Responder",
		MaxSessionDuration: 2 * time.Hour,
		Permissions: []Permission{
			{
				Resource:    "/api/threats",
				Actions:     []string{"read", "act"},
				PurposeTags: []string{"incident_response", "containment"},
			},
			{
				Resource:    "/admin/access",
				Actions:     []string{"read", "modify"},
				PurposeTags: []string{"incident_response", "containment"},
			},
			{
				Resource:    "/tcell/*",
				Actions:     []string{"read", "act"},
				PurposeTags: []string{"incident_response", "containment"},
			},
			{
				Resource:    "/metrics",
				Actions:     []string{"read"},
				PurposeTags: []string{"incident_response", "monitoring"},
			},
		},
	}

	rm.roles[BusinessUser] = RoleDefinition{
		Role:               BusinessUser,
		Name:               "Business User",
		MaxSessionDuration: 12 * time.Hour,
		Permissions: []Permission{
			{
				Resource:    "/api/data",
				Actions:     []string{"read"},
				PurposeTags: []string{"business_operations", "analytics"},
			},
			{
				Resource:    "/api/reports",
				Actions:     []string{"read"},
				PurposeTags: []string{"business_operations", "analytics"},
			},
		},
	}
}

// CreateSession creates a new user session based on role
func (rm *RBACManager) CreateSession(userID string, role UserRole) (*Session, error) {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()

	definition, exists := rm.roles[role]
	if !exists {
		return nil, fmt.Errorf("invalid role: %v", role)
	}

	sessionID := generateSessionID() // Assume this function exists
	expiresAt := time.Now().Add(definition.MaxSessionDuration)

	session := &Session{
		ID:          sessionID,
		UserID:      userID,
		Role:        role,
		Permissions: definition.Permissions,
		CreatedAt:   time.Now(),
		ExpiresAt:   expiresAt,
		JITApplied:  make([]JITPermission, 0),
	}

	rm.sessions[sessionID] = session

	return session, nil
}

// IsAuthorized checks if a user has permission to perform an action on a resource
func (rm *RBACManager) IsAuthorized(sessionID, action, resource string, purpose string) (bool, error) {
	rm.mutex.RLock()
	defer rm.mutex.RUnlock()

	session, exists := rm.sessions[sessionID]
	if !exists {
		return false, fmt.Errorf("session not found: %s", sessionID)
	}

	// Check if session is expired
	if time.Now().After(session.ExpiresAt) {
		return false, fmt.Errorf("session expired")
	}

	// Privilege Creep Prevention: Check if high-privilege roles have active recertification
	if session.Role == SystemAdministrator || session.Role == IncidentResponder {
		if !rm.isRecertified(session.UserID, session.Role) {
			return false, fmt.Errorf("access denied: periodic recertification required for role")
		}
	}

	// Combine regular permissions with JIT permissions
	allPermissions := session.Permissions
	for _, jitPerm := range session.JITApplied {
		if time.Now().Before(jitPerm.ExpiresAt) && jitPerm.Approved {
			allPermissions = append(allPermissions, jitPerm.Permissions...)
		}
	}

	// Check against each permission
	for _, perm := range allPermissions {
		if matchesResource(resource, perm.Resource) {
			for _, allowedAction := range perm.Actions {
				if allowedAction == action || allowedAction == "*" {
					// Check POPIA compliance - verify purpose is allowed
					if purpose != "" {
						for _, allowedPurpose := range perm.PurposeTags {
							if allowedPurpose == purpose {
								return true, nil
							}
						}
						// If purpose is specified but not in allowed purposes, check with OPA
						opaResult, err := rm.checkOPAPolicy(session.UserID, action, resource, purpose)
						if err != nil {
							return false, err
						}
						return opaResult, nil
					}
					return true, nil
				}
			}
		}
	}

	return false, nil
}

// isRecertified checks if a user has an approved recertification for their role
func (rm *RBACManager) isRecertified(userID string, role UserRole) bool {
	if rm.recertManager == nil {
		return true // Default to true if manager not initialized
	}

	rm.recertManager.RLock()
	defer rm.recertManager.RUnlock()
	for _, cert := range rm.recertManager.certifications {
		if cert.UserID == userID && cert.Role == role && cert.Status == Approved {
			return true
		}
	}
	return false
}

// checkOPAPolicy checks with OPA if access should be granted based on business context
func (rm *RBACManager) checkOPAPolicy(userID, action, resource, purpose string) (bool, error) {
	input := map[string]interface{}{
		"user_id":      userID,
		"action":       action,
		"resource":     resource,
		"purpose":      purpose,
		"current_time": time.Now().Unix(),
	}

	return rm.opaClient.CheckPolicy(input)
}

// matchesResource checks if a resource matches a permission resource pattern
func matchesResource(requested, allowed string) bool {
	if allowed == "*" {
		return true
	}

	// Handle wildcard patterns like /api/*
	if len(allowed) > 2 && allowed[len(allowed)-2:] == "/*" {
		prefix := allowed[:len(allowed)-2]
		return requested == prefix || len(requested) > len(prefix) && requested[:len(prefix)] == prefix
	}

	return requested == allowed
}

// RequestJITPermission requests temporary elevated permissions
func (rm *RBACManager) RequestJITPermission(userID, requesterID string, permissions []Permission, duration time.Duration, reason string) (string, error) {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()

	jitID := generateJITID() // Assume this function exists

	jitPermission := &JITPermission{
		UserID:      userID,
		RequesterID: requesterID,
		Permissions: permissions,
		RequestedAt: time.Now(),
		ExpiresAt:   time.Now().Add(duration),
		Approved:    false, // Needs approval
		Reason:      reason,
	}

	rm.jitPermissions[jitID] = jitPermission

	return jitID, nil
}

// ApproveJITPermission approves a JIT permission request
func (rm *RBACManager) ApproveJITPermission(jitID, approverID string) error {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()

	jitPerm, exists := rm.jitPermissions[jitID]
	if !exists {
		return fmt.Errorf("JIT permission request not found: %s", jitID)
	}

	// Separation of Duties: Ensure requester is not the approver
	if jitPerm.UserID == approverID {
		return fmt.Errorf("separation of duties violation: users cannot approve their own JIT requests")
	}

	jitPerm.Approved = true
	jitPerm.ApprovedBy = approverID

	// Add to user's active JIT permissions
	session, exists := rm.sessions[jitPerm.UserID]
	if exists {
		session.JITApplied = append(session.JITApplied, *jitPerm)
	}

	return nil
}

// CleanupExpiredSessions removes expired sessions and JIT permissions
func (rm *RBACManager) CleanupExpiredSessions() {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()

	now := time.Now()

	// Clean up expired sessions
	for id, session := range rm.sessions {
		if now.After(session.ExpiresAt) {
			delete(rm.sessions, id)
		}
	}

	// Clean up expired JIT permissions
	for id, jitPerm := range rm.jitPermissions {
		if now.After(jitPerm.ExpiresAt) {
			delete(rm.jitPermissions, id)

			// Remove from any active sessions
			for _, session := range rm.sessions {
				newJITApplied := make([]JITPermission, 0)
				for _, applied := range session.JITApplied {
					// Compare key fields rather than the entire struct
					if applied.UserID != jitPerm.UserID ||
						applied.RequesterID != jitPerm.RequesterID ||
						!applied.RequestedAt.Equal(jitPerm.RequestedAt) ||
						applied.Reason != jitPerm.Reason {
						newJITApplied = append(newJITApplied, applied)
					}
				}
				session.JITApplied = newJITApplied
			}
		}
	}
}

// RBACMiddleware enforces least privilege by evaluating role, purpose, and JIT status
func (rm *RBACManager) RBACMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sessionID := r.Header.Get("X-Session-ID")
		purpose := r.Header.Get("X-PopIA-Purpose")

		if sessionID == "" {
			http.Error(w, "Authentication session required", http.StatusUnauthorized)
			return
		}

		// Map HTTP methods to RBAC actions
		action := "read"
		switch r.Method {
		case "POST", "PUT", "PATCH":
			action = "write"
		case "DELETE":
			action = "delete"
		default:
			action = "read"
		}

		// Runtime Least Privilege Enforcement
		authorized, err := rm.IsAuthorized(sessionID, action, r.URL.Path, purpose)
		if err != nil || !authorized {
			logMessage := fmt.Sprintf("Access Denied: User in session %s attempted %s on %s with purpose %s", sessionID, action, r.URL.Path, purpose)
			fmt.Println(logMessage)
			http.Error(w, "Access denied: insufficient privileges or purpose mismatch", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// StartCleanupRoutine starts a background routine to clean up expired sessions
func (rm *RBACManager) StartCleanupRoutine() {
	ticker := time.NewTicker(5 * time.Minute)
	go func() {
		for range ticker.C {
			rm.CleanupExpiredSessions()
		}
	}()
}

// GetRoleName returns the name of a role
func (rm *RBACManager) GetRoleName(role UserRole) string {
	def, exists := rm.roles[role]
	if !exists {
		return "Unknown"
	}
	return def.Name
}

// HasPermission checks if a role has the required permissions (simplified role check)
func HasPermission(userRole, requiredRole UserRole) bool {
	if userRole == SystemAdministrator {
		return true // Admins have all permissions
	}
	return userRole == requiredRole
}

// Helper function to generate session IDs (implementation would use crypto/rand)
func generateSessionID() string {
	// In a real implementation, this would generate a secure random session ID
	return fmt.Sprintf("sess_%d", time.Now().UnixNano())
}

// Helper function to generate JIT IDs
func generateJITID() string {
	// In a real implementation, this would generate a secure random JIT ID
	return fmt.Sprintf("jit_%d", time.Now().UnixNano())
}
