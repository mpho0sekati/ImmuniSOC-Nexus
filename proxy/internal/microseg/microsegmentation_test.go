package microseg

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMicrosegmentationManager_CreateSegment(t *testing.T) {
	logger := func(msg string) {} // No-op logger for tests
	manager := NewMicrosegmentationManager(logger)

	// Test successful creation
	tags := map[string]string{"environment": "production", "team": "backend"}
	segment, err := manager.CreateSegment("web-segment", "Web servers segment", tags)
	if err != nil {
		t.Fatalf("CreateSegment failed: %v", err)
	}

	if segment.ID == "" {
		t.Error("Expected segment ID to be set")
	}

	if segment.Name != "web-segment" {
		t.Errorf("Expected name 'web-segment', got '%s'", segment.Name)
	}

	if segment.Description != "Web servers segment" {
		t.Errorf("Expected description 'Web servers segment', got '%s'", segment.Description)
	}

	if len(segment.Tags) != 2 {
		t.Errorf("Expected 2 tags, got %d", len(segment.Tags))
	}

	// Test duplicate name
	_, err = manager.CreateSegment("web-segment", "Another segment", nil)
	if err == nil {
		t.Error("Expected error for duplicate name")
	}

	// Test empty name
	_, err = manager.CreateSegment("", "Empty name segment", nil)
	if err == nil {
		t.Error("Expected error for empty name")
	}
}

func TestMicrosegmentationManager_AddRemoveMembers(t *testing.T) {
	logger := func(msg string) {} // No-op logger for tests
	manager := NewMicrosegmentationManager(logger)

	segment, err := manager.CreateSegment("test-segment", "Test segment", nil)
	if err != nil {
		t.Fatalf("CreateSegment failed: %v", err)
	}

	// Add member
	err = manager.AddMember(segment.ID, "192.168.1.10")
	if err != nil {
		t.Fatalf("AddMember failed: %v", err)
	}

	if !segment.Members["192.168.1.10"] {
		t.Error("Member was not added to segment")
	}

	// Remove member
	err = manager.RemoveMember(segment.ID, "192.168.1.10")
	if err != nil {
		t.Fatalf("RemoveMember failed: %v", err)
	}

	if segment.Members["192.168.1.10"] {
		t.Error("Member was not removed from segment")
	}

	// Try to remove non-existent member
	err = manager.RemoveMember(segment.ID, "192.168.1.10")
	if err != nil {
		t.Errorf("RemoveMember should not return error for non-existent member: %v", err)
	}
}

func TestMicrosegmentationManager_AddPolicy(t *testing.T) {
	logger := func(msg string) {} // No-op logger for tests
	manager := NewMicrosegmentationManager(logger)

	segment, err := manager.CreateSegment("test-segment", "Test segment", nil)
	if err != nil {
		t.Fatalf("CreateSegment failed: %v", err)
	}

	policy := Policy{
		Name:        "allow-web-traffic",
		Action:      "allow",
		Source:      []string{"192.168.1.0/24"},
		Destination: []string{"10.0.0.0/24"},
		Protocol:    []string{"tcp"},
		Port:        []int{80, 443},
		Priority:    10,
		Enabled:     true,
	}

	err = manager.AddPolicy(segment.ID, policy)
	if err != nil {
		t.Fatalf("AddPolicy failed: %v", err)
	}

	if len(segment.Policies) != 1 {
		t.Fatalf("Expected 1 policy, got %d", len(segment.Policies))
	}

	if segment.Policies[0].Name != "allow-web-traffic" {
		t.Errorf("Expected policy name 'allow-web-traffic', got '%s'", segment.Policies[0].Name)
	}

	if segment.Policies[0].Action != "allow" {
		t.Errorf("Expected policy action 'allow', got '%s'", segment.Policies[0].Action)
	}
}

func TestMicrosegmentationManager_IsAccessAllowed(t *testing.T) {
	logger := func(msg string) {} // No-op logger for tests
	manager := NewMicrosegmentationManager(logger)

	// Create two segments
	webSeg, err := manager.CreateSegment("web", "Web servers", nil)
	if err != nil {
		t.Fatalf("CreateSegment failed: %v", err)
	}

	dbSeg, err := manager.CreateSegment("db", "Database servers", nil)
	if err != nil {
		t.Fatalf("CreateSegment failed: %v", err)
	}

	// Add members to segments
	manager.AddMember(webSeg.ID, "192.168.1.10")
	manager.AddMember(dbSeg.ID, "10.0.0.10")

	// Add policy to allow web to DB traffic
	policy := Policy{
		Name:        "web-to-db",
		Action:      "allow",
		Source:      []string{"192.168.1.10"},
		Destination: []string{"10.0.0.10"},
		Protocol:    []string{"tcp"},
		Port:        []int{3306},
		Priority:    10,
		Enabled:     true,
	}
	manager.AddPolicy(webSeg.ID, policy)

	// Test allowed access
	allowed, reason, err := manager.IsAccessAllowed("192.168.1.10", "10.0.0.10", "tcp", 3306)
	if err != nil {
		t.Fatalf("IsAccessAllowed failed: %v", err)
	}

	if !allowed {
		t.Errorf("Expected access to be allowed, got denied. Reason: %s", reason)
	}

	// Test denied access (wrong port)
	allowed, reason, err = manager.IsAccessAllowed("192.168.1.10", "10.0.0.10", "tcp", 80)
	if err != nil {
		t.Fatalf("IsAccessAllowed failed: %v", err)
	}

	if allowed {
		t.Errorf("Expected access to be denied on wrong port, got allowed. Reason: %s", reason)
	}

	// Test denied access (wrong source IP) - this will now be denied because 192.168.2.10 is not in any segment
	// accessing a segmented destination
	allowed, reason, err = manager.IsAccessAllowed("192.168.2.10", "10.0.0.10", "tcp", 3306)
	if err != nil {
		t.Fatalf("IsAccessAllowed failed: %v", err)
	}

	if allowed {
		t.Errorf("Expected access to be denied from wrong source, got allowed. Reason: %s", reason)
	}
}

func TestMicrosegmentationManager_IPInCIDR(t *testing.T) {
	logger := func(msg string) {} // No-op logger for tests
	manager := NewMicrosegmentationManager(logger)

	// Test IP in CIDR
	if !manager.ipInCIDR("192.168.1.10", "192.168.1.0/24") {
		t.Error("Expected IP to be in CIDR range")
	}

	// Test IP not in CIDR
	if manager.ipInCIDR("192.168.2.10", "192.168.1.0/24") {
		t.Error("Expected IP not to be in CIDR range")
	}

	// Test exact IP match
	if !manager.ipInCIDR("192.168.1.10", "192.168.1.10") {
		t.Error("Expected exact IP match to succeed")
	}

	// Test non-matching IP
	if manager.ipInCIDR("192.168.1.10", "192.168.1.20") {
		t.Error("Expected non-matching IP to fail")
	}
}

func TestMicrosegmentationMiddleware(t *testing.T) {
	logger := func(msg string) {} // No-op logger for tests
	manager := NewMicrosegmentationManager(logger)

	// Create a segment and add a policy that allows specific traffic
	seg, err := manager.CreateSegment("allowed-segment", "Allowed segment", nil)
	if err != nil {
		t.Fatalf("CreateSegment failed: %v", err)
	}

	policy := Policy{
		Name:        "allow-from-192.168.1.x",
		Action:      "allow",
		Source:      []string{"192.168.1.0/24"},
		Destination: []string{"10.0.0.0/24"},
		Protocol:    []string{"tcp"},
		Port:        []int{80},
		Priority:    1,
		Enabled:     true,
	}
	manager.AddPolicy(seg.ID, policy)

	// Add a member to the segment
	manager.AddMember(seg.ID, "192.168.1.100")

	// Create a test handler
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// Wrap the handler with the middleware
	middleware := manager.MicrosegmentationMiddleware(testHandler)

	// Create a request from the allowed IP
	req := httptest.NewRequest("GET", "http://10.0.0.10:80/test", nil)
	req.Header.Set("X-Forwarded-For", "192.168.1.100") // This IP should be allowed
	rr := httptest.NewRecorder()

	// Execute the request
	middleware.ServeHTTP(rr, req)

	// Should be allowed if the policy matches
	if rr.Code != http.StatusOK {
		t.Errorf("Expected StatusOK for allowed IP, got %d", rr.Code)
	}

	// Create a request from a non-allowed IP
	req2 := httptest.NewRequest("GET", "http://10.0.0.10:80/test", nil)
	req2.Header.Set("X-Forwarded-For", "192.168.2.100") // This IP is not covered by the policy
	rr2 := httptest.NewRecorder()

	// Execute the request
	middleware.ServeHTTP(rr2, req2)

	// Should be denied (since non-segmented source accessing segmented destination)
	if rr2.Code != http.StatusForbidden {
		t.Errorf("Expected StatusForbidden for non-allowed IP, got %d", rr2.Code)
	}
}

func TestMicrosegmentationManager_ListSegments(t *testing.T) {
	logger := func(msg string) {} // No-op logger for tests
	manager := NewMicrosegmentationManager(logger)

	// Create multiple segments
	_, err := manager.CreateSegment("seg1", "Segment 1", nil)
	if err != nil {
		t.Fatalf("CreateSegment failed: %v", err)
	}

	_, err = manager.CreateSegment("seg2", "Segment 2", nil)
	if err != nil {
		t.Fatalf("CreateSegment failed: %v", err)
	}

	// List segments
	segments := manager.ListSegments()

	if len(segments) != 2 {
		t.Errorf("Expected 2 segments, got %d", len(segments))
	}

	// Verify segment names
	names := make(map[string]bool)
	for _, seg := range segments {
		names[seg.Name] = true
	}

	if !names["seg1"] || !names["seg2"] {
		t.Errorf("Expected to find both segments, got %v", names)
	}
}

func TestMicrosegmentationManager_DeleteSegment(t *testing.T) {
	logger := func(msg string) {} // No-op logger for tests
	manager := NewMicrosegmentationManager(logger)

	// Create a segment
	segment, err := manager.CreateSegment("delete-test", "Delete test", nil)
	if err != nil {
		t.Fatalf("CreateSegment failed: %v", err)
	}

	// Verify it exists
	_, exists := manager.GetSegment(segment.ID)
	if !exists {
		t.Error("Segment should exist after creation")
	}

	// Delete the segment
	err = manager.DeleteSegment(segment.ID)
	if err != nil {
		t.Fatalf("DeleteSegment failed: %v", err)
	}

	// Verify it's gone
	_, exists = manager.GetSegment(segment.ID)
	if exists {
		t.Error("Segment should not exist after deletion")
	}

	// Try to delete non-existent segment
	err = manager.DeleteSegment(segment.ID)
	if err == nil {
		t.Error("Expected error when deleting non-existent segment")
	}
}

func TestMicrosegmentationManager_GetSegment(t *testing.T) {
	logger := func(msg string) {} // No-op logger for tests
	manager := NewMicrosegmentationManager(logger)

	// Create a segment
	segment, err := manager.CreateSegment("get-test", "Get test", nil)
	if err != nil {
		t.Fatalf("CreateSegment failed: %v", err)
	}

	// Get the segment
	retrieved, exists := manager.GetSegment(segment.ID)
	if !exists {
		t.Error("Segment should exist")
	}

	if retrieved.ID != segment.ID {
		t.Errorf("Expected ID %s, got %s", segment.ID, retrieved.ID)
	}

	if retrieved.Name != segment.Name {
		t.Errorf("Expected name %s, got %s", segment.Name, retrieved.Name)
	}

	// Try to get non-existent segment
	_, exists = manager.GetSegment("non-existent")
	if exists {
		t.Error("Non-existent segment should not exist")
	}
}

func TestMicrosegmentationManager_PolicySorting(t *testing.T) {
	logger := func(msg string) {} // No-op logger for tests
	manager := NewMicrosegmentationManager(logger)

	// Create a segment
	segment, err := manager.CreateSegment("sort-test", "Sort test", nil)
	if err != nil {
		t.Fatalf("CreateSegment failed: %v", err)
	}

	// Add policies with different priorities
	policies := []Policy{
		{Name: "low-priority", Priority: 100},
		{Name: "high-priority", Priority: 1},
		{Name: "medium-priority", Priority: 50},
	}

	for _, policy := range policies {
		err := manager.AddPolicy(segment.ID, policy)
		if err != nil {
			t.Fatalf("AddPolicy failed: %v", err)
		}
	}

	// Check that policies are sorted by priority (lowest first)
	if len(segment.Policies) != 3 {
		t.Fatalf("Expected 3 policies, got %d", len(segment.Policies))
	}

	if segment.Policies[0].Name != "high-priority" {
		t.Errorf("Expected high-priority policy first, got %s", segment.Policies[0].Name)
	}

	if segment.Policies[1].Name != "medium-priority" {
		t.Errorf("Expected medium-priority policy second, got %s", segment.Policies[1].Name)
	}

	if segment.Policies[2].Name != "low-priority" {
		t.Errorf("Expected low-priority policy third, got %s", segment.Policies[2].Name)
	}
}

func TestMicrosegmentationUnsegmentedTraffic(t *testing.T) {
	logger := func(msg string) {} // No-op logger for tests
	manager := NewMicrosegmentationManager(logger)

	// Test traffic between IPs that are not in any segment
	// With our current logic, this should be denied by default
	allowed, reason, err := manager.IsAccessAllowed("192.168.1.100", "10.0.0.100", "tcp", 80)
	if err != nil {
		t.Fatalf("IsAccessAllowed failed: %v", err)
	}

	if allowed {
		t.Errorf("Expected unsegmented traffic to be denied, got allowed. Reason: %s", reason)
	}
}