package bloodhound

import (
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewTracker(t *testing.T) {
	tracker := NewTracker()
	if tracker == nil {
		t.Fatal("Expected tracker to be created, got nil")
	}
	
	// Ensure the goroutine starts properly
	time.Sleep(10 * time.Millisecond) // Allow goroutine to start
}

func TestTrackRequest(t *testing.T) {
	tracker := NewTracker()
	
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("User-Agent", "test-agent")
	
	tracker.TrackRequest(req, false)
	
	nodes := tracker.GetNodes()
	if len(nodes) != 1 {
		t.Fatalf("Expected 1 node, got %d", len(nodes))
	}
	
	if nodes[0].UserAgent != "test-agent" {
		t.Errorf("Expected UserAgent 'test-agent', got '%s'", nodes[0].UserAgent)
	}
}

func TestTrackRequestHoneytrap(t *testing.T) {
	tracker := NewTracker()
	
	req := httptest.NewRequest("GET", "/test", nil)
	
	tracker.TrackRequest(req, true) // honeytrap hit
	
	paths := tracker.GetAttackPaths()
	if len(paths) != 1 {
		t.Fatalf("Expected 1 attack path for honeytrap, got %d", len(paths))
	}
	
	if paths[0].AlertLevel != "critical" {
		t.Errorf("Expected alert level 'critical', got '%s'", paths[0].AlertLevel)
	}
}

func TestTrackLateralMovement(t *testing.T) {
	tracker := NewTracker()
	
	// First track a normal request to create a node
	req1 := httptest.NewRequest("GET", "/test1", nil)
	tracker.TrackRequest(req1, false)
	
	// Then track a honeytrap hit to create another node
	req2 := httptest.NewRequest("GET", "/test2", nil)
	tracker.TrackRequest(req2, true) // This creates a honeytrap node
	
	nodes := tracker.GetNodes()
	if len(nodes) < 2 {
		t.Fatal("Not enough nodes created")
	}
	
	// Now simulate lateral movement between the two nodes
	tracker.TrackLateralMovement(nodes[0].ID, nodes[1].ID, "GET")
	
	// Since one of the nodes is a honeytrap, we should get an attack path
	paths := tracker.GetAttackPaths()
	if len(paths) == 0 {
		t.Fatal("Expected attack paths after lateral movement involving honeytrap")
	}
}

func TestGetRecentAttacks(t *testing.T) {
	tracker := NewTracker()
	
	req := httptest.NewRequest("GET", "/test", nil)
	tracker.TrackRequest(req, true) // Creates a critical path
	
	// Get attacks from last 24 hours
	attacks := tracker.GetRecentAttacks(24)
	if len(attacks) != 1 {
		t.Fatalf("Expected 1 recent attack, got %d", len(attacks))
	}
}

func TestGetHighRiskPaths(t *testing.T) {
	tracker := NewTracker()
	
	req := httptest.NewRequest("GET", "/test", nil)
	tracker.TrackRequest(req, true) // Creates high-risk path
	
	paths := tracker.GetHighRiskPaths()
	if len(paths) != 1 {
		t.Fatalf("Expected 1 high-risk path, got %d", len(paths))
	}
}

func TestShutdown(t *testing.T) {
	tracker := NewTracker()
	
	// This should not panic
	tracker.Shutdown()
	
	// Allow some time for shutdown to complete
	time.Sleep(10 * time.Millisecond)
}