package deception

import (
	"testing"
	"time"
)

func TestNewGenerator(t *testing.T) {
	gen := NewGenerator("test")
	if gen == nil {
		t.Fatal("Expected generator to be created, got nil")
	}
	if gen.prefix != "test" {
		t.Errorf("Expected prefix 'test', got '%s'", gen.prefix)
	}
}

func TestGenerateHoneytoken(t *testing.T) {
	gen := NewGenerator("test")
	
	token, err := gen.GenerateHoneytoken("test-desc", 24)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	
	if token.TokenID == "" {
		t.Error("Expected TokenID to be set")
	}
	
	if token.Value == "" {
		t.Error("Expected Value to be set")
	}
	
	if token.Description != "test-desc" {
		t.Errorf("Expected description 'test-desc', got '%s'", token.Description)
	}
	
	if token.Expiry.Before(time.Now()) {
		t.Error("Expected expiry to be in the future")
	}
	
	if !gen.ValidateToken(token) {
		t.Error("Expected generated token to be valid")
	}
}

func TestValidateToken(t *testing.T) {
	gen := NewGenerator("test")
	
	token, err := gen.GenerateHoneytoken("test", 1) // 1 hour expiry
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	
	if !gen.ValidateToken(token) {
		t.Error("Expected valid token to be validated as true")
	}
	
	// Test with nil token
	if gen.ValidateToken(nil) {
		t.Error("Expected nil token to be invalid")
	}
	
	// Test with expired token by manipulating it
	expiredToken := &Honeytoken{
		Expiry: time.Now().Add(-1 * time.Hour), // Expired 1 hour ago
	}
	if gen.ValidateToken(expiredToken) {
		t.Error("Expected expired token to be invalid")
	}
}

func TestGenerateFakePII(t *testing.T) {
	gen := NewGenerator("test")
	
	pii := gen.GenerateFakePII()
	
	requiredKeys := []string{
		"fake_ssn",
		"fake_passport",
		"fake_email",
		"fake_phone",
		"fake_address",
		"fake_employeeid",
	}
	
	for _, key := range requiredKeys {
		if _, exists := pii[key]; !exists {
			t.Errorf("Expected key '%s' in fake PII", key)
		}
	}
}

func TestGenerateFakeCredentials(t *testing.T) {
	gen := NewGenerator("test")
	
	creds := gen.GenerateFakeCredentials()
	
	requiredKeys := []string{
		"fake_username",
		"fake_password",
		"fake_api_key",
		"fake_token",
		"fake_secret",
	}
	
	for _, key := range requiredKeys {
		if _, exists := creds[key]; !exists {
			t.Errorf("Expected key '%s' in fake credentials", key)
		}
	}
}

func TestGenerateDecoyEndpoints(t *testing.T) {
	gen := NewGenerator("test")
	
	endpoints := gen.GenerateDecoyEndpoints()
	
	if len(endpoints) == 0 {
		t.Error("Expected at least one decoy endpoint")
	}
	
	// Check for some expected endpoints
	expectedEndpoints := []string{
		"/admin/login",
		"/api/keys",
		"/api/admin/config",
	}
	
	for _, expected := range expectedEndpoints {
		found := false
		for _, endpoint := range endpoints {
			if endpoint == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected endpoint '%s' in decoy endpoints", expected)
		}
	}
}

func TestGenerateCanaryRecord(t *testing.T) {
	gen := NewGenerator("test")
	
	testTypes := []string{"user", "credential", "database", "unknown"}
	
	for _, recordType := range testTypes {
		record := gen.GenerateCanaryRecord(recordType)
		
		if record == nil {
			t.Errorf("Expected canary record for type '%s', got nil", recordType)
			continue
		}
		
		if record["type"] == nil && recordType != "user" && recordType != "credential" && recordType != "database" {
			// For unknown types, it should have a generic structure
			if record["data"] == nil || record["status"] == nil {
				t.Errorf("Expected generic canary record structure for type '%s'", recordType)
			}
		}
	}
}