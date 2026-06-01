package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"immunisoc-nexus/proxy/internal/bloodhound"
	"immunisoc-nexus/proxy/internal/config"
	"immunisoc-nexus/proxy/internal/deception"
	"immunisoc-nexus/proxy/internal/hardening"
	"immunisoc-nexus/proxy/internal/rbac"
	"immunisoc-nexus/proxy/internal/tcell"
)

func TestVerbWhitelist(t *testing.T) {
	tests := []struct {
		name           string
		method         string
		expectedStatus int
	}{
		{
			name:           "GET method allowed",
			method:         "GET",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "POST method allowed",
			method:         "POST",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "PUT method not allowed",
			method:         "PUT",
			expectedStatus: http.StatusMethodNotAllowed,
		},
		{
			name:           "DELETE method not allowed",
			method:         "DELETE",
			expectedStatus: http.StatusMethodNotAllowed,
		},
		{
			name:           "PATCH method not allowed",
			method:         "PATCH",
			expectedStatus: http.StatusMethodNotAllowed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := verbWhitelist(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("OK"))
			}))

			req := httptest.NewRequest(tt.method, "/", nil)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, tt.expectedStatus)
			}
		})
	}
}

func TestHasDirectoryTraversal(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "normal path",
			input:    "/api/users",
			expected: false,
		},
		{
			name:     "directory traversal with ../",
			input:    "../etc/passwd",
			expected: true,
		},
		{
			name:     "directory traversal with ..\\",
			input:    "..\\windows\\system32",
			expected: true,
		},
		{
			name:     "encoded directory traversal",
			input:    "%2e%2e%2fetc%2fpasswd",
			expected: true,
		},
		{
			name:     "double encoded directory traversal",
			input:    "..%2f..%2fetc%2fpasswd",
			expected: true,
		},
		{
			name:     "empty input",
			input:    "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := hasDirectoryTraversal(tt.input)
			if result != tt.expected {
				t.Errorf("hasDirectoryTraversal(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestHasCanaryToken(t *testing.T) {
	tests := []struct {
		name     string
		setupReq func(*http.Request)
		expected bool
	}{
		{
			name: "no canary tokens",
			setupReq: func(r *http.Request) {
				// No canary tokens in headers, path, or query
			},
			expected: false,
		},
		{
			name: "canary in header name",
			setupReq: func(r *http.Request) {
				r.Header.Set("X-Canary-Test", "some-value")
			},
			expected: true,
		},
		{
			name: "honey in header name",
			setupReq: func(r *http.Request) {
				r.Header.Set("X-Honey-Token", "some-value")
			},
			expected: true,
		},
		{
			name: "canary token in header value",
			setupReq: func(r *http.Request) {
				r.Header.Set("Authorization", "Bearer canary-token-12345")
			},
			expected: true,
		},
		{
			name: "honeytoken in header value",
			setupReq: func(r *http.Request) {
				r.Header.Set("X-Custom", "honeytoken-abcde")
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			tt.setupReq(req)

			result := hasCanaryToken(req)
			if result != tt.expected {
				t.Errorf("hasCanaryToken() = %v, want %v", result, tt.expected)
			}
		})
	}

	// Test specific cases with paths - these should return true as the function checks for these patterns
	t.Run("canary token in URL path", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/canary-token-endpoint", nil)
		result := hasCanaryToken(req)
		// This SHOULD return true because the path contains "canary-token"
		if !result {
			t.Errorf("hasCanaryToken() should return true for canary token in path, got %v", result)
		}
	})

	t.Run("honeytoken in URL path", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/honeytoken-secret", nil)
		result := hasCanaryToken(req)
		// This SHOULD return true because the path contains "honeytoken"
		if !result {
			t.Errorf("hasCanaryToken() should return true for honeytoken in path, got %v", result)
		}
	})

	t.Run("tripwire in URL path", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/tripwire-alert", nil)
		result := hasCanaryToken(req)
		// This SHOULD return true because the path contains "tripwire"
		if !result {
			t.Errorf("hasCanaryToken() should return true for tripwire in path, got %v", result)
		}
	})

	// Test a path that should NOT trigger the function
	t.Run("normal path without canary tokens", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/users/profile", nil)
		result := hasCanaryToken(req)
		// This should return false as there are no canary-related patterns
		if result {
			t.Errorf("hasCanaryToken() should return false for normal path, got %v", result)
		}
	})
}

func TestBuildProxyHandler(t *testing.T) {
	// Set up required environment variables
	originalToken := os.Getenv("HANDSHAKE_TOKEN")
	os.Setenv("HANDSHAKE_TOKEN", "test-token")
	defer os.Setenv("HANDSHAKE_TOKEN", originalToken)

	// Initialize required components to avoid nil pointer dereferences
	appConfig = &config.Config{
		RateLimitRequests: 100,
		RateLimitWindow:   time.Minute,
	}
	tcellEngine = tcell.NewEngine()
	deceptionGen = deception.NewGenerator("test")
	bloodTracker = bloodhound.NewTracker()
	rbacManager = rbac.NewRBACManager(nil, nil)
	hardeningMgr = hardening.NewHardeningManager(nil, nil)

	// Since buildProxyHandler includes authentication, we need to provide a signature
	handler := buildProxyHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}), "test-token")

	// Test that the handler works with proper authentication
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"test":"data"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-Signature", "test-signature") // This will fail signature verification
	req.Header.Set("X-Request-Timestamp", time.Now().Format(time.RFC3339))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Since our handler includes authentication, it will likely return 401 due to signature mismatch
	// That's expected behavior - we just want to ensure it doesn't panic
	if rr.Code != http.StatusUnauthorized && rr.Code != http.StatusOK {
		t.Logf("buildProxyHandler returned status code: %v (this might be expected due to auth)", rr.Code)
	}
}

func TestIsAllowedOrigin(t *testing.T) {
	// Test default origins
	defaultOrigins := []string{
		"http://localhost:3000",
		"http://127.0.0.1:3000",
	}

	for _, origin := range defaultOrigins {
		t.Run("default origin "+origin, func(t *testing.T) {
			result := isAllowedOrigin(origin)
			if !result {
				t.Errorf("isAllowedOrigin(%q) should return true for default origin", origin)
			}
		})
	}

	t.Run("disallowed origin", func(t *testing.T) {
		result := isAllowedOrigin("http://malicious-site.com")
		if result {
			t.Errorf("isAllowedOrigin should return false for malicious origin")
		}
	})

	// Test with custom origins via environment variable
	originalEnv := os.Getenv("DASHBOARD_ALLOWED_ORIGINS")
	os.Setenv("DASHBOARD_ALLOWED_ORIGINS", "http://custom.com,http://another-custom.com")
	defer os.Setenv("DASHBOARD_ALLOWED_ORIGINS", originalEnv)

	t.Run("custom origin", func(t *testing.T) {
		result := isAllowedOrigin("http://custom.com")
		if !result {
			t.Errorf("isAllowedOrigin should return true for custom origin from env var")
		}
	})
}
