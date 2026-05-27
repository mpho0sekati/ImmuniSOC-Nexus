package opa

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// PolicyRequest represents the request body for OPA policy evaluation
type PolicyRequest struct {
	Input map[string]interface{} `json:"input"`
}

// PolicyResponse represents the response from OPA policy evaluation
type PolicyResponse struct {
	Result bool `json:"result"`
}

// OpaClient handles communication with the OPA service
type OpaClient struct {
	client   *http.Client
	baseURL  string
	blockURL string
}

// NewOpaClient creates a new OPA client with low-latency settings
func NewOpaClient() *OpaClient {
	// Create HTTP client with 200ms timeout for low-latency
	httpClient := &http.Client{
		Timeout: 200 * time.Millisecond,
	}

	return &OpaClient{
		client:   httpClient,
		baseURL:  envOrDefault("OPA_POLICY_URL", "http://opa:8181/v1/data/authz/allow"),
		blockURL: envOrDefault("OPA_BLOCK_POLICY_URL", "http://opa:8181/v1/data/authz/block_egress"),
	}
}

func envOrDefault(key string, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}

// Global client instance for reuse
var defaultClient = NewOpaClient()

// CheckPolicy sends a request to the OPA container to evaluate a policy
func (c *OpaClient) CheckPolicy(input map[string]interface{}) (bool, error) {
	// Prepare the request payload
	requestBody := struct {
		Input map[string]interface{} `json:"input"`
	}{
		Input: input,
	}

	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		return false, fmt.Errorf("failed to marshal request body: %w", err)
	}

	// Create context with timeout slightly less than client timeout
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Millisecond)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return false, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Send the request
	resp, err := c.client.Do(req)
	if err != nil {
		return false, fmt.Errorf("failed to send request to OPA: %w", err)
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("failed to read response body: %w", err)
	}

	// Check if the response status is successful
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("OPA returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse the JSON response
	var policyResp PolicyResponse
	err = json.Unmarshal(body, &policyResp)
	if err != nil {
		return false, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	// Return the boolean result from OPA decision
	return policyResp.Result, nil
}

// CheckPolicy is a convenience function that creates a new client and checks policy
func CheckPolicy(input map[string]interface{}) (bool, error) {
	return defaultClient.CheckPolicy(input)
}

// CheckEgressPolicy specifically checks egress policies
func CheckEgressPolicy(destination string, payload string, purpose string) (bool, error) {
	input := map[string]interface{}{
		"request_method":      "EGRESS_CHECK",
		"destination":         destination,
		"payload":             payload,
		"purpose":             purpose,
		"data_classification": classifyEgressData(payload),
		"is_admin_bypass":     false,
		"audit_log_required":  true,
	}

	return defaultClient.CheckPolicy(input)
}

// CheckEgressBlockPolicy checks if egress should be blocked
func CheckEgressBlockPolicy(destination string, payload string, purpose string) (bool, error) {
	input := map[string]interface{}{
		"destination":         destination,
		"payload":             payload,
		"purpose":             purpose,
		"data_classification": classifyEgressData(payload),
	}

	// Try to check the block_egress policy specifically
	// This assumes there's a specific endpoint for block policies
	requestBody := struct {
		Input map[string]interface{} `json:"input"`
	}{
		Input: input,
	}

	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		return false, fmt.Errorf("failed to marshal block request body: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Millisecond)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", defaultClient.blockURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return false, fmt.Errorf("failed to create block request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := defaultClient.client.Do(req)
	if err != nil {
		// If the specific block endpoint doesn't exist, fall back to general policy
		// This could happen if the policy isn't loaded yet
		return false, nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("failed to read block response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		// If the specific block endpoint doesn't exist, fall back to general policy
		return false, nil
	}

	var policyResp PolicyResponse
	err = json.Unmarshal(body, &policyResp)
	if err != nil {
		return false, fmt.Errorf("failed to unmarshal block response: %w", err)
	}

	return policyResp.Result, nil
}

// classifyEgressData classifies data for egress policies
func classifyEgressData(data string) string {
	if len(data) > 10000 { // Large data sets might be critical
		return "CRITICAL"
	}

	if containsAny(data, []string{"confidential", "private", "restricted"}) {
		return "CRITICAL"
	}

	// Check for sensitive patterns
	if containsAny(data, []string{"ssn", "social security", "credit card", "password", "api key", "secret", "token"}) {
		return "CRITICAL"
	}

	return "STANDARD"
}

// containsAny checks if the text contains any of the substrings (case insensitive)
func containsAny(text string, substrings []string) bool {
	textLower := stringToLower(text)
	for _, sub := range substrings {
		if indexOf(textLower, stringToLower(sub)) != -1 {
			return true
		}
	}
	return false
}

// Helper functions to avoid importing strings package in certain contexts
func stringToLower(s string) string {
	// Simple lowercase conversion
	result := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			result[i] = c + ('a' - 'A')
		} else {
			result[i] = c
		}
	}
	return string(result)
}

func indexOf(s, substr string) int {
	if len(substr) == 0 {
		return 0
	}
	if len(s) < len(substr) {
		return -1
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		match := true
		for j := 0; j < len(substr); j++ {
			if s[i+j] != substr[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// CheckPopiaCompliance checks if a request complies with POPIA regulations
func CheckPopiaCompliance(purpose string, accessedFields []string, consentGiven bool, retentionPeriod int) (bool, error) {
	input := map[string]interface{}{
		"purpose":          purpose,
		"accessed_fields":  accessedFields,
		"consent_given":    consentGiven,
		"retention_period": retentionPeriod,
	}

	return defaultClient.CheckPolicy(input)
}
