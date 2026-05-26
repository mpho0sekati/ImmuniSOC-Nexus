package opa

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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
	client  *http.Client
	baseURL string
}

// NewOpaClient creates a new OPA client with low-latency settings
func NewOpaClient() *OpaClient {
	// Create HTTP client with 200ms timeout for low-latency
	httpClient := &http.Client{
		Timeout: 200 * time.Millisecond,
	}

	return &OpaClient{
		client:  httpClient,
		baseURL: "http://opa:8181/v1/data/authz/allow",
	}
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

// CheckPopiaCompliance checks if a request complies with POPIA regulations
func CheckPopiaCompliance(purpose string, accessedFields []string, consentGiven bool, retentionPeriod int) (bool, error) {
	input := map[string]interface{}{
		"purpose":          purpose,
		"accessed_fields":  accessedFields,
		"consent_given":    consentGiven,
		"retention_period": retentionPeriod,
	}

	client := NewOpaClient()
	return client.CheckPolicy(input)
}
