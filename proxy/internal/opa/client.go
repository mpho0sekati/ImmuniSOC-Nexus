package opa

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// PolicyRequest represents the request body for OPA policy evaluation
type PolicyRequest struct {
	Input map[string]interface{} `json:"input"`
}

// PolicyResponse represents the response from OPA policy evaluation
type PolicyResponse struct {
	Result bool `json:"result"`
}

// CheckPolicy sends a request to the OPA container to evaluate a policy
func CheckPolicy(input map[string]interface{}) (bool, error) {
	// Prepare the request payload
	requestBody := PolicyRequest{
		Input: input,
	}

	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		return false, fmt.Errorf("failed to marshal request body: %w", err)
	}

	// Send POST request to OPA endpoint
	url := "http://opa:8181/v1/data/authz/allow" // Standard OPA endpoint
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonData))
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