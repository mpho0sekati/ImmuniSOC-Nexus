package classification

import (
	"regexp"
	"strings"
)

// Tier represents the classification tier
type Tier int

const (
	PUBLIC Tier = iota
	STANDARD
	CRITICAL
)

// Global regex to avoid re-compilation on every request
var alphanumericRegex = regexp.MustCompile("[^a-zA-Z0-9 -]+")

// Classifier handles traffic classification
type Classifier struct{}

// Classify function with alphanumeric cleaning
func (c *Classifier) Classify(input string) (Tier, string) {
	// Clean the input by removing non-alphanumeric characters except spaces and hyphens
	cleaned := cleanInput(input)

	// Determine tier based on input characteristics
	tier := determineTier(cleaned)

	return tier, cleaned
}

// cleanInput uses regex to enforce strict X-User context formats and remove unwanted characters
func cleanInput(input string) string {
	// Remove non-alphanumeric characters except spaces and hyphens using pre-compiled regex
	cleaned := alphanumericRegex.ReplaceAllString(input, "")

	// Trim leading/trailing whitespace
	cleaned = strings.TrimSpace(cleaned)

	return cleaned
}

// determineTier determines the tier based on input characteristics
func determineTier(input string) Tier {
	if len(input) == 0 {
		return PUBLIC
	}

	// Simple heuristic for determining tier
	length := len(input)
	if length > 100 {
		return CRITICAL
	} else if length > 50 {
		return STANDARD
	}

	return PUBLIC
}

// AnalyzeTraffic returns the status of the classification engine
func AnalyzeTraffic() string {
	return "Classification Engine Active"
}
