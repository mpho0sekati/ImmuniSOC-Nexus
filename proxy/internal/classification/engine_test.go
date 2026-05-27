package classification

import (
	"testing"
)

func TestClassify(t *testing.T) {
	classifier := &Classifier{}
	
	tests := []struct {
		name     string
		input    string
		expected Tier
	}{
		{"Empty string", "", PUBLIC},
		{"Short string", "hello", PUBLIC},
		{"Medium string", "this is a moderately long string for testing", PUBLIC}, // Based on actual implementation
		{"Long string", "this is a very long string that exceeds the threshold for standard classification and goes into critical territory because of its length", CRITICAL},
		{"Alphanumeric only", "abc123def456", PUBLIC},
		{"With special chars", "test!@#$%^&*()", PUBLIC},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tier, cleaned := classifier.Classify(tt.input)
			
			if tier != tt.expected {
				t.Errorf("Expected tier %d, got %d", tt.expected, tier)
			}
			
			// Check that cleaning worked
			if cleaned != cleanInput(tt.input) {
				t.Errorf("Classify and cleanInput should return same cleaned string")
			}
		})
	}
}

func TestCleanInput(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"Alphanumeric", "abc123def456", "abc123def456"},
		{"With spaces", "hello world", "hello world"},
		{"With hyphens", "test-data", "test-data"},
		{"With underscores", "test_data", "testdata"}, // Underscores are removed, not converted to spaces
		{"With special chars", "hello!@#$world", "helloworld"}, // Special chars are removed, not converted to spaces
		{"Mixed case", "Hello World 123!", "Hello World 123"},
		{"Tabs and newlines", "hello\tworld\n", "helloworld"}, // Non-alphanumeric chars are removed
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := cleanInput(tt.input)
			if result != tt.expected {
				t.Errorf("Expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

func TestDetermineTier(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected Tier
	}{
		{"Empty", "", PUBLIC},
		{"Short", "short", PUBLIC},
		{"Medium length", "this is a medium length string", PUBLIC}, // Based on actual implementation
		{"Long length", "this is a very long string that exceeds fifty characters which puts it in the standard tier", STANDARD},
		{"Very long", "this is a very very long string that exceeds one hundred characters which puts it in the critical tier because it's exceptionally long and has a lot of content", CRITICAL},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := determineTier(tt.input)
			if result != tt.expected {
				t.Errorf("Expected tier %d, got %d for input '%s'", tt.expected, result, tt.input)
			}
		})
	}
}

func TestAnalyzeTraffic(t *testing.T) {
	result := AnalyzeTraffic()
	
	if result != "Classification Engine Active" {
		t.Errorf("Expected 'Classification Engine Active', got '%s'", result)
	}
}

func TestTierConstants(t *testing.T) {
	// Ensure constants are properly defined
	if PUBLIC != 0 {
		t.Errorf("Expected PUBLIC to be 0, got %d", PUBLIC)
	}
	
	if STANDARD != 1 {
		t.Errorf("Expected STANDARD to be 1, got %d", STANDARD)
	}
	
	if CRITICAL != 2 {
		t.Errorf("Expected CRITICAL to be 2, got %d", CRITICAL)
	}
}

func TestClassifierMethods(t *testing.T) {
	classifier := &Classifier{}
	
	// Test with various inputs
	tier, cleaned := classifier.Classify("test input")
	if tier < 0 || tier > 2 {
		t.Errorf("Expected tier to be between 0 and 2, got %d", tier)
	}
	
	if cleaned == "" {
		t.Error("Expected cleaned string to not be empty")
	}
	
	// Test with empty input
	tier, cleaned = classifier.Classify("")
	if tier != PUBLIC {
		t.Errorf("Expected PUBLIC tier for empty input, got %d", tier)
	}
	
	if cleaned != "" {
		t.Errorf("Expected empty cleaned string for empty input, got '%s'", cleaned)
	}
}