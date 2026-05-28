package opa

import (
	"strings"
	"testing"
)

func TestClassifyEgressData(t *testing.T) {
	tests := []struct {
		name     string
		data     string
		expected string
	}{
		{
			name:     "large data set",
			data:     strings.Repeat("a", 10001), // More than 10000 bytes
			expected: "CRITICAL",
		},
		{
			name:     "confidential data",
			data:     "This is confidential information",
			expected: "CRITICAL",
		},
		{
			name:     "private data",
			data:     "Private data here",
			expected: "CRITICAL",
		},
		{
			name:     "restricted data",
			data:     "Restricted access data",
			expected: "CRITICAL",
		},
		{
			name:     "sensitive pattern data - ssn",
			data:     "User has social security number",
			expected: "CRITICAL",
		},
		{
			name:     "sensitive pattern data - credit card",
			data:     "Credit card information",
			expected: "CRITICAL",
		},
		{
			name:     "sensitive pattern data - password",
			data:     "Password reset required",
			expected: "CRITICAL",
		},
		{
			name:     "standard data",
			data:     "Regular public data",
			expected: "STANDARD",
		},
		{
			name:     "small private data (will be CRITICAL due to keyword match)",
			data:     "private",
			expected: "CRITICAL", // Will match the "private" keyword check
		},
		{
			name:     "data with sensitive keywords but not critical",
			data:     "This is a normal document",
			expected: "STANDARD",
		},
		{
			name:     "data with restricted keyword",
			data:     "This is restricted information",
			expected: "CRITICAL", // Will match "restricted" keyword
		},
		{
			name:     "short data without sensitive keywords",
			data:     "public data",
			expected: "STANDARD", // Short and no sensitive keywords
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := classifyEgressData(tt.data)
			if result != tt.expected {
				t.Errorf("classifyEgressData() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestContainsAny(t *testing.T) {
	tests := []struct {
		name       string
		text       string
		substrings []string
		expected   bool
	}{
		{
			name:       "text contains substring",
			text:       "hello world",
			substrings: []string{"world"},
			expected:   true,
		},
		{
			name:       "text does not contain substring",
			text:       "hello world",
			substrings: []string{"goodbye"},
			expected:   false,
		},
		{
			name:       "text contains multiple substrings",
			text:       "hello world goodbye",
			substrings: []string{"world", "goodbye"},
			expected:   true,
		},
		{
			name:       "text contains none of the substrings",
			text:       "hello world",
			substrings: []string{"goodbye", "farewell"},
			expected:   false,
		},
		{
			name:       "case insensitive match",
			text:       "Hello World",
			substrings: []string{"world"},
			expected:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := containsAny(tt.text, tt.substrings)
			if result != tt.expected {
				t.Errorf("containsAny() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestStringToLower(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "mixed case",
			input:    "Hello World",
			expected: "hello world",
		},
		{
			name:     "all uppercase",
			input:    "HELLO",
			expected: "hello",
		},
		{
			name:     "all lowercase",
			input:    "hello",
			expected: "hello",
		},
		{
			name:     "numbers and symbols",
			input:    "Hello123!",
			expected: "hello123!",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := stringToLower(tt.input)
			if result != tt.expected {
				t.Errorf("stringToLower() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestIndexOf(t *testing.T) {
	tests := []struct {
		name     string
		s        string
		substr   string
		expected int
	}{
		{
			name:     "substring exists",
			s:        "hello world",
			substr:   "world",
			expected: 6,
		},
		{
			name:     "substring at beginning",
			s:        "hello world",
			substr:   "hello",
			expected: 0,
		},
		{
			name:     "substring at end",
			s:        "hello world",
			substr:   "ld",
			expected: 9,
		},
		{
			name:     "substring not found",
			s:        "hello world",
			substr:   "goodbye",
			expected: -1,
		},
		{
			name:     "empty substring",
			s:        "hi",
			substr:   "",
			expected: 0,
		},
		{
			name:     "substring longer than string",
			s:        "hi",
			substr:   "hello",
			expected: -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := indexOf(tt.s, tt.substr)
			if result != tt.expected {
				t.Errorf("indexOf() = %v, want %v", result, tt.expected)
			}
		})
	}
}