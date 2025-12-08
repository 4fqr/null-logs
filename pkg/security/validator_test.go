package security

import (
	"strings"
	"testing"
)

func TestValidateFilePath(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name        string
		path        string
		allowedDirs []string
		shouldError bool
	}{
		{
			name:        "Valid path within allowed dir",
			path:        "/home/user/test.txt",
			allowedDirs: []string{"/home/user"},
			shouldError: false,
		},
		{
			name:        "Path traversal attempt",
			path:        "/home/user/../../../etc/passwd",
			allowedDirs: []string{"/home/user"},
			shouldError: true,
		},
		{
			name:        "Path outside allowed dirs",
			path:        "/tmp/test.txt",
			allowedDirs: []string{"/home/user"},
			shouldError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateFilePath(tt.path, tt.allowedDirs)
			if (err != nil) != tt.shouldError {
				t.Errorf("ValidateFilePath() error = %v, shouldError %v", err, tt.shouldError)
			}
		})
	}
}

func TestSanitizeRuleID(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name        string
		ruleID      string
		shouldError bool
	}{
		{
			name:        "Valid rule ID",
			ruleID:      "win_mimikatz_001",
			shouldError: false,
		},
		{
			name:        "Invalid characters",
			ruleID:      "win_mimikatz; DROP TABLE",
			shouldError: true,
		},
		{
			name:        "Too long",
			ruleID:      strings.Repeat("a", 150),
			shouldError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := validator.SanitizeRuleID(tt.ruleID)
			if (err != nil) != tt.shouldError {
				t.Errorf("SanitizeRuleID() error = %v, shouldError %v", err, tt.shouldError)
			}
		})
	}
}

func TestSanitizeLogOutput(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name     string
		input    string
		contains string
	}{
		{
			name:     "Sanitize private IP",
			input:    "Connection from 192.168.1.100",
			contains: "[PRIVATE_IP]",
		},
		{
			name:     "Sanitize email",
			input:    "User test@example.com logged in",
			contains: "[EMAIL]",
		},
		{
			name:     "Sanitize API key",
			input:    "api_key: sk-1234567890abcdef",
			contains: "[REDACTED_CREDENTIAL]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.SanitizeLogOutput(tt.input)
			if !strings.Contains(result, tt.contains) {
				t.Errorf("SanitizeLogOutput() = %v, expected to contain %v", result, tt.contains)
			}
		})
	}
}

func TestRateLimiter(t *testing.T) {
	limiter := NewRateLimiter(3)

	// First 3 operations should succeed
	for i := 0; i < 3; i++ {
		if !limiter.Allow() {
			t.Errorf("Operation %d should be allowed", i)
		}
	}

	// 4th operation should fail
	if limiter.Allow() {
		t.Error("Operation 4 should be blocked")
	}

	// Reset and try again
	limiter.Reset()
	if !limiter.Allow() {
		t.Error("Operation after reset should be allowed")
	}
}
