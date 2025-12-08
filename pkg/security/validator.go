package security

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Validator performs security checks on inputs and operations
type Validator struct{}

// NewValidator creates a new security validator
func NewValidator() *Validator {
	return &Validator{}
}

// ValidateFilePath ensures path is safe and doesn't escape intended directories
func (v *Validator) ValidateFilePath(path string, allowedDirs []string) error {
	// Clean path to prevent directory traversal
	cleanPath := filepath.Clean(path)
	
	// Check for path traversal attempts
	if strings.Contains(cleanPath, "..") {
		return fmt.Errorf("path traversal detected: %s", path)
	}
	
	// Verify path is within allowed directories
	if len(allowedDirs) > 0 {
		allowed := false
		for _, dir := range allowedDirs {
			if strings.HasPrefix(cleanPath, filepath.Clean(dir)) {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("path outside allowed directories: %s", path)
		}
	}
	
	return nil
}

// SanitizeRuleID prevents injection attacks in rule IDs
func (v *Validator) SanitizeRuleID(ruleID string) (string, error) {
	// Only allow alphanumeric, dash, and underscore
	validPattern := regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
	if !validPattern.MatchString(ruleID) {
		return "", fmt.Errorf("invalid rule ID format: %s", ruleID)
	}
	
	// Limit length to prevent DoS
	if len(ruleID) > 128 {
		return "", fmt.Errorf("rule ID too long: %d characters", len(ruleID))
	}
	
	return ruleID, nil
}

// ValidateCommand checks if a command is safe to execute
func (v *Validator) ValidateCommand(cmd string, allowedCommands []string) error {
	// Check against whitelist
	for _, allowed := range allowedCommands {
		if cmd == allowed || strings.HasPrefix(cmd, allowed+" ") {
			return nil
		}
	}
	
	return fmt.Errorf("command not in whitelist: %s", cmd)
}

// SanitizeLogOutput removes potentially sensitive information
func (v *Validator) SanitizeLogOutput(log string) string {
	// Remove common sensitive patterns
	patterns := map[string]string{
		// Private IP addresses (keep for analysis but mark)
		`\b192\.168\.\d{1,3}\.\d{1,3}\b`:     "[PRIVATE_IP]",
		`\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`:  "[PRIVATE_IP]",
		`\b172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}\b`: "[PRIVATE_IP]",
		
		// Email addresses
		`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`: "[EMAIL]",
		
		// Credit card numbers (basic pattern)
		`\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b`: "[REDACTED]",
		
		// Social security numbers
		`\b\d{3}-\d{2}-\d{4}\b`: "[REDACTED]",
		
		// API keys and tokens (common patterns)
		`(?i)(api[_-]?key|token|secret|password)\s*[:=]\s*[^\s]+`: "[REDACTED_CREDENTIAL]",
	}
	
	sanitized := log
	for pattern, replacement := range patterns {
		re := regexp.MustCompile(pattern)
		sanitized = re.ReplaceAllString(sanitized, replacement)
	}
	
	return sanitized
}

// ValidateRuleFile checks if a Sigma rule file is safe to load
func (v *Validator) ValidateRuleFile(filePath string) error {
	// Check file extension
	if filepath.Ext(filePath) != ".yml" && filepath.Ext(filePath) != ".yaml" {
		return fmt.Errorf("invalid file extension: must be .yml or .yaml")
	}
	
	// Check file size (prevent DoS)
	info, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("cannot stat file: %w", err)
	}
	
	if info.Size() > 10*1024*1024 { // 10MB max
		return fmt.Errorf("rule file too large: %d bytes", info.Size())
	}
	
	return nil
}

// ComputeFileHash computes SHA256 hash of a file for integrity checking
func (v *Validator) ComputeFileHash(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()
	
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// ValidateIPAddress checks if an IP is safe (not localhost/loopback in production)
func (v *Validator) ValidateIPAddress(ip string) error {
	// Block dangerous IPs
	dangerous := []string{
		"127.0.0.1",
		"localhost",
		"0.0.0.0",
		"::1",
	}
	
	for _, danger := range dangerous {
		if strings.Contains(strings.ToLower(ip), danger) {
			return fmt.Errorf("dangerous IP address: %s", ip)
		}
	}
	
	return nil
}

// RateLimiter provides simple rate limiting for operations
type RateLimiter struct {
	maxOperations int
	operations    int
}

// NewRateLimiter creates a rate limiter
func NewRateLimiter(maxOps int) *RateLimiter {
	return &RateLimiter{
		maxOperations: maxOps,
		operations:    0,
	}
}

// Allow checks if operation is allowed
func (r *RateLimiter) Allow() bool {
	if r.operations >= r.maxOperations {
		return false
	}
	r.operations++
	return true
}

// Reset resets the counter
func (r *RateLimiter) Reset() {
	r.operations = 0
}
