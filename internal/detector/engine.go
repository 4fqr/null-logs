package detector

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/nullsector/null-log/pkg/models"
	"gopkg.in/yaml.v3"
)

// Engine manages threat detection using Sigma rules
type Engine struct {
	rules    []*models.SigmaRule
	rulesMux sync.RWMutex
}

// NewEngine creates a new detection engine
func NewEngine(rulesDir string) (*Engine, error) {
	engine := &Engine{
		rules: make([]*models.SigmaRule, 0),
	}

	if err := engine.LoadRules(rulesDir); err != nil {
		return nil, err
	}

	return engine, nil
}

// LoadRules loads all YAML rules from a directory
func (e *Engine) LoadRules(rulesDir string) error {
	e.rulesMux.Lock()
	defer e.rulesMux.Unlock()

	return filepath.Walk(rulesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() || !strings.HasSuffix(path, ".yml") && !strings.HasSuffix(path, ".yaml") {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read rule %s: %w", path, err)
		}

		var rule models.SigmaRule
		if err := yaml.Unmarshal(data, &rule); err != nil {
			return fmt.Errorf("failed to parse rule %s: %w", path, err)
		}

		e.rules = append(e.rules, &rule)
		return nil
	})
}

// Analyze checks an event against all loaded rules
func (e *Engine) Analyze(ctx context.Context, event *models.Event) []*models.Detection {
	e.rulesMux.RLock()
	defer e.rulesMux.RUnlock()

	var detections []*models.Detection

	for _, rule := range e.rules {
		if match := e.matchRule(rule, event); match {
			detection := e.createDetection(rule, event)
			detections = append(detections, detection)
		}
	}

	return detections
}

// matchRule evaluates if an event matches a Sigma rule
func (e *Engine) matchRule(rule *models.SigmaRule, event *models.Event) bool {
	// Check logsource matches
	if !e.matchLogsource(rule.Logsource, event) {
		return false
	}

	// Get detection conditions
	detection := rule.Detection
	if detection == nil {
		return false
	}

	// Get selection criteria
	selection, ok := detection["selection"].(map[string]interface{})
	if !ok {
		return false
	}

	// Check all selection conditions
	return e.matchSelection(selection, event)
}

// matchLogsource checks if event source matches rule requirements
func (e *Engine) matchLogsource(logsource map[string]string, event *models.Event) bool {
	if logsource == nil {
		return true // No source restriction
	}

	// Check product (windows, linux, macos)
	if product, ok := logsource["product"]; ok {
		if !strings.Contains(strings.ToLower(event.Source), strings.ToLower(product)) {
			return false
		}
	}

	// Check category (process_creation, network_connection, etc)
	if category, ok := logsource["category"]; ok {
		if !strings.Contains(strings.ToLower(event.EventType), strings.ToLower(category)) {
			return false
		}
	}

	return true
}

// matchSelection checks if event fields match selection criteria
func (e *Engine) matchSelection(selection map[string]interface{}, event *models.Event) bool {
	matchCount := 0
	totalConditions := len(selection)

	for field, value := range selection {
		fieldValue := e.getEventField(field, event)
		if fieldValue == "" {
			continue
		}

		// Handle different value types
		switch v := value.(type) {
		case string:
			if e.matchPattern(v, fieldValue) {
				matchCount++
			}
		case []interface{}:
			// OR condition - match any value
			for _, item := range v {
				if str, ok := item.(string); ok {
					if e.matchPattern(str, fieldValue) {
						matchCount++
						break
					}
				}
			}
		}
	}

	// All conditions must match
	return matchCount == totalConditions
}

// getEventField extracts field value from event
func (e *Engine) getEventField(field string, event *models.Event) string {
	field = strings.ToLower(field)

	switch field {
	case "eventid", "eventtype":
		return event.EventType
	case "commandline":
		return strings.ToLower(event.CommandLine)
	case "image", "processname":
		return strings.ToLower(event.ProcessName)
	case "parentimage", "parentprocess":
		return strings.ToLower(event.ParentProcess)
	case "user", "username":
		return strings.ToLower(event.User)
	case "destinationip", "remoteip":
		return event.RemoteIP
	default:
		// Check metadata
		if val, ok := event.Metadata[field]; ok {
			return strings.ToLower(fmt.Sprintf("%v", val))
		}
	}

	return ""
}

// matchPattern checks if value matches a pattern (supports wildcards and regex)
func (e *Engine) matchPattern(pattern, value string) bool {
	pattern = strings.ToLower(pattern)
	value = strings.ToLower(value)

	// Exact match
	if pattern == value {
		return true
	}

	// Contains match
	if strings.Contains(value, pattern) {
		return true
	}

	// Wildcard pattern (convert to regex)
	if strings.Contains(pattern, "*") || strings.Contains(pattern, "?") {
		regexPattern := strings.ReplaceAll(pattern, "*", ".*")
		regexPattern = strings.ReplaceAll(regexPattern, "?", ".")
		regexPattern = "^" + regexPattern + "$"

		if matched, _ := regexp.MatchString(regexPattern, value); matched {
			return true
		}
	}

	return false
}

// createDetection creates a detection result from a matched rule
func (e *Engine) createDetection(rule *models.SigmaRule, event *models.Event) *models.Detection {
	severity := e.convertSeverity(rule.Level)

	detection := &models.Detection{
		ID:            fmt.Sprintf("det_%d", event.Timestamp.Unix()),
		RuleID:        rule.ID,
		RuleName:      rule.Title,
		Severity:      severity,
		Event:         event,
		Summary:       rule.Summary,
		Technical:     rule.Technical,
		Remediation:   rule.Remediation,
		LearningLink:  rule.LearningLink,
		DetectedAt:    event.Timestamp,
		FalsePositive: false,
	}

	// Auto-generate explanations if not provided
	if detection.Summary == "" {
		detection.Summary = e.generateSummary(rule, event)
	}
	if detection.Technical == "" {
		detection.Technical = e.generateTechnical(rule, event)
	}
	if detection.Remediation == "" {
		detection.Remediation = e.generateRemediation(rule, event)
	}

	return detection
}

// convertSeverity maps Sigma levels to our severity enum
func (e *Engine) convertSeverity(level string) models.Severity {
	switch strings.ToLower(level) {
	case "critical", "high":
		return models.SeverityCritical
	case "medium":
		return models.SeverityWarning
	default:
		return models.SeverityInfo
	}
}

// generateSummary creates a plain-English summary
func (e *Engine) generateSummary(rule *models.SigmaRule, event *models.Event) string {
	return fmt.Sprintf("Detected: %s on process '%s'", rule.Title, event.ProcessName)
}

// generateTechnical creates technical details
func (e *Engine) generateTechnical(rule *models.SigmaRule, event *models.Event) string {
	details := fmt.Sprintf("Rule: %s\n", rule.Title)
	details += fmt.Sprintf("Process: %s (PID: %d)\n", event.ProcessName, event.ProcessID)
	if event.CommandLine != "" {
		details += fmt.Sprintf("Command: %s\n", event.CommandLine)
	}
	if event.User != "" {
		details += fmt.Sprintf("User: %s\n", event.User)
	}
	return details
}

// generateRemediation suggests actions
func (e *Engine) generateRemediation(rule *models.SigmaRule, event *models.Event) string {
	actions := []string{
		"1. Investigate the process and its parent",
		"2. Check if the binary is legitimate",
		"3. Review recent system changes",
	}

	if event.RemoteIP != "" {
		actions = append(actions, fmt.Sprintf("4. Block IP address: %s", event.RemoteIP))
	}

	return strings.Join(actions, "\n")
}

// GetRuleByID retrieves a rule by its ID
func (e *Engine) GetRuleByID(id string) *models.SigmaRule {
	e.rulesMux.RLock()
	defer e.rulesMux.RUnlock()

	for _, rule := range e.rules {
		if rule.ID == id {
			return rule
		}
	}
	return nil
}

// GetAllRules returns all loaded rules
func (e *Engine) GetAllRules() []*models.SigmaRule {
	e.rulesMux.RLock()
	defer e.rulesMux.RUnlock()
	return e.rules
}
