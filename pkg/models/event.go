package models

import "time"

// Severity levels for detected events
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityWarning  Severity = "WARNING"
	SeverityInfo     Severity = "INFO"
)

// Event represents a normalized log event from any platform
type Event struct {
	ID            string
	Timestamp     time.Time
	Source        string
	EventType     string
	ProcessName   string
	ProcessID     int
	User          string
	CommandLine   string
	ParentProcess string
	RemoteIP      string
	RemotePort    int
	LocalPort     int
	Protocol      string
	RawLog        string
	Metadata      map[string]interface{}
}

// Detection represents a threat detection result
type Detection struct {
	ID             string
	RuleID         string
	RuleName       string
	Severity       Severity
	Event          *Event
	Summary        string        // Plain-English explanation
	Technical      string        // Technical breakdown
	Remediation    string        // What to do next
	LearningLink   string        // Educational resource
	DetectedAt     time.Time
	FalsePositive  bool
}

// NetworkConnection represents an active network connection
type NetworkConnection struct {
	ProcessName   string
	PID           int
	LocalAddr     string
	LocalPort     int
	RemoteAddr    string
	RemotePort    int
	Domain        string
	State         string
	Protocol      string
	BytesSent     uint64
	BytesReceived uint64
	JA3Hash       string
	Tags          []string // Threat intel tags
}

// SigmaRule represents a detection rule (simplified Sigma format)
type SigmaRule struct {
	ID          string                 `yaml:"id"`
	Title       string                 `yaml:"title"`
	Description string                 `yaml:"description"`
	Author      string                 `yaml:"author"`
	Date        string                 `yaml:"date"`
	Level       string                 `yaml:"level"`
	Status      string                 `yaml:"status"`
	Logsource   map[string]string      `yaml:"logsource"`
	Detection   map[string]interface{} `yaml:"detection"`
	FalsePositives []string            `yaml:"falsepositives"`
	Tags        []string               `yaml:"tags"`
	
	// Educational fields (custom extensions)
	Summary      string `yaml:"x_summary"`
	Technical    string `yaml:"x_technical"`
	Remediation  string `yaml:"x_remediation"`
	LearningLink string `yaml:"x_learning_link"`
}
