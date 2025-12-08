package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// NewReportCmd creates the report generation command
func NewReportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "report",
		Short: "Generate security report",
		Long:  `Generate a sanitized security report suitable for sharing`,
		RunE:  runReport,
	}

	cmd.Flags().StringP("format", "f", "text", "Output format: text, json, discord")
	cmd.Flags().StringP("output", "o", "", "Output file (default: stdout)")
	cmd.Flags().BoolP("sanitize", "s", true, "Redact sensitive information")

	return cmd
}

func runReport(cmd *cobra.Command, args []string) error {
	format, _ := cmd.Flags().GetString("format")
	output, _ := cmd.Flags().GetString("output")
	sanitize, _ := cmd.Flags().GetBool("sanitize")

	fmt.Println("📊 Generating security report...\n")

	// Gather report data (in real implementation, this would collect from logs)
	report := &SecurityReport{
		GeneratedAt: time.Now(),
		System: SystemInfo{
			Hostname: getHostname(),
			OS:       getOSInfo(),
		},
		Summary: ReportSummary{
			TotalEvents:   1524,
			TotalDetections: 12,
			CriticalCount:   2,
			WarningCount:    7,
			InfoCount:       3,
		},
		TopDetections: []DetectionSummary{
			{
				RuleName:  "Suspicious PowerShell Execution",
				Severity:  "CRITICAL",
				Count:     2,
				FirstSeen: time.Now().Add(-4 * time.Hour),
				LastSeen:  time.Now().Add(-1 * time.Hour),
			},
			{
				RuleName:  "Multiple Failed Login Attempts",
				Severity:  "WARNING",
				Count:     5,
				FirstSeen: time.Now().Add(-6 * time.Hour),
				LastSeen:  time.Now().Add(-30 * time.Minute),
			},
		},
	}

	// Sanitize if requested
	if sanitize {
		report = sanitizeReport(report)
	}

	// Format output
	var reportStr string
	var err error

	switch format {
	case "json":
		reportStr, err = formatJSON(report)
	case "discord":
		reportStr = formatDiscord(report)
	case "text":
		fallthrough
	default:
		reportStr = formatText(report)
	}

	if err != nil {
		return fmt.Errorf("failed to format report: %w", err)
	}

	// Output
	if output != "" {
		if err := os.WriteFile(output, []byte(reportStr), 0644); err != nil {
			return fmt.Errorf("failed to write report: %w", err)
		}
		fmt.Printf("✓ Report saved to: %s\n", output)
	} else {
		fmt.Println(reportStr)
	}

	return nil
}

// Report structures
type SecurityReport struct {
	GeneratedAt   time.Time
	System        SystemInfo
	Summary       ReportSummary
	TopDetections []DetectionSummary
}

type SystemInfo struct {
	Hostname string
	OS       string
}

type ReportSummary struct {
	TotalEvents     int
	TotalDetections int
	CriticalCount   int
	WarningCount    int
	InfoCount       int
}

type DetectionSummary struct {
	RuleName  string
	Severity  string
	Count     int
	FirstSeen time.Time
	LastSeen  time.Time
}

func sanitizeReport(report *SecurityReport) *SecurityReport {
	// Redact hostname
	report.System.Hostname = "[REDACTED]"
	
	// Sanitize detection details (in real impl, would remove IPs, usernames, etc.)
	return report
}

func formatText(report *SecurityReport) string {
	var sb strings.Builder
	
	sb.WriteString("═══════════════════════════════════════════════\n")
	sb.WriteString("         NULL.LOG SECURITY REPORT\n")
	sb.WriteString("═══════════════════════════════════════════════\n\n")
	
	sb.WriteString(fmt.Sprintf("Generated: %s\n", report.GeneratedAt.Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("System: %s (%s)\n\n", report.System.Hostname, report.System.OS))
	
	sb.WriteString("SUMMARY\n")
	sb.WriteString("-------\n")
	sb.WriteString(fmt.Sprintf("Total Events:    %d\n", report.Summary.TotalEvents))
	sb.WriteString(fmt.Sprintf("Total Detections: %d\n", report.Summary.TotalDetections))
	sb.WriteString(fmt.Sprintf("  Critical:      %d\n", report.Summary.CriticalCount))
	sb.WriteString(fmt.Sprintf("  Warning:       %d\n", report.Summary.WarningCount))
	sb.WriteString(fmt.Sprintf("  Info:          %d\n\n", report.Summary.InfoCount))
	
	sb.WriteString("TOP DETECTIONS\n")
	sb.WriteString("--------------\n")
	for _, det := range report.TopDetections {
		sb.WriteString(fmt.Sprintf("• %s [%s]\n", det.RuleName, det.Severity))
		sb.WriteString(fmt.Sprintf("  Count: %d | First: %s | Last: %s\n\n",
			det.Count,
			det.FirstSeen.Format("15:04:05"),
			det.LastSeen.Format("15:04:05"),
		))
	}
	
	return sb.String()
}

func formatJSON(report *SecurityReport) (string, error) {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func formatDiscord(report *SecurityReport) string {
	var sb strings.Builder
	
	sb.WriteString("```\n")
	sb.WriteString("🔒 NULL.LOG SECURITY REPORT\n")
	sb.WriteString("═══════════════════════════\n\n")
	
	sb.WriteString(fmt.Sprintf("📅 %s\n\n", report.GeneratedAt.Format("2006-01-02 15:04")))
	
	sb.WriteString(fmt.Sprintf("Events: %d | Detections: %d\n", 
		report.Summary.TotalEvents, 
		report.Summary.TotalDetections))
	
	if report.Summary.CriticalCount > 0 {
		sb.WriteString(fmt.Sprintf("🔴 Critical: %d\n", report.Summary.CriticalCount))
	}
	if report.Summary.WarningCount > 0 {
		sb.WriteString(fmt.Sprintf("🟠 Warning: %d\n", report.Summary.WarningCount))
	}
	
	sb.WriteString("\n")
	for i, det := range report.TopDetections {
		if i >= 3 {
			break
		}
		sb.WriteString(fmt.Sprintf("%d. %s [%s] (x%d)\n", 
			i+1, det.RuleName, det.Severity, det.Count))
	}
	
	sb.WriteString("```")
	
	return sb.String()
}

func getHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return hostname
}

func getOSInfo() string {
	return fmt.Sprintf("%s", os.Getenv("OS"))
}
