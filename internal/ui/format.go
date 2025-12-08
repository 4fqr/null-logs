package ui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/nullsector/null-log/pkg/models"
)

var (
	// Color scheme
	colorCritical = lipgloss.Color("#FF0000")
	colorWarning  = lipgloss.Color("#FFA500")
	colorInfo     = lipgloss.Color("#00FF00")
	colorMuted    = lipgloss.Color("#666666")
	colorHeader   = lipgloss.Color("#00FFFF")

	// Styles
	criticalStyle = lipgloss.NewStyle().Foreground(colorCritical).Bold(true)
	warningStyle  = lipgloss.NewStyle().Foreground(colorWarning).Bold(true)
	infoStyle     = lipgloss.NewStyle().Foreground(colorInfo)
	mutedStyle    = lipgloss.NewStyle().Foreground(colorMuted)
	headerStyle   = lipgloss.NewStyle().Foreground(colorHeader).Bold(true)

	// Box styles
	boxStyle = lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(colorHeader).
		Padding(1, 2)

	tableHeaderStyle = lipgloss.NewStyle().
		Foreground(colorHeader).
		Bold(true).
		Underline(true)
)

// FormatDetection renders a detection in a beautiful format
func FormatDetection(d *models.Detection) string {
	var output strings.Builder

	// Severity indicator
	severityIcon := "[!]"
	severityStyle := warningStyle
	switch d.Severity {
	case models.SeverityCritical:
		severityStyle = criticalStyle
	case models.SeverityWarning:
		severityStyle = warningStyle
	case models.SeverityInfo:
		severityStyle = infoStyle
	}

	// Header line
	output.WriteString(severityStyle.Render(fmt.Sprintf("%s %s", severityIcon, d.Severity)))
	output.WriteString(fmt.Sprintf(" %s\n", d.RuleName))
	output.WriteString(mutedStyle.Render(fmt.Sprintf("    Detected at: %s\n", d.DetectedAt.Format("15:04:05"))))
	output.WriteString("\n")

	// Summary (beginner-friendly)
	if d.Summary != "" {
		output.WriteString(lipgloss.NewStyle().Bold(true).Render("What happened?") + "\n")
		output.WriteString(fmt.Sprintf("    %s\n\n", d.Summary))
	}

	// Technical details
	if d.Technical != "" {
		output.WriteString(lipgloss.NewStyle().Bold(true).Render("Technical Details:") + "\n")
		for _, line := range strings.Split(d.Technical, "\n") {
			if strings.TrimSpace(line) != "" {
				output.WriteString(fmt.Sprintf("    %s\n", line))
			}
		}
		output.WriteString("\n")
	}

	// Remediation
	if d.Remediation != "" {
		output.WriteString(lipgloss.NewStyle().Bold(true).Render("What should I do?") + "\n")
		for _, line := range strings.Split(d.Remediation, "\n") {
			if strings.TrimSpace(line) != "" {
				output.WriteString(fmt.Sprintf("    %s\n", line))
			}
		}
		output.WriteString("\n")
	}

	// Learning link
	if d.LearningLink != "" {
		output.WriteString(mutedStyle.Render(fmt.Sprintf("    Learn more: %s\n", d.LearningLink)))
	}

	return boxStyle.Render(output.String())
}

// FormatTable renders detections in a table format
func FormatTable(detections []*models.Detection) string {
	if len(detections) == 0 {
		return mutedStyle.Render("No threats detected")
	}

	var output strings.Builder

	// Table header
	output.WriteString(tableHeaderStyle.Render(fmt.Sprintf("%-25s %-30s %-15s", "TIME", "EVENT", "SEVERITY")))
	output.WriteString("\n")
	output.WriteString(strings.Repeat("─", 75))
	output.WriteString("\n")

	// Rows
	for _, d := range detections {
		timestamp := d.DetectedAt.Format("15:04:05")
		event := truncate(d.RuleName, 30)
		
		var severityStr string
		switch d.Severity {
		case models.SeverityCritical:
			severityStr = criticalStyle.Render("🔴 CRITICAL")
		case models.SeverityWarning:
			severityStr = warningStyle.Render("🟠 WARNING")
		case models.SeverityInfo:
			severityStr = infoStyle.Render("🟢 INFO")
		}

		output.WriteString(fmt.Sprintf("%-25s %-30s %s\n", timestamp, event, severityStr))
	}

	return output.String()
}

// FormatNetworkTable renders network connections in table format
func FormatNetworkTable(connections []*models.NetworkConnection) string {
	if len(connections) == 0 {
		return mutedStyle.Render("No active connections")
	}

	var output strings.Builder

	// Table header
	output.WriteString(tableHeaderStyle.Render(fmt.Sprintf("%-20s %-6s %-25s %-25s %-12s", 
		"PROCESS", "PID", "LOCAL", "REMOTE", "STATE")))
	output.WriteString("\n")
	output.WriteString(strings.Repeat("─", 95))
	output.WriteString("\n")

	// Rows
	for _, conn := range connections {
		processName := truncate(conn.ProcessName, 20)
		pid := fmt.Sprintf("%d", conn.PID)
		local := fmt.Sprintf("%s:%d", truncate(conn.LocalAddr, 15), conn.LocalPort)
		
		// Use domain if available, otherwise IP
		remoteName := conn.RemoteAddr
		if conn.Domain != "" && conn.Domain != conn.RemoteAddr {
			remoteName = conn.Domain
		}
		remote := fmt.Sprintf("%s:%d", truncate(remoteName, 15), conn.RemotePort)
		
		state := conn.State
		
		// Highlight suspicious connections
		style := lipgloss.NewStyle()
		if len(conn.Tags) > 0 {
			style = warningStyle
		}

		line := fmt.Sprintf("%-20s %-6s %-25s %-25s %-12s", 
			processName, pid, local, remote, state)
		
		output.WriteString(style.Render(line))
		
		// Show tags if present
		if len(conn.Tags) > 0 {
			output.WriteString(criticalStyle.Render(fmt.Sprintf(" [%s]", strings.Join(conn.Tags, ", "))))
		}
		
		output.WriteString("\n")
	}

	return output.String()
}

// FormatHeader creates a banner header
func FormatHeader() string {
	logo := `
 ███╗   ██╗██╗   ██╗██╗     ██╗         ██╗      ██████╗  ██████╗ 
 ████╗  ██║██║   ██║██║     ██║         ██║     ██╔═══██╗██╔════╝ 
 ██╔██╗ ██║██║   ██║██║     ██║         ██║     ██║   ██║██║  ███╗
 ██║╚██╗██║██║   ██║██║     ██║         ██║     ██║   ██║██║   ██║
 ██║ ╚████║╚██████╔╝███████╗███████╗    ███████╗╚██████╔╝╚██████╔╝
 ╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚══════╝    ╚══════╝ ╚═════╝  ╚═════╝ 
`
	header := headerStyle.Render(logo)
	tagline := mutedStyle.Render("Elite-tier security observability for everyone")
	
	return header + "\n" + tagline + "\n"
}

// FormatStats renders system statistics
func FormatStats(totalEvents, totalDetections, criticalCount int) string {
	stats := fmt.Sprintf(
		"Events: %s | Detections: %s | Critical: %s",
		infoStyle.Render(fmt.Sprintf("%d", totalEvents)),
		warningStyle.Render(fmt.Sprintf("%d", totalDetections)),
		criticalStyle.Render(fmt.Sprintf("%d", criticalCount)),
	)
	return boxStyle.Render(stats)
}

// FormatHelp renders help text
func FormatHelp() string {
	help := `
Controls:
  [?] Toggle this help
  [q] Quit
  [c] Clear screen
  [↑↓] Scroll events
  [r] Refresh
`
	return mutedStyle.Render(help)
}

// FormatLegalDisclaimer renders the first-run disclaimer
func FormatLegalDisclaimer() string {
	disclaimer := `
═══════════════════════════════════════════════════════════════════
                         LEGAL DISCLAIMER
═══════════════════════════════════════════════════════════════════

null.log is a defensive security tool designed for:
  • Monitoring systems YOU OWN
  • Systems you have EXPLICIT PERMISSION to monitor
  • Educational and research purposes on isolated environments

This tool:
  ✓ Processes ALL data locally (100% offline, 100% private)
  ✓ Never phones home or sends telemetry
  ✓ Requires appropriate system permissions to read logs

You are responsible for:
  • Complying with applicable laws and regulations
  • Obtaining proper authorization before use
  • Using this tool ethically and responsibly

By proceeding, you acknowledge that you understand and accept
these terms.

Press ENTER to continue...
═══════════════════════════════════════════════════════════════════
`
	return disclaimer
}

// truncate shortens a string to fit in a column
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// FormatTimeSince returns a human-readable time duration
func FormatTimeSince(t time.Time) string {
	duration := time.Since(t)
	
	if duration < time.Minute {
		return fmt.Sprintf("%ds ago", int(duration.Seconds()))
	} else if duration < time.Hour {
		return fmt.Sprintf("%dm ago", int(duration.Minutes()))
	} else if duration < 24*time.Hour {
		return fmt.Sprintf("%dh ago", int(duration.Hours()))
	}
	
	return fmt.Sprintf("%dd ago", int(duration.Hours()/24))
}
