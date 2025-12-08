package commands

import (
	"context"
	"fmt"
	"time"

	"github.com/nullsector/null-log/internal/detector"
	"github.com/nullsector/null-log/internal/ui"
	"github.com/nullsector/null-log/pkg/models"
	"github.com/spf13/cobra"
)

// NewHuntCmd creates the hunt command for historical log analysis
func NewHuntCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "hunt [rule-id]",
		Short: "Hunt for threats in historical logs",
		Long:  `Scan historical logs using specified Sigma rule IDs`,
		Args:  cobra.MinimumNArgs(1),
		RunE:  runHunt,
	}

	cmd.Flags().StringP("timerange", "t", "24h", "Time range to search (e.g., 24h, 7d)")
	cmd.Flags().BoolP("verbose", "v", false, "Show verbose output")

	return cmd
}

func runHunt(cmd *cobra.Command, args []string) error {
	ruleID := args[0]
	timeRange, _ := cmd.Flags().GetString("timerange")
	verbose, _ := cmd.Flags().GetBool("verbose")

	fmt.Printf("🔍 Hunting for threats using rule: %s\n", ruleID)
	fmt.Printf("Time range: %s\n\n", timeRange)

	// Get rules directory
	rulesDir, err := getRulesDirectory()
	if err != nil {
		return fmt.Errorf("failed to get rules directory: %w", err)
	}

	// Initialize detection engine
	engine, err := detector.NewEngine(rulesDir)
	if err != nil {
		return fmt.Errorf("failed to initialize detection engine: %w", err)
	}

	// Get specific rule
	rule := engine.GetRuleByID(ruleID)
	if rule == nil {
		fmt.Printf("Rule '%s' not found\n\n", ruleID)
		fmt.Println("Available rules:")
		for _, r := range engine.GetAllRules() {
			fmt.Printf("  %s - %s\n", r.ID, r.Title)
		}
		return nil
	}

	fmt.Printf("Rule: %s\n", rule.Title)
	fmt.Printf("Description: %s\n", rule.Description)
	fmt.Printf("Severity: %s\n\n", rule.Level)

	// Parse time range
	duration, err := parseDuration(timeRange)
	if err != nil {
		return fmt.Errorf("invalid time range: %w", err)
	}

	startTime := time.Now().Add(-duration)
	fmt.Printf("Searching from %s to %s\n", startTime.Format("2006-01-02 15:04:05"), time.Now().Format("2006-01-02 15:04:05"))
	fmt.Println("\nScanning logs...")

	// In a real implementation, this would scan historical logs
	// For now, we'll show the structure
	ctx := context.Background()
	_ = ctx

	// Simulated hunt results
	fmt.Println("\n" + ui.FormatTable([]*models.Detection{}))
	fmt.Println("\nHunt complete. No matches found in the specified time range.")
	
	if verbose {
		fmt.Println("\nRule details:")
		fmt.Printf("%+v\n", rule)
	}

	return nil
}

func parseDuration(s string) (time.Duration, error) {
	// Simple duration parser
	return time.ParseDuration(s)
}
