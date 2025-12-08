package commands

import (
	"fmt"
	"strings"

	"github.com/nullsector/null-log/internal/ui"
	"github.com/nullsector/null-log/pkg/models"
	"github.com/nullsector/null-log/pkg/network"
	"github.com/spf13/cobra"
)

// NewNetCmd creates the network monitoring command
func NewNetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "net",
		Short: "Show active network connections",
		Long:  `Display all active network connections with process info and threat intelligence`,
		RunE:  runNet,
	}

	cmd.Flags().BoolP("verbose", "v", false, "Show detailed connection info")
	cmd.Flags().StringP("filter", "f", "", "Filter by process name")

	return cmd
}

func runNet(cmd *cobra.Command, args []string) error {
	verbose, _ := cmd.Flags().GetBool("verbose")
	filter, _ := cmd.Flags().GetString("filter")

	fmt.Println("🌐 Scanning active network connections...\n")

	scanner := network.NewScanner()
	connections, err := scanner.GetActiveConnections()
	if err != nil {
		return fmt.Errorf("failed to scan connections: %w", err)
	}

	// Apply filter if specified
	if filter != "" {
		var filtered []*models.NetworkConnection
		for _, conn := range connections {
			if strings.Contains(strings.ToLower(conn.ProcessName), strings.ToLower(filter)) {
				filtered = append(filtered, conn)
			}
		}
		connections = filtered
	}

	fmt.Printf("Found %d active connections\n\n", len(connections))
	fmt.Println(ui.FormatNetworkTable(connections))

	if verbose {
		fmt.Println("\nDetailed Information:")
		for _, conn := range connections {
			if conn.JA3Hash != "" {
				fmt.Printf("  %s:%d -> JA3: %s\n", conn.ProcessName, conn.PID, conn.JA3Hash)
			}
			if len(conn.Tags) > 0 {
				fmt.Printf("    Tags: %v\n", conn.Tags)
			}
		}
	}

	// Highlight suspicious connections
	suspiciousCount := 0
	for _, conn := range connections {
		if len(conn.Tags) > 0 {
			suspiciousCount++
		}
	}

	if suspiciousCount > 0 {
		fmt.Printf("\n⚠️  Found %d suspicious connections!\n", suspiciousCount)
		fmt.Println("Run 'null.log live' for real-time threat detection")
	}

	return nil
}
