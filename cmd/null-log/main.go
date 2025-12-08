package main

import (
	"fmt"
	"os"

	"github.com/nullsector/null-log/cmd/null-log/commands"
	"github.com/nullsector/null-log/internal/ui"
	"github.com/spf13/cobra"
)

var version = "1.0.0"

func main() {
	// Show beautiful banner
	ui.ShowBanner()
	
	rootCmd := &cobra.Command{
		Use:   "null.log",
		Short: "Elite-tier security observability for everyone",
		Long: `null.log - Production-grade, cross-platform security monitoring tool
		
Delivers professional threat detection with zero setup and no external dependencies.
Built for everyone from beginners to professional defenders.`,
		Version: version,
	}

	// Add commands
	rootCmd.AddCommand(commands.NewLiveCmd())
	rootCmd.AddCommand(commands.NewHuntCmd())
	rootCmd.AddCommand(commands.NewNetCmd())
	rootCmd.AddCommand(commands.NewReportCmd())
	rootCmd.AddCommand(commands.NewCleanCmd())
	rootCmd.AddCommand(commands.NewUpdateCmd())

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
