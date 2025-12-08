package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/nullsector/null-log/pkg/security"
	"github.com/spf13/cobra"
)

// NewCleanCmd creates the forensic cleanup command
func NewCleanCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "clean",
		Short: "Clean forensic artifacts (lab use only)",
		Long:  `Safely remove forensic artifacts after security labs - NEVER use on production systems`,
		RunE:  runClean,
	}

	cmd.Flags().Bool("dry-run", false, "Show what would be cleaned without actually cleaning")
	cmd.Flags().Bool("apply", false, "Actually perform cleanup (required for safety)")

	return cmd
}

func runClean(cmd *cobra.Command, args []string) error {
	dryRun, _ := cmd.Flags().GetBool("dry-run")
	apply, _ := cmd.Flags().GetBool("apply")

	if !dryRun && !apply {
		fmt.Println("⚠️  ERROR: This command requires either --dry-run or --apply flag")
		fmt.Println("\nThe clean command can delete system files. Use with extreme caution!")
		fmt.Println("\nUsage:")
		fmt.Println("  null.log clean --dry-run   # Preview what would be cleaned")
		fmt.Println("  null.log clean --apply     # Actually perform cleanup")
		return nil
	}

	// Security validation
	validator := security.NewValidator()
	
	// Warn about destructive operation
	fmt.Println("\n⚠️  WARNING: DESTRUCTIVE OPERATION")
	fmt.Println("This command is designed for lab environments only.")
	fmt.Println("NEVER use on production systems.")
	fmt.Println("═════════════════════════════════════════════════════\n")

	fmt.Println("🧹 Forensic Artifact Cleanup Tool")
	fmt.Println("═════════════════════════════════\n")

	if dryRun {
		fmt.Println("DRY RUN MODE - No files will be deleted\n")
	} else {
		fmt.Println("⚠️  LIVE MODE - Files will be permanently deleted!")
		fmt.Println("Press Ctrl+C now to abort...\n")
	}

	// Get home directory for validation
	homeDir, _ := os.UserHomeDir()
	
	// Define cleanup targets
	targets := getCleanupTargets()

	fmt.Printf("Found %d cleanup targets:\n\n", len(targets))

	for _, target := range targets {
		exists := fileExists(target.Path)
		status := "NOT FOUND"
		if exists {
			status = "FOUND"
		}

		fmt.Printf("[%s] %s\n", status, target.Description)
		fmt.Printf("        %s\n", target.Path)

		if exists && apply {
			// Security check: never delete system-critical paths
			if isCriticalPath(target.Path) {
				fmt.Printf("        SKIPPED: Critical system path\n")
				continue
			}
			
			// Validate path safety
			if err := validator.ValidateFilePath(target.Path, []string{homeDir, os.TempDir()}); err != nil {
				fmt.Printf("        SKIPPED: %v\n", err)
				continue
			}
			
			if err := os.Remove(target.Path); err != nil {
				fmt.Printf("        ERROR: %v\n", err)
			} else {
				fmt.Printf("        ✓ DELETED\n")
			}
		}
		fmt.Println()
	}

	if dryRun {
		fmt.Println("Dry run complete. Use --apply to actually clean these files.")
	} else {
		fmt.Println("✓ Cleanup complete")
	}

	return nil
}

type CleanupTarget struct {
	Path        string
	Description string
}

// isCriticalPath prevents deletion of system-critical paths
func isCriticalPath(path string) bool {
	critical := []string{
		"C:\\Windows",
		"C:\\Program Files",
		"/etc",
		"/bin",
		"/sbin",
		"/usr/bin",
		"/usr/sbin",
		"/System",
		"/Library",
	}
	
	cleanPath := filepath.Clean(path)
	for _, crit := range critical {
		if strings.HasPrefix(cleanPath, crit) {
			return true
		}
	}
	
	return false
}

func getCleanupTargets() []CleanupTarget {
	homeDir, _ := os.UserHomeDir()
	
	targets := []CleanupTarget{}

	switch runtime.GOOS {
	case "windows":
		targets = append(targets,
			CleanupTarget{
				Path:        filepath.Join(os.Getenv("TEMP"), "*.log"),
				Description: "Temporary log files",
			},
			CleanupTarget{
				Path:        filepath.Join(homeDir, "AppData", "Local", "Temp", "*.tmp"),
				Description: "Temporary files",
			},
		)

	case "linux", "darwin":
		targets = append(targets,
			CleanupTarget{
				Path:        filepath.Join(homeDir, ".bash_history"),
				Description: "Bash history",
			},
			CleanupTarget{
				Path:        filepath.Join(homeDir, ".zsh_history"),
				Description: "Zsh history",
			},
			CleanupTarget{
				Path:        "/tmp/*.log",
				Description: "Temporary log files",
			},
		)
	}

	return targets
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
