package commands

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/nullsector/null-log/internal/collector"
	"github.com/nullsector/null-log/internal/detector"
	"github.com/nullsector/null-log/internal/ui"
	"github.com/spf13/cobra"
)

// NewLiveCmd creates the live monitoring command
func NewLiveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "live",
		Short: "Real-time security monitoring dashboard",
		Long:  `Start the live monitoring dashboard with real-time threat detection`,
		RunE:  runLive,
	}

	return cmd
}

func runLive(cmd *cobra.Command, args []string) error {
	// Show legal disclaimer on first run
	if !hasAcceptedDisclaimer() {
		fmt.Print(ui.FormatLegalDisclaimer())
		reader := bufio.NewReader(os.Stdin)
		reader.ReadString('\n')
		markDisclaimerAccepted()
	}

	// Initialize components
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		cancel()
	}()

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

	fmt.Printf("Loaded %d detection rules\n", len(engine.GetAllRules()))

	// Initialize collectors
	collectorMgr := collector.NewManager()
	
	// Register platform-specific collectors
	switch runtime.GOOS {
	case "windows":
		collectorMgr.Register(collector.NewWindowsEventCollector())
	case "linux":
		collectorMgr.Register(collector.NewLinuxJournalCollector())
		collectorMgr.Register(collector.NewLinuxAuthLogCollector())
	case "darwin":
		collectorMgr.Register(collector.NewDarwinUnifiedLogCollector())
	}

	activeCollectors := collectorMgr.GetActiveCollectors()
	fmt.Printf("Active collectors: %v\n", activeCollectors)
	
	if len(activeCollectors) == 0 {
		return fmt.Errorf("no log collectors available on this system")
	}

	// Start collecting events
	events, err := collectorMgr.Start(ctx)
	if err != nil {
		return fmt.Errorf("failed to start collectors: %w", err)
	}

	fmt.Println("\nStarting live monitoring dashboard...")
	time.Sleep(2 * time.Second)

	// Initialize UI
	model := ui.NewLiveModel()
	p := tea.NewProgram(model, tea.WithAltScreen())

	// Process events in background
	go func() {
		totalEvents := 0
		criticalCount := 0

		for {
			select {
			case <-ctx.Done():
				return
			case event := <-events:
				if event == nil {
					continue
				}

				totalEvents++

				// Analyze event for threats
				detections := engine.Analyze(ctx, event)
				for _, detection := range detections {
					if detection.Severity == "CRITICAL" {
						criticalCount++
					}
					
					// Send to UI
					p.Send(detection)
				}

				// Update stats periodically
				if totalEvents%10 == 0 {
					p.Send(ui.UpdateStats(totalEvents, criticalCount))
				}
			}
		}
	}()

	// Run UI
	if _, err := p.Run(); err != nil {
		return fmt.Errorf("error running UI: %w", err)
	}

	return nil
}

// getRulesDirectory returns the path to Sigma rules
func getRulesDirectory() (string, error) {
	// Try multiple locations in order of priority
	
	// 1. Current working directory ./rules
	cwd, _ := os.Getwd()
	cwdRules := filepath.Join(cwd, "rules")
	if _, err := os.Stat(cwdRules); err == nil {
		entries, _ := os.ReadDir(cwdRules)
		if len(entries) > 0 {
			return cwdRules, nil
		}
	}
	
	// 2. Executable directory ./rules (for when binary is moved)
	exePath, err := os.Executable()
	if err == nil {
		exeDir := filepath.Dir(exePath)
		exeRules := filepath.Join(exeDir, "rules")
		if _, err := os.Stat(exeRules); err == nil {
			entries, _ := os.ReadDir(exeRules)
			if len(entries) > 0 {
				return exeRules, nil
			}
		}
		
		// 3. One level up from executable (for bin/null-log.exe case)
		parentRules := filepath.Join(filepath.Dir(exeDir), "rules")
		if _, err := os.Stat(parentRules); err == nil {
			entries, _ := os.ReadDir(parentRules)
			if len(entries) > 0 {
				return parentRules, nil
			}
		}
	}

	// 4. User config directory
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %w", err)
	}

	userRulesDir := filepath.Join(homeDir, ".null.log", "rules")
	if err := os.MkdirAll(userRulesDir, 0755); err != nil {
		return "", err
	}

	return userRulesDir, nil
}

// hasAcceptedDisclaimer checks if user has accepted the legal disclaimer
func hasAcceptedDisclaimer() bool {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return false
	}

	flagFile := filepath.Join(homeDir, ".null.log", ".disclaimer_accepted")
	_, err = os.Stat(flagFile)
	return err == nil
}

// markDisclaimerAccepted creates a flag file
func markDisclaimerAccepted() error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	configDir := filepath.Join(homeDir, ".null.log")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return err
	}

	flagFile := filepath.Join(configDir, ".disclaimer_accepted")
	return os.WriteFile(flagFile, []byte(time.Now().Format(time.RFC3339)), 0644)
}
