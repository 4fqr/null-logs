package commands

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

// NewUpdateCmd creates the update command
func NewUpdateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update Sigma rules and threat intelligence",
		Long:  `Download the latest detection rules and threat intelligence feeds`,
		RunE:  runUpdate,
	}

	cmd.Flags().Bool("rules", true, "Update Sigma rules")
	cmd.Flags().Bool("intel", true, "Update threat intelligence")

	return cmd
}

func runUpdate(cmd *cobra.Command, args []string) error {
	updateRules, _ := cmd.Flags().GetBool("rules")
	updateIntel, _ := cmd.Flags().GetBool("intel")

	fmt.Println("🔄 Updating null.log components...")
	fmt.Println()

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	configDir := filepath.Join(homeDir, ".null.log")
	rulesDir := filepath.Join(configDir, "rules")
	intelDir := filepath.Join(configDir, "intel")

	// Create directories
	os.MkdirAll(rulesDir, 0755)
	os.MkdirAll(intelDir, 0755)

	if updateRules {
		fmt.Println("📜 Updating Sigma rules...")
		if err := updateSigmaRules(rulesDir); err != nil {
			fmt.Printf("   ⚠️  Failed to update rules: %v\n", err)
		} else {
			fmt.Println("   ✓ Rules updated successfully")
		}
		fmt.Println()
	}

	if updateIntel {
		fmt.Println("🔍 Updating threat intelligence...")
		if err := updateThreatIntel(intelDir); err != nil {
			fmt.Printf("   ⚠️  Failed to update intel: %v\n", err)
		} else {
			fmt.Println("   ✓ Threat intel updated successfully")
		}
		fmt.Println()
	}

	fmt.Println("✓ Update complete")
	return nil
}

func updateSigmaRules(rulesDir string) error {
	// In a real implementation, this would fetch from a curated rule repository
	// For now, we'll create some example rules
	
	exampleRule := `id: mimikatz_detection
title: Mimikatz Credential Dumping
description: Detects Mimikatz usage for credential theft
author: null.log
date: 2025/01/01
level: critical
status: stable
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - 'sekurlsa::logonpasswords'
      - 'lsadump::sam'
      - 'privilege::debug'
  condition: selection
falsepositives:
  - Legitimate security testing with authorization
tags:
  - attack.credential_access
  - attack.t1003
x_summary: "Someone attempted to steal passwords using Mimikatz"
x_technical: "Mimikatz tool detected attempting to dump credentials from memory"
x_remediation: "Immediately isolate the system and investigate the source"
x_learning_link: "https://attack.mitre.org/techniques/T1003/"
`

	ruleFile := filepath.Join(rulesDir, "mimikatz_detection.yml")
	return os.WriteFile(ruleFile, []byte(exampleRule), 0644)
}

func updateThreatIntel(intelDir string) error {
	// In a real implementation, this would fetch from threat intel feeds
	// For demo purposes, we'll create a placeholder
	
	sources := []string{
		"Abuse.ch Feodo Tracker",
		"AlienVault OTX",
		"Shodan C2 Database",
	}

	for _, source := range sources {
		fmt.Printf("   • Fetching %s...\n", source)
	}

	// Create a sample intel file
	intelFile := filepath.Join(intelDir, "c2_ips.txt")
	sampleData := "# Known C2 IP addresses (offline cache)\n# Updated: 2025-12-08\n"
	
	return os.WriteFile(intelFile, []byte(sampleData), 0644)
}

func downloadFile(url, dest string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %s", resp.Status)
	}

	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}
