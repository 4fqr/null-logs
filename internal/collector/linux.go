//go:build linux
// +build linux

package collector

import (
	"bufio"
	"context"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/nullsector/null-log/pkg/models"
)

// LinuxJournalCollector collects logs from journalctl
type LinuxJournalCollector struct{}

func NewLinuxJournalCollector() *LinuxJournalCollector {
	return &LinuxJournalCollector{}
}

func (l *LinuxJournalCollector) Name() string {
	return "journalctl"
}

func (l *LinuxJournalCollector) IsAvailable() bool {
	_, err := exec.LookPath("journalctl")
	return err == nil
}

func (l *LinuxJournalCollector) Start(ctx context.Context, events chan<- *models.Event) error {
	// Start journalctl in follow mode with JSON output
	cmd := exec.CommandContext(ctx, "journalctl", "-f", "-o", "json", "--no-pager")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}

	if err := cmd.Start(); err != nil {
		return err
	}

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		if evt := l.parseJournalEntry(line); evt != nil {
			select {
			case events <- evt:
			case <-ctx.Done():
				return nil
			}
		}
	}

	return cmd.Wait()
}

func (l *LinuxJournalCollector) parseJournalEntry(jsonLine string) *models.Event {
	// Simplified JSON parsing - in production use encoding/json
	evt := &models.Event{
		Timestamp: time.Now(),
		Source:    "journald",
		Metadata:  make(map[string]interface{}),
	}

	// Extract key fields (simplified parser)
	if strings.Contains(jsonLine, "_PID") {
		parts := strings.Split(jsonLine, "\"_PID\":\"")
		if len(parts) > 1 {
			pidStr := strings.Split(parts[1], "\"")[0]
			if pid, err := strconv.Atoi(pidStr); err == nil {
				evt.ProcessID = pid
			}
		}
	}

	if strings.Contains(jsonLine, "_COMM") {
		parts := strings.Split(jsonLine, "\"_COMM\":\"")
		if len(parts) > 1 {
			evt.ProcessName = strings.Split(parts[1], "\"")[0]
		}
	}

	evt.RawLog = jsonLine
	return evt
}

// LinuxAuthLogCollector reads /var/log/auth.log
type LinuxAuthLogCollector struct{}

func NewLinuxAuthLogCollector() *LinuxAuthLogCollector {
	return &LinuxAuthLogCollector{}
}

func (l *LinuxAuthLogCollector) Name() string {
	return "auth.log"
}

func (l *LinuxAuthLogCollector) IsAvailable() bool {
	cmd := exec.Command("test", "-f", "/var/log/auth.log")
	return cmd.Run() == nil
}

func (l *LinuxAuthLogCollector) Start(ctx context.Context, events chan<- *models.Event) error {
	cmd := exec.CommandContext(ctx, "tail", "-f", "/var/log/auth.log")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}

	if err := cmd.Start(); err != nil {
		return err
	}

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		evt := &models.Event{
			Timestamp: time.Now(),
			Source:    "/var/log/auth.log",
			RawLog:    line,
			EventType: "auth",
			Metadata:  make(map[string]interface{}),
		}

		// Parse SSH/sudo events
		if strings.Contains(line, "sshd") {
			evt.ProcessName = "sshd"
			if strings.Contains(line, "Accepted") {
				evt.EventType = "ssh_login_success"
			} else if strings.Contains(line, "Failed") {
				evt.EventType = "ssh_login_failed"
			}
		} else if strings.Contains(line, "sudo") {
			evt.ProcessName = "sudo"
			evt.EventType = "sudo_command"
		}

		select {
		case events <- evt:
		case <-ctx.Done():
			return nil
		}
	}

	return cmd.Wait()
}
