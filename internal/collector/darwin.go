//go:build darwin
// +build darwin

package collector

import (
	"bufio"
	"context"
	"os/exec"
	"strings"
	"time"

	"github.com/nullsector/null-log/pkg/models"
)

// DarwinUnifiedLogCollector collects logs from macOS Unified Logging
type DarwinUnifiedLogCollector struct{}

func NewDarwinUnifiedLogCollector() *DarwinUnifiedLogCollector {
	return &DarwinUnifiedLogCollector{}
}

func (d *DarwinUnifiedLogCollector) Name() string {
	return "macOS Unified Logging"
}

func (d *DarwinUnifiedLogCollector) IsAvailable() bool {
	_, err := exec.LookPath("log")
	return err == nil
}

func (d *DarwinUnifiedLogCollector) Start(ctx context.Context, events chan<- *models.Event) error {
	// Stream logs with predicates for security-relevant events
	cmd := exec.CommandContext(ctx, "log", "stream",
		"--predicate", "eventType == 'logEvent' OR eventType == 'activityCreateEvent'",
		"--style", "json")
	
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
		if evt := d.parseUnifiedLogEntry(line); evt != nil {
			select {
			case events <- evt:
			case <-ctx.Done():
				return nil
			}
		}
	}

	return cmd.Wait()
}

func (d *DarwinUnifiedLogCollector) parseUnifiedLogEntry(jsonLine string) *models.Event {
	evt := &models.Event{
		Timestamp: time.Now(),
		Source:    "unified_log",
		Metadata:  make(map[string]interface{}),
		RawLog:    jsonLine,
	}

	// Simplified JSON parsing
	if strings.Contains(jsonLine, "\"processImagePath\"") {
		parts := strings.Split(jsonLine, "\"processImagePath\":\"")
		if len(parts) > 1 {
			evt.ProcessName = strings.Split(parts[1], "\"")[0]
		}
	}

	if strings.Contains(jsonLine, "\"eventMessage\"") {
		parts := strings.Split(jsonLine, "\"eventMessage\":\"")
		if len(parts) > 1 {
			evt.EventType = strings.Split(parts[1], "\"")[0]
		}
	}

	return evt
}
