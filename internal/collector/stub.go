//go:build windows
// +build windows

package collector

import (
	"context"
	"github.com/nullsector/null-log/pkg/models"
)

// Stub collectors for Linux and macOS when running on Windows

type LinuxJournalCollector struct{}

func NewLinuxJournalCollector() *LinuxJournalCollector {
	return &LinuxJournalCollector{}
}

func (l *LinuxJournalCollector) Name() string {
	return "journalctl"
}

func (l *LinuxJournalCollector) IsAvailable() bool {
	return false
}

func (l *LinuxJournalCollector) Start(ctx context.Context, events chan<- *models.Event) error {
	return nil
}

type LinuxAuthLogCollector struct{}

func NewLinuxAuthLogCollector() *LinuxAuthLogCollector {
	return &LinuxAuthLogCollector{}
}

func (l *LinuxAuthLogCollector) Name() string {
	return "auth.log"
}

func (l *LinuxAuthLogCollector) IsAvailable() bool {
	return false
}

func (l *LinuxAuthLogCollector) Start(ctx context.Context, events chan<- *models.Event) error {
	return nil
}

type DarwinUnifiedLogCollector struct{}

func NewDarwinUnifiedLogCollector() *DarwinUnifiedLogCollector {
	return &DarwinUnifiedLogCollector{}
}

func (d *DarwinUnifiedLogCollector) Name() string {
	return "unified_log"
}

func (d *DarwinUnifiedLogCollector) IsAvailable() bool {
	return false
}

func (d *DarwinUnifiedLogCollector) Start(ctx context.Context, events chan<- *models.Event) error {
	return nil
}
