//go:build darwin
// +build darwin

package collector

import (
	"context"
	"github.com/nullsector/null-log/pkg/models"
)

// Stub collectors for Windows and Linux when running on macOS

type WindowsEventCollector struct{}

func NewWindowsEventCollector() *WindowsEventCollector {
	return &WindowsEventCollector{}
}

func (w *WindowsEventCollector) Name() string {
	return "windows_event_log"
}

func (w *WindowsEventCollector) IsAvailable() bool {
	return false
}

func (w *WindowsEventCollector) Start(ctx context.Context, events chan<- *models.Event) error {
	return nil
}

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
