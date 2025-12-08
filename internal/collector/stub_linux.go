//go:build linux
// +build linux

package collector

import (
	"context"
	"github.com/nullsector/null-log/pkg/models"
)

// Stub collectors for Windows and macOS when running on Linux

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
