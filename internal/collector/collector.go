package collector

import (
	"context"
	"github.com/nullsector/null-log/pkg/models"
)

// Collector is the interface all platform-specific collectors must implement
type Collector interface {
	// Start begins collecting logs and sends events to the channel
	Start(ctx context.Context, events chan<- *models.Event) error
	
	// Name returns the collector name
	Name() string
	
	// IsAvailable checks if this collector can run on the current system
	IsAvailable() bool
}

// Manager coordinates multiple collectors
type Manager struct {
	collectors []Collector
	events     chan *models.Event
}

// NewManager creates a new collector manager
func NewManager() *Manager {
	return &Manager{
		collectors: []Collector{},
		events:     make(chan *models.Event, 1000),
	}
}

// Register adds a collector to the manager
func (m *Manager) Register(c Collector) {
	if c.IsAvailable() {
		m.collectors = append(m.collectors, c)
	}
}

// Start begins all registered collectors
func (m *Manager) Start(ctx context.Context) (<-chan *models.Event, error) {
	for _, collector := range m.collectors {
		go func(c Collector) {
			if err := c.Start(ctx, m.events); err != nil {
				// Log error but don't crash - graceful degradation
			}
		}(collector)
	}
	return m.events, nil
}

// GetActiveCollectors returns list of running collectors
func (m *Manager) GetActiveCollectors() []string {
	names := make([]string, len(m.collectors))
	for i, c := range m.collectors {
		names[i] = c.Name()
	}
	return names
}
