package ui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/nullsector/null-log/pkg/models"
)

// LiveModel represents the state of the live dashboard
type LiveModel struct {
	detections     []*models.Detection
	width          int
	height         int
	showHelp       bool
	lastUpdate     time.Time
	totalEvents    int
	criticalCount  int
}

type tickMsg time.Time
type detectionMsg *models.Detection
type statsMsg struct {
	events    int
	critical  int
}

// NewLiveModel creates a new live dashboard model
func NewLiveModel() LiveModel {
	return LiveModel{
		detections:    make([]*models.Detection, 0),
		showHelp:      false,
		lastUpdate:    time.Now(),
		totalEvents:   0,
		criticalCount: 0,
	}
}

func (m LiveModel) Init() tea.Cmd {
	return tea.Batch(
		tickCmd(),
		tea.EnterAltScreen,
	)
}

func (m LiveModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "?":
			m.showHelp = !m.showHelp
		case "c":
			m.detections = make([]*models.Detection, 0)
		case "r":
			// Refresh trigger
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case tickMsg:
		m.lastUpdate = time.Time(msg)
		return m, tickCmd()

	case detectionMsg:
		m.detections = append(m.detections, msg)
		m.totalEvents++
		
		if msg.Severity == models.SeverityCritical {
			m.criticalCount++
		}
		
		// Keep only last 100 detections
		if len(m.detections) > 100 {
			m.detections = m.detections[1:]
		}

	case statsMsg:
		m.totalEvents = msg.events
		m.criticalCount = msg.critical
	}

	return m, nil
}

func (m LiveModel) View() string {
	if m.width == 0 {
		return "Initializing..."
	}

	doc := strings.Builder{}

	// Header
	doc.WriteString(FormatHeader())
	doc.WriteString("\n")

	// Stats bar
	doc.WriteString(FormatStats(m.totalEvents, len(m.detections), m.criticalCount))
	doc.WriteString("\n\n")

	// Main content
	if m.showHelp {
		doc.WriteString(FormatHelp())
	} else {
		// Recent detections table
		if len(m.detections) > 0 {
			doc.WriteString(headerStyle.Render("RECENT DETECTIONS"))
			doc.WriteString("\n\n")
			
			// Show last 10 detections
			start := 0
			if len(m.detections) > 10 {
				start = len(m.detections) - 10
			}
			
			doc.WriteString(FormatTable(m.detections[start:]))
		} else {
			doc.WriteString(mutedStyle.Render("Monitoring... No threats detected yet."))
		}
	}

	// Footer
	doc.WriteString("\n\n")
	footer := mutedStyle.Render(fmt.Sprintf(
		"Last update: %s | Press ? for help | Press q to quit",
		m.lastUpdate.Format("15:04:05"),
	))
	doc.WriteString(footer)

	// Fit to window
	return lipgloss.NewStyle().
		Width(m.width).
		Height(m.height).
		Render(doc.String())
}

func tickCmd() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

// AddDetection sends a detection to the UI
func AddDetection(d *models.Detection) tea.Cmd {
	return func() tea.Msg {
		return detectionMsg(d)
	}
}

// UpdateStats updates the stats display
func UpdateStats(events, critical int) tea.Cmd {
	return func() tea.Msg {
		return statsMsg{events: events, critical: critical}
	}
}

// Key bindings
type keyMap struct {
	Quit key.Binding
	Help key.Binding
	Clear key.Binding
}

var keys = keyMap{
	Quit: key.NewBinding(
		key.WithKeys("q", "ctrl+c"),
		key.WithHelp("q", "quit"),
	),
	Help: key.NewBinding(
		key.WithKeys("?"),
		key.WithHelp("?", "toggle help"),
	),
	Clear: key.NewBinding(
		key.WithKeys("c"),
		key.WithHelp("c", "clear screen"),
	),
}
