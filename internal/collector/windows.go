//go:build windows
// +build windows

package collector

import (
	"context"
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
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
	// Generate realistic attack simulations so users see detections immediately
	go func() {
		username := os.Getenv("USERNAME")
		if username == "" {
			username = "SYSTEM"
		}

		// Wait a bit then generate attack events
		time.Sleep(1 * time.Second)

		// 1. Suspicious PowerShell with bypass
		events <- &models.Event{
			ID:            "demo_attack_1",
			Timestamp:     time.Now(),
			Source:        "Security",
			EventType:     "process_creation",
			ProcessName:   "powershell.exe",
			ProcessID:     8472,
			User:          username,
			CommandLine:   "powershell.exe -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -EncodedCommand JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtACgALABbAEMAbwBuAHYAZQByAHQAXQA6ADoARgByAG8AbQBCAGEAcwBlADYANABTAHQAcgBpAG4AZwAoACIASAA0AHMASQBBAEEAQQBBAEEAQQBBAEEAQQBLADEAVgB5ADIALwBiAE0AQgBBAC8AdwA9ACIALQA=",
			ParentProcess: "explorer.exe",
			RawLog:        "[SIMULATED] Malicious PowerShell detected - encoded payload execution",
			Metadata: map[string]interface{}{
				"EventID": 4688,
				"image":   "\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
			},
		}

		time.Sleep(2 * time.Second)

		// 2. Mimikatz credential dumping attempt
		events <- &models.Event{
			ID:            "demo_attack_2",
			Timestamp:     time.Now(),
			Source:        "Security",
			EventType:     "process_creation",
			ProcessName:   "rundll32.exe",
			ProcessID:     5632,
			User:          username,
			CommandLine:   "rundll32.exe C:\\Windows\\System32\\comsvcs.dll MiniDump 624 C:\\temp\\lsass.dmp full",
			ParentProcess: "cmd.exe",
			RawLog:        "[SIMULATED] LSASS memory dump attempt - credential theft",
			Metadata: map[string]interface{}{
				"EventID":        4688,
				"TargetFilename": "lsass.dmp",
			},
		}

		time.Sleep(2 * time.Second)

		// 3. Registry persistence
		events <- &models.Event{
			ID:          "demo_attack_3",
			Timestamp:   time.Now(),
			Source:      "Security",
			EventType:   "registry_value",
			ProcessName: "reg.exe",
			ProcessID:   9124,
			User:        username,
			CommandLine: "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v SecurityUpdate /t REG_SZ /d C:\\Windows\\Temp\\malware.exe /f",
			RawLog:      "[SIMULATED] Malicious registry run key added for persistence",
			Metadata: map[string]interface{}{
				"EventID":      13,
				"TargetObject": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\SecurityUpdate",
				"Details":      "C:\\Windows\\Temp\\malware.exe",
			},
		}

		time.Sleep(2 * time.Second)

		// 4. Suspicious scheduled task
		events <- &models.Event{
			ID:            "demo_attack_4",
			Timestamp:     time.Now(),
			Source:        "Security",
			EventType:     "process_creation",
			ProcessName:   "schtasks.exe",
			ProcessID:     7753,
			User:          username,
			CommandLine:   "schtasks /create /tn WindowsUpdate /tr C:\\Users\\Public\\update.exe /sc minute /mo 5 /ru SYSTEM",
			ParentProcess: "powershell.exe",
			RawLog:        "[SIMULATED] Suspicious scheduled task created for persistence",
			Metadata: map[string]interface{}{
				"EventID":  4698,
				"TaskName": "\\WindowsUpdate",
			},
		}

		time.Sleep(3 * time.Second)

		// 5. Windows Defender disabled
		events <- &models.Event{
			ID:          "demo_attack_5",
			Timestamp:   time.Now(),
			Source:      "Microsoft-Windows-Windows Defender",
			EventType:   "service_stopped",
			ProcessName: "powershell.exe",
			ProcessID:   4421,
			User:        username,
			CommandLine: "Set-MpPreference -DisableRealtimeMonitoring $true",
			RawLog:      "[SIMULATED] Windows Defender real-time protection disabled",
			Metadata: map[string]interface{}{
				"EventID": 5001,
				"Action":  "disabled",
			},
		}

		time.Sleep(2 * time.Second)

		// 6. Suspicious service creation
		events <- &models.Event{
			ID:          "demo_attack_6",
			Timestamp:   time.Now(),
			Source:      "System",
			EventType:   "service_creation",
			ProcessName: "services.exe",
			ProcessID:   624,
			User:        "SYSTEM",
			CommandLine: "sc create WindowsUpdateService binPath= C:\\ProgramData\\svchost.exe start= auto",
			RawLog:      "[SIMULATED] Suspicious service created with svchost name",
			Metadata: map[string]interface{}{
				"EventID":     7045,
				"ServiceName": "WindowsUpdateService",
				"ImagePath":   "C:\\ProgramData\\svchost.exe",
			},
		}

		time.Sleep(2 * time.Second)

		// 7. Suspicious driver load
		events <- &models.Event{
			ID:          "demo_attack_7",
			Timestamp:   time.Now(),
			Source:      "Security",
			EventType:   "driver_load",
			ProcessName: "System",
			ProcessID:   4,
			User:        "SYSTEM",
			CommandLine: "",
			RawLog:      "[SIMULATED] Unsigned kernel driver loaded - possible rootkit",
			Metadata: map[string]interface{}{
				"EventID":     6,
				"ImageLoaded": "\\??\\C:\\Windows\\System32\\drivers\\rtcore64.sys",
				"Signed":      "false",
			},
		}

		time.Sleep(3 * time.Second)

		// 8. WMI persistence
		events <- &models.Event{
			ID:            "demo_attack_8",
			Timestamp:     time.Now(),
			Source:        "Security",
			EventType:     "wmi_event",
			ProcessName:   "wmic.exe",
			ProcessID:     3358,
			User:          username,
			CommandLine:   "wmic /NAMESPACE:\\\\root\\subscription PATH __EventFilter CREATE Name=\"BotFilter\", EventNameSpace=\"root\\cimv2\",QueryLanguage=\"WQL\", Query=\"SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'\"",
			ParentProcess: "powershell.exe",
			RawLog:        "[SIMULATED] WMI event subscription created for persistence",
			Metadata: map[string]interface{}{
				"EventID":        19,
				"EventNamespace": "root\\subscription",
			},
		}

		// Continuous monitoring message
		time.Sleep(5 * time.Second)
		events <- &models.Event{
			ID:          "status_1",
			Timestamp:   time.Now(),
			Source:      "null.log",
			EventType:   "monitoring_active",
			ProcessName: "null-log.exe",
			ProcessID:   os.Getpid(),
			User:        username,
			RawLog:      "Real-time monitoring active - waiting for actual system events...",
			Metadata: map[string]interface{}{
				"status": "monitoring",
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
		EventID     int `xml:"EventID"`
		TimeCreated struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
		Computer string `xml:"Computer"`
		Channel  string `xml:"Channel"`
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
