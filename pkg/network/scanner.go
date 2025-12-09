package network

import (
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nullsector/null-log/pkg/models"
)

// Scanner provides cross-platform network connection monitoring with threat detection
type Scanner struct {
	connectionHistory map[string]*ConnectionStats
	historyMux        sync.RWMutex
}

// ConnectionStats tracks connection patterns for threat detection
type ConnectionStats struct {
	FirstSeen       time.Time
	LastSeen        time.Time
	ConnectionCount int
	Ports           map[int]int // port -> connection count
	RemoteIPs       map[string]int
	BytesSent       int64
	BytesReceived   int64
}

// NewScanner creates a new network scanner
func NewScanner() *Scanner {
	return &Scanner{
		connectionHistory: make(map[string]*ConnectionStats),
	}
}

// GetActiveConnections returns all active network connections
func (s *Scanner) GetActiveConnections() ([]*models.NetworkConnection, error) {
	switch runtime.GOOS {
	case "windows":
		return s.getWindowsConnections()
	case "linux":
		return s.getLinuxConnections()
	case "darwin":
		return s.getDarwinConnections()
	default:
		return nil, fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

// getWindowsConnections uses Get-NetTCPConnection PowerShell cmdlet
func (s *Scanner) getWindowsConnections() ([]*models.NetworkConnection, error) {
	cmd := exec.Command("powershell", "-Command",
		"Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess | ConvertTo-Json")

	output, err := cmd.Output()
	if err != nil {
		// Fallback to netstat
		return s.getWindowsNetstat()
	}

	return s.parseWindowsJSON(string(output))
}

// getWindowsNetstat fallback using netstat
func (s *Scanner) getWindowsNetstat() ([]*models.NetworkConnection, error) {
	cmd := exec.Command("netstat", "-ano")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	return s.parseNetstat(string(output), "windows")
}

// getLinuxConnections uses ss command (faster than netstat)
func (s *Scanner) getLinuxConnections() ([]*models.NetworkConnection, error) {
	cmd := exec.Command("ss", "-tunapl")
	output, err := cmd.Output()
	if err != nil {
		// Fallback to netstat
		cmd = exec.Command("netstat", "-tunapl")
		output, err = cmd.Output()
		if err != nil {
			return nil, err
		}
	}

	return s.parseNetstat(string(output), "linux")
}

// getDarwinConnections uses lsof for macOS
func (s *Scanner) getDarwinConnections() ([]*models.NetworkConnection, error) {
	cmd := exec.Command("lsof", "-i", "-n", "-P")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	return s.parseLsof(string(output))
}

// parseNetstat parses netstat output (cross-platform)
func (s *Scanner) parseNetstat(output, platform string) ([]*models.NetworkConnection, error) {
	var connections []*models.NetworkConnection
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}

		// Skip header lines
		if strings.Contains(line, "Proto") || strings.Contains(line, "Active") {
			continue
		}

		conn := &models.NetworkConnection{
			Protocol: fields[0],
		}

		// Parse local address
		localAddr := fields[3]
		if platform == "windows" {
			localAddr = fields[1]
		}
		if parts := strings.Split(localAddr, ":"); len(parts) >= 2 {
			conn.LocalAddr = strings.Join(parts[:len(parts)-1], ":")
			if port, err := strconv.Atoi(parts[len(parts)-1]); err == nil {
				conn.LocalPort = port
			}
		}

		// Parse remote address
		remoteAddr := fields[4]
		if platform == "windows" {
			remoteAddr = fields[2]
		}
		if parts := strings.Split(remoteAddr, ":"); len(parts) >= 2 {
			conn.RemoteAddr = strings.Join(parts[:len(parts)-1], ":")
			if port, err := strconv.Atoi(parts[len(parts)-1]); err == nil {
				conn.RemotePort = port
			}
		}

		// Parse state
		if platform == "windows" && len(fields) > 3 {
			conn.State = fields[3]
			if len(fields) > 4 {
				if pid, err := strconv.Atoi(fields[4]); err == nil {
					conn.PID = pid
				}
			}
		} else if len(fields) > 5 {
			conn.State = fields[5]
		}

		// Resolve domain from IP
		if conn.RemoteAddr != "" && conn.RemoteAddr != "*" && conn.RemoteAddr != "0.0.0.0" {
			conn.Domain = s.resolveDomain(conn.RemoteAddr)
		}

		connections = append(connections, conn)
	}

	return connections, nil
}

// parseLsof parses lsof output for macOS
func (s *Scanner) parseLsof(output string) ([]*models.NetworkConnection, error) {
	var connections []*models.NetworkConnection
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "COMMAND") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 9 {
			continue
		}

		conn := &models.NetworkConnection{
			ProcessName: fields[0],
		}

		if pid, err := strconv.Atoi(fields[1]); err == nil {
			conn.PID = pid
		}

		// Parse connection string (e.g., "192.168.1.1:443->8.8.8.8:80")
		connStr := fields[8]
		if parts := strings.Split(connStr, "->"); len(parts) == 2 {
			// Local address
			if localParts := strings.Split(parts[0], ":"); len(localParts) == 2 {
				conn.LocalAddr = localParts[0]
				if port, err := strconv.Atoi(localParts[1]); err == nil {
					conn.LocalPort = port
				}
			}

			// Remote address
			if remoteParts := strings.Split(parts[1], ":"); len(remoteParts) == 2 {
				conn.RemoteAddr = remoteParts[0]
				if port, err := strconv.Atoi(remoteParts[1]); err == nil {
					conn.RemotePort = port
				}
				conn.Domain = s.resolveDomain(conn.RemoteAddr)
			}
		}

		conn.State = "ESTABLISHED"
		connections = append(connections, conn)
	}

	return connections, nil
}

// parseWindowsJSON parses PowerShell JSON output
func (s *Scanner) parseWindowsJSON(jsonStr string) ([]*models.NetworkConnection, error) {
	// Simplified JSON parsing - in production use encoding/json
	var connections []*models.NetworkConnection

	// Basic parsing for demo
	lines := strings.Split(jsonStr, "\n")
	var currentConn *models.NetworkConnection

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "{") {
			currentConn = &models.NetworkConnection{}
		} else if strings.HasPrefix(line, "}") && currentConn != nil {
			connections = append(connections, currentConn)
		} else if currentConn != nil {
			if strings.Contains(line, "LocalAddress") {
				parts := strings.Split(line, ":")
				if len(parts) > 1 {
					addr := strings.Trim(strings.TrimSpace(parts[1]), "\",")
					currentConn.LocalAddr = addr
				}
			} else if strings.Contains(line, "RemoteAddress") {
				parts := strings.Split(line, ":")
				if len(parts) > 1 {
					addr := strings.Trim(strings.TrimSpace(parts[1]), "\",")
					currentConn.RemoteAddr = addr
					currentConn.Domain = s.resolveDomain(addr)
				}
			} else if strings.Contains(line, "RemotePort") {
				parts := strings.Split(line, ":")
				if len(parts) > 1 {
					portStr := strings.Trim(strings.TrimSpace(parts[1]), ",")
					if port, err := strconv.Atoi(portStr); err == nil {
						currentConn.RemotePort = port
					}
				}
			}
		}
	}

	return connections, nil
}

// resolveDomain attempts reverse DNS lookup
func (s *Scanner) resolveDomain(ip string) string {
	// Skip private IPs
	if s.isPrivateIP(ip) {
		return ip
	}

	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		return ip
	}

	return strings.TrimSuffix(names[0], ".")
}

// isPrivateIP checks if IP is in private range
func (s *Scanner) isPrivateIP(ip string) bool {
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	for _, cidr := range privateRanges {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if ipNet.Contains(parsedIP) {
			return true
		}
	}

	return false
}

// DetectThreats analyzes connections for suspicious patterns
func (s *Scanner) DetectThreats(connections []*models.NetworkConnection) []ThreatDetection {
	s.historyMux.Lock()
	defer s.historyMux.Unlock()

	var threats []ThreatDetection
	now := time.Now()

	// Group connections by process and remote IP
	processStats := make(map[string]*ConnectionStats)
	ipStats := make(map[string]*ConnectionStats)

	for _, conn := range connections {
		// Track by process
		procKey := fmt.Sprintf("%s:%d", conn.ProcessName, conn.PID)
		if _, exists := processStats[procKey]; !exists {
			processStats[procKey] = &ConnectionStats{
				FirstSeen: now,
				Ports:     make(map[int]int),
				RemoteIPs: make(map[string]int),
			}
		}
		processStats[procKey].ConnectionCount++
		processStats[procKey].Ports[conn.RemotePort]++
		processStats[procKey].RemoteIPs[conn.RemoteAddr]++
		processStats[procKey].LastSeen = now

		// Track by remote IP
		if conn.RemoteAddr != "" && conn.RemoteAddr != "*" && conn.RemoteAddr != "0.0.0.0" {
			if _, exists := ipStats[conn.RemoteAddr]; !exists {
				ipStats[conn.RemoteAddr] = &ConnectionStats{
					FirstSeen: now,
					Ports:     make(map[int]int),
					RemoteIPs: make(map[string]int),
				}
			}
			ipStats[conn.RemoteAddr].ConnectionCount++
			ipStats[conn.RemoteAddr].Ports[conn.LocalPort]++
			ipStats[conn.RemoteAddr].LastSeen = now
		}
	}

	// Detect port scanning (many ports from one IP)
	for ip, stats := range ipStats {
		if len(stats.Ports) > 10 && stats.ConnectionCount > 20 {
			threats = append(threats, ThreatDetection{
				Type:         "Port Scan",
				Severity:     "HIGH",
				Source:       ip,
				Description:  fmt.Sprintf("Possible port scan detected from %s - %d connections to %d different ports", ip, stats.ConnectionCount, len(stats.Ports)),
				PortsScanned: len(stats.Ports),
				Evidence:     fmt.Sprintf("Connections: %d, Unique ports: %d", stats.ConnectionCount, len(stats.Ports)),
			})
		}
	}

	// Detect nmap-style scans (rapid sequential port connections)
	for ip, stats := range ipStats {
		if len(stats.Ports) >= 5 && len(stats.Ports) <= 100 {
			portList := make([]int, 0, len(stats.Ports))
			for port := range stats.Ports {
				portList = append(portList, port)
			}

			// Check if ports are sequential or common scan patterns
			if s.isSequentialPorts(portList) || s.isCommonScanPattern(portList) {
				threats = append(threats, ThreatDetection{
					Type:         "Nmap Scan",
					Severity:     "CRITICAL",
					Source:       ip,
					Description:  fmt.Sprintf("Nmap-style port scan detected from %s - scanning %d ports", ip, len(stats.Ports)),
					PortsScanned: len(stats.Ports),
					Evidence:     fmt.Sprintf("Sequential/pattern-based scan detected on ports: %v", portList),
				})
			}
		}
	}

	// Detect SYN flood (many connections to same port)
	for ip, stats := range ipStats {
		for port, count := range stats.Ports {
			if count > 50 {
				threats = append(threats, ThreatDetection{
					Type:         "SYN Flood",
					Severity:     "CRITICAL",
					Source:       ip,
					Description:  fmt.Sprintf("Possible SYN flood attack from %s to port %d - %d connections", ip, port, count),
					PortsScanned: 1,
					Evidence:     fmt.Sprintf("%d rapid connections to port %d", count, port),
				})
			}
		}
	}

	// Detect suspicious process behavior (connecting to many IPs)
	for procKey, stats := range processStats {
		if len(stats.RemoteIPs) > 20 {
			threats = append(threats, ThreatDetection{
				Type:         "Suspicious Process",
				Severity:     "HIGH",
				Source:       procKey,
				Description:  fmt.Sprintf("Process %s connecting to %d different IPs - possible C2 or scanning", procKey, len(stats.RemoteIPs)),
				PortsScanned: len(stats.Ports),
				Evidence:     fmt.Sprintf("Connections to %d unique IPs, %d unique ports", len(stats.RemoteIPs), len(stats.Ports)),
			})
		}
	}

	// Detect reverse shells (connections to non-standard high ports)
	for _, conn := range connections {
		if conn.RemotePort >= 4444 && conn.RemotePort <= 9999 && !s.isCommonPort(conn.RemotePort) {
			if !s.isPrivateIP(conn.RemoteAddr) {
				threats = append(threats, ThreatDetection{
					Type:         "Reverse Shell",
					Severity:     "CRITICAL",
					Source:       conn.RemoteAddr,
					Description:  fmt.Sprintf("Possible reverse shell: %s connecting to %s:%d", conn.ProcessName, conn.RemoteAddr, conn.RemotePort),
					PortsScanned: 1,
					Evidence:     fmt.Sprintf("Process: %s (PID: %d), Remote: %s:%d", conn.ProcessName, conn.PID, conn.RemoteAddr, conn.RemotePort),
				})
			}
		}
	}

	// Detect beaconing (regular periodic connections)
	for procKey, stats := range processStats {
		if stats.ConnectionCount > 10 && len(stats.RemoteIPs) == 1 {
			threats = append(threats, ThreatDetection{
				Type:         "C2 Beaconing",
				Severity:     "HIGH",
				Source:       procKey,
				Description:  fmt.Sprintf("Regular beaconing pattern detected from %s - %d connections to single IP", procKey, stats.ConnectionCount),
				PortsScanned: 0,
				Evidence:     fmt.Sprintf("%d periodic connections suggesting C2 callback", stats.ConnectionCount),
			})
		}
	}

	return threats
}

// ThreatDetection represents a detected network threat
type ThreatDetection struct {
	Type         string
	Severity     string
	Source       string
	Description  string
	PortsScanned int
	Evidence     string
}

// isSequentialPorts checks if ports are sequential
func (s *Scanner) isSequentialPorts(ports []int) bool {
	if len(ports) < 3 {
		return false
	}

	// Sort isn't imported but we can check gaps
	sequential := 0
	for i := 0; i < len(ports)-1; i++ {
		for j := i + 1; j < len(ports); j++ {
			diff := ports[j] - ports[i]
			if diff >= 1 && diff <= 3 {
				sequential++
			}
		}
	}

	return sequential > len(ports)/2
}

// isCommonScanPattern checks for common nmap/masscan patterns
func (s *Scanner) isCommonScanPattern(ports []int) bool {
	commonPatterns := []int{21, 22, 23, 25, 80, 443, 445, 3389, 8080, 3306, 5432, 1433, 27017}
	matches := 0

	for _, port := range ports {
		for _, pattern := range commonPatterns {
			if port == pattern {
				matches++
				break
			}
		}
	}

	return matches >= 3
}

// isCommonPort checks if port is a well-known legitimate service
func (s *Scanner) isCommonPort(port int) bool {
	commonPorts := []int{80, 443, 8080, 8443, 9000, 5000, 3000, 5001, 5555, 6000, 6666, 7777, 8888, 9999}
	for _, p := range commonPorts {
		if port == p {
			return true
		}
	}
	return false
}
