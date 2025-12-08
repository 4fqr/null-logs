package network

import (
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strconv"
	"strings"

	"github.com/nullsector/null-log/pkg/models"
)

// Scanner provides cross-platform network connection monitoring
type Scanner struct{}

// NewScanner creates a new network scanner
func NewScanner() *Scanner {
	return &Scanner{}
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
