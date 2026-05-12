package detector

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Connection represents a detected network connection tied to a process.
type Connection struct {
	Protocol   string // "tcp", "tcp6", "udp"
	LocalAddr  string // local ip:port
	RemoteAddr string // remote ip:port
	State      string // "ESTABLISHED", "LISTEN", etc.
	PID        int
	Process    string // process name
	Cmdline    string // full command line (best-effort)
}

// Alert represents a confirmed detection of a suspicious reverse shell.
type Alert struct {
	Timestamp  time.Time
	Pattern    Pattern
	Connection Connection
	Score      int    // 0-100 confidence score
	Details    string // human-readable explanation
}

// Detector holds configuration and state for the detection engine.
type Detector struct {
	patterns  []Pattern
	procNames map[string]struct{}
	mu        sync.RWMutex
	alerts    []Alert
}

// New creates a Detector with the default pattern set.
func New() *Detector {
	return &Detector{
		patterns:  DefaultPatterns(),
		procNames: ProcessNameSet(),
	}
}

// Scan performs a single scan of all network connections and returns any alerts.
func (d *Detector) Scan() ([]Alert, error) {
	conns, err := d.getConnections()
	if err != nil {
		return nil, fmt.Errorf("failed to get connections: %w", err)
	}

	var found []Alert
	for _, conn := range conns {
		if alerts := d.evaluate(conn); len(alerts) > 0 {
			found = append(found, alerts...)
		}
	}

	d.mu.Lock()
	d.alerts = append(d.alerts, found...)
	d.mu.Unlock()

	return found, nil
}

// Alerts returns all accumulated alerts.
func (d *Detector) Alerts() []Alert {
	d.mu.RLock()
	defer d.mu.RUnlock()
	cp := make([]Alert, len(d.alerts))
	copy(cp, d.alerts)
	return cp
}

// ClearAlerts resets the accumulated alert list.
func (d *Detector) ClearAlerts() {
	d.mu.Lock()
	d.alerts = nil
	d.mu.Unlock()
}

// evaluate checks a single connection against all patterns and returns matching alerts.
func (d *Detector) evaluate(conn Connection) []Alert {
	procLower := strings.ToLower(conn.Process)
	var alerts []Alert

	for _, pat := range d.patterns {
		matched := false
		for _, name := range pat.ProcessNames {
			if strings.ToLower(name) == procLower {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}

		// Process name matched a pattern and it has an active network connection.
		score := d.calculateScore(conn, pat)
		detail := fmt.Sprintf("Process '%s' (PID %d) matched pattern '%s'. Remote: %s, State: %s",
			conn.Process, conn.PID, pat.Name, conn.RemoteAddr, conn.State)

		if conn.Cmdline != "" {
			detail += fmt.Sprintf(", Cmdline: %s", conn.Cmdline)
		}

		alerts = append(alerts, Alert{
			Timestamp:  time.Now(),
			Pattern:    pat,
			Connection: conn,
			Score:      score,
			Details:    detail,
		})
	}
	return alerts
}

// calculateScore assigns a confidence score based on connection properties and command-line matches.
func (d *Detector) calculateScore(conn Connection, pat Pattern) int {
	score := 40 // base: process name matched + has network connection

	// Established outbound connections are more suspicious than listening
	if strings.EqualFold(conn.State, "ESTABLISHED") {
		score += 20
	}

	// Non-standard remote ports increase suspicion
	if port := extractPort(conn.RemoteAddr); port > 0 {
		if port > 1024 && port != 8080 && port != 8443 && port != 443 && port != 80 {
			score += 10 // non-standard port
		}
		// Very common reverse shell ports
		if port == 4444 || port == 4445 || port == 5555 || port == 1337 || port == 9001 || port == 9002 {
			score += 15
		}
	}

	// Command-line pattern matching
	cmdLower := strings.ToLower(conn.Cmdline)
	if cmdLower != "" {
		for _, cp := range pat.CmdPatterns {
			if strings.Contains(cmdLower, strings.ToLower(cp)) {
				score += 15
				break // one cmdline match is enough
			}
		}
	}

	if score > 100 {
		score = 100
	}
	return score
}

// extractPort pulls the port number from an addr string like "1.2.3.4:8080" or "[::1]:8080".
func extractPort(addr string) int {
	idx := strings.LastIndex(addr, ":")
	if idx < 0 || idx == len(addr)-1 {
		return 0
	}
	p, err := strconv.Atoi(addr[idx+1:])
	if err != nil {
		return 0
	}
	return p
}

// getConnections retrieves active network connections with process info.
// It delegates to platform-specific implementations.
func (d *Detector) getConnections() ([]Connection, error) {
	switch runtime.GOOS {
	case "linux":
		return d.getConnectionsLinux()
	case "darwin":
		return d.getConnectionsDarwin()
	default:
		return nil, fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

// getConnectionsLinux uses /proc/net/tcp + /proc/PID for fast enumeration on Linux.
func (d *Detector) getConnectionsLinux() ([]Connection, error) {
	// Use ss (faster) with fallback to netstat
	out, err := exec.Command("ss", "-tupn", "--no-header").CombinedOutput()
	if err != nil {
		// Fallback to netstat
		out, err = exec.Command("netstat", "-tupn", "--no-header").CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf("ss and netstat both failed: %w (output: %s)", err, string(out))
		}
		return d.parseNetstat(string(out)), nil
	}
	return d.parseSS(string(out)), nil
}

// getConnectionsDarwin uses lsof for macOS since netstat -p is not available.
func (d *Detector) getConnectionsDarwin() ([]Connection, error) {
	out, err := exec.Command("lsof", "-i", "-n", "-P", "+c", "0").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("lsof failed: %w (output: %s)", err, string(out))
	}
	return d.parseLsof(string(out)), nil
}

// parseSS parses output from `ss -tupn --no-header`.
// Example line:
// tcp   ESTAB  0  0  10.0.0.5:45678  1.2.3.4:4444  users:(("bash",pid=1234,fd=3))
func (d *Detector) parseSS(output string) []Connection {
	var conns []Connection
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}

		proto := fields[0]
		state := fields[1]
		localAddr := fields[4]
		remoteAddr := fields[5]

		pid := 0
		procName := ""
		cmdline := ""

		// Parse users:(("bash",pid=1234,fd=3))
		if len(fields) >= 7 {
			usersField := strings.Join(fields[6:], " ")
			pid, procName = parseSSUsers(usersField)
			if pid > 0 {
				cmdline = readProcCmdline(pid)
			}
		}

		if procName == "" {
			continue
		}

		// Only include if process name is in our watch set
		if _, ok := d.procNames[strings.ToLower(procName)]; !ok {
			continue
		}

		conns = append(conns, Connection{
			Protocol:   proto,
			LocalAddr:  localAddr,
			RemoteAddr: remoteAddr,
			State:      state,
			PID:        pid,
			Process:    procName,
			Cmdline:    cmdline,
		})
	}
	return conns
}

// parseSSUsers extracts PID and process name from ss users field.
func parseSSUsers(field string) (int, string) {
	// Format: users:(("bash",pid=1234,fd=3))
	pidIdx := strings.Index(field, "pid=")
	if pidIdx < 0 {
		return 0, ""
	}
	// Extract process name — between ((" and ",
	nameStart := strings.Index(field, "((\"")
	nameEnd := strings.Index(field, "\",")
	procName := ""
	if nameStart >= 0 && nameEnd > nameStart+3 {
		procName = field[nameStart+3 : nameEnd]
	}

	pidStr := field[pidIdx+4:]
	if commaIdx := strings.IndexAny(pidStr, ",)"); commaIdx > 0 {
		pidStr = pidStr[:commaIdx]
	}
	pid, _ := strconv.Atoi(pidStr)
	return pid, procName
}

// readProcCmdline reads /proc/PID/cmdline on Linux.
func readProcCmdline(pid int) string {
	out, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return ""
	}
	// cmdline is null-separated
	return strings.ReplaceAll(string(out), "\x00", " ")
}

// parseNetstat parses output from `netstat -tupn --no-header`.
func (d *Detector) parseNetstat(output string) []Connection {
	var conns []Connection
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 7 {
			continue
		}

		proto := fields[0]
		localAddr := fields[3]
		remoteAddr := fields[4]
		state := fields[5]
		pidProg := fields[6] // "1234/bash"

		parts := strings.SplitN(pidProg, "/", 2)
		if len(parts) != 2 {
			continue
		}
		pid, _ := strconv.Atoi(parts[0])
		procName := parts[1]

		if _, ok := d.procNames[strings.ToLower(procName)]; !ok {
			continue
		}

		cmdline := ""
		if pid > 0 {
			cmdline = readProcCmdline(pid)
		}

		conns = append(conns, Connection{
			Protocol:   proto,
			LocalAddr:  localAddr,
			RemoteAddr: remoteAddr,
			State:      state,
			PID:        pid,
			Process:    procName,
			Cmdline:    cmdline,
		})
	}
	return conns
}

// parseLsof parses output from `lsof -i -n -P +c 0`.
// Example header: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
// Example line:   bash    1234 root 3u IPv4 12345 0t0 TCP 10.0.0.5:45678->1.2.3.4:4444 (ESTABLISHED)
func (d *Detector) parseLsof(output string) []Connection {
	var conns []Connection
	lines := strings.Split(output, "\n")

	for i, line := range lines {
		if i == 0 {
			continue // skip header
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 9 {
			continue
		}

		procName := fields[0]
		pid, _ := strconv.Atoi(fields[1])
		proto := strings.ToLower(fields[7]) // NODE column: TCP, UDP
		nameField := fields[8]              // e.g., "10.0.0.5:45678->1.2.3.4:4444"

		// Check if this process is in our watch set
		if _, ok := d.procNames[strings.ToLower(procName)]; !ok {
			continue
		}

		state := ""
		if len(fields) >= 10 {
			state = strings.Trim(fields[9], "()")
		}

		localAddr := ""
		remoteAddr := ""
		if strings.Contains(nameField, "->") {
			parts := strings.SplitN(nameField, "->", 2)
			localAddr = parts[0]
			remoteAddr = parts[1]
		} else {
			localAddr = nameField
		}

		// Read command line on macOS via ps
		cmdline := readMacCmdline(pid)

		conns = append(conns, Connection{
			Protocol:   proto,
			LocalAddr:  localAddr,
			RemoteAddr: remoteAddr,
			State:      state,
			PID:        pid,
			Process:    procName,
			Cmdline:    cmdline,
		})
	}
	return conns
}

// readMacCmdline retrieves the full command line for a PID on macOS.
func readMacCmdline(pid int) string {
	out, err := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "args=").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
