package detector

// Pattern defines a reverse shell detection pattern.
type Pattern struct {
	Name        string   // Human-readable name (e.g., "Bash Reverse Shell")
	Category    string   // Category grouping (e.g., "shell", "scripting", "networking")
	Severity    string   // "critical", "high", "medium", "low"
	ProcessNames []string // Process names to match (case-insensitive)
	Description string   // What this pattern detects
	CmdPatterns []string // Suspicious command-line argument patterns (substring match)
}

// DefaultPatterns returns all built-in reverse shell detection patterns.
func DefaultPatterns() []Pattern {
	return []Pattern{
		// --- Shell-based reverse shells ---
		{
			Name:         "Bash Reverse Shell",
			Category:     "shell",
			Severity:     "critical",
			ProcessNames: []string{"bash"},
			Description:  "Bash process with active network connection — classic /dev/tcp or bash -i redirect",
			CmdPatterns:  []string{"/dev/tcp", "/dev/udp", "bash -i", "bash -c", "0>&1", "1>&0"},
		},
		{
			Name:         "Zsh Reverse Shell",
			Category:     "shell",
			Severity:     "critical",
			ProcessNames: []string{"zsh"},
			Description:  "Zsh process with active network connection — zsh-based reverse shell",
			CmdPatterns:  []string{"zsh -c", "ztcp", "/dev/tcp", "0>&1"},
		},
		{
			Name:         "Sh Reverse Shell",
			Category:     "shell",
			Severity:     "critical",
			ProcessNames: []string{"sh", "dash"},
			Description:  "POSIX shell with active network connection — sh -i or dash redirect",
			CmdPatterns:  []string{"sh -i", "sh -c", "/dev/tcp", "0>&1"},
		},

		// --- Scripting language reverse shells ---
		{
			Name:         "Python Reverse Shell",
			Category:     "scripting",
			Severity:     "critical",
			ProcessNames: []string{"python", "python2", "python3", "python3.9", "python3.10", "python3.11", "python3.12", "python3.13"},
			Description:  "Python process with network connection — socket-based reverse shell",
			CmdPatterns:  []string{"import socket", "import subprocess", "import os", "pty.spawn", "socket.socket"},
		},
		{
			Name:         "Perl Reverse Shell",
			Category:     "scripting",
			Severity:     "critical",
			ProcessNames: []string{"perl", "perl5"},
			Description:  "Perl process with network connection — IO::Socket reverse shell",
			CmdPatterns:  []string{"IO::Socket", "exec", "fdopen", "/bin/sh", "/bin/bash"},
		},
		{
			Name:         "Ruby Reverse Shell",
			Category:     "scripting",
			Severity:     "high",
			ProcessNames: []string{"ruby", "irb"},
			Description:  "Ruby process with network connection — TCPSocket reverse shell",
			CmdPatterns:  []string{"TCPSocket", "Socket", "exec", "IO.popen", "/bin/sh"},
		},
		{
			Name:         "PHP Reverse Shell",
			Category:     "scripting",
			Severity:     "critical",
			ProcessNames: []string{"php", "php-fpm", "php-cgi"},
			Description:  "PHP process with network connection — fsockopen or exec reverse shell",
			CmdPatterns:  []string{"fsockopen", "exec", "shell_exec", "system", "popen", "proc_open"},
		},
		{
			Name:         "Node.js Reverse Shell",
			Category:     "scripting",
			Severity:     "high",
			ProcessNames: []string{"node", "nodejs"},
			Description:  "Node.js process with network connection — child_process reverse shell",
			CmdPatterns:  []string{"child_process", "net.Socket", "exec", "spawn", "/bin/sh"},
		},
		{
			Name:         "Lua Reverse Shell",
			Category:     "scripting",
			Severity:     "high",
			ProcessNames: []string{"lua", "lua5.1", "lua5.3", "lua5.4", "luajit"},
			Description:  "Lua process with network connection — os.execute reverse shell",
			CmdPatterns:  []string{"os.execute", "io.popen", "socket.tcp"},
		},
		{
			Name:         "Awk Reverse Shell",
			Category:     "scripting",
			Severity:     "high",
			ProcessNames: []string{"awk", "gawk", "mawk", "nawk"},
			Description:  "Awk process with network connection — /inet reverse shell",
			CmdPatterns:  []string{"/inet/tcp", "getline", "|&"},
		},

		// --- Networking tools ---
		{
			Name:         "Netcat Reverse Shell",
			Category:     "networking",
			Severity:     "critical",
			ProcessNames: []string{"nc", "ncat", "netcat", "nc.openbsd", "nc.traditional"},
			Description:  "Netcat process with active connection — classic nc -e or pipe shell",
			CmdPatterns:  []string{"-e /bin", "-e /bin/sh", "-e /bin/bash", "-c /bin", "mkfifo", "/tmp/f"},
		},
		{
			Name:         "Socat Reverse Shell",
			Category:     "networking",
			Severity:     "critical",
			ProcessNames: []string{"socat"},
			Description:  "Socat bidirectional relay — often used for encrypted reverse shells",
			CmdPatterns:  []string{"TCP:", "EXEC:", "PTY", "stdin", "stdout"},
		},
		{
			Name:         "Telnet Reverse Shell",
			Category:     "networking",
			Severity:     "high",
			ProcessNames: []string{"telnet"},
			Description:  "Telnet process with piped shell — telnet-based reverse shell",
			CmdPatterns:  []string{"mkfifo", "/tmp/", "|/bin/sh", "|/bin/bash"},
		},
		{
			Name:         "OpenSSL Reverse Shell",
			Category:     "networking",
			Severity:     "critical",
			ProcessNames: []string{"openssl"},
			Description:  "OpenSSL s_client used as encrypted reverse shell transport",
			CmdPatterns:  []string{"s_client", "-connect", "quiet", "/bin/sh", "/bin/bash"},
		},

		// --- Compiled/binary reverse shells ---
		{
			Name:         "Meterpreter / Msfvenom Payload",
			Category:     "implant",
			Severity:     "critical",
			ProcessNames: []string{"meterpreter", "msfconsole", "msfvenom"},
			Description:  "Known Metasploit process detected with network activity",
			CmdPatterns:  []string{"meterpreter", "reverse_tcp", "reverse_http", "payload"},
		},
		{
			Name:         "PowerShell Reverse Shell",
			Category:     "shell",
			Severity:     "critical",
			ProcessNames: []string{"pwsh", "powershell"},
			Description:  "PowerShell process with network connection — IEX download cradle or socket",
			CmdPatterns:  []string{"IEX", "Invoke-Expression", "Net.Sockets", "TCPClient", "DownloadString", "WebClient"},
		},
		{
			Name:         "Xterm Reverse Shell",
			Category:     "shell",
			Severity:     "high",
			ProcessNames: []string{"xterm"},
			Description:  "Xterm process with network connection — xterm -display reverse shell",
			CmdPatterns:  []string{"-display", ":1"},
		},
	}
}

// ProcessNameSet returns a de-duplicated set of all process names across all patterns.
func ProcessNameSet() map[string]struct{} {
	set := make(map[string]struct{})
	for _, p := range DefaultPatterns() {
		for _, name := range p.ProcessNames {
			set[name] = struct{}{}
		}
	}
	return set
}
