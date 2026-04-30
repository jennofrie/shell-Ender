<p align="center">
  <img src="assets/banner.svg" alt="shell-Ender Banner" width="800">
</p>

<p align="center">
  <a href="https://go.dev"><img src="https://img.shields.io/badge/Go-1.26+-00ADD8?style=flat-square&logo=go&logoColor=white" alt="Go"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-green?style=flat-square" alt="License"></a>
  <a href="#"><img src="https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-blue?style=flat-square" alt="Platform"></a>
  <a href="#"><img src="https://img.shields.io/badge/Team-Blue%20Team-0066cc?style=flat-square" alt="Blue Team"></a>
</p>

<h3 align="center">Real-Time Reverse Shell Detection Engine</h3>

---

> [!NOTE]
> **shell-Ender** is a **blue team defensive tool** designed for incident responders, SOC analysts, and system administrators. It continuously monitors active network connections and correlates them with known reverse shell process patterns to detect active compromise in real time.

## Features

- **20+ Detection Patterns** -- Bash, Python, Perl, Ruby, PHP, Node.js, Netcat, Socat, Lua, Awk, PowerShell, Meterpreter, OpenSSL, Xterm, and more
- **Real-Time Continuous Monitoring** -- Goroutine-based concurrent scanning with configurable intervals
- **Confidence Scoring** -- Each alert is scored 0-100 based on process name, connection state, port analysis, and command-line pattern matching
- **Cross-Platform** -- Native support for Linux (`ss`/`netstat`) and macOS (`lsof`)
- **Auto-Kill Mode** -- Optionally terminate detected reverse shell processes automatically
- **Dual Output Formats** -- Human-readable table or machine-parseable JSON for SIEM integration
- **Graceful Shutdown** -- Signal handling (SIGINT/SIGTERM) with session summary on exit
- **Structured Logging** -- Leveled logging (debug, info, warn, error) via `slog`
- **Zero Dependencies** -- Pure Go standard library, no third-party packages
- **Static Binary** -- Single binary deployment, no runtime dependencies

## Quick Start

### Build from source

```bash
git clone https://github.com/jennofrie/shell-Ender.git
cd shell-Ender
go build -o shell-Ender .
```

### Run a scan

```bash
# One-time scan (requires root for full process visibility)
sudo ./shell-Ender scan

# Continuous monitoring
sudo ./shell-Ender scan --watch

# JSON output for SIEM ingestion
sudo ./shell-Ender scan --format json --watch

# Auto-terminate detected shells
sudo ./shell-Ender scan --kill --watch

# Only show high-confidence alerts (score >= 60)
sudo ./shell-Ender scan --min-score 60 --watch
```

### List detection patterns

```bash
./shell-Ender patterns
./shell-Ender patterns --format json
```

## Usage

```
USAGE:
  shell-Ender <command> [flags]

COMMANDS:
  scan        Scan for reverse shell connections
  patterns    List all detection patterns
  version     Print version information
  help        Show this help message

SCAN FLAGS:
  --watch          Run continuously (Ctrl+C to stop)
  --interval 5s    Scan interval for continuous mode (default: 5s)
  --format table   Output format: table, json (default: table)
  --min-score 0    Minimum confidence score to report (default: 0)
  --kill           Automatically terminate detected processes
  --verbose        Show info messages even for clean scans
  --log-level info Log level: debug, info, warn, error
```

## Detection Patterns

| Pattern | Category | Severity | Processes |
|---------|----------|----------|-----------|
| Bash Reverse Shell | shell | CRITICAL | bash |
| Zsh Reverse Shell | shell | CRITICAL | zsh |
| Sh Reverse Shell | shell | CRITICAL | sh, dash |
| Python Reverse Shell | scripting | CRITICAL | python, python2, python3, python3.x |
| Perl Reverse Shell | scripting | CRITICAL | perl, perl5 |
| Ruby Reverse Shell | scripting | HIGH | ruby, irb |
| PHP Reverse Shell | scripting | CRITICAL | php, php-fpm, php-cgi |
| Node.js Reverse Shell | scripting | HIGH | node, nodejs |
| Lua Reverse Shell | scripting | HIGH | lua, luajit, lua5.x |
| Awk Reverse Shell | scripting | HIGH | awk, gawk, mawk, nawk |
| Netcat Reverse Shell | networking | CRITICAL | nc, ncat, netcat |
| Socat Reverse Shell | networking | CRITICAL | socat |
| Telnet Reverse Shell | networking | HIGH | telnet |
| OpenSSL Reverse Shell | networking | CRITICAL | openssl |
| Meterpreter Payload | implant | CRITICAL | meterpreter, msfconsole |
| PowerShell Reverse Shell | shell | CRITICAL | pwsh, powershell |
| Xterm Reverse Shell | shell | HIGH | xterm |

## Confidence Scoring

Each detection is assigned a confidence score (0-100) based on multiple factors:

| Factor | Points | Description |
|--------|--------|-------------|
| Process match | +40 | Process name matches a known reverse shell tool |
| ESTABLISHED state | +20 | Connection is actively established (not just listening) |
| Non-standard port | +10 | Remote port is non-standard (not 80/443/8080/8443) |
| Known shell port | +15 | Remote port matches common shell ports (4444, 1337, 9001, etc.) |
| Command-line match | +15 | Process arguments contain suspicious patterns |

## Architecture

```
shell-Ender/
├── main.go                          # Entry point
├── cmd/
│   └── root.go                      # CLI parsing, signal handling, banner
├── internal/
│   ├── detector/
│   │   ├── detector.go              # Core detection engine, platform-specific parsers
│   │   └── patterns.go              # All reverse shell pattern definitions
│   ├── monitor/
│   │   ├── monitor.go               # Scan loop, goroutine orchestration
│   │   └── kill.go                  # Process termination
│   └── output/
│       └── formatter.go             # Table and JSON output rendering
├── assets/
│   └── banner.svg                   # Project banner
├── README.md
└── CLAUDE.md
```

### How It Works

1. **Connection Enumeration** -- On each scan cycle, shell-Ender queries active network connections using platform-native tools (`lsof` on macOS, `ss`/`netstat` on Linux)
2. **Process Correlation** -- Each connection's process name is checked against 20+ known reverse shell patterns
3. **Command-Line Analysis** -- For matched processes, the full command line is retrieved and scanned for suspicious argument patterns (e.g., `/dev/tcp`, `pty.spawn`, `IO::Socket`)
4. **Confidence Scoring** -- Multiple factors (connection state, port, command-line patterns) are combined into a 0-100 confidence score
5. **Alerting** -- Detections above the minimum score threshold are output in the chosen format
6. **Response** -- In kill mode, detected processes are automatically terminated via SIGKILL

## Integrations

### SIEM / Log Aggregation

Pipe JSON output directly into your SIEM:

```bash
sudo ./shell-Ender scan --format json --watch 2>/dev/null | jq . >> /var/log/shell-ender.json
```

### Systemd Service

```ini
[Unit]
Description=shell-Ender Reverse Shell Detection
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/shell-Ender scan --watch --format json --log-level warn
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

### Cron (periodic scan)

```bash
*/5 * * * * /usr/local/bin/shell-Ender scan --format json >> /var/log/shell-ender.json 2>&1
```

## Author

**Jennofrie Daguil** ([@Jennofrie](https://github.com/jennofrie))

## License

[MIT](LICENSE)
