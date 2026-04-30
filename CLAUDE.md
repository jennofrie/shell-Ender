# CLAUDE.md — shell-Ender

## Overview

shell-Ender is a blue team defensive tool that detects malicious reverse shell connections in real time. It monitors active network connections, correlates them with known reverse shell process patterns, and alerts or auto-terminates threats.

## Tech Stack

- **Language**: Go 1.26+ (pure standard library, zero dependencies)
- **Module**: `github.com/jennofrie/shell-Ender`
- **Platform**: Linux + macOS (cross-platform, static binary)

## Project Structure

```
main.go                 → Entry point
cmd/root.go             → CLI parsing, flags, signal handling, banner
internal/detector/
  patterns.go           → All reverse shell detection pattern definitions
  detector.go           → Core engine: connection enumeration, pattern matching, scoring
internal/monitor/
  monitor.go            → Scan loop orchestration, continuous monitoring
  kill.go               → Process termination (SIGKILL)
internal/output/
  formatter.go          → Table + JSON output rendering
```

## Build & Run

```bash
go build -o shell-Ender .
sudo ./shell-Ender scan              # one-time scan
sudo ./shell-Ender scan --watch      # continuous monitoring
./shell-Ender patterns               # list all detection patterns
```

## Key Design Decisions

- Uses `lsof` on macOS, `ss` (with `netstat` fallback) on Linux for connection enumeration
- Detection patterns are defined declaratively in `patterns.go` — add new patterns there
- Confidence scoring combines process name, connection state, port analysis, and cmdline matching
- No third-party dependencies — everything uses Go standard library
- Structured logging via `log/slog`

## Adding New Patterns

Edit `internal/detector/patterns.go` and add a new `Pattern` struct to the `DefaultPatterns()` slice. Fields:
- `Name`: Human-readable identifier
- `Category`: "shell", "scripting", "networking", "implant"
- `Severity`: "critical", "high", "medium", "low"
- `ProcessNames`: Slice of process names to match (case-insensitive)
- `CmdPatterns`: Suspicious command-line substrings for scoring boost

## Conventions

- Conventional commits: `feat:`, `fix:`, `chore:`
- No third-party dependencies unless absolutely necessary
- Platform-specific code goes in `detector.go` with runtime.GOOS switches
- All output goes through `output/formatter.go`
