package cmd

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jennofrie/shell-Ender/internal/monitor"
	"github.com/jennofrie/shell-Ender/internal/output"
)

const version = "2.0.0"

const banner = `
███████╗██╗  ██╗███████╗██╗     ██╗     ███████╗███╗   ██╗██████╗ ███████╗██████╗
██╔════╝██║  ██║██╔════╝██║     ██║     ██╔════╝████╗  ██║██╔══██╗██╔════╝██╔══██╗
███████╗███████║█████╗  ██║     ██║     █████╗  ██╔██╗ ██║██║  ██║█████╗  ██████╔╝
╚════██║██╔══██║██╔══╝  ██║     ██║     ██╔══╝  ██║╚██╗██║██║  ██║██╔══╝  ██╔══██╗
███████║██║  ██║███████╗███████╗███████╗███████╗██║ ╚████║██████╔╝███████╗██║  ██║
╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝╚══════╝╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═╝  ╚═╝
`

// Execute is the main entry point for the CLI.
func Execute() {
	// Subcommands
	scanCmd := flag.NewFlagSet("scan", flag.ExitOnError)
	patternsCmd := flag.NewFlagSet("patterns", flag.ExitOnError)
	versionCmd := flag.NewFlagSet("version", flag.ExitOnError)

	// Scan flags
	interval := scanCmd.Duration("interval", 5*time.Second, "Scan interval for continuous mode")
	format := scanCmd.String("format", "table", "Output format: table, json")
	minScore := scanCmd.Int("min-score", 0, "Minimum confidence score to report (0-100)")
	kill := scanCmd.Bool("kill", false, "Automatically terminate detected reverse shells")
	continuous := scanCmd.Bool("watch", false, "Run continuously (Ctrl+C to stop)")
	verbose := scanCmd.Bool("verbose", false, "Show info messages for clean scans")
	logLevel := scanCmd.String("log-level", "info", "Log level: debug, info, warn, error")

	// Patterns flags
	patFormat := patternsCmd.String("format", "table", "Output format: table, json")

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(0)
	}

	switch os.Args[1] {
	case "scan":
		scanCmd.Parse(os.Args[2:])
		runScan(*interval, *format, *minScore, *kill, *continuous, *verbose, *logLevel)

	case "patterns":
		patternsCmd.Parse(os.Args[2:])
		output.PrintPatterns(*patFormat)

	case "version":
		versionCmd.Parse(os.Args[2:])
		fmt.Printf("shell-Ender v%s\n", version)

	case "help", "-h", "--help":
		printUsage()

	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func runScan(interval time.Duration, format string, minScore int, kill, continuous, verbose bool, logLevel string) {
	fmt.Print(banner)
	fmt.Printf("  Real-Time Reverse Shell Detection Engine v%s\n", version)
	fmt.Printf("  by @Jennofrie\n\n")

	logger := setupLogger(logLevel)

	if kill {
		logger.Warn("kill mode enabled — detected processes will be terminated")
	}

	cfg := monitor.Config{
		Interval:     interval,
		Format:       format,
		MinScore:     minScore,
		KillOnDetect: kill,
		Continuous:   continuous,
		Verbose:      verbose,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Graceful shutdown on SIGINT/SIGTERM
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		logger.Info("received signal, shutting down gracefully", "signal", sig.String())
		cancel()
	}()

	mon := monitor.New(cfg, logger)
	if err := mon.Run(ctx); err != nil && ctx.Err() == nil {
		logger.Error("monitor exited with error", "error", err)
		os.Exit(1)
	}
}

func setupLogger(level string) *slog.Logger {
	var lvl slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{Level: lvl}
	handler := slog.NewTextHandler(os.Stderr, opts)
	return slog.New(handler)
}

func printUsage() {
	fmt.Print(banner)
	fmt.Printf("  Real-Time Reverse Shell Detection Engine v%s\n", version)
	fmt.Printf("  by @Jennofrie\n\n")

	fmt.Println("USAGE:")
	fmt.Println("  shell-Ender <command> [flags]")
	fmt.Println()
	fmt.Println("COMMANDS:")
	fmt.Println("  scan        Scan for reverse shell connections")
	fmt.Println("  patterns    List all detection patterns")
	fmt.Println("  version     Print version information")
	fmt.Println("  help        Show this help message")
	fmt.Println()
	fmt.Println("SCAN FLAGS:")
	fmt.Println("  --watch          Run continuously (Ctrl+C to stop)")
	fmt.Println("  --interval 5s    Scan interval for continuous mode (default: 5s)")
	fmt.Println("  --format table   Output format: table, json (default: table)")
	fmt.Println("  --min-score 0    Minimum confidence score to report (default: 0)")
	fmt.Println("  --kill           Automatically terminate detected processes")
	fmt.Println("  --verbose        Show info messages even for clean scans")
	fmt.Println("  --log-level info Log level: debug, info, warn, error")
	fmt.Println()
	fmt.Println("EXAMPLES:")
	fmt.Println("  sudo shell-Ender scan                    # One-time scan")
	fmt.Println("  sudo shell-Ender scan --watch            # Continuous monitoring")
	fmt.Println("  sudo shell-Ender scan --format json      # JSON output")
	fmt.Println("  sudo shell-Ender scan --kill --watch     # Auto-kill mode")
	fmt.Println("  sudo shell-Ender scan --min-score 60     # Only high-confidence alerts")
	fmt.Println("  shell-Ender patterns                     # List detection patterns")
	fmt.Println("  shell-Ender patterns --format json       # Patterns as JSON")
	fmt.Println()
	fmt.Println("NOTE: scan command requires root/sudo for full process visibility.")
}
