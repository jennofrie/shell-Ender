package monitor

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/jennofrie/shell-Ender/internal/detector"
	"github.com/jennofrie/shell-Ender/internal/output"
)

// Config holds runtime configuration for the monitor loop.
type Config struct {
	Interval       time.Duration // Scan interval (default 5s)
	Format         string        // "table" or "json"
	MinScore       int           // Minimum score to report (0-100)
	KillOnDetect   bool          // Automatically SIGKILL detected processes
	Continuous     bool          // Run continuously or single scan
	Verbose        bool          // Show info-level messages for clean scans
}

// DefaultConfig returns sensible defaults.
func DefaultConfig() Config {
	return Config{
		Interval:   5 * time.Second,
		Format:     "table",
		MinScore:   0,
		Continuous: false,
		Verbose:    false,
	}
}

// Monitor orchestrates periodic scans using the detector.
type Monitor struct {
	cfg      Config
	det      *detector.Detector
	fmt      *output.Formatter
	logger   *slog.Logger
	mu       sync.Mutex
	scanNum  int
}

// New creates a new Monitor with the given config.
func New(cfg Config, logger *slog.Logger) *Monitor {
	return &Monitor{
		cfg:    cfg,
		det:    detector.New(),
		fmt:    output.NewFormatter(cfg.Format),
		logger: logger,
	}
}

// Run starts the monitoring loop. It blocks until ctx is cancelled.
func (m *Monitor) Run(ctx context.Context) error {
	m.logger.Info("shell-Ender engine started",
		"interval", m.cfg.Interval.String(),
		"format", m.cfg.Format,
		"min_score", m.cfg.MinScore,
		"continuous", m.cfg.Continuous,
		"kill_on_detect", m.cfg.KillOnDetect,
	)

	// Always do an initial scan immediately
	if err := m.scan(ctx); err != nil {
		m.logger.Error("scan failed", "error", err)
		if !m.cfg.Continuous {
			return err
		}
	}

	if !m.cfg.Continuous {
		return nil
	}

	ticker := time.NewTicker(m.cfg.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			m.logger.Info("shutting down monitor", "reason", ctx.Err())
			m.printSummary()
			return nil
		case <-ticker.C:
			if err := m.scan(ctx); err != nil {
				m.logger.Error("scan failed", "error", err)
			}
		}
	}
}

// scan performs a single detection scan cycle.
func (m *Monitor) scan(ctx context.Context) error {
	m.mu.Lock()
	m.scanNum++
	num := m.scanNum
	m.mu.Unlock()

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	start := time.Now()
	alerts, err := m.det.Scan()
	elapsed := time.Since(start)

	if err != nil {
		return fmt.Errorf("scan #%d failed: %w", num, err)
	}

	// Filter by minimum score
	var filtered []detector.Alert
	for _, a := range alerts {
		if a.Score >= m.cfg.MinScore {
			filtered = append(filtered, a)
		}
	}

	if len(filtered) == 0 {
		if m.cfg.Verbose {
			m.logger.Info("scan complete — no threats detected",
				"scan", num,
				"elapsed", elapsed.Round(time.Millisecond).String(),
			)
		}
		return nil
	}

	// We have detections
	m.logger.Warn("reverse shell candidates detected",
		"scan", num,
		"count", len(filtered),
		"elapsed", elapsed.Round(time.Millisecond).String(),
	)

	m.fmt.PrintAlerts(filtered)

	if m.cfg.KillOnDetect {
		m.killDetected(filtered)
	}

	return nil
}

// killDetected sends SIGKILL to all detected PIDs.
func (m *Monitor) killDetected(alerts []detector.Alert) {
	killed := make(map[int]bool)
	for _, a := range alerts {
		pid := a.Connection.PID
		if pid <= 0 || killed[pid] {
			continue
		}
		if err := killProcess(pid); err != nil {
			m.logger.Error("failed to kill process",
				"pid", pid,
				"process", a.Connection.Process,
				"error", err,
			)
		} else {
			m.logger.Warn("terminated malicious process",
				"pid", pid,
				"process", a.Connection.Process,
				"pattern", a.Pattern.Name,
			)
			killed[pid] = true
		}
	}
}

// printSummary outputs a final summary of all alerts accumulated during the session.
func (m *Monitor) printSummary() {
	all := m.det.Alerts()
	if len(all) == 0 {
		m.logger.Info("session complete — no threats detected across all scans",
			"total_scans", m.scanNum,
		)
		return
	}

	m.logger.Warn("session summary",
		"total_scans", m.scanNum,
		"total_alerts", len(all),
	)
}
