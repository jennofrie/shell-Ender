package output

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/jennofrie/shell-Ender/internal/detector"
)

// Formatter handles output rendering in different formats.
type Formatter struct {
	format string
}

// NewFormatter creates a formatter for the given format ("table" or "json").
func NewFormatter(format string) *Formatter {
	return &Formatter{format: strings.ToLower(format)}
}

// PrintAlerts renders a slice of alerts to stdout.
func (f *Formatter) PrintAlerts(alerts []detector.Alert) {
	switch f.format {
	case "json":
		f.printJSON(alerts)
	default:
		f.printTable(alerts)
	}
}

// jsonAlert is the JSON-serializable representation of an alert.
type jsonAlert struct {
	Timestamp  string `json:"timestamp"`
	Pattern    string `json:"pattern"`
	Category   string `json:"category"`
	Severity   string `json:"severity"`
	Score      int    `json:"score"`
	Process    string `json:"process"`
	PID        int    `json:"pid"`
	Protocol   string `json:"protocol"`
	LocalAddr  string `json:"local_addr"`
	RemoteAddr string `json:"remote_addr"`
	State      string `json:"state"`
	Cmdline    string `json:"cmdline,omitempty"`
	Details    string `json:"details"`
}

func (f *Formatter) printJSON(alerts []detector.Alert) {
	var out []jsonAlert
	for _, a := range alerts {
		out = append(out, jsonAlert{
			Timestamp:  a.Timestamp.Format(time.RFC3339),
			Pattern:    a.Pattern.Name,
			Category:   a.Pattern.Category,
			Severity:   a.Pattern.Severity,
			Score:      a.Score,
			Process:    a.Connection.Process,
			PID:        a.Connection.PID,
			Protocol:   a.Connection.Protocol,
			LocalAddr:  a.Connection.LocalAddr,
			RemoteAddr: a.Connection.RemoteAddr,
			State:      a.Connection.State,
			Cmdline:    a.Connection.Cmdline,
			Details:    a.Details,
		})
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(out)
}

func (f *Formatter) printTable(alerts []detector.Alert) {
	fmt.Println()
	fmt.Println(severityBanner("ALERT", len(alerts)))
	fmt.Println()

	w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
	fmt.Fprintln(w, "SEVERITY\tSCORE\tPATTERN\tPROCESS\tPID\tREMOTE ADDR\tSTATE\t")
	fmt.Fprintln(w, "--------\t-----\t-------\t-------\t---\t-----------\t-----\t")

	for _, a := range alerts {
		sevIcon := severityIcon(a.Pattern.Severity)
		fmt.Fprintf(w, "%s %s\t%d\t%s\t%s\t%d\t%s\t%s\t\n",
			sevIcon,
			strings.ToUpper(a.Pattern.Severity),
			a.Score,
			a.Pattern.Name,
			a.Connection.Process,
			a.Connection.PID,
			a.Connection.RemoteAddr,
			a.Connection.State,
		)
	}
	w.Flush()

	// Print command lines if available
	for _, a := range alerts {
		if a.Connection.Cmdline != "" {
			fmt.Printf("\n  PID %d cmdline: %s\n", a.Connection.PID, a.Connection.Cmdline)
		}
	}
	fmt.Println()
}

func severityIcon(sev string) string {
	switch strings.ToLower(sev) {
	case "critical":
		return "[!!!]"
	case "high":
		return "[!! ]"
	case "medium":
		return "[!  ]"
	case "low":
		return "[.  ]"
	default:
		return "[?  ]"
	}
}

func severityBanner(label string, count int) string {
	return fmt.Sprintf("=== %s: %d suspicious connection(s) detected ===", label, count)
}

// PrintPatterns outputs all registered detection patterns.
func PrintPatterns(format string) {
	patterns := detector.DefaultPatterns()

	if strings.ToLower(format) == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(patterns)
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
	fmt.Fprintln(w, "PATTERN\tCATEGORY\tSEVERITY\tPROCESSES\t")
	fmt.Fprintln(w, "-------\t--------\t--------\t---------\t")
	for _, p := range patterns {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t\n",
			p.Name,
			p.Category,
			strings.ToUpper(p.Severity),
			strings.Join(p.ProcessNames, ", "),
		)
	}
	w.Flush()

	fmt.Printf("\nTotal patterns: %d\n", len(patterns))
}
