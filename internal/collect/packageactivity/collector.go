// Package packageactivity reads package-manager transaction logs directly
// (no apt/dpkg/yum binary required) and reduces them to one bounded,
// timestamped entry per transaction -- never one entry per package, so a
// 40-package upgrade run does not become 40 timeline lines.
//
// Two distributions are supported: Debian/Ubuntu via apt's own
// /var/log/apt/history.log, which is already grouped one block per
// transaction, and the classic RHEL/CentOS /var/log/yum.log, which is not
// (grouped here by matching-minute timestamps). Modern dnf-only hosts that
// never populate yum.log are not covered; dnf's own history lives in a
// SQLite database this project does not take a dependency on to read.
package packageactivity

import (
	"context"
	"errors"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/elcool0r/glimpse/internal/collect"
	"github.com/elcool0r/glimpse/internal/model"
)

const (
	// maxFileBytes bounds how much of a log is read, from the end: apt and
	// yum both append newest-last, so the tail is what a lookback needs.
	maxFileBytes = 512 << 10
	// maxTransactions caps how many transactions one report carries,
	// consistent with the bounded-evidence convention used elsewhere.
	maxTransactions = 50
)

type Collector struct {
	ReadTail func(path string, maxBytes int) ([]byte, error)
}

func New() *Collector { return &Collector{ReadTail: ReadTail} }

func (Collector) Name() string { return "package-activity" }

// Static marks this as a gauge: the log files are read once for the report,
// not sampled across the window.
func (Collector) Static() {}

func (c Collector) Collect(ctx context.Context) (collect.Data, error) {
	if err := ctx.Err(); err != nil {
		return collect.Data{}, err
	}
	readTail := c.ReadTail
	if readTail == nil {
		readTail = ReadTail
	}
	var activity []model.PackageActivity
	var diagnostics []model.CollectionStatus

	if raw, err := readTail("/var/log/apt/history.log", maxFileBytes); err == nil {
		activity = append(activity, ParseAptHistory(string(raw))...)
	} else if !os.IsNotExist(err) {
		diagnostics = append(diagnostics, model.CollectionStatus{Status: "unavailable", Detail: "apt history: " + err.Error()})
	}

	if raw, err := readTail("/var/log/yum.log", maxFileBytes); err == nil {
		activity = append(activity, ParseYumLog(string(raw), time.Now())...)
	} else if !os.IsNotExist(err) {
		diagnostics = append(diagnostics, model.CollectionStatus{Status: "unavailable", Detail: "yum log: " + err.Error()})
	}

	sort.Slice(activity, func(i, j int) bool { return activity[i].At.Before(activity[j].At) })
	if len(activity) > maxTransactions {
		activity = activity[len(activity)-maxTransactions:]
	}
	return collect.Data{PackageActivity: activity, Diagnostics: diagnostics}, nil
}

// ReadTail reads at most maxBytes from the end of path.
func ReadTail(path string, maxBytes int) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	size := info.Size()
	toRead := size
	if toRead > int64(maxBytes) {
		toRead = int64(maxBytes)
		if _, err := f.Seek(-toRead, io.SeekEnd); err != nil {
			return nil, err
		}
	}
	buf := make([]byte, toRead)
	n, err := io.ReadFull(f, buf)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, err
	}
	return buf[:n], nil
}

// aptTimestampLayout matches apt's own history.log "Start-Date:"/"End-Date:"
// formatting, in the host's local time (whitespace between the date and
// time fields is collapsed before parsing, since apt pads it).
const aptTimestampLayout = "2006-01-02 15:04:05"

// ParseAptHistory reads /var/log/apt/history.log: blocks of "Key: value"
// lines separated by a blank line, one block per apt invocation. Each
// Install/Upgrade/Remove/Purge line lists its packages comma-separated,
// with each package's own version parenthetical also containing a comma --
// splitTopLevelEntries only splits at paren-depth zero so that does not
// over-count.
func ParseAptHistory(output string) []model.PackageActivity {
	var activity []model.PackageActivity
	for _, block := range strings.Split(output, "\n\n") {
		var at time.Time
		counts := map[string]int{}
		for _, line := range strings.Split(block, "\n") {
			key, value, ok := strings.Cut(line, ": ")
			if !ok {
				continue
			}
			switch key {
			case "Start-Date":
				collapsed := strings.Join(strings.Fields(value), " ")
				if t, err := time.ParseInLocation(aptTimestampLayout, collapsed, time.Local); err == nil {
					at = t
				}
			case "Install", "Upgrade", "Remove", "Purge", "Reinstall":
				counts[strings.ToLower(key)] += len(splitTopLevelEntries(value))
			}
		}
		if at.IsZero() || len(counts) == 0 {
			continue
		}
		activity = append(activity, model.PackageActivity{At: at, Manager: "apt", Summary: summarizeCounts(counts)})
	}
	return activity
}

// yumLineLayout matches the classic yum.log line prefix, which carries no
// year; the current year is assumed, correcting back one year if that
// would place the record implausibly in the future (a log rotated across a
// year boundary).
const yumLineLayout = "Jan 02 15:04:05 2006"

// ParseYumLog reads the classic /var/log/yum.log (RHEL/CentOS 7 and
// earlier): one ungrouped line per package, "Mon DD HH:MM:SS
// Action: package-nevra". Lines are grouped into one transaction per
// distinct minute, since yum.log itself carries no transaction boundary.
func ParseYumLog(output string, now time.Time) []model.PackageActivity {
	type bucket struct {
		at     time.Time
		counts map[string]int
	}
	order := make([]string, 0)
	buckets := make(map[string]*bucket)
	for _, line := range strings.Split(output, "\n") {
		fields := strings.SplitN(strings.TrimSpace(line), " ", 4)
		if len(fields) < 4 {
			continue
		}
		stamp := strings.Join(fields[:3], " ")
		action, _, ok := strings.Cut(fields[3], ":")
		if !ok {
			continue
		}
		action = strings.ToLower(strings.TrimSpace(action))
		switch action {
		case "installed", "updated", "erased", "obsoleted":
		default:
			continue
		}
		t, err := time.ParseInLocation(yumLineLayout, stamp+" "+strconv.Itoa(now.Year()), time.Local)
		if err != nil {
			continue
		}
		if t.After(now.Add(24 * time.Hour)) {
			t = t.AddDate(-1, 0, 0)
		}
		key := t.Format("2006-01-02 15:04")
		b, exists := buckets[key]
		if !exists {
			b = &bucket{at: t, counts: map[string]int{}}
			buckets[key] = b
			order = append(order, key)
		}
		b.counts[action]++
	}
	activity := make([]model.PackageActivity, 0, len(order))
	for _, key := range order {
		b := buckets[key]
		activity = append(activity, model.PackageActivity{At: b.at, Manager: "yum", Summary: summarizeCounts(b.counts)})
	}
	return activity
}

// splitTopLevelEntries splits an apt package list on the commas that
// separate entries, not the commas inside a version parenthetical.
func splitTopLevelEntries(value string) []string {
	var entries []string
	depth := 0
	start := 0
	for i, r := range value {
		switch r {
		case '(':
			depth++
		case ')':
			depth--
		case ',':
			if depth == 0 {
				entries = append(entries, strings.TrimSpace(value[start:i]))
				start = i + 1
			}
		}
	}
	if tail := strings.TrimSpace(value[start:]); tail != "" {
		entries = append(entries, tail)
	}
	return entries
}

func summarizeCounts(counts map[string]int) string {
	order := []string{"install", "upgrade", "updated", "installed", "reinstall", "remove", "purge", "erased", "obsoleted"}
	labels := map[string]string{
		"install": "installed", "upgrade": "upgraded", "reinstall": "reinstalled",
		"remove": "removed", "purge": "purged",
		"updated": "updated", "installed": "installed", "erased": "erased", "obsoleted": "obsoleted",
	}
	var parts []string
	seen := map[string]bool{}
	for _, key := range order {
		n, ok := counts[key]
		if !ok || n == 0 || seen[labels[key]] {
			continue
		}
		seen[labels[key]] = true
		parts = append(parts, pluralize(n, labels[key]))
	}
	return strings.Join(parts, ", ")
}

func pluralize(n int, verb string) string {
	if n == 1 {
		return "1 package " + verb
	}
	return strconv.Itoa(n) + " packages " + verb
}
