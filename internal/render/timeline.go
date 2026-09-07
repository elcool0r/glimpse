package render

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/elcool0r/glimpse/internal/model"
)

// maxTimelineEvents bounds the list to a quick read of "what led up to
// this", not a full log dump -- if a host had that many notable events
// today, the journal itself is the right place to keep reading.
const maxTimelineEvents = 20

// timelineEvent is one entry in the "Recent events" section: something that
// happened at a specific, known moment. Ongoing state (a filesystem that is
// currently 95% full, a degraded RAID array) deliberately has no place here
// -- this report cannot say when that condition started, and guessing would
// be worse than leaving it out; that state is already reported properly
// elsewhere (the metric row and Details). source names where the fact came
// from (kernel, systemd, a container runtime, apt/yum, ssh, sudo), so a
// reader knows which log to open to dig further without guessing.
type timelineEvent struct {
	at     time.Time
	label  string
	source string
}

// renderTimeline prints today's notable events -- kernel/hardware faults,
// container incidents, and service failures/restarts -- in chronological
// order (oldest first, latest last, the way a log or scrollback reads), so
// a critical finding arrives with the story leading up to it instead of
// only its own isolated snapshot. It always prints the section header once
// invoked (by a critical finding or
// --events), even when nothing qualifies: a silently empty section would be
// indistinguishable from --events doing nothing at all.
func renderTimeline(w io.Writer, width int, r model.Report, color bool) {
	events := collectTimelineEvents(r)
	// Oldest first, latest last: this reads top-to-bottom the way a log or
	// scrollback does, with "now" nearest the prompt.
	sort.Slice(events, func(i, j int) bool { return events[i].at.Before(events[j].at) })
	fmt.Fprintln(w)
	writeWrapped(w, width, "", sectionHeader("Recent events (today)", color))
	if len(events) == 0 {
		// A silently empty section here is indistinguishable from the flag
		// doing nothing; say plainly that nothing qualified rather than just
		// omitting the section, especially since --events was asked for.
		writeWrapped(w, width, "", "No kernel, container, service, package, login, or sudo events with a known time were recorded today.")
		return
	}
	omitted := 0
	if len(events) > maxTimelineEvents {
		// The events being cut are the oldest ones (index 0 onward), since
		// the most recent must survive the cap; say so before the list
		// rather than after, since it now describes what came before it.
		omitted = len(events) - maxTimelineEvents
		events = events[omitted:]
		writeWrapped(w, width, "", fmt.Sprintf("(%d more event(s) earlier today)", omitted))
	}
	for _, e := range events {
		writeWrapped(w, width, "", fmt.Sprintf("%s  %s  %s", metadata(e.at.Local().Format("15:04"), color), metadata("["+e.source+"]", color), cleanText(e.label)))
	}
}

// collectTimelineEvents gathers events from data this report already
// collected. Two kinds of source exist:
//
//   - A real historical timestamp: kernel journal entries, container log
//     lines, package-manager transactions, SSH logins, and sudo commands all
//     carry (or can derive) a real moment. Anything without one cannot be
//     placed on the timeline and is left out (it still appears elsewhere).
//   - A live fact with no historical record of when it started: a
//     currently-failed systemd unit, a container this sample found
//     unhealthy or OOM-killed. These are stamped "now" -- true for the
//     instant this report ran, not a claim about exactly when the fault
//     began.
//
// Only today (local midnight through now) is kept; scoping to a wider
// rolling window is a reasonable next step but not this one.
func collectTimelineEvents(r model.Report) []timelineEvent {
	now := r.GeneratedAt
	if now.IsZero() {
		now = time.Now()
	}
	local := now.Local()
	midnight := time.Date(local.Year(), local.Month(), local.Day(), 0, 0, 0, 0, local.Location())

	var events []timelineEvent
	add := func(at time.Time, source, label string) {
		if at.Before(midnight) {
			return
		}
		events = append(events, timelineEvent{at: at, label: label, source: source})
	}
	addAged := func(age *float64, source, label string) {
		if age == nil {
			return
		}
		add(now.Add(-time.Duration(*age*float64(time.Second))), source, label)
	}

	if r.Host.BootTime != nil {
		add(*r.Host.BootTime, "system", "system booted")
	}

	if k := r.Metrics.Kernel; k != nil {
		for _, event := range k.Events {
			addAged(event.AgeSeconds, "kernel", cleanText(event.Message))
		}
	}

	for _, runtime := range r.Metrics.Containers {
		for _, c := range runtime.Containers {
			name := c.Name
			if name == "" {
				name = c.ID
			}
			source := runtime.Runtime
			switch {
			case c.OOMKilled:
				add(now, source, fmt.Sprintf("container %s was OOM-killed", name))
			case c.Healthy != nil && !*c.Healthy:
				add(now, source, fmt.Sprintf("container %s is unhealthy", name))
			}
			if c.RestartCount > 0 {
				add(now, source, fmt.Sprintf("container %s restarted (%d time(s) during the sample)", name, c.RestartCount))
			}
			if strings.EqualFold(c.State, "exited") && c.HasRestartPolicy {
				add(now, source, fmt.Sprintf("container %s exited despite its restart policy", name))
			}
			// Only the same concrete failure signatures the analyzer treats
			// as actionable belong on a timeline of significant events;
			// generic log wording containing "error" is noise here too.
			for _, event := range c.LogEvents {
				if !timelineSpecificLogKind(event.Kind) {
					continue
				}
				addAged(event.AgeSeconds, source, fmt.Sprintf("container %s: %s", name, cleanText(event.Message)))
			}
		}
	}

	if s := r.Metrics.Systemd; s != nil {
		for _, unit := range s.FailedUnits {
			add(now, "systemd", fmt.Sprintf("%s failed", cleanText(unit)))
		}
		// RestartsDelta only sees a restart that happens to fall inside
		// glimpse's own few-second sample -- a unit restarted a minute
		// before glimpse ran would show nothing there. RecentStarts, from
		// systemd's own ActiveEnterTimestamp, has the real time regardless
		// of when glimpse happened to run, so it takes priority; the delta
		// count is folded into that line when both are known, and only
		// used on its own as a fallback if the timestamp wasn't available.
		restartCounts := make(map[string]uint64, len(s.RestartingUnits))
		for _, unit := range s.RestartingUnits {
			restartCounts[unit.Unit] = unit.RestartsDelta
		}
		reported := make(map[string]bool, len(s.RecentStarts))
		for _, start := range s.RecentStarts {
			label := fmt.Sprintf("%s (re)started", cleanText(start.Unit))
			if delta, ok := restartCounts[start.Unit]; ok {
				label = fmt.Sprintf("%s restarted (%d time(s) during this sample)", cleanText(start.Unit), delta)
			}
			add(start.At, "systemd", label)
			reported[start.Unit] = true
		}
		for unit, delta := range restartCounts {
			if reported[unit] {
				continue
			}
			add(now, "systemd", fmt.Sprintf("%s restarted %d time(s) during the sample", cleanText(unit), delta))
		}
	}

	for _, activity := range r.Metrics.PackageActivity {
		if activity.Summary == "" {
			continue
		}
		add(activity.At, activity.Manager, activity.Summary)
	}

	for _, login := range r.Metrics.Logins {
		label := fmt.Sprintf("login: %s", cleanText(login.User))
		if login.Source != "" {
			label += " from " + cleanText(login.Source)
		}
		if login.Method != "" {
			label += " (" + cleanText(login.Method) + ")"
		}
		add(login.At, "ssh", label)
	}

	for _, cmd := range r.Metrics.SudoCommands {
		label := fmt.Sprintf("%s ran sudo", cleanText(cmd.User))
		if cmd.RunAs != "" && !strings.EqualFold(cmd.RunAs, "root") {
			label += " as " + cleanText(cmd.RunAs)
		}
		label += ": " + truncateForDisplay(cleanText(cmd.Command), 80)
		add(cmd.At, "sudo", label)
	}

	return events
}

// truncateForDisplay caps a raw command line to a readable length; the full
// text is still available in the underlying model/JSON for anyone who needs
// it.
func truncateForDisplay(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

// timelineSpecificLogKind mirrors analyze.specificLogKind: only a concrete
// failure signature, not generic "error"/"failure" wording, is significant
// enough for the timeline. It is duplicated in miniature here, the same way
// dnsStatus duplicates analyze.dnsFindings, because the renderer decides
// what belongs in a display list, not a health verdict.
func timelineSpecificLogKind(kind string) bool {
	switch kind {
	case "oom", "panic", "segmentation_fault", "uncaught_exception",
		"data_corruption", "read_only_filesystem":
		return true
	default:
		return false
	}
}
