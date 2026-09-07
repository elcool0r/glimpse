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
// elsewhere (the metric row and Details).
type timelineEvent struct {
	at    time.Time
	label string
}

// renderTimeline prints today's notable events -- kernel/hardware faults,
// container incidents, and service failures/restarts -- in chronological
// order (most recent first), so a critical finding arrives with the story
// leading up to it instead of only its own isolated snapshot. It always
// prints the section header once invoked (by a critical finding or
// --events), even when nothing qualifies: a silently empty section would be
// indistinguishable from --events doing nothing at all.
func renderTimeline(w io.Writer, width int, r model.Report, color bool) {
	events := collectTimelineEvents(r)
	sort.Slice(events, func(i, j int) bool { return events[i].at.After(events[j].at) })
	fmt.Fprintln(w)
	writeWrapped(w, width, "", sectionHeader("Recent events (today)", color))
	if len(events) == 0 {
		// A silently empty section here is indistinguishable from the flag
		// doing nothing; say plainly that nothing qualified rather than just
		// omitting the section, especially since --events was asked for.
		writeWrapped(w, width, "", "No kernel, container, or service events with a known time were recorded today.")
		return
	}
	omitted := 0
	if len(events) > maxTimelineEvents {
		omitted = len(events) - maxTimelineEvents
		events = events[:maxTimelineEvents]
	}
	for _, e := range events {
		writeWrapped(w, width, "", fmt.Sprintf("%s  %s", metadata(e.at.Local().Format("15:04"), color), cleanText(e.label)))
	}
	if omitted > 0 {
		writeWrapped(w, width, "", fmt.Sprintf("(%d more event(s) earlier today)", omitted))
	}
}

// collectTimelineEvents gathers events from data this report already
// collected. Two kinds of source exist:
//
//   - A real historical timestamp: kernel journal entries and container log
//     lines both carry an age at collection time, so their actual
//     wall-clock moment can be recovered. Anything without an age cannot be
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
	add := func(at time.Time, label string) {
		if at.Before(midnight) {
			return
		}
		events = append(events, timelineEvent{at: at, label: label})
	}
	addAged := func(age *float64, label string) {
		if age == nil {
			return
		}
		add(now.Add(-time.Duration(*age*float64(time.Second))), label)
	}

	if k := r.Metrics.Kernel; k != nil {
		for _, event := range k.Events {
			addAged(event.AgeSeconds, cleanText(event.Message))
		}
	}

	for _, runtime := range r.Metrics.Containers {
		for _, c := range runtime.Containers {
			name := c.Name
			if name == "" {
				name = c.ID
			}
			switch {
			case c.OOMKilled:
				add(now, fmt.Sprintf("container %s was OOM-killed", name))
			case c.Healthy != nil && !*c.Healthy:
				add(now, fmt.Sprintf("container %s is unhealthy", name))
			}
			if c.RestartCount > 0 {
				add(now, fmt.Sprintf("container %s restarted (%d time(s) during the sample)", name, c.RestartCount))
			}
			if strings.EqualFold(c.State, "exited") && c.HasRestartPolicy {
				add(now, fmt.Sprintf("container %s exited despite its restart policy", name))
			}
			// Only the same concrete failure signatures the analyzer treats
			// as actionable belong on a timeline of significant events;
			// generic log wording containing "error" is noise here too.
			for _, event := range c.LogEvents {
				if !timelineSpecificLogKind(event.Kind) {
					continue
				}
				addAged(event.AgeSeconds, fmt.Sprintf("container %s: %s", name, cleanText(event.Message)))
			}
		}
	}

	if s := r.Metrics.Systemd; s != nil {
		for _, unit := range s.FailedUnits {
			add(now, fmt.Sprintf("%s failed", cleanText(unit)))
		}
		for _, unit := range s.RestartingUnits {
			add(now, fmt.Sprintf("%s restarted %d time(s) during the sample", cleanText(unit.Unit), unit.RestartsDelta))
		}
	}

	return events
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
