// Package mountinfo parses /proc/<pid>/mountinfo.
//
// It exists so mount state has exactly one parser: the filesystem capacity
// collector and the persistent-mount check previously carried separate
// implementations whose unescaping had already diverged.
package mountinfo

import (
	"bufio"
	"errors"
	"io"
	"strings"
)

// Entry is one mounted filesystem.
type Entry struct {
	Source   string
	Target   string
	Type     string
	Options  []string
	ReadOnly bool
}

// Parse reads mountinfo records. A malformed record is skipped rather than
// failing the whole read: one unrecognized line must not remove every mount
// from the report. Parse fails only when no record could be read at all.
func Parse(r io.Reader) ([]Entry, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var entries []Entry
	skipped := 0
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		entry, ok := parseLine(line)
		if !ok {
			skipped++
			continue
		}
		entries = append(entries, entry)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		if skipped > 0 {
			return nil, errors.New("mountinfo: no parsable entries")
		}
		return nil, errors.New("mountinfo: empty")
	}
	return entries, nil
}

// parseLine decodes one record. Fields 0..5 are fixed, an optional-field list
// follows, and a single "-" separates it from the filesystem type, source and
// superblock options. The separator search starts after the fixed fields so a
// mount point literally named "-" cannot be mistaken for it.
func parseLine(line string) (Entry, bool) {
	fields := strings.Fields(line)
	if len(fields) < 10 {
		return Entry{}, false
	}
	separator := -1
	for i := 6; i < len(fields); i++ {
		if fields[i] == "-" {
			separator = i
			break
		}
	}
	if separator < 6 || len(fields) < separator+3 {
		return Entry{}, false
	}
	options := strings.Split(fields[5], ",")
	readOnly := false
	for _, option := range options {
		if option == "ro" {
			readOnly = true
		}
	}
	return Entry{
		Source:   Unescape(fields[separator+2]),
		Target:   Unescape(fields[4]),
		Type:     fields[separator+1],
		Options:  options,
		ReadOnly: readOnly,
	}, true
}

// Unescape decodes the octal sequences the kernel writes for characters that
// would otherwise break field splitting.
func Unescape(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	for _, pair := range [][2]string{{`\040`, " "}, {`\011`, "\t"}, {`\012`, "\n"}, {`\134`, `\`}} {
		s = strings.ReplaceAll(s, pair[0], pair[1])
	}
	return s
}

// Targets returns the set of mounted paths, for presence checks.
func Targets(entries []Entry) map[string]bool {
	targets := make(map[string]bool, len(entries))
	for _, entry := range entries {
		targets[entry.Target] = true
	}
	return targets
}
