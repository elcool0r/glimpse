// Package pingutil shares the system-ping invocation and output parsing
// between collectors that need an ICMP probe (gatewayping, pathmtu), so the
// iputils/BusyBox/macOS output-format handling exists in exactly one place.
package pingutil

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/elcool0r/glimpse/internal/collect/command"
)

const maxOutput = 8 << 10

// Run executes `ping` with args and parses its summary line. A nonzero exit
// status is routine -- ping exits 1 on any packet loss, including partial
// loss with a perfectly good summary to parse -- so output is trusted over
// the exit code, exactly like this codebase's other optional commands
// (smartctl, zpool status).
func Run(ctx context.Context, run func(context.Context, string, ...string) ([]byte, error), path string, args ...string) (sent, received int, avgMillis float64, err error) {
	output, runErr := run(ctx, path, args...)
	sent, received, avgMillis, parseErr := ParseOutput(string(output))
	if parseErr != nil {
		if runErr != nil {
			return 0, 0, 0, fmt.Errorf("%v", runErr)
		}
		return 0, 0, 0, parseErr
	}
	return sent, received, avgMillis, nil
}

// RunCommand adapts command.Run to the func(context.Context, string,
// ...string) ([]byte, error) shape Run expects.
func RunCommand(ctx context.Context, path string, args ...string) ([]byte, error) {
	result, err := command.Run(ctx, command.Options{MaxOutput: maxOutput}, path, args...)
	return result.Output, err
}

// ParseOutput reads the summary line iputils and BusyBox ping both print,
// e.g. "3 packets transmitted, 2 received, 33.3% packet loss, time 2003ms"
// and, when present, the round-trip line, e.g.
// "rtt min/avg/max/mdev = 11.9/12.1/12.3/0.16 ms" (macOS adds a trailing
// stddev field; only the first two fields after "=" are read, so the extra
// field does not matter). A missing summary line (killed before completion,
// unexpected output format) is reported as an error so the caller can mark
// the whole probe unavailable rather than fabricate a result.
func ParseOutput(output string) (sent, received int, avgMillis float64, err error) {
	found := false
	scanner := bufio.NewScanner(bytes.NewReader([]byte(output)))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "packets transmitted") {
			for _, part := range strings.Split(line, ",") {
				part = strings.TrimSpace(part)
				switch {
				case strings.HasSuffix(part, "packets transmitted"):
					sent = firstInt(part)
				case strings.HasSuffix(part, "received"):
					received = firstInt(part)
				}
			}
			found = true
			continue
		}
		if strings.HasPrefix(line, "rtt ") || strings.HasPrefix(line, "round-trip ") {
			if idx := strings.Index(line, "="); idx >= 0 {
				fields := strings.Fields(line[idx+1:])
				if len(fields) > 0 {
					timings := strings.Split(fields[0], "/")
					if len(timings) >= 2 {
						avgMillis, _ = strconv.ParseFloat(timings[1], 64)
					}
				}
			}
		}
	}
	if !found {
		return 0, 0, 0, fmt.Errorf("no summary line in ping output")
	}
	return sent, received, avgMillis, nil
}

// firstInt extracts the leading integer of a string such as "3 packets
// transmitted" or "2 received".
func firstInt(s string) int {
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return 0
	}
	value, _ := strconv.Atoi(fields[0])
	return value
}
