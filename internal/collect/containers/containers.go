// Package containers reads optional Docker and Podman state using their CLIs.
package containers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/elcool0r/glimpse/internal/collect"
	"github.com/elcool0r/glimpse/internal/collect/command"
	"github.com/elcool0r/glimpse/internal/model"
)

const commandTimeout = 3 * time.Second
const maxContainers = 64

// Log collection deliberately has tighter bounds than state inspection. Logs
// are diagnostic context, never a reason to turn an optional integration into
// a slow or memory-hungry check.
const (
	logCommandTimeout = 2 * time.Second
	logTotalTimeout   = 16 * time.Second
	// Logs are checked for every discovered, relevant container, up to the
	// inspection limit. The shared deadline remains the guard against a slow
	// runtime, rather than an arbitrary small subset.
	maxLogContainers = maxContainers
	maxLogLines      = 200
	maxLogBytes      = 128 << 10
	maxLogLineBytes  = 512
)

type Collector struct {
	Timeout         time.Duration
	LogTimeout      time.Duration
	LogTotalTimeout time.Duration
	lookPath        func(string) (string, error)
	run             func(context.Context, string, ...string) ([]byte, error)
	runLogs         logRunner
	now             func() time.Time
}

// logRunner reads bounded log output. It reports truncation separately from
// failure: a clipped read still yields usable evidence, while a failed read
// yields none and must be visible as missing coverage.
type logRunner func(ctx context.Context, args []string, path string) ([]byte, bool, error)

func New() *Collector {
	return &Collector{lookPath: exec.LookPath, run: runCommand, runLogs: runLimitedLogCommand}
}
func (c *Collector) Name() string { return "containers" }

type snapshot struct{ restarts map[string]uint64 }

type runtimeCommand struct {
	name string
	path string
}

func (c *Collector) Collect(parent context.Context) (collect.Data, error) {
	lookup := c.lookPath
	if lookup == nil {
		lookup = exec.LookPath
	}
	run := c.run
	if run == nil {
		run = runCommand
	}
	runLogs := c.runLogs
	if runLogs == nil {
		runLogs = runLimitedLogCommand
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = commandTimeout
	}
	logTotal := c.LogTotalTimeout
	if logTotal <= 0 {
		logTotal = logTotalTimeout
	}
	endpoint := dockerEndpoint()
	var result []model.ContainerRuntime
	restarts := map[string]uint64{}
	var diagnostics []model.CollectionStatus
	var missingRuntimes []string
	runtimes := make([]runtimeCommand, 0, 2)
	for _, runtime := range []string{"podman", "docker"} {
		path, err := lookup(runtime)
		if err != nil {
			missingRuntimes = append(missingRuntimes, fmt.Sprintf("%s: %v", runtime, err))
			continue
		}
		runtimes = append(runtimes, runtimeCommand{name: runtime, path: path})
	}
	// Divide one total log budget between the installed runtimes. Without this,
	// a slow Podman log query can consume every permitted check and leave Docker
	// unexamined on hosts that run both engines.
	remainingLogContainers := maxLogContainers
	remainingLogBudget := logTotal
	for runtimeIndex, runtimeCommand := range runtimes {
		runtime := runtimeCommand.name
		path := runtimeCommand.path
		ctx, cancel := context.WithTimeout(parent, timeout)
		idsRaw, err := run(ctx, path, runtimeArgs(runtime, endpoint, "ps", "--all", "--quiet", "--no-trunc")...)
		cancel()
		if err != nil {
			if parent.Err() != nil {
				return collect.Data{Containers: result, Snapshot: snapshot{restarts: restarts}, Diagnostics: diagnostics}, parent.Err()
			}
			diagnostics = append(diagnostics, model.CollectionStatus{Collector: c.Name(), Status: "unavailable", Detail: fmt.Sprintf("%s list failed: %v", runtime, err)})
			continue
		}
		ids, discovered, inspectionLimited := boundedIDsWithCoverage(string(idsRaw))
		if len(ids) == 0 {
			result = append(result, model.ContainerRuntime{
				Runtime: runtime, Containers: []model.Container{},
				ContainersDiscovered: discovered, ContainersInspected: len(ids), ContainerInspectionLimited: inspectionLimited,
			})
			continue
		}
		ctx, cancel = context.WithTimeout(parent, timeout)
		args := runtimeArgs(runtime, endpoint, "inspect", "--format", "{{json .}}")
		args = append(args, ids...)
		raw, err := run(ctx, path, args...)
		cancel()
		if err != nil {
			if parent.Err() != nil {
				return collect.Data{Containers: result, Snapshot: snapshot{restarts: restarts}, Diagnostics: diagnostics}, parent.Err()
			}
			diagnostics = append(diagnostics, model.CollectionStatus{Collector: c.Name(), Status: "error", Detail: fmt.Sprintf("%s inspect failed: %v", runtime, err)})
			continue
		}
		containers, rawRestarts, parseErr := parseInspectJSONLinesStrict(string(raw))
		if parseErr != nil {
			diagnostics = append(diagnostics, model.CollectionStatus{Collector: c.Name(), Status: "error", Detail: fmt.Sprintf("%s inspect parse failed: %v", runtime, parseErr)})
			if len(containers) == 0 {
				continue
			}
		}
		// A runtime can expose many containers. Bound both the number of log
		// calls and their combined wall time, so a full report stays responsive
		// even when a runtime is under load or its log storage is slow.
		remainingRuntimes := len(runtimes) - runtimeIndex
		logsChecked, logsAttempted := 0, 0
		if remainingLogContainers > 0 && remainingLogBudget > 0 {
			// Ceiling division reserves at least an equal share for every later
			// runtime. The final runtime receives the remainder.
			logLimit := (remainingLogContainers + remainingRuntimes - 1) / remainingRuntimes
			logBudget := remainingLogBudget / time.Duration(remainingRuntimes)
			if logBudget <= 0 {
				logBudget = remainingLogBudget
			}
			logCtx, logCancel := context.WithTimeout(parent, logBudget)
			outcome := c.collectLogs(logCtx, runLogs, runtime, endpoint, path, containers, logLimit)
			logCancel()
			logsChecked, logsAttempted = outcome.read, outcome.attempted
			// A container whose logs could not be read has not been checked.
			// Counting it as checked claimed coverage that did not exist.
			for _, failure := range outcome.failures {
				diagnostics = append(diagnostics, model.CollectionStatus{Collector: c.Name(), Status: "unavailable", Detail: fmt.Sprintf("%s logs unavailable for %s: %v", runtime, failure.name, failure.err)})
			}
			if outcome.truncated > 0 {
				diagnostics = append(diagnostics, model.CollectionStatus{Collector: c.Name(), Status: "unavailable", Detail: fmt.Sprintf("%s logs truncated at %d KiB for %d container(s); evidence may be incomplete", runtime, maxLogBytes>>10, outcome.truncated)})
			}
			remainingLogContainers -= logsAttempted
			remainingLogBudget -= logBudget
		}
		if parent.Err() != nil {
			return collect.Data{Containers: result, Snapshot: snapshot{restarts: restarts}, Diagnostics: diagnostics}, parent.Err()
		}
		for id, count := range rawRestarts {
			restarts[runtime+":"+id] = count
		}
		logCandidates := countLogRelevant(containers)
		result = append(result, model.ContainerRuntime{
			Runtime: runtime, Containers: containers,
			ContainersDiscovered: discovered, ContainersInspected: len(ids), ContainerInspectionLimited: inspectionLimited,
			LogsChecked: logsChecked, LogCandidates: logCandidates,
			LogWindow: "last hour", LogCheckLimited: logsChecked < logCandidates,
		})
	}
	// Missing runtimes are normal on a host that uses the other engine. Only
	// report them as collector unavailability when neither runtime produced an
	// observation; otherwise a successful Docker query must not be obscured by
	// an absent Podman binary (or vice versa).
	if len(result) == 0 {
		for _, detail := range missingRuntimes {
			diagnostics = append(diagnostics, model.CollectionStatus{Collector: c.Name(), Status: "unavailable", Detail: detail})
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Runtime < result[j].Runtime })
	return collect.Data{Containers: result, Snapshot: snapshot{restarts: restarts}, Diagnostics: diagnostics}, nil
}

// runtimeArgs makes every inspection explicitly local. Docker's host flag
// prevents DOCKER_HOST/DOCKER_CONTEXT from redirecting the command to a
// network endpoint. Podman's remote=false prevents CONTAINER_HOST and its
// remote context from being consulted while retaining normal local storage.
func runtimeArgs(runtime, dockerEndpoint string, args ...string) []string {
	prefix := make([]string, 0, len(args)+2)
	if runtime == "docker" {
		prefix = append(prefix, "--host", dockerEndpoint)
	} else if runtime == "podman" {
		prefix = append(prefix, "--remote=false")
	}
	return append(prefix, args...)
}

func dockerEndpoint() string {
	// Prefer the rootless local daemon socket when it exists, then the usual
	// system socket. Never use an inherited endpoint or context for discovery.
	candidates := make([]string, 0, 2)
	if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
		candidates = append(candidates, filepath.Join(dir, "docker.sock"))
	}
	// XDG_RUNTIME_DIR is commonly unset for services and SSH sessions, while
	// rootless Docker still uses /run/user/<uid>/docker.sock.
	if uid := os.Getuid(); uid >= 0 {
		candidates = append(candidates, filepath.Join("/run/user", fmt.Sprint(uid), "docker.sock"))
	}
	for _, candidate := range candidates {
		if info, err := os.Stat(candidate); err == nil && info.Mode()&os.ModeSocket != 0 {
			return "unix://" + candidate
		}
	}
	return "unix:///var/run/docker.sock"
}

// logOutcome separates what was attempted from what was actually read, so a
// runtime that refuses or truncates log output cannot be reported as covered.
type logOutcome struct {
	attempted int
	read      int
	truncated int
	failures  []logFailure
}

type logFailure struct {
	name string
	err  error
}

func (c *Collector) collectLogs(parent context.Context, run logRunner, runtime, endpoint, path string, items []model.Container, limit int) logOutcome {
	var outcome logOutcome
	if len(items) == 0 || parent.Err() != nil || limit <= 0 {
		return outcome
	}
	perCommand := c.LogTimeout
	if perCommand <= 0 {
		perCommand = logCommandTimeout
	}
	for i := range items {
		if outcome.attempted >= limit || parent.Err() != nil || !logRelevant(items[i]) {
			continue
		}
		commandCtx, commandCancel := context.WithTimeout(parent, perCommand)
		// Both CLIs accept this direct, non-shell invocation. `--since 1h`
		// bounds the useful incident window, while --timestamps gives the
		// renderer a real event time instead of making it guess when a log
		// incident happened.
		raw, truncated, err := run(commandCtx, runtimeArgs(runtime, endpoint, "logs", "--timestamps", "--since", "1h", "--tail", fmt.Sprint(maxLogLines), items[i].ID), path)
		commandCancel()
		outcome.attempted++
		if err != nil {
			name := items[i].Name
			if name == "" {
				name = items[i].ID
			}
			outcome.failures = append(outcome.failures, logFailure{name: name, err: err})
			continue // optional logs must never make container state unavailable
		}
		outcome.read++
		if truncated {
			outcome.truncated++
		}
		// This is the defined reference time for timestamped log records. It
		// is captured after the bounded command returns, so a record dated in
		// the future due to clock skew is conservatively reported as age zero.
		items[i].LogEvents = ClassifyLogEventsAt(string(raw), c.collectionTime())
	}
	return outcome
}

func (c *Collector) collectionTime() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

func logRelevant(item model.Container) bool {
	switch item.State {
	case "running", "restarting", "exited", "dead":
		return item.ID != ""
	default:
		return false
	}
}

func countLogRelevant(items []model.Container) int {
	count := 0
	for _, item := range items {
		if logRelevant(item) {
			count++
		}
	}
	return count
}
func (c *Collector) Delta(first, last collect.Data) (collect.Data, error) {
	a, aok := first.Snapshot.(snapshot)
	b, bok := last.Snapshot.(snapshot)
	if !aok || !bok {
		return collect.Data{Containers: last.Containers}, errors.New("container restart baseline unavailable")
	}
	out := last.Containers
	var reset []string
	for ri := range out {
		for ci := range out[ri].Containers {
			x := &out[ri].Containers[ci]
			x.RestartCount = 0
			key := out[ri].Runtime + ":" + x.ID
			before, ok := a.restarts[key]
			if !ok {
				// The container was created during the window, which is an
				// ordinary event rather than a collection fault. It has no
				// interval to report, so its restart delta stays zero until a
				// full window is available — the same rule the network
				// collector applies to a newly created interface.
				continue
			}
			if b.restarts[key] >= before {
				x.RestartCount = b.restarts[key] - before
				continue
			}
			reset = append(reset, key)
		}
	}
	if len(reset) > 0 {
		return collect.Data{Containers: out}, fmt.Errorf("container restart counter went backwards for %s", strings.Join(reset, ", "))
	}
	return collect.Data{Containers: out}, nil
}
func boundedIDs(text string) []string {
	ids, _, _ := boundedIDsWithCoverage(text)
	return ids
}

// boundedIDsWithCoverage returns the number of distinct IDs observed in the
// list response separately from the fixed-size inspection subset. The runtime
// command itself is output-bounded, so discovered is only exact within the
// response it returned.
func boundedIDsWithCoverage(text string) (ids []string, discovered int, limited bool) {
	ids = make([]string, 0, maxContainers)
	seen := map[string]struct{}{}
	for _, line := range strings.Split(text, "\n") {
		id := strings.TrimSpace(line)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		discovered++
		if len(ids) >= maxContainers {
			limited = true
			continue
		}
		ids = append(ids, id)
	}
	return ids, discovered, limited
}

// ParseInspectJSONLines parses the one-JSON-object-per-container output from
// `runtime inspect --format '{{json .}}'`. Unknown fields are intentionally
// ignored so stable output survives runtime version changes.
func ParseInspectJSONLines(text string) ([]model.Container, map[string]uint64) {
	items, restarts, _ := parseInspectJSONLinesStrict(text)
	return items, restarts
}

func parseInspectJSONLinesStrict(text string) ([]model.Container, map[string]uint64, error) {
	type health struct {
		Status string `json:"Status"`
	}
	type state struct {
		Status     string  `json:"Status"`
		Running    bool    `json:"Running"`
		OOMKilled  bool    `json:"OOMKilled"`
		Restarting bool    `json:"Restarting"`
		Health     *health `json:"Health"`
	}
	type hostConfig struct {
		RestartPolicy struct {
			Name string `json:"Name"`
		} `json:"RestartPolicy"`
	}
	type inspect struct {
		ID           string     `json:"Id"`
		Name         string     `json:"Name"`
		RestartCount uint64     `json:"RestartCount"`
		State        state      `json:"State"`
		HostConfig   hostConfig `json:"HostConfig"`
	}
	items := make([]model.Container, 0)
	restarts := map[string]uint64{}
	var parseErrors []string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var x inspect
		if err := json.Unmarshal([]byte(line), &x); err != nil {
			parseErrors = append(parseErrors, err.Error())
			continue
		}
		if x.ID == "" {
			parseErrors = append(parseErrors, "inspection object has no container ID")
			continue
		}
		name := strings.TrimPrefix(x.Name, "/")
		if name == "" {
			name = x.ID
		}
		state := strings.ToLower(x.State.Status)
		if state == "" {
			if x.State.Running {
				state = "running"
			} else {
				state = "unknown"
			}
		}
		item := model.Container{ID: x.ID, Name: name, State: state, OOMKilled: x.State.OOMKilled, HasRestartPolicy: x.HostConfig.RestartPolicy.Name != "" && x.HostConfig.RestartPolicy.Name != "no"}
		if x.State.Health != nil {
			// Docker/Podman use transitional states such as "starting". Those
			// are not a failed health check and must remain unknown to avoid a
			// false warning during a normal container start.
			switch strings.ToLower(x.State.Health.Status) {
			case "healthy":
				healthy := true
				item.Healthy = &healthy
			case "unhealthy":
				healthy := false
				item.Healthy = &healthy
			}
		}
		items = append(items, item)
		restarts[x.ID] = x.RestartCount
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })
	if len(items) == 0 {
		parseErrors = append(parseErrors, "no valid container objects")
	}
	if len(parseErrors) > 0 {
		return items, restarts, errors.New(strings.Join(parseErrors, "; "))
	}
	return items, restarts, nil
}
func runCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	result, err := command.Run(ctx, command.Options{Env: localRuntimeEnv()}, name, args...)
	return result.Output, err
}

func localRuntimeEnv() []string {
	entries := os.Environ()
	env := make([]string, 0, len(entries))
	for _, entry := range entries {
		key := entry
		if i := strings.IndexByte(entry, '='); i >= 0 {
			key = entry[:i]
		}
		switch key {
		case "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH", "CONTAINER_HOST", "CONTAINER_CONNECTION", "PODMAN_HOST":
			continue
		}
		env = append(env, entry)
	}
	return env
}

// runLimitedLogCommand bounds client output even when one application log line
// is exceptionally large. The bound truncates: a chatty container must still
// contribute the evidence it already produced rather than none at all.
// Truncation keeps the earliest bytes of the window, which is acceptable
// because `--tail` has already restricted the read to recent records; the
// caller reports the clipping so partial evidence is never mistaken for a
// complete read.
func runLimitedLogCommand(ctx context.Context, args []string, path string) ([]byte, bool, error) {
	result, err := command.Run(ctx, command.Options{Env: localRuntimeEnv(), MaxOutput: maxLogBytes, CaptureStderr: true}, path, args...)
	if err != nil {
		return nil, false, err
	}
	return result.Output, result.Truncated, nil
}

type logPattern struct {
	kind  string
	match *regexp.Regexp
}

// These patterns cover concrete failure signatures as well as explicit
// application error/failure messages. Generic matches are filtered for common
// success phrases such as "completed without error" below.
var containerLogPatterns = []logPattern{
	{kind: "oom", match: regexp.MustCompile(`(?i)\b(?:out of memory|oom[- ]kill(?:ed)?|cannot allocate memory)\b`)},
	{kind: "panic", match: regexp.MustCompile(`(?i)(?:\bpanic:|\bfatal error:)`)},
	{kind: "segmentation_fault", match: regexp.MustCompile(`(?i)\b(?:segmentation fault|sigsegv)\b`)},
	{kind: "uncaught_exception", match: regexp.MustCompile(`(?i)\b(?:uncaught exception|traceback \(most recent call last\))`)},
	{kind: "data_corruption", match: regexp.MustCompile(`(?i)\b(?:database corruption|corrupt(?:ed)? (?:database|data|file))\b`)},
	{kind: "read_only_filesystem", match: regexp.MustCompile(`(?i)\bread-only file system\b`)},
	{kind: "failure", match: regexp.MustCompile(`(?i)\b(?:failed|failure|failures)\b`)},
	{kind: "error", match: regexp.MustCompile(`(?i)\berrors?\b`)},
}

var benignGenericLogPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\b(?:error|errors|failure|failures)\s*[:=]?\s*0\b`),
	regexp.MustCompile(`(?i)\b0\s+(?:errors?|failures?)\b`),
}

// ClassifyLogEvents returns every distinct, explicitly classified
// application-log match. It is not capped: the input text itself is already
// bounded (maxLogBytes per container), so the number of distinct matches
// cannot be unbounded, and capping it separately only produced a
// same-looking count on every container that happened to exceed the cap.
// It preserves the legacy parser API for untimestamped input. Collectors that
// request runtime timestamps should call ClassifyLogEventsAt with their
// collection reference.
func ClassifyLogEvents(text string) []model.LogEvent {
	return ClassifyLogEventsAt(text, time.Time{})
}

// ClassifyLogEventsAt classifies runtime log output and calculates event ages
// from leading RFC3339/RFC3339Nano timestamps. A missing or malformed
// timestamp keeps AgeSeconds nil; it must never be presented as happening now.
// The timestamp itself is not retained in the message. For duplicate
// kind/message pairs, the newest timestamped instance wins.
func ClassifyLogEventsAt(text string, collectedAt time.Time) []model.LogEvent {
	events := make([]model.LogEvent, 0)
	seen := make(map[string]int)
	times := make(map[string]time.Time)
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		messageLine, eventAt := splitRuntimeLogTimestamp(line)
		for _, pattern := range containerLogPatterns {
			if !pattern.match.MatchString(messageLine) {
				continue
			}
			if (pattern.kind == "error" || pattern.kind == "failure") && benignGenericLogLine(messageLine) {
				break
			}
			message := truncateLogLine(messageLine)
			key := pattern.kind + "\x00" + message
			index, duplicate := seen[key]
			if duplicate {
				if eventAt != nil {
					previousAt, known := times[key]
					if !known || eventAt.After(previousAt) {
						events[index].AgeSeconds = logAgeSeconds(*eventAt, collectedAt)
						times[key] = *eventAt
					}
				}
				break
			}
			seen[key] = len(events)
			if eventAt != nil {
				times[key] = *eventAt
			}
			events = append(events, model.LogEvent{Kind: pattern.kind, Message: message, AgeSeconds: logAgeSecondsAt(eventAt, collectedAt)})
			break
		}
	}
	return events
}

// splitRuntimeLogTimestamp recognizes the prefix emitted by Docker and Podman
// with --timestamps. If it cannot parse the prefix exactly, it leaves the line
// intact so the diagnostic text remains visible and unaged.
func splitRuntimeLogTimestamp(line string) (string, *time.Time) {
	separator := strings.IndexAny(line, " \t")
	if separator <= 0 {
		return line, nil
	}
	at, err := time.Parse(time.RFC3339Nano, line[:separator])
	if err != nil {
		return line, nil
	}
	return strings.TrimSpace(line[separator:]), &at
}

func logAgeSecondsAt(eventAt *time.Time, collectedAt time.Time) *float64 {
	if eventAt == nil || collectedAt.IsZero() {
		return nil
	}
	return logAgeSeconds(*eventAt, collectedAt)
}

func logAgeSeconds(eventAt, collectedAt time.Time) *float64 {
	age := collectedAt.Sub(eventAt).Seconds()
	if age < 0 {
		age = 0
	}
	return &age
}

func benignGenericLogLine(line string) bool {
	lower := strings.ToLower(line)
	if strings.Contains(lower, "without error") || strings.Contains(lower, "without failure") || strings.Contains(lower, "error-free") {
		return true
	}
	for _, pattern := range benignGenericLogPatterns {
		if pattern.MatchString(lower) {
			return true
		}
	}
	return false
}

// truncateLogLine clips on a rune boundary. Cutting mid-rune leaves invalid
// UTF-8, which the JSON encoder then rewrites as replacement characters.
func truncateLogLine(line string) string {
	if len(line) <= maxLogLineBytes {
		return line
	}
	cut := maxLogLineBytes - 3
	for cut > 0 && !utf8.RuneStart(line[cut]) {
		cut--
	}
	return line[:cut] + "..."
}
