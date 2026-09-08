package containers

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/elcool0r/glimpse/internal/analyze"
	"github.com/elcool0r/glimpse/internal/collect"
	"github.com/elcool0r/glimpse/internal/model"
)

func TestParseInspectJSONLines(t *testing.T) {
	raw := `{"Id":"abc","Name":"/web","RestartCount":3,"State":{"Status":"running","Health":{"Status":"healthy"}},"HostConfig":{"RestartPolicy":{"Name":"unless-stopped"}}}` + "\n" + `not json`
	items, restarts := ParseInspectJSONLines(raw)
	if len(items) != 1 || items[0].Name != "web" || items[0].Healthy == nil || !*items[0].Healthy || !items[0].HasRestartPolicy || restarts["abc"] != 3 {
		t.Fatalf("%+v %#v", items, restarts)
	}
}

func TestParseAndDeltaRealDockerRestartCount(t *testing.T) {
	firstItems, firstRestarts := ParseInspectJSONLines(`{"Id":"abc","Name":"/web","RestartCount":1,"State":{"Status":"running"}}`)
	lastItems, lastRestarts := ParseInspectJSONLines(`{"Id":"abc","Name":"/web","RestartCount":4,"State":{"Status":"running"}}`)
	if len(firstItems) != 1 || len(lastItems) != 1 || firstRestarts["abc"] != 1 || lastRestarts["abc"] != 4 {
		t.Fatalf("restart snapshots first=%v/%v last=%v/%v", firstItems, firstRestarts, lastItems, lastRestarts)
	}
	data, err := (&Collector{}).Delta(
		collect.Data{Snapshot: snapshot{restarts: map[string]uint64{"docker:abc": firstRestarts["abc"]}}},
		collect.Data{Containers: []model.ContainerRuntime{{Runtime: "docker", Containers: lastItems}}, Snapshot: snapshot{restarts: map[string]uint64{"docker:abc": lastRestarts["abc"]}}},
	)
	if err != nil || len(data.Containers) != 1 || data.Containers[0].Containers[0].RestartCount != 3 {
		t.Fatalf("delta=%+v err=%v", data, err)
	}
	report := model.Report{Metrics: model.Metrics{CPU: &model.CPU{}, Containers: data.Containers}}
	analyze.Report(&report)
	for _, finding := range report.Findings {
		if finding.ID == "container-docker-web-restarts" && finding.Severity == model.SeverityCritical {
			return
		}
	}
	t.Fatalf("real-shaped 1->4 restart delta did not produce a critical finding: %+v", report.Findings)
}
func TestBoundedIDs(t *testing.T) {
	got := boundedIDs("a\na\n b \n")
	if len(got) != 2 || got[1] != "b" {
		t.Fatal(got)
	}
}

func TestBoundedIDsReportsInspectionCoverage(t *testing.T) {
	var raw strings.Builder
	for i := 0; i < maxContainers+1; i++ {
		fmt.Fprintf(&raw, "container-%03d\n", i)
	}
	ids, discovered, limited := boundedIDsWithCoverage(raw.String())
	if len(ids) != maxContainers || discovered != maxContainers+1 || !limited {
		t.Fatalf("ids=%d discovered=%d limited=%v", len(ids), discovered, limited)
	}
}

func TestTransitionalHealthIsUnknown(t *testing.T) {
	items, _ := ParseInspectJSONLines(`{"Id":"abc","Name":"/web","State":{"Health":{"Status":"starting"}}}`)
	if len(items) != 1 || items[0].Healthy != nil {
		t.Fatalf("%+v", items)
	}
}

func TestClassifyLogEventsDetectsApplicationErrorsAndFailurePatterns(t *testing.T) {
	raw := `2026-01-01 INFO completed without error
2026-01-01 ERROR request failed with HTTP 503
error
panic: unexpected nil pointer
kernel: Out of memory: Killed process 22
Traceback (most recent call last):
database corruption detected`
	got := ClassifyLogEvents(raw)
	wantKinds := []string{"failure", "error", "panic", "oom", "uncaught_exception", "data_corruption"}
	if len(got) != len(wantKinds) {
		t.Fatalf("events=%+v", got)
	}
	for i, kind := range wantKinds {
		if got[i].Kind != kind {
			t.Fatalf("event %d = %+v, want kind %q", i, got[i], kind)
		}
	}
}

func TestClassifyLogEventsIgnoresSuccessfulErrorCounts(t *testing.T) {
	got := ClassifyLogEvents("completed with errors: 0\nhealth check passed, 0 failures\n")
	if len(got) != 0 {
		t.Fatalf("successful error counts became findings: %+v", got)
	}
}

func TestClassifyLogEventsDetectsPlainStdoutAndStderrText(t *testing.T) {
	got := ClassifyLogEvents("error\nfoo error\n")
	if len(got) != 2 || got[0].Kind != "error" || got[1].Kind != "error" {
		t.Fatalf("plain application errors were not classified: %+v", got)
	}
}

// The count is not capped: it is bounded only by how many distinct matches
// exist in the already-bounded log read (maxLogBytes per container).
func TestClassifyLogEventsDeduplicatesButDoesNotCapCount(t *testing.T) {
	raw := "panic: first\npanic: first\n"
	const distinctCount = 25
	for i := 0; i < distinctCount; i++ {
		raw += fmt.Sprintf("fatal error: distinct %d\n", i)
	}
	got := ClassifyLogEvents(raw)
	want := distinctCount + 1 // the exact duplicate collapses to one event; nothing else is capped.
	if len(got) != want {
		t.Fatalf("got %d events, want %d: %+v", len(got), want, got)
	}
}

func TestCollectLogsIsBoundedAndSkipsIrrelevantStates(t *testing.T) {
	var calls [][]string
	c := &Collector{
		LogTimeout:      time.Second,
		LogTotalTimeout: time.Second,
		runLogs: func(_ context.Context, args []string, _ string) ([]byte, bool, error) {
			calls = append(calls, args)
			return []byte("panic: boom\n"), false, nil
		},
	}
	items := []model.Container{
		{ID: "run", State: "running"},
		{ID: "created", State: "created"},
		{ID: "exit", State: "exited"},
	}
	c.collectLogs(context.Background(), c.runLogs, "podman", "unix:///var/run/docker.sock", "/usr/bin/wrapper", items, maxLogContainers)
	if len(calls) != 2 {
		t.Fatalf("calls=%v", calls)
	}
	want := []string{"--remote=false", "logs", "--since", "1h", "--tail", "200", "run"}
	if !reflect.DeepEqual(calls[0], want) {
		t.Fatalf("args=%q want=%q", calls[0], want)
	}
	if len(items[0].LogEvents) != 1 || len(items[1].LogEvents) != 0 || len(items[2].LogEvents) != 1 {
		t.Fatalf("items=%+v", items)
	}
}

func TestCollectForcesLocalRuntimeModes(t *testing.T) {
	t.Setenv("DOCKER_HOST", "tcp://attacker.example:2375")
	t.Setenv("DOCKER_CONTEXT", "remote-prod")
	t.Setenv("CONTAINER_HOST", "tcp://attacker.example:9999")
	var calls [][]string
	c := &Collector{
		lookPath: func(name string) (string, error) { return name, nil },
		run: func(_ context.Context, name string, args ...string) ([]byte, error) {
			calls = append(calls, append([]string{name}, args...))
			if args[len(args)-1] == "--no-trunc" {
				return nil, nil
			}
			return nil, nil
		},
	}
	if _, err := c.Collect(context.Background()); err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(calls) != 2 || calls[0][0] != "podman" || calls[0][1] != "--remote=false" {
		t.Fatalf("calls=%q", calls)
	}
	if calls[1][0] != "docker" || calls[1][1] != "--host" || !strings.HasPrefix(calls[1][2], "unix://") {
		t.Fatalf("calls=%q", calls)
	}
}

func TestCollectReportsBoundedInspectionCoverage(t *testing.T) {
	var listed strings.Builder
	for i := 0; i < maxContainers+1; i++ {
		fmt.Fprintf(&listed, "container-%03d\n", i)
	}
	c := &Collector{
		lookPath: func(name string) (string, error) {
			if name == "docker" {
				return "", errors.New("not installed")
			}
			return name, nil
		},
		run: func(_ context.Context, _ string, args ...string) ([]byte, error) {
			if args[len(args)-1] == "--no-trunc" {
				return []byte(listed.String()), nil
			}
			return []byte(`{"Id":"container-000","State":{"Status":"running"}}`), nil
		},
	}
	data, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	if len(data.Containers) != 1 {
		t.Fatalf("containers=%+v", data.Containers)
	}
	got := data.Containers[0]
	if got.ContainersDiscovered != maxContainers+1 || got.ContainersInspected != maxContainers || !got.ContainerInspectionLimited {
		t.Fatalf("coverage=%+v", got)
	}
}

func TestCollectReturnsPartialDataAndErrorOnDeniedSocket(t *testing.T) {
	c := &Collector{
		lookPath: func(name string) (string, error) { return name, nil },
		run: func(_ context.Context, name string, args ...string) ([]byte, error) {
			if name == "podman" {
				return []byte("podman denied"), errors.New("permission denied")
			}
			if args[len(args)-1] == "--no-trunc" {
				return []byte("docker-id\n"), nil
			}
			return []byte(`{"Id":"docker-id","State":{"Status":"running"}}`), nil
		},
		runLogs: func(context.Context, []string, string) ([]byte, bool, error) { return nil, false, errors.New("denied") },
	}
	data, err := c.Collect(context.Background())
	if err != nil || len(data.Diagnostics) == 0 || !strings.Contains(data.Diagnostics[0].Detail, "podman list failed") {
		t.Fatalf("diagnostics=%+v err=%v", data.Diagnostics, err)
	}
	if len(data.Containers) != 1 || data.Containers[0].Runtime != "docker" || data.Containers[0].LogWindow != "last hour" {
		t.Fatalf("partial data=%+v", data.Containers)
	}
	// A container whose logs could not be read has not been checked. Counting
	// it claimed coverage that never happened, and left LogCheckLimited false.
	if data.Containers[0].LogsChecked != 0 || !data.Containers[0].LogCheckLimited {
		t.Fatalf("unread logs reported as checked: %+v", data.Containers[0])
	}
	var reported bool
	for _, diagnostic := range data.Diagnostics {
		reported = reported || strings.Contains(diagnostic.Detail, "logs unavailable")
	}
	if !reported {
		t.Fatalf("unreadable logs left no diagnostic: %+v", data.Diagnostics)
	}
}

func TestDeltaPreservesGaugesWhenBaselineMissing(t *testing.T) {
	healthy := true
	last := collect.Data{Containers: []model.ContainerRuntime{{Runtime: "podman", Containers: []model.Container{{ID: "id", Name: "web", State: "running", Healthy: &healthy}}}}, Snapshot: snapshot{restarts: map[string]uint64{"podman:id": 4}}}
	c := &Collector{}
	data, err := c.Delta(collect.Data{}, last)
	if err == nil || len(data.Containers) != 1 || data.Containers[0].Containers[0].Healthy == nil {
		t.Fatalf("data=%+v err=%v", data, err)
	}
}

func TestCollectLogsContinuesAfterOptionalFailure(t *testing.T) {
	calls := 0
	c := &Collector{runLogs: func(_ context.Context, _ []string, _ string) ([]byte, bool, error) {
		calls++
		if calls == 1 {
			return nil, false, errors.New("log access denied")
		}
		return []byte("segmentation fault"), false, nil
	}}
	items := []model.Container{{ID: "a", State: "running"}, {ID: "b", State: "running"}}
	c.collectLogs(context.Background(), c.runLogs, "podman", "", "wrapper", items, maxLogContainers)
	if calls != 2 || len(items[0].LogEvents) != 0 || len(items[1].LogEvents) != 1 {
		t.Fatalf("calls=%d items=%+v", calls, items)
	}
}

func TestCollectLogsHonorsSharedContainerLimit(t *testing.T) {
	calls := 0
	c := &Collector{runLogs: func(_ context.Context, _ []string, _ string) ([]byte, bool, error) {
		calls++
		return nil, false, nil
	}}
	items := []model.Container{{ID: "a", State: "running"}, {ID: "b", State: "running"}, {ID: "c", State: "running"}}
	outcome := c.collectLogs(context.Background(), c.runLogs, "podman", "", "wrapper", items, 2)
	if outcome.read != 2 || calls != 2 {
		t.Fatalf("outcome=%+v calls=%d", outcome, calls)
	}
}

func TestCollectReservesLogChecksForEachAvailableRuntime(t *testing.T) {
	var logCalls []string
	c := &Collector{
		lookPath: func(name string) (string, error) { return name, nil },
		run: func(_ context.Context, name string, args ...string) ([]byte, error) {
			if args[len(args)-1] == "--no-trunc" {
				return []byte("a\nb\nc\nd\ne\nf\ng\nh\ni\nj\nk\nl\n"), nil
			}
			var out strings.Builder
			for _, id := range args[len(args)-12:] {
				fmt.Fprintf(&out, `{"Id":%q,"Name":%q,"State":{"Status":"running"}}`+"\n", name+id, "/"+id)
			}
			return []byte(out.String()), nil
		},
		runLogs: func(_ context.Context, args []string, path string) ([]byte, bool, error) {
			logCalls = append(logCalls, path)
			return nil, false, nil
		},
	}
	if _, err := c.Collect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(logCalls) != 24 {
		t.Fatalf("calls=%d, want all 24 discovered containers", len(logCalls))
	}
	seen := map[string]int{}
	for _, name := range logCalls {
		seen[name]++
	}
	if seen["podman"] != 12 || seen["docker"] != 12 {
		t.Fatalf("log checks not shared fairly: %v", seen)
	}
}

func TestOversizedLogOutputIsTruncatedNotDiscarded(t *testing.T) {
	// Aborting the read at the cap abandoned everything already collected, so
	// a container that logs more than the cap in an hour contributed no
	// evidence at all while still being reported as checked.
	oversized := "panic: boom\n" + strings.Repeat("noise\n", maxLogBytes/6)
	c := &Collector{runLogs: func(_ context.Context, _ []string, _ string) ([]byte, bool, error) {
		out := []byte(oversized)
		truncated := false
		if len(out) > maxLogBytes {
			out, truncated = out[:maxLogBytes], true
		}
		return out, truncated, nil
	}}
	items := []model.Container{{ID: "a", State: "running"}}
	outcome := c.collectLogs(context.Background(), c.runLogs, "podman", "", "wrapper", items, maxLogContainers)
	if outcome.read != 1 || outcome.truncated != 1 {
		t.Fatalf("outcome=%+v", outcome)
	}
	if len(items[0].LogEvents) == 0 {
		t.Fatal("truncated output produced no evidence")
	}
}

func TestTruncatedLogLineStaysValidUTF8(t *testing.T) {
	line := strings.Repeat("a", 508) + strings.Repeat("€", 20)
	if got := truncateLogLine(line); !utf8.ValidString(got) {
		t.Fatalf("truncation split a rune: %q", got)
	}
}

func TestDeltaTreatsContainerCreatedDuringWindowAsNormal(t *testing.T) {
	// Starting a container mid-sample is an ordinary event, not a collection
	// fault; it has no interval, so its restart delta simply stays zero.
	first := collect.Data{Snapshot: snapshot{restarts: map[string]uint64{"docker:old": 2}}}
	last := collect.Data{
		Containers: []model.ContainerRuntime{{Runtime: "docker", Containers: []model.Container{
			{ID: "old", Name: "old"}, {ID: "new", Name: "new"},
		}}},
		Snapshot: snapshot{restarts: map[string]uint64{"docker:old": 3, "docker:new": 0}},
	}
	data, err := (&Collector{}).Delta(first, last)
	if err != nil {
		t.Fatalf("new container reported as an error: %v", err)
	}
	got := data.Containers[0].Containers
	if got[0].RestartCount != 1 || got[1].RestartCount != 0 {
		t.Fatalf("restart deltas=%+v", got)
	}
}

func TestDeltaRejectsRestartCounterReset(t *testing.T) {
	first := collect.Data{Snapshot: snapshot{restarts: map[string]uint64{"docker:abc": 4}}}
	last := collect.Data{
		Containers: []model.ContainerRuntime{{Runtime: "docker", Containers: []model.Container{{ID: "abc", State: "running"}}}},
		Snapshot:   snapshot{restarts: map[string]uint64{"docker:abc": 1}},
	}
	data, err := (&Collector{}).Delta(first, last)
	if err == nil || data.Containers[0].Containers[0].RestartCount != 0 {
		t.Fatalf("reset was treated as a restart delta: data=%+v err=%v", data, err)
	}
}

func TestCollectPropagatesParentCancellationDuringLogs(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := &Collector{
		lookPath: func(name string) (string, error) {
			if name == "podman" {
				return "/usr/bin/podman", nil
			}
			return "", errors.New("missing")
		},
		run: func(_ context.Context, _ string, args ...string) ([]byte, error) {
			if args[len(args)-1] == "--no-trunc" {
				return []byte("abc\n"), nil
			}
			return []byte(`{"Id":"abc","State":{"Status":"running"}}`), nil
		},
		runLogs: func(_ context.Context, _ []string, _ string) ([]byte, bool, error) {
			cancel()
			return nil, false, context.Canceled
		},
	}
	if _, err := c.Collect(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v", err)
	}
}

func TestRuntimeEnvironmentHelper(t *testing.T) {
	if os.Getenv("GLIMPSE_ENV_HELPER") != "1" {
		return
	}
	for _, key := range []string{"DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH", "CONTAINER_HOST", "CONTAINER_CONNECTION", "PODMAN_HOST"} {
		if os.Getenv(key) != "" {
			os.Exit(9)
		}
	}
	if os.Getenv("GLIMPSE_PRESERVED_ENV") != "keep" {
		os.Exit(10)
	}
	fmt.Fprint(os.Stdout, "local environment")
	os.Exit(0)
}

func TestActualRuntimeProcessesStripRemoteEnvironment(t *testing.T) {
	t.Setenv("GLIMPSE_ENV_HELPER", "1")
	t.Setenv("GLIMPSE_PRESERVED_ENV", "keep")
	for _, key := range []string{"DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH", "CONTAINER_HOST", "CONTAINER_CONNECTION", "PODMAN_HOST"} {
		t.Setenv(key, "remote-value")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err := runCommand(ctx, os.Args[0], "-test.run=^TestRuntimeEnvironmentHelper$")
	if err != nil || string(out) != "local environment" {
		t.Fatalf("state command environment not isolated: %s %v", out, err)
	}
	logOut, _, logErr := runLimitedLogCommand(ctx, []string{"-test.run=^TestRuntimeEnvironmentHelper$"}, os.Args[0])
	if logErr != nil || string(logOut) != "local environment" {
		t.Fatalf("log command environment not isolated: %s %v", logOut, logErr)
	}
}

func TestRunLimitedLogCommandCapturesApplicationStderrOnSuccess(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	out, _, err := runLimitedLogCommand(ctx, []string{"-c", "printf 'panic: stderr-only' >&2"}, "sh")
	if err != nil || len(ClassifyLogEvents(string(out))) != 1 {
		t.Fatalf("output=%q events=%+v err=%v", out, ClassifyLogEvents(string(out)), err)
	}
}

func TestRunLimitedLogCommandRejectsFailedClientDiagnostics(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	out, _, err := runLimitedLogCommand(ctx, []string{"-c", "printf 'panic: client diagnostic' >&2; exit 7"}, "sh")
	if err == nil || out != nil {
		t.Fatalf("output=%q err=%v; failed log commands must not be classified", out, err)
	}
}

func TestUnavailableRuntimesDoNotBecomeEmptySuccessfulObservation(t *testing.T) {
	c := &Collector{lookPath: func(string) (string, error) { return "", errors.New("not installed") }}
	got, err := c.Collect(context.Background())
	if err != nil || got.Containers != nil || len(got.Diagnostics) != 2 {
		t.Fatalf("unavailable collection lost: %+v %v", got, err)
	}
}

func TestMissingPodmanDoesNotHideDockerObservation(t *testing.T) {
	c := &Collector{
		lookPath: func(name string) (string, error) {
			if name == "podman" {
				return "", errors.New("not installed")
			}
			return "/usr/bin/docker", nil
		},
		run: func(_ context.Context, _ string, args ...string) ([]byte, error) {
			if args[len(args)-1] == "--no-trunc" {
				return []byte("docker-id\n"), nil
			}
			return []byte(`{"Id":"docker-id","State":{"Status":"running"}}`), nil
		},
		runLogs: func(context.Context, []string, string) ([]byte, bool, error) { return nil, false, nil },
	}
	got, err := c.Collect(context.Background())
	if err != nil || len(got.Containers) != 1 || got.Containers[0].Runtime != "docker" {
		t.Fatalf("data=%+v err=%v", got, err)
	}
	if len(got.Diagnostics) != 0 {
		t.Fatalf("missing optional runtime obscured successful query: %+v", got.Diagnostics)
	}
}

func TestMissingDockerDoesNotHidePodmanObservation(t *testing.T) {
	c := &Collector{
		lookPath: func(name string) (string, error) {
			if name == "docker" {
				return "", errors.New("not installed")
			}
			return "/usr/bin/podman", nil
		},
		run: func(_ context.Context, _ string, args ...string) ([]byte, error) {
			if args[len(args)-1] == "--no-trunc" {
				return []byte("podman-id\n"), nil
			}
			return []byte(`{"Id":"podman-id","State":{"Status":"running"}}`), nil
		},
		runLogs: func(context.Context, []string, string) ([]byte, bool, error) { return nil, false, nil },
	}
	got, err := c.Collect(context.Background())
	if err != nil || len(got.Containers) != 1 || got.Containers[0].Runtime != "podman" {
		t.Fatalf("data=%+v err=%v", got, err)
	}
	if len(got.Diagnostics) != 0 {
		t.Fatalf("missing optional runtime obscured successful query: %+v", got.Diagnostics)
	}
}
