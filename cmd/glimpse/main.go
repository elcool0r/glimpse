//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/elcool0r/glimpse/internal/analyze"
	"github.com/elcool0r/glimpse/internal/app"
	"github.com/elcool0r/glimpse/internal/collect"
	"github.com/elcool0r/glimpse/internal/collect/cgroupv2"
	"github.com/elcool0r/glimpse/internal/collect/containers"
	"github.com/elcool0r/glimpse/internal/collect/cpu"
	"github.com/elcool0r/glimpse/internal/collect/deletedfiles"
	"github.com/elcool0r/glimpse/internal/collect/disk"
	"github.com/elcool0r/glimpse/internal/collect/dnsresolution"
	"github.com/elcool0r/glimpse/internal/collect/filesystem"
	"github.com/elcool0r/glimpse/internal/collect/gatewayping"
	"github.com/elcool0r/glimpse/internal/collect/hardware"
	"github.com/elcool0r/glimpse/internal/collect/httpcheck"
	"github.com/elcool0r/glimpse/internal/collect/icmpcheck"
	"github.com/elcool0r/glimpse/internal/collect/ipv6check"
	"github.com/elcool0r/glimpse/internal/collect/kernel"
	"github.com/elcool0r/glimpse/internal/collect/memory"
	"github.com/elcool0r/glimpse/internal/collect/network"
	"github.com/elcool0r/glimpse/internal/collect/networkstate"
	"github.com/elcool0r/glimpse/internal/collect/packageactivity"
	"github.com/elcool0r/glimpse/internal/collect/packageupdates"
	"github.com/elcool0r/glimpse/internal/collect/pathmtu"
	"github.com/elcool0r/glimpse/internal/collect/process"
	"github.com/elcool0r/glimpse/internal/collect/resources"
	"github.com/elcool0r/glimpse/internal/collect/security"
	"github.com/elcool0r/glimpse/internal/collect/storage"
	"github.com/elcool0r/glimpse/internal/collect/storagehealth"
	"github.com/elcool0r/glimpse/internal/collect/systemd"
	"github.com/elcool0r/glimpse/internal/collect/thermal"
	"github.com/elcool0r/glimpse/internal/collect/timesync"
	"github.com/elcool0r/glimpse/internal/collect/zfs"
	"github.com/elcool0r/glimpse/internal/model"
	"github.com/elcool0r/glimpse/internal/platform"
	"github.com/elcool0r/glimpse/internal/render"
	"github.com/elcool0r/glimpse/internal/version"
)

// cliFlags holds every registered flag's destination, so registerFlags is
// the one place a flag is defined and both main and the bash-completion
// generator (and its test) work from the same flag set instead of a second,
// easily-forgotten list.
type cliFlags struct {
	duration                                                                                                                          *time.Duration
	noContainers, jsonOutput, noColor, verbose, quiet, events, eventsAll, disableExternalChecks, noProxy, showVersion, bashCompletion *bool
}

func registerFlags(fs *flag.FlagSet) *cliFlags {
	f := &cliFlags{
		duration:              fs.Duration("duration", 5*time.Second, "sampling duration (default: 5s); increase for a longer, more thorough sample, e.g. --duration 60s"),
		noContainers:          fs.Bool("no-containers", false, "disable automatic container inspection"),
		jsonOutput:            fs.Bool("json", false, "emit stable JSON"),
		noColor:               fs.Bool("no-color", false, "disable color output"),
		verbose:               fs.Bool("verbose", false, "show every check performed, not just problems"),
		quiet:                 fs.Bool("quiet", false, "only show checks that are not OK (INFO, WARN, CRIT, or UNKNOWN)"),
		events:                fs.Bool("events", false, "always show today's recent-events timeline (normally shown only when a critical finding is present)"),
		eventsAll:             fs.Bool("events-all", false, "show every recent event instead of the most recent 20; implies --events"),
		disableExternalChecks: fs.Bool("disable-external-checks", false, "disable active checks that send real network traffic (DNS resolution, gateway/external/IPv6 ICMP, path MTU probe, HTTP/HTTPS GET); on by default"),
		noProxy:               fs.Bool("no-proxy", false, "do not use HTTP_PROXY, HTTPS_PROXY, or NO_PROXY for HTTP/HTTPS active checks"),
		showVersion:           fs.Bool("version", false, "print version"),
		bashCompletion:        fs.Bool("bash-completion", false, "print Bash completion script; use as: source <(glimpse --bash-completion)"),
	}
	fs.Usage = usage
	return f
}

func main() {
	if err := requireLongOptions(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(3)
	}
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	f := registerFlags(flag.CommandLine)
	if err := flag.CommandLine.Parse(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		os.Exit(3)
	}
	if *f.bashCompletion {
		fmt.Fprint(os.Stdout, bashCompletionScript(flag.CommandLine))
		return
	}
	if *f.showVersion {
		fmt.Println(version.Version)
		return
	}
	if *f.duration < 0 || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "duration must be non-negative and positional arguments are not supported")
		os.Exit(3)
	}
	containerEnabled := !*f.noContainers && runtimeAvailable()
	collectors := defaultCollectors(containerEnabled, !*f.disableExternalChecks, *f.noProxy)
	stdoutTTY := platform.IsTerminal(os.Stdout)
	stderrTTY := platform.IsTerminal(os.Stderr)
	colorEnabled := progressColorEnabled(*f.noColor, os.Getenv("NO_COLOR"))
	var progress func(app.Progress)
	if progressEnabled(*f.jsonOutput, stderrTTY) {
		progress = progressWriter(os.Stderr, colorEnabled)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	report := app.Run(ctx, app.Config{Duration: *f.duration, SampleInterval: time.Second, Full: true, IncludeContainers: containerEnabled, Progress: progress}, collectors)
	analyze.Report(&report)
	code := writeReport(os.Stdout, os.Stderr, report, *f.jsonOutput, *f.verbose, render.Options{Color: colorEnabled && stdoutTTY, Verbose: *f.verbose, Width: platform.TerminalWidth(os.Stdout), ASCII: !stdoutTTY, Quiet: *f.quiet, Events: *f.events, EventsAll: *f.eventsAll})
	if ctx.Err() != nil {
		code = 3
	}
	os.Exit(code)
}

// defaultCollectors is the registered collection profile. It is a function so
// a test can assert that every metric the analyzer and renderer branch on is
// actually reachable: the TCP collector previously existed, was tested, and
// was documented, but was never registered, leaving its model field, its
// findings and its report row unreachable in the shipped binary.
func defaultCollectors(includeContainers, enableExternalChecks bool, disableProxy ...bool) []collect.Collector {
	collectors := []collect.Collector{
		cpu.Collector{}, memory.Collector{}, filesystem.Collector{}, disk.Collector{},
		network.Collector{}, network.TCPCollector{}, networkstate.New(), thermal.Collector{},
		process.Collector{}, systemd.New(), kernel.New(), timesync.New(), resources.New(),
		security.New(), cgroupv2.New(), zfs.New(), storage.New(), hardware.New(),
		storagehealth.New(), deletedfiles.New(), packageactivity.New(), packageupdates.New(),
	}
	if includeContainers {
		collectors = append(collectors, containers.New())
	}
	if enableExternalChecks {
		noProxy := len(disableProxy) > 0 && disableProxy[0]
		collectors = append(collectors, dnsresolution.New(), gatewayping.New(), pathmtu.New(), httpcheck.New(noProxy), icmpcheck.New(), ipv6check.New())
	}
	return collectors
}

func requireLongOptions(args []string) error {
	for _, arg := range args {
		if arg == "--" {
			break
		}
		if strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--") {
			return fmt.Errorf("single-dash option %q is not supported; use --%s", arg, strings.TrimPrefix(arg, "-"))
		}
	}
	return nil
}

func writeReport(stdout, stderr io.Writer, report model.Report, jsonOutput, verbose bool, options render.Options) int {
	if jsonOutput {
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(report); err != nil {
			fmt.Fprintln(stderr, err)
			return 3
		}
	} else {
		output := &checkedWriter{Writer: stdout}
		render.Write(output, report, options)
		if output.err != nil {
			fmt.Fprintln(stderr, output.err)
			return 3
		}
	}
	if verbose {
		for _, status := range report.Collection {
			if status.Status != "ok" {
				fmt.Fprintf(stderr, "%s: %s %s\n", render.SafeText(status.Collector), render.SafeText(status.Status), render.SafeText(status.Detail))
			}
		}
	}
	for _, status := range report.Collection {
		if status.Collector == "sampling" && status.Status == "error" {
			return 3
		}
	}
	switch report.Score.Status {
	case model.SeverityCritical:
		return 2
	case model.SeverityWarning:
		return 1
	case model.SeverityUnknown:
		return 3
	default:
		return 0
	}
}

func runtimeAvailable() bool {
	for _, runtime := range []string{"podman", "docker"} {
		if _, err := exec.LookPath(runtime); err == nil {
			return true
		}
	}
	return false
}

// progressEnabled keeps progress off structured JSON output and only enables
// transient terminal control on the stream that receives it.
func progressEnabled(jsonOutput, stderrTTY bool) bool {
	return !jsonOutput && stderrTTY
}

func progressColorEnabled(noColor bool, noColorEnvironment string) bool {
	return !noColor && noColorEnvironment == ""
}

func progressWriter(w io.Writer, color bool) func(app.Progress) {
	shown := false
	const cyan = "\033[36m"
	const white = "\033[37m"
	const reset = "\033[0m"
	const clearLine = "\r\033[2K"
	formatDuration := func(d time.Duration) string {
		if d < 0 {
			d = 0
		}
		return fmt.Sprintf("%02ds", int(d.Round(time.Second)/time.Second))
	}
	return func(progress app.Progress) {
		write := func(plain, colored string) {
			if color {
				fmt.Fprint(w, colored)
				return
			}
			fmt.Fprint(w, plain)
		}
		switch progress.Phase {
		case "baseline":
			if !shown {
				write("Collecting health data...", cyan+"Collecting health data..."+reset)
				shown = true
			}
		case "sampling":
			elapsed, duration := formatDuration(progress.Elapsed), formatDuration(progress.Duration)
			write("\rSampling health data: "+elapsed+" / "+duration,
				fmt.Sprintf(clearLine+cyan+"Sampling health data: "+white+"%s / %s"+reset, elapsed, duration))
			shown = true
		case "final":
			write("\rProcessing health data...", clearLine+cyan+"Processing health data..."+reset)
			shown = true
		case "complete":
			if shown {
				// Clear the transient TTY status so the final report starts at the
				// first visible line, without a stale timer or progress history.
				if color {
					fmt.Fprint(w, clearLine)
				} else {
					fmt.Fprint(w, "\n")
				}
			}
		}
	}
}

func usage() {
	fmt.Fprintln(flag.CommandLine.Output(), "Usage: glimpse [--duration DURATION] [--json] [--no-color]")
	fmt.Fprintln(flag.CommandLine.Output(), "")
	fmt.Fprintln(flag.CommandLine.Output(), "By default glimpse performs a quick 5-second health check. Pass --duration for a longer, more thorough sample. All options use long --names.")
	fmt.Fprintln(flag.CommandLine.Output(), "")
	fmt.Fprintln(flag.CommandLine.Output(), "Options:")
	flag.VisitAll(func(f *flag.Flag) {
		name, value := "--"+f.Name, ""
		if f.DefValue != "false" && f.DefValue != "" {
			value = "=" + f.DefValue
		}
		fmt.Fprintf(flag.CommandLine.Output(), "  %-34s %s\n", name+value, f.Usage)
	})
}

// bashCompletionScript builds the completion word list from the flags
// actually registered on flag.CommandLine, so a new flag can't be added
// without also appearing here -- a fixed word list previously went stale
// the moment a flag was added and nobody remembered to update this string.
func bashCompletionScript(fs *flag.FlagSet) string {
	names := []string{"--help"}
	fs.VisitAll(func(f *flag.Flag) {
		names = append(names, "--"+f.Name)
	})
	sort.Strings(names)
	return "# Bash completion for glimpse.\n" +
		"_glimpse() {\n" +
		"    local current previous\n" +
		"    current=\"${COMP_WORDS[COMP_CWORD]}\"\n" +
		"    previous=\"${COMP_WORDS[COMP_CWORD-1]}\"\n" +
		"    case \"$previous\" in\n" +
		"        --duration) COMPREPLY=( $(compgen -W '5s 30s 60s 5m' -- \"$current\") ); return 0 ;;\n" +
		"    esac\n" +
		"    COMPREPLY=( $(compgen -W '" + strings.Join(names, " ") + "' -- \"$current\") )\n" +
		"}\n" +
		"complete -F _glimpse glimpse\n"
}

// Keep renderer's writer-only API while propagating failed output to callers.
type checkedWriter struct {
	io.Writer
	err error
}

func (w *checkedWriter) Write(p []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	n, err := w.Writer.Write(p)
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	w.err = err
	return n, err
}
