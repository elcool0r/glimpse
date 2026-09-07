package security

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestCollectParsesFactsAndSortsVulnerabilities(t *testing.T) {
	files := map[string]string{
		"/var/run/reboot-required":                              "",
		"/proc/sys/kernel/tainted":                              "4096\n",
		"/sys/fs/selinux/enforce":                               "1\n",
		"/sys/module/apparmor/parameters/enabled":               "Y\n",
		"/sys/devices/system/cpu/vulnerabilities/spectre_v2":    "Mitigation: Retpolines\n",
		"/sys/devices/system/cpu/vulnerabilities/itlb_multihit": "KVM: Mitigation: VMX disabled\n",
	}
	c := &Collector{readFile: func(path string) ([]byte, error) {
		v, ok := files[path]
		if !ok {
			return nil, os.ErrNotExist
		}
		return []byte(v), nil
	}, readDir: func(string) ([]os.DirEntry, error) {
		return []os.DirEntry{fakeEntry{"spectre_v2"}, fakeEntry{"itlb_multihit"}}, nil
	}}
	data, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	s := data.Security
	if s == nil || !s.Available || s.RebootRequired == nil || !*s.RebootRequired || s.KernelTaintMask != 4096 || s.SELinux != "enforcing" || s.AppArmor != "enabled" {
		t.Fatalf("unexpected security data: %+v", s)
	}
	if len(s.Vulnerabilities) != 2 || s.Vulnerabilities[0].Name != "itlb_multihit" {
		t.Fatalf("vulnerabilities not sorted: %+v", s.Vulnerabilities)
	}
}

func TestCollectUnavailableIsExplicit(t *testing.T) {
	c := &Collector{readFile: func(string) ([]byte, error) { return nil, errors.New("denied") }, readDir: func(string) ([]os.DirEntry, error) { return nil, errors.New("denied") }}
	c.lookPath = func(string) (string, error) { return "", os.ErrNotExist }
	data, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if data.Security == nil || data.Security.Available || data.Security.SELinux != "unknown" || data.Security.AppArmor != "unknown" || data.Security.RebootRequired != nil || data.Security.KernelTainted != nil {
		t.Fatalf("expected unknown optional facts: %+v", data.Security)
	}
}

func TestCollectDoesNotTreatMissingOptionalInterfacesAsDisabled(t *testing.T) {
	c := &Collector{readFile: func(string) ([]byte, error) { return nil, os.ErrNotExist }, readDir: func(string) ([]os.DirEntry, error) { return nil, os.ErrNotExist }}
	c.lookPath = func(string) (string, error) { return "", os.ErrNotExist }
	data, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if data.Security == nil || data.Security.Available || data.Security.RebootRequired != nil || data.Security.SELinux != "unknown" || data.Security.AppArmor != "unknown" {
		t.Fatalf("missing optional interfaces became policy facts: %+v", data.Security)
	}
}

func TestCollectReportsSELinuxPermissive(t *testing.T) {
	c := &Collector{readFile: func(path string) ([]byte, error) {
		if path == "/sys/fs/selinux/enforce" {
			return []byte("0\n"), nil
		}
		return nil, os.ErrNotExist
	}, readDir: func(string) ([]os.DirEntry, error) { return nil, os.ErrNotExist }}
	data, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if data.Security == nil || !data.Security.Available || data.Security.SELinux != "permissive" {
		t.Fatalf("SELinux permissive state not collected: %+v", data.Security)
	}
}

func TestTaintedModuleNamesReadsPerModuleTaint(t *testing.T) {
	files := map[string]string{
		"/sys/module/spl/taint":   "O",
		"/sys/module/zfs/taint":   "PO",
		"/sys/module/ixgbe/taint": "",
	}
	got := taintedModuleNames(func(path string) ([]byte, error) {
		value, ok := files[path]
		if !ok {
			return nil, os.ErrNotExist
		}
		return []byte(value), nil
	}, "spl 123 0 - Live 0x0\nzfs 456 0 - Live 0x0\nixgbe 789 0 - Live 0x0\n")
	if len(got) != 2 || got[0] != "spl" || got[1] != "zfs" {
		t.Fatalf("unexpected taint modules: %v", got)
	}
}

type fakeEntry struct{ name string }

func (f fakeEntry) Name() string               { return f.name }
func (f fakeEntry) IsDir() bool                { return false }
func (f fakeEntry) Type() os.FileMode          { return 0 }
func (f fakeEntry) Info() (os.FileInfo, error) { return nil, nil }

// The previous query read the last 300 records of the whole journal and counted
// matches inside them: on a busy host those records are the last few seconds,
// so a real attack could score zero while a quiet host scored high. The count
// needs a defined window and a defined population.
func TestJournalQueriesAreFilteredAndWindowed(t *testing.T) {
	var queries [][]string
	c := New()
	c.readFile = func(string) ([]byte, error) { return nil, os.ErrNotExist }
	c.readDir = func(string) ([]os.DirEntry, error) { return nil, os.ErrNotExist }
	c.lookPath = func(name string) (string, error) {
		if name == "journalctl" {
			return "/usr/bin/journalctl", nil
		}
		return "", errors.New("missing")
	}
	c.run = func(_ context.Context, _ string, args ...string) ([]byte, error) {
		queries = append(queries, args)
		return nil, nil
	}
	data, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(queries) != 3 {
		t.Fatalf("queries=%q", queries)
	}
	auth := strings.Join(queries[0], " ")
	if !strings.Contains(auth, authprivFacility) {
		t.Fatalf("authentication query is not filtered to the auth facility: %q", auth)
	}
	if !strings.Contains(auth, "--since=-"+journalWindow) {
		t.Fatalf("authentication query has no bounded window: %q", auth)
	}
	sudo := strings.Join(queries[1], " ")
	if !strings.Contains(sudo, "_COMM=sudo") || !strings.Contains(sudo, "--since=-"+journalEventsWindow) {
		t.Fatalf("sudo query is not a bounded, wider-window read: %q", sudo)
	}
	denials := strings.Join(queries[2], " ")
	if !strings.Contains(denials, "-k") || !strings.Contains(denials, "--since=-"+journalWindow) {
		t.Fatalf("denial query is not a bounded kernel read: %q", denials)
	}
	if data.Security == nil || data.Security.JournalWindow != journalWindow {
		t.Fatalf("window not reported to consumers: %+v", data.Security)
	}
}

func TestFailedJournalQueryIsReportedAsMissingCoverage(t *testing.T) {
	c := New()
	c.readFile = func(string) ([]byte, error) { return nil, os.ErrNotExist }
	c.readDir = func(string) ([]os.DirEntry, error) { return nil, os.ErrNotExist }
	c.lookPath = func(name string) (string, error) {
		if name == "journalctl" {
			return "/usr/bin/journalctl", nil
		}
		return "", errors.New("missing")
	}
	c.run = func(context.Context, string, ...string) ([]byte, error) {
		return nil, errors.New("permission denied")
	}
	data, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(data.Diagnostics) < 2 {
		t.Fatalf("denied journal reported as success: %+v", data.Diagnostics)
	}
}

func TestParseLastLoginsExtractsUserAndSource(t *testing.T) {
	input := "daniel   pts/1        203.0.113.5      2026-09-07T14:41:00+02:00 - 2026-09-07T14:42:00+02:00  (00:00)\n" +
		"daniel   pts/1        203.0.113.5      2026-09-07T11:17:00+02:00   still logged in\n"
	got := ParseLastLogins(input)
	if len(got) != 2 {
		t.Fatalf("expected 2 logins, got %#v", got)
	}
	if got[0].User != "daniel" || got[0].Source != "203.0.113.5" {
		t.Fatalf("unexpected first login: %+v", got[0])
	}
	if !got[0].At.Before(got[1].At) {
		t.Fatalf("expected chronological order: %+v", got)
	}
	if got[0].Method != "" {
		t.Fatalf("last cannot reveal an auth method: %+v", got[0])
	}
}

// A local console login has no remote host/IP field at all -- that absence
// is exactly what distinguishes it from an SSH session, so it must not be
// reported as one.
func TestParseLastLoginsSkipsLocalLogins(t *testing.T) {
	input := "daniel   tty1                          2026-09-07T09:00:00+02:00   still logged in\n"
	if got := ParseLastLogins(input); len(got) != 0 {
		t.Fatalf("expected no logins for a local console session, got %#v", got)
	}
}

// The reboot pseudo-entry and the "wtmp begins" trailer must not be
// reported as a login.
func TestParseLastLoginsSkipsPseudoEntries(t *testing.T) {
	input := "reboot   system boot  6.8.0-138-generic 2026-09-07T08:00:00+02:00\n" +
		"wtmp begins 2026-01-01T00:00:00+01:00\n"
	if got := ParseLastLogins(input); len(got) != 0 {
		t.Fatalf("expected no logins, got %#v", got)
	}
}

func TestParseFlexibleISOAcceptsBothOffsetForms(t *testing.T) {
	for _, s := range []string{"2026-09-07T14:41:00+02:00", "2026-09-07T14:41:00+0200"} {
		if _, err := parseFlexibleISO(s); err != nil {
			t.Errorf("%s: %v", s, err)
		}
	}
}

func TestParseSudoCommandsExtractsInteractiveCommands(t *testing.T) {
	input := "1700000000 kuhlpunkt.de sudo[2532844]: daniel : TTY=pts/1 ; PWD=/home/daniel ; USER=root ; COMMAND=/usr/bin/apt update\n"
	got := ParseSudoCommands(input)
	if len(got) != 1 {
		t.Fatalf("expected one sudo event, got %#v", got)
	}
	if got[0].User != "daniel" || got[0].RunAs != "root" || got[0].Command != "/usr/bin/apt update" {
		t.Fatalf("unexpected sudo event: %+v", got[0])
	}
}

// sudo logs TTY=unknown for a cron job or script with no controlling
// terminal; that must be excluded the same way a non-interactive SSH
// session is.
func TestParseSudoCommandsExcludesNonInteractive(t *testing.T) {
	input := "1700000000 kuhlpunkt.de sudo[999]: root : TTY=unknown ; PWD=/ ; USER=root ; COMMAND=/usr/local/bin/backup.sh\n"
	if got := ParseSudoCommands(input); len(got) != 0 {
		t.Fatalf("expected the cron/script invocation excluded, got %#v", got)
	}
}

// A command argument may itself contain " ; ", which must not truncate the
// captured command or be mistaken for a field separator.
func TestParseSudoCommandsCapturesFullCommand(t *testing.T) {
	input := `1700000000 kuhlpunkt.de sudo[1]: daniel : TTY=pts/1 ; PWD=/home/daniel ; USER=root ; COMMAND=/usr/bin/bash -c "echo a ; echo b"` + "\n"
	got := ParseSudoCommands(input)
	if len(got) != 1 || !strings.Contains(got[0].Command, "echo a ; echo b") {
		t.Fatalf("command truncated: %#v", got)
	}
}

// The module name becomes a path component; the kernel never allows separators
// in one, so anything that contains them is not a module.
func TestTaintedModuleNamesRejectPathSeparators(t *testing.T) {
	var read []string
	readFile := func(path string) ([]byte, error) {
		read = append(read, path)
		return []byte("P"), nil
	}
	got := taintedModuleNames(readFile, "zfs 100 0 - Live 0x0\n../../etc 1 0 - Live 0x0\nspl 2 0 - Live 0x0\n")
	if len(got) != 2 || got[0] != "zfs" || got[1] != "spl" {
		t.Fatalf("modules=%v", got)
	}
	for _, path := range read {
		if strings.Contains(path, "..") {
			t.Fatalf("traversal reached the filesystem: %q", path)
		}
	}
}
