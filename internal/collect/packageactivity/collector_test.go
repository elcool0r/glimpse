package packageactivity

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestParseAptHistoryGroupsOneEntryPerTransaction(t *testing.T) {
	input := "Start-Date: 2026-01-06  14:31:00\n" +
		"Commandline: apt upgrade\n" +
		"Upgrade: nginx:amd64 (1.18.0-0ubuntu1, 1.18.0-6ubuntu14.4), curl:amd64 (7.81.0-1, 7.81.0-2)\n" +
		"End-Date: 2026-01-06  14:31:15\n" +
		"\n" +
		"Start-Date: 2026-01-06  09:00:02\n" +
		"Commandline: /usr/bin/unattended-upgrade\n" +
		"Install: linux-image-6.8.0-45-generic:amd64 (6.8.0-45.45, automatic)\n" +
		"End-Date: 2026-01-06  09:02:31\n"
	got := ParseAptHistory(input)
	if len(got) != 2 {
		t.Fatalf("expected one entry per transaction, got %#v", got)
	}
	if got[0].Manager != "apt" || got[0].Summary != "2 packages upgraded" {
		t.Fatalf("unexpected first transaction: %+v", got[0])
	}
	if got[1].Summary != "1 package installed" {
		t.Fatalf("unexpected second transaction: %+v", got[1])
	}
	want := time.Date(2026, 1, 6, 14, 31, 0, 0, time.Local)
	if !got[0].At.Equal(want) {
		t.Fatalf("got time %v, want %v", got[0].At, want)
	}
}

// A package's own version parenthetical contains a comma; naively splitting
// the whole line on "," would count "nginx:amd64 (1.0" and "1.1)" as two
// separate packages instead of one.
func TestParseAptHistoryDoesNotOvercountVersionCommas(t *testing.T) {
	input := "Start-Date: 2026-01-06  14:31:00\n" +
		"Upgrade: nginx:amd64 (1.0, 1.1)\n" +
		"End-Date: 2026-01-06  14:31:05\n"
	got := ParseAptHistory(input)
	if len(got) != 1 || got[0].Summary != "1 package upgraded" {
		t.Fatalf("overcounted: %#v", got)
	}
}

func TestParseAptHistoryIgnoresBlocksWithoutPackageActions(t *testing.T) {
	input := "Start-Date: 2026-01-06  14:31:00\n" +
		"Commandline: apt update\n" +
		"End-Date: 2026-01-06  14:31:05\n"
	if got := ParseAptHistory(input); len(got) != 0 {
		t.Fatalf("expected no entries for a plain 'apt update': %#v", got)
	}
}

func TestParseYumLogGroupsByMinute(t *testing.T) {
	now := time.Date(2026, 1, 6, 18, 0, 0, 0, time.Local)
	input := "Jan 06 14:31:02 Installed: nginx-filesystem-1.18.0-1.el7.noarch\n" +
		"Jan 06 14:31:02 Updated: nginx-1.18.0-1.el7.x86_64\n" +
		"Jan 06 09:00:00 Erased: old-package-1.0-1.el7.x86_64\n"
	got := ParseYumLog(input, now)
	if len(got) != 2 {
		t.Fatalf("expected 2 grouped transactions, got %#v", got)
	}
	if got[0].Manager != "yum" {
		t.Fatalf("manager not set: %+v", got[0])
	}
}

// yum.log carries no year; a record whose reconstructed time lands in the
// future (a log spanning a year boundary) must be corrected back a year
// rather than reported as happening tomorrow.
func TestParseYumLogHandlesYearBoundary(t *testing.T) {
	now := time.Date(2026, 1, 2, 8, 0, 0, 0, time.Local)
	input := "Dec 30 10:00:00 Installed: foo-1.0-1.noarch\n"
	got := ParseYumLog(input, now)
	if len(got) != 1 {
		t.Fatalf("expected one entry, got %#v", got)
	}
	if got[0].At.Year() != 2025 {
		t.Fatalf("expected the year corrected back to 2025, got %v", got[0].At)
	}
}

func TestReadTailReturnsOnlyTheRequestedSuffix(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/log"
	if err := os.WriteFile(path, []byte("0123456789"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := ReadTail(path, 4)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "6789" {
		t.Fatalf("got %q, want the last 4 bytes", got)
	}
}

func TestReadTailReturnsWholeFileWhenSmallerThanTheCap(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/log"
	if err := os.WriteFile(path, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := ReadTail(path, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello" {
		t.Fatalf("got %q", got)
	}
}

func TestCollectMergesBothSourcesAndSorts(t *testing.T) {
	c := Collector{ReadTail: func(path string, _ int) ([]byte, error) {
		switch path {
		case "/var/log/apt/history.log":
			return []byte("Start-Date: 2026-01-06  14:00:00\nInstall: foo:amd64 (1.0, automatic)\nEnd-Date: 2026-01-06  14:00:05\n"), nil
		case "/var/log/yum.log":
			return nil, os.ErrNotExist
		}
		return nil, os.ErrNotExist
	}}
	data, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(data.PackageActivity) != 1 || data.PackageActivity[0].Manager != "apt" {
		t.Fatalf("unexpected result: %#v", data.PackageActivity)
	}
}

func TestCollectReportsUnavailableWhenNeitherLogIsAMissingFile(t *testing.T) {
	c := Collector{ReadTail: func(string, int) ([]byte, error) {
		return nil, &os.PathError{Op: "open", Path: "x", Err: os.ErrPermission}
	}}
	data, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(data.Diagnostics) != 2 {
		t.Fatalf("expected a diagnostic per source, got %#v", data.Diagnostics)
	}
}
