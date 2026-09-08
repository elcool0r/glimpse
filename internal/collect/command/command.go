// Package command centralizes optional external command execution.
//
// Every collector that shells out shares these semantics:
//
//   - the context bounds the command, and WaitDelay bounds the wait for a
//     process that ignores the kill signal (a device command blocked in
//     uninterruptible sleep on failing hardware would otherwise hang the
//     report forever, which is precisely the case Glimpse must survive);
//   - stdout is capped and truncated rather than discarded, so a chatty
//     source degrades to partial evidence instead of no evidence;
//   - stderr belongs to the client by default; callers can explicitly opt into
//     capturing it when a command's stderr carries application evidence.
package command

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
)

// WaitDelay bounds how long Run waits for a killed process to release its
// output pipes. A Go context can request cancellation, but only WaitDelay
// makes the wait itself terminate when the process cannot be reaped.
const WaitDelay = 2 * time.Second

// DefaultMaxOutput bounds output retained by invocations that do not need a
// collector-specific limit. Commands are optional evidence sources; one
// unexpectedly chatty implementation must not be able to consume unbounded
// process memory before its timeout expires.
const DefaultMaxOutput = 1 << 20

// Options adjusts one invocation. The zero value inherits the current
// environment, forces stable C-locale command output, and applies
// DefaultMaxOutput. Set MaxOutput negative only for a deliberately unbounded
// invocation.
type Options struct {
	// Env replaces the child environment when non-nil.
	Env []string
	// MaxOutput caps retained output in bytes. With CaptureStderr, stdout and
	// stderr share this total bound. Zero uses DefaultMaxOutput; negative
	// disables the cap.
	MaxOutput int
	// CaptureStderr merges stderr into the bounded output stream. This is
	// intended for commands whose stderr carries application data, such as a
	// container log reader. The default remains discard because most command
	// stderr is client diagnostics rather than collected evidence.
	CaptureStderr bool
}

// Result reports what an invocation produced.
type Result struct {
	Output []byte
	// Truncated is true when MaxOutput clipped the output. The retained prefix
	// is still valid input for line-oriented parsers.
	Truncated bool
}

// Output runs name with args and returns its stdout.
func Output(ctx context.Context, name string, args ...string) ([]byte, error) {
	result, err := Run(ctx, Options{}, name, args...)
	return result.Output, err
}

// Run executes name with args under opts. A non-zero exit status is returned
// as an error together with whatever output was produced, so callers that
// treat specific exit codes as data (smartctl health bits, zpool status on an
// unhealthy pool) can still use the output.
func Run(ctx context.Context, opts Options, name string, args ...string) (Result, error) {
	var out limitedBuffer
	out.limit = outputLimit(opts.MaxOutput)
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = stableLocaleEnv(opts.Env)
	cmd.Stdout = &out
	if opts.CaptureStderr {
		cmd.Stderr = &out
	} else {
		cmd.Stderr = io.Discard
	}
	// Without WaitDelay, Wait blocks until the process releases its pipes even
	// after the context kills it; an uninterruptible process never does.
	cmd.WaitDelay = WaitDelay
	err := cmd.Run()
	return Result{Output: out.Bytes(), Truncated: out.truncated}, err
}

func outputLimit(limit int) int {
	if limit == 0 {
		return DefaultMaxOutput
	}
	return limit
}

// stableLocaleEnv returns an environment with locale-sensitive command output
// normalized to the portable C locale. Most collectors parse machine-like
// English labels from optional tools; preserving a host's localized output
// would turn a healthy capability into a parser failure. Options.Env still
// replaces the inherited environment, except for these enforced locale keys.
func stableLocaleEnv(env []string) []string {
	if env == nil {
		env = os.Environ()
	}
	result := make([]string, 0, len(env)+2)
	for _, entry := range env {
		key, _, _ := strings.Cut(entry, "=")
		if key == "LC_ALL" || key == "LANG" {
			continue
		}
		result = append(result, entry)
	}
	return append(result, "LC_ALL=C", "LANG=C")
}

// limitedBuffer keeps a bounded prefix of the output.
//
// The buffer is a field rather than an embedded type on purpose. Embedding
// bytes.Buffer promotes its ReadFrom method, and io.Copy — which is how
// os/exec drains a non-file Stdout — prefers ReadFrom over Write. A cap
// implemented as a Write method on an embedding type is therefore bypassed
// entirely and never applies.
//
// It also reports success to the copier after the cap is reached: returning an
// error there aborts the copy and abandons the bytes already collected, turning
// a chatty source into no evidence at all.
type limitedBuffer struct {
	buf       bytes.Buffer
	limit     int
	truncated bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.limit <= 0 {
		return b.buf.Write(p)
	}
	remaining := b.limit - b.buf.Len()
	if remaining <= 0 {
		b.truncated = true
		return len(p), nil
	}
	if len(p) > remaining {
		b.truncated = true
		if _, err := b.buf.Write(p[:remaining]); err != nil {
			return 0, err
		}
		return len(p), nil
	}
	return b.buf.Write(p)
}

func (b *limitedBuffer) Bytes() []byte {
	return b.buf.Bytes()
}
