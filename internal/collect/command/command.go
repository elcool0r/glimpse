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
//   - stderr belongs to the client, never to the collected evidence.
package command

import (
	"bytes"
	"context"
	"io"
	"os/exec"
	"time"
)

// WaitDelay bounds how long Run waits for a killed process to release its
// output pipes. A Go context can request cancellation, but only WaitDelay
// makes the wait itself terminate when the process cannot be reaped.
const WaitDelay = 2 * time.Second

// Options adjusts one invocation. The zero value inherits the current
// environment and does not cap output.
type Options struct {
	// Env replaces the child environment when non-nil.
	Env []string
	// MaxOutput caps retained stdout in bytes. Zero means no cap.
	MaxOutput int
}

// Result reports what an invocation produced.
type Result struct {
	Output []byte
	// Truncated is true when MaxOutput clipped stdout. The retained prefix is
	// still valid input for line-oriented parsers.
	Truncated bool
}

// Output runs name with args and returns its stdout.
func Output(ctx context.Context, name string, args ...string) ([]byte, error) {
	result, err := Run(ctx, Options{}, name, args...)
	return result.Output, err
}

// Run executes name with args under opts. A non-zero exit status is returned
// as an error together with whatever stdout was produced, so callers that
// treat specific exit codes as data (smartctl health bits, zpool status on an
// unhealthy pool) can still use the output.
func Run(ctx context.Context, opts Options, name string, args ...string) (Result, error) {
	var out limitedBuffer
	out.limit = opts.MaxOutput
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = opts.Env
	cmd.Stdout = &out
	cmd.Stderr = io.Discard
	// Without WaitDelay, Wait blocks until the process releases its pipes even
	// after the context kills it; an uninterruptible process never does.
	cmd.WaitDelay = WaitDelay
	err := cmd.Run()
	return Result{Output: out.Bytes(), Truncated: out.truncated}, err
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

func (b *limitedBuffer) Bytes() []byte { return b.buf.Bytes() }
