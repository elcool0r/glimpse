//go:build !linux

// glimpse reads /proc and /sys and issues Linux-specific syscalls, so there is
// nothing meaningful for it to report on another operating system. This file
// exists so `go install` still succeeds there and the binary can say so
// plainly, instead of failing with a wall of syscall type errors from half a
// dozen internal packages that names no cause the reader can act on.
package main

import (
	"fmt"
	"os"
	"runtime"
)

func main() {
	fmt.Fprintf(os.Stderr, "glimpse only supports Linux; this binary was built for %s/%s.\n", runtime.GOOS, runtime.GOARCH)
	// 3 is this tool's exit code for "could not produce a report".
	os.Exit(3)
}
