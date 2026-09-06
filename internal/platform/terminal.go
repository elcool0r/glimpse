package platform

import (
	"os"
	"strconv"
	"syscall"
	"unsafe"
)

// MinimumWidth is the narrowest width the renderer accepts from the terminal.
// Anything smaller is treated as unknown so the conservative default applies.
const MinimumWidth = 40

type winsize struct{ rows, columns, xpixels, ypixels uint16 }

// windowSize asks the kernel for the terminal geometry of f. It also answers
// whether f is a terminal at all: the ioctl fails for pipes, regular files and
// character devices such as /dev/null, which a file-mode check cannot
// distinguish from a real TTY.
func windowSize(f *os.File) (uint16, bool) {
	if f == nil {
		return 0, false
	}
	var size winsize
	_, _, errno := syscall.Syscall6(syscall.SYS_IOCTL, f.Fd(),
		uintptr(syscall.TIOCGWINSZ), uintptr(unsafe.Pointer(&size)), 0, 0, 0)
	if errno != 0 {
		return 0, false
	}
	return size.columns, true
}

// IsTerminal reports whether f is an interactive terminal. os.ModeCharDevice
// is not sufficient: /dev/null and /dev/zero are character devices too, and
// treating them as a TTY enables color and progress output for redirected runs.
func IsTerminal(f *os.File) bool {
	_, ok := windowSize(f)
	return ok
}

// TerminalWidth returns the usable width of f, or 0 when it is unknown. The
// kernel is asked first; COLUMNS is only a fallback because shells keep it as
// a shell variable and normally do not export it to child processes.
func TerminalWidth(f *os.File) int {
	if columns, ok := windowSize(f); ok && int(columns) >= MinimumWidth {
		return int(columns)
	}
	width, err := strconv.Atoi(os.Getenv("COLUMNS"))
	if err != nil || width < MinimumWidth {
		return 0
	}
	return width
}
