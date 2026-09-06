// Package platform provides small platform-level facts independent of feature collectors.
package platform

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/elcool0r/glimpse/internal/model"
)

func Host() model.Host {
	hostname, _ := os.Hostname()
	host := model.Host{
		Hostname:     hostname,
		OS:           runtime.GOOS,
		Architecture: runtime.GOARCH,
		CPUCount:     runtime.NumCPU(),
		IsRoot:       os.Geteuid() == 0,
	}
	if info, err := os.ReadFile("/etc/os-release"); err == nil {
		for _, line := range strings.Split(string(info), "\n") {
			key, value, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			value = strings.Trim(value, "\"")
			switch key {
			case "PRETTY_NAME":
				host.OS = value
			case "VERSION_ID":
				host.OSVersion = value
			}
		}
	}
	if release, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		host.Kernel = strings.TrimSpace(string(release))
	}
	if uptime, err := linuxUptime(); err == nil {
		host.UptimeSeconds = uptime.Seconds()
		bootTime := time.Now().Add(-uptime)
		host.BootTime = &bootTime
	}
	return host
}

func linuxUptime() (time.Duration, error) {
	f, err := os.Open("/proc/uptime")
	if err != nil {
		return 0, err
	}
	defer f.Close()
	var seconds float64
	if _, err := fmt.Fscan(f, &seconds); err != nil {
		return 0, err
	}
	return time.Duration(seconds * float64(time.Second)), nil
}
