# glimpse

> **Note:** this project is [vibe-coded](https://en.wikipedia.org/wiki/Vibe_coding) — built almost entirely through conversations with an AI coding agent (Claude). The architecture, tests, and design decisions were steered and reviewed by a human, but most of the code was written by AI.

[![CI](https://github.com/elcool0r/glimpse/actions/workflows/ci.yml/badge.svg)](https://github.com/elcool0r/glimpse/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/elcool0r/glimpse.svg)](https://pkg.go.dev/github.com/elcool0r/glimpse)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**A fast, honest health check for your Linux box.** No agents to install, no dashboards to babysit, no telemetry phoning home — just run it and get a straight answer about what could be wrong.

```
$ glimpse
GLIMPSE  web-03
Linux · 6.8.0-45-generic · 8 CPUs · sampled 5s

Overall  CRIT  55/100 CRITICAL
CPU OK  18% avg · load 1.42 · I/O wait 2.1%
Memory OK  61.0% available (9.6 GiB / 16.0 GiB) · swap 0 B / 4.0 GiB used
Storage CRIT  2 mounted · / 97.0% used · 2.0 GiB available
Disk OK  1 physical disk · sda 12% busy · 600 KiB/s
Network OK  1 interface · eth0 (1 Gb/s) RX 600 KiB/s · TX 200 KiB/s
Services CRIT  1 failed unit

Details
CRIT  Filesystem nearly full
    / (ext4) is 97.0% used.
    Free space or review retention policies.
CRIT  Failed systemd units
    1 failed unit: nginx.service
    Run systemctl --failed and inspect the affected unit logs.
```

## Features

- **Zero setup** — one binary, no daemon, no config file, no root required for most checks
- **Fast** — a useful report in 5 seconds by default; `--duration 60s` for a deeper sample
- **Broad coverage** — CPU, memory, disk I/O, filesystems, network, thermal, processes, systemd, kernel log events, security posture (SELinux/AppArmor, failed logins, kernel taint), RAID/LVM, ZFS, SMART/NVMe, containers (Docker/Podman), cgroup v2, and more
- **Active network diagnostics** — DNS resolution (local *and* external resolver), gateway reachability, path MTU black-hole detection, and outbound HTTP/HTTPS checks, all opt-out rather than opt-in
- **Correlated, not noisy** — findings require multiple corroborating signals, with conservative, documented thresholds (see [`HEALTH-CHECKS.md`](HEALTH-CHECKS.md))
- **Scriptable** — `--json` for a stable, versioned schema; meaningful exit codes for CI/cron
- **Safe by design** — read-only, no destructive commands, bounded external command timeouts, sanitized terminal output

## Install

**Download a release binary** (Linux amd64/arm64, no dependencies):

```bash
curl -LO https://github.com/elcool0r/glimpse/releases/latest/download/glimpse-linux-amd64
chmod +x glimpse-linux-amd64
sudo mv glimpse-linux-amd64 /usr/local/bin/glimpse
```

(swap `amd64` for `arm64` on an ARM host)

**Or with Go:**

```bash
go install github.com/elcool0r/glimpse/cmd/glimpse@latest
```

**Or build from source:**

```bash
git clone https://github.com/elcool0r/glimpse.git
cd glimpse
go build -o glimpse ./cmd/glimpse
```

Requires Go 1.24+ to build. The binary has no runtime dependencies — optional integrations (SMART, ZFS, containers, etc.) are used automatically when the relevant command is present, and skipped gracefully when it isn't.

## Usage

```bash
glimpse                              # quick 5-second health check
glimpse --duration 60s               # longer, more thorough sample
glimpse --json                       # machine-readable output
glimpse --verbose                    # show every check performed, not just problems
glimpse --disable-external-checks    # passive collection only, no network traffic sent
glimpse --no-containers              # skip Docker/Podman inspection
```

| Flag | Description |
| --- | --- |
| `--duration <dur>` | Sampling window (default `5s`) |
| `--json` | Emit a stable, versioned JSON report instead of the terminal report |
| `--verbose` | Show every check performed and its full detail, not just problems |
| `--no-color` | Disable ANSI colors (also respects `NO_COLOR`) |
| `--no-containers` | Disable Docker/Podman inspection |
| `--disable-external-checks` | Disable the active DNS/gateway/MTU/HTTP checks that send real network traffic |
| `--bash-completion` | Print a Bash completion script |
| `--version` | Print the version and exit |

Exit codes are meaningful for scripting:

| Code | Meaning |
| --- | --- |
| `0` | Healthy, or informational findings only |
| `1` | Warning findings |
| `2` | Critical findings |
| `3` | Insufficient data, interrupted sampling, invalid arguments, or output failure |

## What it checks

glimpse reads `/proc` and `/sys` directly wherever possible, and shells out to well-known optional commands (`systemctl`, `smartctl`, `zpool`, `ss`, `ping`, docker/podman CLIs, ...) with bounded timeouts when they're needed and available. Every check gracefully degrades to "unavailable" rather than failing the whole report — a missing `smartctl` or a rootless container runtime never crashes glimpse, it just shows up as a coverage note.

Several checks are active rather than passive — they send real traffic instead of only reading local kernel state:

- **DNS resolution** against your configured local nameserver *and* an external resolver, analyzed separately so a firewalled outbound path isn't confused with a broken local resolver
- **Gateway ping** to detect an unreachable, lossy, or high-latency default gateway
- **External ICMP ping** to a fixed internet anchor, independent of the gateway — a healthy gateway only proves the local link works
- **IPv6 ping** to an external anchor, but only when the host has a global IPv6 address configured; an IPv4-only host is not a fault and is skipped entirely
- **Path MTU discovery** to catch a black-holed path (as opposed to a merely reduced-but-healthy MTU behind a VPN or PPPoE, which is normal and not flagged)
- **HTTP/HTTPS GET, forced over IPv4,** to catch the case where DNS and ICMP both work but web traffic specifically doesn't (captive portal, proxy, TLS interception, a firewall rule scoped to one protocol)

All of the above are on by default and can be turned off together with `--disable-external-checks`.

One more check reads only local state but is worth calling out: a bounded scan of `/proc/*/fd` finds file descriptors still open on deleted files — the classic "disk is full but nothing looks large" symptom, where a process keeps a rotated or removed file's data alive until it closes the handle.

The full list of checks, their thresholds, and the reasoning behind each one is documented in [`HEALTH-CHECKS.md`](HEALTH-CHECKS.md).

## Design principles

- **No telemetry, no network access by default beyond the active checks above** — glimpse never phones home
- **Read-only** — no remediation, no destructive commands, no policy changes
- **Rootless-friendly** — most checks work without root; the ones that need elevated access degrade gracefully without it
- **Bounded, always** — every external command has both a context deadline and a wait deadline, so a hung device query can't hang the report
- **A stable JSON contract** — fields are additive, never renamed, so scripts built against it keep working

## Contributing

Issues and pull requests are welcome.

## License

[MIT](LICENSE)
