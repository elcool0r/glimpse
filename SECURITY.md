# Security Policy

## Supported versions

Security fixes are developed against the latest release and the default
branch. Users should keep Glimpse updated when a new release is available.

## Reporting a vulnerability

Please do not disclose security vulnerabilities in a public issue.

Use GitHub’s private vulnerability reporting feature for this repository when
available. If it is unavailable, contact the repository owner through the
contact method listed in the owner’s GitHub profile and include “Glimpse
security report” in the subject.

Useful details include:

- the affected version or commit;
- the operating system and execution context;
- clear reproduction steps or a proof of concept;
- the impact you believe the issue has; and
- any suggested mitigation.

Please allow maintainers reasonable time to investigate and prepare a fix
before making the report public. We will acknowledge valid reports, keep the
reporter informed when practical, and credit reporters who want attribution.

Glimpse is intended to be read-only and does not upload host data. Reports
about unexpected network access, command execution, privilege use, sensitive
data exposure, or unsafe parsing are especially valuable.

## Execution model and trust boundaries

A few properties are worth stating explicitly, because they define what a
report can and cannot be about.

- **Optional tools are resolved through `PATH`.** Glimpse locates
  `systemctl`, `smartctl`, `nvme`, `zpool`, `ss`, `ping`, `last`,
  `journalctl`, and the Docker/Podman clients with `exec.LookPath`, and
  executes them directly — never through a shell, and never with any argument
  taken from an untrusted source. A caller who controls `PATH` therefore
  controls which binaries run, which matters when Glimpse is invoked with
  elevated privileges. Run it under `sudo`'s `secure_path`, or with an
  explicit `PATH`, rather than with `sudo -E` from an untrusted environment.
- **Output is host data.** Mount points, unit names, container names, ZFS
  pool names, log lines, and `/var/crash` filenames all reach the terminal.
  They are sanitized before being written (control characters, format
  characters, and embedded newlines are replaced), so a crafted name cannot
  inject terminal escapes or forge report lines. A case where unsanitized
  text reaches the terminal is a valid report.
- **Active checks send real traffic.** DNS resolution, gateway/external/IPv6
  ICMP, the path-MTU probe, and the HTTP/HTTPS GET are on by default and
  contact fixed, non-tracking endpoints. `--disable-external-checks` turns the
  whole group off; `--no-proxy` additionally ignores `HTTP_PROXY`,
  `HTTPS_PROXY`, and `NO_PROXY`.

## Verifying a release binary

Every release publishes a `SHA256SUMS` file alongside the binaries, and each
binary carries a GitHub build-provenance attestation:

```bash
sha256sum --check --ignore-missing SHA256SUMS
gh attestation verify glimpse-linux-amd64 --repo elcool0r/glimpse
```

