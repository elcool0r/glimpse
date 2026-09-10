# Contributing to Glimpse

Thanks for helping improve Glimpse. Contributions should keep the CLI useful,
conservative, rootless-friendly, and easy to maintain.

## Before you start

For larger changes, open an issue first so the direction can be discussed.
Small fixes, documentation improvements, tests, and focused collectors can go
directly into a pull request.

Please read [`AGENTS.md`](AGENTS.md) for the project’s architecture, safety,
testing, and reporting expectations.

## Development

Glimpse requires Go 1.24 or newer. A typical local check is:

```bash
go test ./...
go vet ./...
go build ./cmd/glimpse
```

When practical, also run:

```bash
go test -race ./...
```

The normal development target is a Linux host, but parser and analysis tests
should remain runnable on other platforms where possible. New `/proc`, `/sys`,
or command-output parsing should use fixtures and focused unit tests.

## Design expectations

- Keep optional integrations optional; a missing command or permission should
  not make the whole report fail.
- Use context timeouts for external commands.
- Prefer evidence and correlated signals over single-threshold warnings.
- Preserve the stable JSON schema unless a breaking change is explicitly
  justified.
- Do not add telemetry, destructive operations, or automatic privilege
  escalation.
- Update `internal/version/VERSION` for every user-visible change.

## Pull requests

Keep pull requests focused and explain the user-facing result. Include tests
for new parsing or analysis behaviour, document relevant threshold changes,
and mention any limitations or Linux-specific assumptions.

Before requesting review, confirm that the test and vet commands pass and that
the default report, `--json`, and non-TTY output still behave sensibly when
the change affects rendering or collection.

By contributing, you agree that your contribution is provided under the
repository’s [MIT License](LICENSE).
