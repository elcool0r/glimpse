# Glimpse Code Review Fix Progress

## Purpose

Persistent handoff state for resolving accepted R01–R21 in CODE_REVIEW_REPORT.md across usage windows. Current code and regression tests take precedence over stale notes.

## Current repository state

- Last updated: 2026-09-08
- Current commit: e476753ad533be22c1830d99a07ab0910838eb16
- Working tree at start: pre-existing `.gitignore` change; untracked `CODE_REVIEW_REPORT.md`. Preserve both.
- Working tree at checkpoint 4: prior fixes and user changes preserved; R05 files and tests added to the uncommitted tree. No commit created. Base HEAD remains unchanged.
- Application version: 0.13.10.
- Current batch: checkpoint 4, R05 complete. Stop before R07 because the five-hour allowance is 97% used.
- `PLAN.md` is absent; AGENTS.md and CODE_REVIEW_AGENTS.md were read.

## Session status

- Objective: make path-MTU output state only the DF probe evidence actually observed.
- Last completed action: full checkpoint 4 validation after independent Terra review.
- Safe checkpoint: YES — R05 is implemented, independently reviewed, documented, versioned, and fully validated.
- Budget assessment: five-hour allowance is 97% used and weekly allowance is 45% used. Stop at this safe checkpoint and resume R07 after reset.

## Finding status

| Finding | Severity | Status | Owner | Validation |
| --- | --- | --- | --- | --- |
| R01 | HIGH | FIXED | Luna; Terra QA | Real JSON → delta 3 → CRIT; reset/new-container tests PASS |
| R02 | HIGH | FIXED | Luna; Terra QA | Stream, bound, failure, default-policy and cancellation tests PASS |
| R03 | HIGH | FIXED | Luna; Terra QA | Parser/analyzer/render/JSON, numeric bounds; tests/race/vet PASS |
| R04 | HIGH | FIXED | Luna; Terra QA | Newest OOM/IO, merge, age/ties; tests/race/vet PASS |
| R05 | HIGH | FIXED | Sol semantics; Luna implementation; Terra QA | Silent-drop/explicit-feedback/analyzer/render/JSON regressions; full tests/race/vet PASS |
| R06 | MEDIUM | FIXED | Sol semantics; Luna implementation; Terra QA | Invalid-baseline/source/reset/actionable/JSON/render regressions; full tests/race/vet PASS |
| R07 | MEDIUM | TODO | | Pending |
| R08 | MEDIUM | TODO | | Pending |
| R09 | MEDIUM | TODO | | Pending |
| R10 | MEDIUM | TODO | | Pending |
| R11 | MEDIUM | TODO | | Pending |
| R12 | MEDIUM | TODO | | Pending |
| R13 | MEDIUM | TODO | | Pending |
| R14 | MEDIUM | TODO | | Pending |
| R15 | MEDIUM | TODO | | Pending |
| R16 | MEDIUM | TODO | | Pending |
| R17 | MEDIUM | TODO | | Pending |
| R18 | MEDIUM | TODO | | Pending |
| R19 | MEDIUM | TODO | | Pending |
| R20 | LOW | TODO | | Pending |
| R21 | LOW | TODO | | Pending |

Statuses: TODO, INVESTIGATING, IMPLEMENTING, IMPLEMENTED, VALIDATING, FIXED, BLOCKED. FIXED requires regression validation.

## Completed work

### R05 — Observational IPv4 DF probe reporting

- Root cause: a smaller DF echo reply was called an exact path MTU and proof that PMTUD worked; raw packet-too-big output was discarded, making explicit feedback indistinguishable from silence.
- Implementation: `discovered_mtu` remains compatible but now means the largest tested IPv4 DF packet that replied. Bounded stdout/stderr under the shared C locale records narrow `frag needed`/`message too long` evidence in additive `packet_too_big_feedback`. Existing finding IDs, severities, and impacts remain; analyzer, renderer, comments, README, HEALTH-CHECKS, and ignored COVERAGE wording state only observed replies/non-replies and feedback.
- Regressions: silent large drops then smaller reply cannot claim exact MTU, health, or working PMTUD; explicit feedback is preserved separately for reduced and all-no-reply series; timeout-only series remains distinct; zero-value collector fallback captures stderr; JSON true round-trips; compact/verbose/quiet output stays factual. Terra PASS, no blockers.
- Checkpoint: uncommitted checkpoint 4, version 0.13.10.

### R06 — Cgroup observation validity

- Root cause: failed or malformed cgroup reads collapsed into zero/nil, so a later readable lifetime counter could be subtracted from a fabricated baseline and reported as a sampled incident.
- Implementation: the collector records optional per-file validity and per-group sampling markers. Valid nil limits mean kernel `max`; invalid nil limits mean unavailable. Memory-event and CPU-stat deltas require complete, valid, monotonic observations from the same resolved cgroup directory. Invalid boundaries zero only the affected deltas, while valid final gauges survive. Analyzer rules reject explicit invalid evidence and retain nil-as-legacy compatibility. Verbose rendering distinguishes measured zero, unlimited, unavailable, and unsampled groups without inventing usage ratios.
- Files: `internal/collect/cgroupv2/cgroup.go`, `cgroup_test.go`, `r06_qa_test.go`; cgroup model and JSON test; analyzer validity gates/tests; integration renderer and validity tests; `HEALTH-CHECKS.md`; version.
- Regression validation: actual denied baseline then lifetime `oom_kill 100` through Collect→Delta→analyze→JSON produces no finding; missing required counters, malformed gauges, `max`, source changes, counter resets, missing boundaries, final-gauge preservation, valid actionable OOM/throttling deltas, explicit false versus legacy nil, JSON round-trip, and mixed verbose states all pass. Terra reported no production or coverage blockers.
- Compatibility: additive optional schema-1 JSON fields; nil validity remains legacy-valid. CLI flags, exit codes, thresholds, and normal compact output are unchanged. R12 host/local pressure scope remains deferred.
- Checkpoint: uncommitted checkpoint 3, version 0.13.9.

### R03 — ZFS error evidence

- Root cause: only root rows parsed; scaled values silently became zero.
- Implementation: status -P -p requests literal counters; root counters retain their meaning. Optional vdev_errors stores each affected row independently, with name/state/read/write/checksum. No hierarchy sum and one existing WARN/15-point impact per ONLINE pool. Renderer handles leaf-only errors in normal/verbose/quiet output.
- Legacy K/M/G/T/P/E values use binary scales and are explicitly approximate in JSON and reports. NaN/Inf/overflow values are rejected before uint64 conversion; literal uint64 maximum remains exact.
- Files: ZFS collector/tests, ZFSPool model, zfsFindings, analyzer/zfs_review_test.go, ZFS renderer section and render/zfs_review_test.go.
- Regression validation: leaf-only and distinct/repeated parent-child counters, scaled root/leaf, exact integers and invalid/boundary values, literal command flags; one WARN without duplicate scoring; parser→analyzer→normal/verbose/quiet; JSON root0/vdev7 distinction. Terra focused uncached race/vet PASS. Mirror and RAIDZ fixture variants both pass focused uncached tests.
- Compatibility: additive optional approximate/vdev_errors JSON fields, schema remains 1; root fields, CLI flags and exit codes unchanged. All vdev error rows are evidence, not a unique-error total. Existing systemd changes preserved.
- Checkpoint: uncommitted checkpoint 2, version0.13.8. No live ZFS or Linux host validation.

### R04 — Newest kernel incident

- Root cause: first chronological event won canonical-kind deduplication.
- Implementation: shared merge policy selects smallest known age within and across scans, known over unknown, stable ties/positions, OOM/cgroup OOM shared key. Malformed timestamps remain unknown.
- Files: internal/collect/kernel/kernel.go and kernel_test.go.
- Regression validation: oldest/recent and reversed OOM, ordinary I/O, cross-scan canonical duplicates, known/unknown/ties; parser→analyzer current OOM is CRIT. Focused tests/race/vet PASS; Terra approved behavior. Shared merge cleanup and NaN/+Inf/-1 timestamp table pass focused race/vet and full checkpoint validation.
- Compatibility: existing model fields and severity thresholds unchanged. No live journal tested. Version included in checkpoint 2 (0.13.8).

### R01 — Docker restart counters

- Root cause: parser read State.RestartCount instead of the inspection object's top-level field.
- Implementation: moved the decoded field and counter lookup to the top level; corrected the unrealistic existing fixture.
- Files: `internal/collect/containers/containers.go`, `containers_test.go`; `internal/analyze/analyze_test.go`.
- Tests: real JSON counts 1→4 flow through Delta and analyze.Report to a critical finding; reset counter yields an error and zero delta; existing new-container delta remains zero. Existing Podman analyzer fixture now also checks severity.
- Validation: Luna and Terra focused tests/race/vet PASS. Primary full-suite results below.
- Decisions/compatibility: no nested fallback without a supported runtime contract; JSON output/CLI/scoring unchanged. Correctly observed restarts now activate existing findings.
- Checkpoint: working-tree checkpoint 1, version 0.13.5; no commit created.
- Remaining concerns: live runtime validation not performed; R19 timestamp propagation is still pending.

### R02 — Application stderr evidence

- Root cause: the common command helper discarded stderr, including Docker application logs.
- Implementation: added explicit `command.Options.CaptureStderr`; only the container log runner opts in. Both streams share the existing bounded buffer. Failed log commands still discard output before classification.
- Files: `internal/collect/command/command.go`, `command_test.go`; `internal/collect/containers/containers.go`, `containers_test.go`.
- Tests: real subprocess stderr-only panic classification, successful mixed output, total bound/truncation, captured output plus command error, log-specific failure rejection, default stderr discard, and cancellation with merged streams. Existing log-failure coverage accounting remains tested.
- Validation: Luna and Terra focused tests/race/vet PASS; no scoped QA findings remain.
- Decisions/compatibility: Go os/exec serializes writes to the same comparable writer, so no additional locking is needed. Existing timeout, WaitDelay, environment isolation and output caps remain. Successful logs can now produce previously missing findings; no JSON/CLI contract change.
- Checkpoint: working-tree checkpoint 1, version 0.13.5; HEALTH-CHECKS documents the repaired behavior.
- Remaining concerns: live Docker/Podman daemons not exercised; runtime timestamps remain R19.

## Current work in progress

- R01–R06 remain FIXED. No implementation is in progress; the next bounded finding is R07.
- Checkpoint 4 used Sol for evidence semantics, Luna/primary for implementation, Terra for adversarial validation, and the primary agent for integration, version, docs, full validation, and this file.
- Newer pre-existing systemd StateChangeTimestamp/FailedUnitSince changes span systemd collector/tests, model and analyzer/tests. Preserve them; they are not credited to an accepted finding. Start diff saved at /tmp/glimpse-fix-checkpoint2-start.diff.
- Checkpoint 4 start diff/status are saved at `/tmp/glimpse-fix-checkpoint4-start.diff` and `/tmp/glimpse-fix-checkpoint4-start-status.txt`.
- No known code/test failures. Full tests need permission for local loopback test servers; module downloads remain disabled.

## Architectural decisions

### AD-001 — Log-specific stream capture

Context: Docker application stderr is valuable evidence, while other command stderr generally contains client diagnostics.
Decision: explicitly opt in to combined bounded streams for container log commands; retain existing default command behavior. Failed log commands provide coverage diagnostics, not health evidence.
Reason: fix the actual stream boundary without changing every integration's interpretation.
Affected findings: R02; R19 must preserve this behavior when adding timestamps later.
Compatibility: no CLI, JSON schema, exit-code, or scoring contract changes intended.

### AD-002 — Preserve ZFS root counters and add vdev evidence

Context: root counters and child counters are separate observations and must not be summed across redundant layers.
Decision: preserve root counter field meanings and add optional per-vdev error records. Request literal zpool counters. Legacy scaled values must remain identified as approximate or raw evidence, never silently measured zero.
Reason: retain fault evidence without changing established JSON field semantics or double-counting.
Affected findings: R03. Compatibility: additive optional schema-1 fields; no CLI/exit-code changes.

### AD-003 — Newest known canonical kernel event

Keep the smallest known age per canonical kind within and across scans; known ages take precedence over unknown ages, ties retain first encounter order. OOM/cgroup OOM retain one shared key. Preserve unknown timestamps without inventing current time. Affected finding: R04; no schema change.

### AD-004 — Explicit cgroup observation validity

Context: zero, unlimited (`max`), unreadable, malformed, and unsampled currently collapse into zero or nil.
Decision: add optional `*bool` validity markers for current/limit gauges and sampled memory-event/CPU-stat groups. Nil means legacy/unspecified and preserves existing hand-built/serialized behavior; collector output always sets true or false. A valid nil limit means `max`; an invalid nil limit means unavailable. Counter deltas require two valid, monotonic observations of the same normalized cgroup path. Invalid sampling zeroes that group's deltas while retaining final gauges.
Reason: this prevents historical counters from becoming sampled incidents without breaking schema-v1 consumers or existing fixtures.
Affected findings: R06; R12 must reuse this source/validity foundation. R10/R21 should follow the same nil-means-legacy compatibility policy where applicable.
Compatibility implications: additive optional JSON fields; schema remains 1. Analyzer rules accept nil as legacy-valid and reject explicit false. Collection diagnostics and unavailable gauge detail remain verbose-only; no CLI flag, exit-code, or threshold change.

### AD-005 — Path-MTU probes report observations, not PMTUD health

Context: descending DF echo probes can observe replies and packet-too-big text, but a smaller reply alone cannot prove the exact path MTU, kernel adaptation, or working PMTUD.
Decision: retain `discovered_mtu` for schema compatibility and define it as the largest tested IPv4 DF packet size that received an echo reply. Add one optional JSON evidence bit for narrowly recognized packet-too-big output. Capture bounded combined probe output under the shared C locale. Keep existing finding IDs, but titles, evidence, rendering, comments, and docs state only tested replies/non-replies and whether packet-too-big feedback was observed. Absence of feedback never proves it was filtered.
Reason: this repairs the false reassurance while preserving API and scoring compatibility and distinguishes explicit feedback from timeout-only loss.
Affected finding: R05.
Compatibility implications: additive schema-1 field; existing `discovered_mtu`, finding IDs, severity/impact, CLI flags, and exit codes remain. No numeric MTU is inferred from feedback text.

## Shared/root-cause changes and dependency plan

1. Lost evidence: R01/R02 now; R03 ZFS literal/per-vdev errors and R04 newest kernel events next (independent file ownership). R06 cgroup per-file validity follows as its own checkpoint.
2. Semantics/lifecycle: R05 MTU claims, R07 bounded intermediate collection, R08 endpoint D-state claims, R11 coherent CPU deltas, R12 local cgroup pressure, R13 host CPU scope. R12 depends on R06 validity decisions. Use Sol selectively for R05/R08/R11–R13; coordinate shared model/analyzer changes centrally.
3. Validity/output: R10 interval validity before R09 insufficient-data rendering and R18 coverage consistency. R17 latency severity and R16 visible-PID filtering are localized but share renderer files; serialize ownership.
4. Targeted integrations: R14 route selection and R15 auth facilities independent; R19 log timestamps depends on R02; R21 MemAvailable presence should reuse R10 validity conventions. R20 progress stream/color policy is independent of collectors.
5. Each bounded checkpoint includes regression tests, Terra QA, version bump, focused and full tests/vet; race for shared/concurrent code. Update docs alongside behavior. Final checkpoint covers all requested output modes and supported builds.

Shared command capture gained an opt-in policy in checkpoint 1. Checkpoint 2 introduces per-vdev ZFS evidence and newest canonical kernel event selection; details below.

## Validation history

### Checkpoint 4 — 2026-09-08, version 0.13.10

- R05 focused uncached tests/race for pathmtu, analyzer, model, and renderer; full `go vet ./...`; gofmt and `git diff --check`: PASS. Terra final QA PASS with no blockers.
- Full `go test -count=1 ./...` and `go test -race -count=1 ./...`: PASS using approved local loopback test servers. Logs: `/tmp/glimpse-fix-checkpoint4-tests.txt`, `/tmp/glimpse-fix-checkpoint4-race.txt`.
- Native and `CGO_ENABLED=0` Linux amd64/arm64 builds: PASS; known nonfatal read-only module stat-cache warnings only.
- Native version 0.13.10. Redirected normal/verbose/quiet/JSON duration-zero checks: expected exit 3, no ANSI, JSON schema 1/unknown score; expected macOS unavailable diagnostics only in verbose stderr. No live Linux path-MTU probe was run.

### Checkpoint 3 — 2026-09-08, version 0.13.9

- R06 per-file cgroup validity and same-source sampled deltas independently reviewed by Terra: PASS with no blockers. Focused uncached tests/race for cgroupv2, analyzer, model, renderer, and app; full `go vet ./...`; gofmt and `git diff --check`: PASS.
- Full `go test -count=1 ./...` and `go test -race -count=1 ./...`: PASS using approved local loopback test servers. Logs: `/tmp/glimpse-fix-checkpoint3-tests.txt`, `/tmp/glimpse-fix-checkpoint3-race.txt`.
- Native and `CGO_ENABLED=0` Linux amd64/arm64 builds: PASS. Nonfatal module stat-cache warnings remain due the read-only module cache.
- Native version 0.13.9. Redirected normal/verbose/quiet/JSON duration-zero checks with external checks and containers disabled: expected exit 3, no ANSI, JSON schema 1 with unknown score. Verbose stderr contains expected macOS unavailable-source diagnostics; other mode stderr is empty. R09 insufficient-data wording remains pending.
- Environment: macOS arm64, Go 1.27.0; `GOPROXY=off`, `GOSUMDB=off`, `GOCACHE=/tmp/glimpse-go-cache`. No live Linux/cgroup namespace was exercised.

### Checkpoint 2 — 2026-09-08, version 0.13.8

- Resumed after allowance reset; original R01/R02 fixes intact. Focused command/containers/systemd/analyze verification PASS. Newer systemd timestamp changes and version0.13.7 pre-existed; source diff saved /tmp/glimpse-fix-checkpoint2-start.diff and preserved.
- Full go test -count=1 ./..., go vet ./..., go test -race -count=1 ./...: PASS. Scoped ZFS/kernel/analyzer/render uncached race and vet: PASS with Terra independent review.
- gofmt/diff checks: PASS. Native and CGO_ENABLED=0 Linux amd64/arm64 builds: PASS (nonfatal module stat-cache warnings).
- Native version0.13.8; normal/verbose/quiet/JSON with duration0, no containers/external checks, --no-color, redirected stdout/stderr: PASS expected exit3/noANSI; schema1 unknown JSON. R09 insufficient-data wording remains unfixed, so these smoke results do not claim that verdict is visually correct.
- Not run: live Linux/ZFS/journald, NO_COLOR/narrow PTY matrix this checkpoint. Final all-findings validation must still run the complete matrix.
- macOS arm64, Go1.27.0; GOPROXY=off GOSUMDB=off GOCACHE=/tmp/glimpse-go-cache. Sandboxed HTTP tests failed loopback permission; full suite passed with escalation for local loopback servers.
- Logs: /tmp/glimpse-fix-checkpoint2-tests.txt and /tmp/glimpse-fix-checkpoint2-race.txt. Final test-only mirror/RAIDZ variant passed uncached ZFS package tests.

### Checkpoint 1 — 2026-09-08, version 0.13.5

- Focused command/containers/analyze tests, race tests, vet: PASS (Luna and independent Terra).
- Full `go test -count=1 ./...`, `go vet ./...`, `go test -race -count=1 ./...`: PASS, including final rerun after the last regression assertion.
- `gofmt -l` on changed Go packages/tests: no files; `git diff --check`: PASS.
- Native build and CGO_ENABLED=0 Linux amd64/arm64 cross-builds: PASS.
- Native `--version`: 0.13.5. Normal and JSON smoke runs with duration 0, external checks/containers disabled, redirected streams and --no-color: expected exit 3; no ANSI; JSON schema 1 and unknown score. R09 remains pending, so this is not validation of the ordinary insufficient-data wording.
- Environment: macOS arm64, Go 1.27.0. Go cache redirected under /tmp; module downloads disabled using GOPROXY=off/GOSUMDB=off. Full tests/race granted permission for local loopback test servers. Some builds emitted nonfatal module stat-cache write warnings but exited successfully.
- Not run this checkpoint: live Linux, Docker/Podman daemons, full CLI mode matrix. Existing review results do not substitute for final all-finding validation.
- Logs: `/tmp/glimpse-fix-checkpoint1-tests.txt`, `/tmp/glimpse-fix-checkpoint1-race.txt` (temporary, rerun if unavailable).

## Files changed so far

- `FIX_PROGRESS.md` — repair plan and resumable state.
- `internal/collect/pathmtu/collector.go`, `collector_test.go`, `r05_qa_test.go` — R05 combined bounded evidence, semantics, and regressions.
- `internal/analyze/backlog.go`, `httpcheck_test.go` — R05 observational findings and evidence tests.
- `internal/render/integrations.go`, `render.go`, `render_test.go`, `pathmtu_review_test.go` — R05 factual output and mode regressions.
- `internal/model/model.go`, `model_test.go` — additive R05 feedback field/JSON test alongside prior fields.
- `README.md`, `HEALTH-CHECKS.md`, ignored `COVERAGE.md` — R05 documented evidence limits.
- `internal/collect/cgroupv2/cgroup.go`, `cgroup_test.go`, `r06_qa_test.go` — R06 per-file/group validity, source identity, safe deltas and regressions.
- `internal/model/model.go`, `model_test.go` — R06 optional cgroup validity JSON fields/tests; R03 and pre-existing systemd fields preserved.
- `internal/analyze/analyze.go`, `cgroup_validity_test.go` — R06 validity gates and compatibility tests; earlier changes preserved.
- `internal/render/integrations.go`, `cgroup_validity_test.go` — R06 explicit verbose validity states; R03 changes preserved.
- `internal/collect/zfs/zfs.go`, `zfs_test.go` — R03 literal/scaled/vdev evidence.
- `internal/model/model.go` — R03 optional ZFS fields; pre-existing systemd field preserved; also listed above for R06.
- `internal/analyze/analyze.go`, `zfs_review_test.go` — R03 findings; pre-existing failedUnitsSummary preserved.
- `internal/render/integrations.go`, `zfs_review_test.go` — R03 severity/evidence/JSON consistency.
- `internal/collect/kernel/kernel.go`, `kernel_test.go` — R04 newest canonical events.
- `internal/collect/systemd/systemd.go`, `systemd_test.go` — newer pre-existing user changes, outside repair scope.
- `internal/collect/containers/containers.go` — top-level restart field and log stderr opt-in.
- `internal/collect/containers/containers_test.go` — real-shaped restart pipeline, resets and subprocess log regressions.
- `internal/collect/command/command.go` — opt-in bounded combined output.
- `internal/collect/command/command_test.go` — stream/bound/failure/default/cancellation regressions.
- `internal/analyze/analyze_test.go` — critical severity assertion.
- `HEALTH-CHECKS.md` — corrected container evidence behavior.
- `internal/version/VERSION` — checkpoint1: 0.13.4→0.13.5; pre-existing resume version0.13.7→checkpoint2 version0.13.8; checkpoint3 version0.13.9; checkpoint4 version0.13.10.
- `.gitignore` — pre-existing user change, outside repair scope.
- `CODE_REVIEW_REPORT.md` — existing untracked review deliverable, outside repair modifications.

## Deferred / blocked issues

R07–R21 are deliberately deferred to subsequent bounded checkpoints, not blocked. No product decision is needed. Do not consume the whole repair task in one session.

## Next actions

1. Verify this uncommitted checkpoint and remaining allowance. R01–R06 are complete; do not redo them. Preserve newer systemd timestamp work, `.gitignore`, and ignored `COVERAGE.md`.
2. Next: R07, bounded intermediate trend collection. Inspect `internal/app/app.go` `sampleTrends`/`collectTrendAll` and lifecycle tests. Bound each intermediate call by both a small observation budget and the remaining sample window; preserve completed observations on expiry.
3. Required R07 regressions: cooperative and non-cooperative blocked trend collectors cannot hold a finite run beyond its bound, and a late result cannot mutate the returned report. Use Sol for lifecycle/concurrency semantics and Terra for leak/race/adversarial QA.
4. Bump version from 0.13.10, run focused lifecycle tests/race, then full tests/vet/race and checkpoint validation. Stop if the available window cannot safely complete R07.

## Resume instructions

Read AGENTS.md, CODE_REVIEW_AGENTS.md, CODE_REVIEW_REPORT.md and this file; read PLAN.md if now present. Inspect `git status --short` and `git diff`, preserve unrelated changes, verify the last checkpoint against code/tests. Check remaining allowance before implementation. Continue exact next actions; do not restart completed work or mark unvalidated changes FIXED.
