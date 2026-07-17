# Discovery Performance Baseline

This document defines the reproducible measurement boundary for P7-T01. A compiled metric collector is not a performance result. Rows marked `Pending authorized Runner measurement` must not be replaced with zeroes or estimates.

## Instrumentation Contract

- The discovery actor measures backend task latency with a monotonic clock for fast process scans, port scans, per-process enrichment, and project association.
- A non-cancelled backend completion is included in latency percentiles whether it succeeds or returns a structured error. Actor-cancelled work is counted separately and excluded from percentiles.
- Each operation retains at most the latest 256 completed samples. `p50` and `p95` use the nearest-rank method over the retained window; an empty window reports `None`.
- The in-memory snapshot contains only counts, durations, configured intervals, capacities, and concurrency. It contains no PID, path, command line, environment, log content, credential, or network upload.
- Default fast and port scan periods are 2 seconds and 5 seconds. Default enrichment and project concurrency are both 4.

## Bounded Delivery Contract

- Discovery mutations use a 16 ms last-write-wins accumulator. One event contains at most 128 entities and an estimated 512 KiB payload; a single entity that cannot fit is rejected before accumulation and reported as a bounded `ProcessPublication`, port-scan, or availability failure.
- Enrichment accepts at most 64 complete process identities per request. Visible rows are debounced by 100 ms, the selected row is immediate, and an unchanged visible/selected set is refreshed every 10 seconds. The desktop keeps one request in flight and only the latest pending request.
- Revision state accepts at most 16,384 processes and 65,536 port bindings. A process or port entity is limited to a conservatively accounted 512 KiB encoded JSON budget, including 64 bytes per entity for Rust/JavaScript numeric-format differences. One revision delta is limited to 128 entities and 512 KiB, and the complete process-plus-port state to 128 MiB. A rejected delta does not modify state.
- Snapshot synchronization freezes one revision and returns ordered chunks of at most 1,024 entities and 768 KiB JSON. Every chunk carries the same random snapshot ID, revision, declared entity counts, and total encoded-entity upper bound; the desktop validates continuity, strict DTO shape, delta uniqueness, duplicate identities, declared totals, and cumulative bytes before one atomic commit. A malformed chunk may reset the Bridge connection once; a busy reset command uses one bounded exponential-backoff timer, while repeated malformed data remains in an explicit terminal protocol state.
- At most four frozen sessions and 256 MiB of conservatively accounted pinned entity data are retained. Idle sessions expire after 30 seconds and all sessions after five minutes. The desktop additionally caps buffered revision events at 1,024 events and 8 MiB.
- These are compile-reviewed resource contracts, not measured throughput or latency results. The assembled Supervisor host and real discovery event route remain pending, so no runtime delivery claim is made here.

## Reference Host

The following host facts were collected read-only on 2026-07-16. MagicTools, the Supervisor, fixtures, migrations, and native discovery scans were not started.

| Field | Value |
|---|---|
| Platform | Windows 11 Pro x64, version 10.0.26200, build 26200 |
| CPU | AMD Ryzen 7 5700X, 8 cores / 16 logical processors |
| Memory | 31.9 GiB visible RAM |
| System disk | KINGSTON SA2000M8500G, 465.8 GiB fixed disk |
| Power plan | Unavailable to the non-elevated read-only query; must be recorded by the authorized Runner |
| Rust target | `x86_64-pc-windows-msvc` |
| Workspace revision | Uncommitted implementation workspace; record an immutable commit for an authorized run |

## Measurement Procedure

1. Use a release build on an immutable revision and record OS build, CPU, memory, disk, power mode, process count, port count, and MagicTools configuration.
2. Keep the default 2-second fast and 5-second port periods unless the result row explicitly states otherwise.
3. Warm up for at least two minutes, then collect at least 256 non-cancelled completions for every reported operation. Record total completed, failed, and cancelled counts in addition to the retained-window percentile.
4. Measure idle and declared development-load scenarios separately. Do not start fixtures, child processes, sockets, or log producers without explicit authorization.
5. Record fast-scan p95, port-scan p95, enrichment p95, project-association p95, and new-process visibility latency. The visibility target at the default period is no more than three seconds.
6. Treat permission-limited and unsupported native results as structured outcomes, not zero-duration or zero-value successes.

## Results

| Target | Fast period | Port period | Workload | Retained samples | Fast p95 | Port p95 | Enrichment p95 | Project p95 | New-process visibility | Status |
|---|---:|---:|---|---:|---:|---:|---:|---:|---:|---|
| Windows 11 x64 reference host | 2 s | 5 s | Not run | 0 | N/A | N/A | N/A | N/A | N/A | Pending authorized Runner measurement |
| macOS Intel | 2 s | 5 s | Not run | 0 | N/A | N/A | N/A | N/A | N/A | Pending macOS Runner measurement |
| macOS Apple Silicon | 2 s | 5 s | Not run | 0 | N/A | N/A | N/A | N/A | N/A | Pending macOS Runner measurement |

## Acceptance Boundary

Formatting and compilation can verify bounded storage, percentile semantics, request limits, and snapshot privacy. They cannot satisfy the plan's real p95 or visibility-latency acceptance criterion. That criterion remains pending until an authorized run records actual samples on the named target.
