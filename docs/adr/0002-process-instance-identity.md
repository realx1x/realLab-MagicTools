# ADR-0002: Process Identity Uses Boot ID, PID, and Native Start Time

- Status: Accepted
- Date: 2026-07-14
- Owners: Dev Process Manager maintainers

## Context

Operating systems reuse PIDs. A delayed stop, stale database row, or reconnect can otherwise address a different process than the one originally observed.

## Decision

Every actionable process is identified by `ProcessInstanceKey { boot_id, pid, native_start_time }`. PID alone is never sufficient for stop, update, recovery, parent association, or history correlation. Command fingerprints may support diagnostics but are not identity.

Immediately before every signal or destructive operation, the platform adapter re-reads native start time and compares the complete key. On Windows, it first opens a process handle, then validates and operates through that handle so lookup and action share the same kernel object. A mismatch returns `IDENTITY_MISMATCH` without sending a signal.

Unavailable identity data is represented as `Unknown`, `AccessLimited`, or `NotSupported`; zero and empty strings are not substitutes.

## Consequences

- Discovery must expose a stable boot identifier and native process creation time.
- Recovery can produce `Recovered`, `ExitedWhileOffline`, `IdentityMismatch`, or `Orphaned` without guessing.
- Processes whose identity cannot be verified cannot be stopped by the application.

## Alternatives Considered

- PID only: rejected because PID reuse creates an unacceptable wrong-process kill risk.
- PID plus command line: rejected because command lines can repeat and may be inaccessible.
- Executable path hash: rejected because multiple simultaneous instances remain ambiguous.

## Validation

Platform adapters must preserve the native start-time precision used during both discovery and pre-operation validation.
