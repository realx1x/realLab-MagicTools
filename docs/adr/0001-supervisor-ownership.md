# ADR-0001: The Per-User Supervisor Owns Managed Processes

- Status: Accepted
- Date: 2026-07-14
- Owners: Dev Process Manager maintainers

## Context

The desktop UI can be hidden, restarted, upgraded, or terminated independently of processes it launches. Tying child handles, job objects, process groups, log pipes, or database writes to the Tauri process would lose management authority when the window exits.

## Decision

A single independent Supervisor runs per logged-in user. It is the sole owner of managed process handles, Windows Job Objects, macOS process groups, log and PTY sessions, run state, revisions, and SQLite writes. The Tauri bridge is a validated RPC client and event forwarder only.

Closing the window hides it to the tray. A UI crash or restart does not terminate the Supervisor or managed processes. Explicit application exit with active runs offers keep running, stop all, or cancel. System logout or restart is not automatically recovered in V1; the next Supervisor reconciles persisted run records against complete process instance identities.

Supervisor replacement during upgrade requires an explicit handoff protocol. No process is adopted from a stale PID alone.

## Consequences

- UI availability is not part of managed-process lifetime.
- The Supervisor must enforce a per-user single-instance lock and authenticated IPC.
- SQLite has one writer, simplifying revision and migration ordering.
- An upgrade cannot replace a locked Supervisor binary without handling active runs and ownership transfer.

## Alternatives Considered

- Tauri owns children: rejected because UI exit or crash loses handles and logs.
- OS service or daemon: rejected because V1 is scoped to the current user and session.
- Re-adopt by PID: rejected because PID reuse can target an unrelated process.

## Validation

Platform spikes must compile the ownership primitives. Real lifecycle behavior is recorded separately and is not claimed by compilation alone.
