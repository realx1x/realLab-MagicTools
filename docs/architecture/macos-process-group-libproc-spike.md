# macOS Process Group and libproc Spike

- Task ID: P0-T03
- Platform: macOS 13+, Intel and Apple Silicon
- Toolchain: Rust stable, `libc = 0.2.186`, `nix = 0.31.3`
- Date: 2026-07-14
- Status: Implemented; macOS target compilation pending

## Question

Determine the control boundary provided by an application-created process group and the visibility and permission behavior of `libproc` process and socket discovery.

## Experiment

The isolated `experiments/macos-process-group` crate contains only macOS code. A `pre_exec` hook calls the async-signal-safe `setpgid(0, 0)` before `exec`. The parent verifies that PGID equals the child PID and captures native start seconds and microseconds through `proc_pidinfo(PROC_PIDTBSDINFO)`.

Graceful and force stop use `SIGTERM` and `SIGKILL` through `killpg`. Before either signal, the implementation re-reads native start time and PGID. An identity or group mismatch fails closed. Cleanup after a failed post-spawn verification uses the newly created `Child` handle and waits for it; it does not walk a PID tree.

Process discovery uses `proc_pidinfo`. Socket discovery first retrieves bounded `proc_fdinfo` entries and only calls `proc_pidfdinfo(PROC_PIDFDSOCKETINFO)` for socket descriptors. The spike limits an FD scan to 16,384 entries and each native socket result to 4 KiB; production must additionally apply a semaphore, cache results, and scan only selected or classification-candidate processes.

## Control Boundary

- A process remaining in the Supervisor-created PGID can receive group `SIGTERM` and `SIGKILL`.
- A child that daemonizes, calls `setsid`, or changes its process group has left that boundary and is reported as `Orphaned` or not fully managed.
- No recursive PID traversal is used to pretend that an escaped descendant remains controlled.
- PID/PGID alone is insufficient: native start time is revalidated immediately before signaling.

## Permission and Failure Behavior

| Condition | Structured result |
|---|---|
| SIP, protected process, or insufficient access (`EPERM`/`EACCES`) | `AccessLimited` |
| Process disappears during scan (`ESRCH`) | `NotFound` for that process, not a failed global scan |
| Native structure is shorter than required | `ShortRead`, treated as a platform incompatibility |
| Native start time changes | `IdentityMismatch`; no signal is sent |
| PGID changes | `ProcessGroupChanged`; no group signal is sent |
| `setpgid` fails before exec | Spawn fails and user code is not executed |
| Post-spawn identity/PGID capture fails | The owned child is terminated and waited |

## Current Conclusion

The design has a concrete process-group ownership boundary and a separate, permission-aware discovery path. `libproc` visibility does not establish lifecycle ownership. High-cost FD scanning must remain delayed, cached, bounded, and concurrency limited.

This Windows host has no macOS Rust target or macOS native SDK, and the plan requires a corresponding macOS Runner. The crate therefore has not been marked compiled or real-system validated. Non-macOS builds fail explicitly rather than exposing a placeholder implementation.

## Remaining Validation

- `cargo check` on macOS 13 Intel and Apple Silicon runners.
- Real `SIGTERM`/timeout/`SIGKILL` behavior and simultaneous child exit.
- `setsid`, daemonization, and explicit PGID escape behavior.
- SIP-protected process, other-user process, and rapidly closing FD behavior.
- IPv4/IPv6 TCP/UDP socket structure conversion on both architectures.
