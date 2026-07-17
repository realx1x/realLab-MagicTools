# ADR-0005: Operations Remain in the Current User and Session

- Status: Accepted
- Date: 2026-07-14
- Owners: Dev Process Manager maintainers

## Context

Development-process management does not require system-wide administrative control. Elevating the complete UI or Supervisor would magnify the impact of command, webview, IPC, and dependency vulnerabilities.

## Decision

The UI and Supervisor run unelevated for the current logged-in user and session. V1 does not enable `SeDebugPrivilege`, install a system service, bypass macOS protections, or operate on other users' processes. Permission failures are returned as `ACCESS_DENIED`, `AccessLimited`, or `NotSupported` and remain visible in the UI.

Runtime directories, database files, logs, sockets, lock files, and session tokens are restricted to the current user. Secrets are stored through Windows Credential Manager/DPAPI or macOS Keychain adapters; SQLite contains references only. No process, path, command, log, or usage telemetry is uploaded.

Any future elevation requires a separately designed, signed, minimal broker and a new ADR. It cannot be added as an implicit fallback.

## Consequences

- Some elevated, protected, or other-user process details and operations remain unavailable.
- Cross-platform capability states must distinguish access-limited from unsupported and unknown.
- Installation remains per user by default.

## Alternatives Considered

- Run the application as administrator/root: rejected as excessive and incompatible with the security boundary.
- Silently omit protected processes: rejected because users need an accurate permission state.

## Validation

Native adapters compile on their target runners; real permission behavior requires explicitly authorized target-system checks.
