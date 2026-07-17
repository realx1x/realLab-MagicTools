# Architecture Decision Records

Architecture decisions are immutable records. Superseded decisions remain in this directory and point to the replacing ADR.

| ADR | Decision | Status |
|---|---|---|
| [0001](0001-supervisor-ownership.md) | The per-user Supervisor owns managed processes | Accepted |
| [0002](0002-process-instance-identity.md) | Process identity uses boot ID, PID, and native start time | Accepted |
| [0003](0003-secure-versioned-local-ipc.md) | Local IPC is authenticated and versioned | Accepted |
| [0004](0004-managed-and-external-stop-semantics.md) | Managed and external stop semantics remain separate | Accepted |
| [0005](0005-current-user-permission-scope.md) | Operations remain in the current user and session | Accepted |

Use [0000-adr-template.md](0000-adr-template.md) for new decisions. A decision that changes one of these accepted constraints must first supersede the relevant ADR and update the implementation plan.
