# System Boundaries

Dev Process Manager consists of a React UI, a minimal Tauri bridge, and an independent per-user Rust Supervisor.

```text
React UI
  -> validated Tauri commands and events
Tauri Bridge
  -> authenticated, versioned local RPC
Per-user Supervisor
  -> discovery, lifecycle, logging, recovery, SQLite
Platform adapters
  -> Windows and macOS native APIs
```

The UI owns presentation and user confirmation, not process state. The bridge validates and forwards but does not write SQLite or hold a child process, PTY, or platform control object. The Supervisor is the sole source of truth and sole database writer. Platform adapters translate native behavior into shared domain states without embedding classification or UI policy.

The accepted boundaries are defined by ADR-0001 through ADR-0005. Platform spikes must use [platform-spike-template.md](platform-spike-template.md) and must distinguish compiled evidence from real-system validation.
