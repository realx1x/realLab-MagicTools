# Authenticated Local IPC Security Spike

- Task ID: P0-T04
- Platforms: Windows 10/11 x64; macOS 13 Intel and Apple Silicon
- Date: 2026-07-14
- Status: Compiled on Windows x64; macOS Runner pending

## Security Layers

The endpoint and protocol use independent controls. Endpoint ACLs prevent other local users from opening the transport. A random token and challenge/response reject a caller that does not possess the token and prevent the token from being transmitted over the pipe. Protocol negotiation prevents a UI and Supervisor with incompatible message semantics from continuing. Because the token file is readable by the same SID, these controls do not claim isolation from malicious code already running as that user.

## Windows Named Pipe

The spike reads `TokenUser` from the current process token, converts that exact SID to SDDL, and creates an overlapped message-mode Named Pipe with a protected DACL granting generic-all only to that SID. The handle is non-inheritable, rejects remote clients, has bounded 64 KiB transport buffers, and accepts a validated application-specific name. It does not depend on a permissive default ACL.

P2 wraps the owned overlapped handle in the asynchronous adapter and adds connect/disconnect state. The production byte-mode pipe uses a stable SID-and-session endpoint, verifies the connected client's session before authentication, and scopes the Windows runtime/token directory to that session. A production token file uses the same current-user-only DACL; the session token is never placed in the pipe name or logs.

## macOS Unix Socket

The spike rejects a symlink runtime directory, creates or restricts it to `0700`, accepts one normal socket-name component, and binds a Unix Domain Socket with mode `0600`. Stale cleanup only removes a path whose `symlink_metadata` identifies it as a Unix socket. A regular file, directory, or symlink is rejected rather than deleted.

## Handshake and Framing

Each Supervisor start creates a 256-bit random token with the operating system RNG and stores it in a current-user-only token file. The client offers at most 16 protocol versions and a random 256-bit nonce. The server chooses the highest compatible version, adds its own nonce, and proves token possession with HMAC-SHA-256 over a domain-separated transcript. The client verifies it and returns a separate role-bound proof. The token itself is never transmitted, serialized, logged, or included in `Debug` output.

Business RPC is rejected until both proofs succeed. Requests carry protocol version, request ID, optional operation ID, timeout, method, and params. Messages are Serde JSON inside a four-byte big-endian length prefix with a 1 MiB business-frame limit; the production adapter applies a smaller 16 KiB limit before authentication. Truncation, trailing bytes, invalid JSON, oversized frames, failed proof, and incompatible versions fail closed; newline framing is not used.

## Failure and Compatibility Behavior

| Condition | Result |
|---|---|
| Other Windows user | Named Pipe DACL denies open |
| Other macOS user | private directory and socket mode deny open |
| Same-user caller without token | challenge proof fails before RPC |
| Replayed proof with new nonce | transcript differs and verification fails |
| No common protocol version | explicit incompatible-version failure |
| Oversized or malformed frame | connection-level protocol error before dispatch |
| Stale non-socket path | cleanup is refused |

Compilation proves API and framing types, not the real denial behavior of another OS account. Cross-user connection, token file ACL/mode, replay, and filesystem race scenarios require explicitly authorized target-system validation.

The Windows x64 crate passed `cargo fmt --check` and `cargo check`. The macOS Unix Socket module remains pending compilation on Intel and Apple Silicon runners; neither platform has been marked real-system validated.
