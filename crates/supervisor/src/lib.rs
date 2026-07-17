//! Per-user Supervisor runtime ownership and local security boundaries.

#[cfg(not(any(windows, target_os = "macos")))]
compile_error!("the Supervisor runtime supports only Windows and macOS");

#[cfg(any(windows, target_os = "macos"))]
mod catalog_rpc;
#[cfg(any(windows, target_os = "macos"))]
mod diagnostics;
#[cfg(any(windows, target_os = "macos"))]
mod diagnostics_rpc;
#[cfg(any(windows, target_os = "macos"))]
mod enrichment_rpc;
#[cfg(any(windows, target_os = "macos"))]
mod exit_rpc;
#[cfg(any(windows, target_os = "macos"))]
mod external_stop;
#[cfg(any(windows, target_os = "macos"))]
mod history_rpc;
#[cfg(any(windows, target_os = "macos"))]
mod log_rpc;
#[cfg(target_os = "macos")]
mod macos_unix_socket;
#[cfg(any(windows, target_os = "macos"))]
mod managed_runs;
mod platform;
mod profile_credentials;
#[cfg(any(windows, target_os = "macos"))]
mod profile_rpc;
mod revision;
#[cfg(any(windows, target_os = "macos"))]
mod stop_rpc;
#[cfg(windows)]
mod windows_named_pipe;

#[cfg(any(windows, target_os = "macos"))]
pub use catalog_rpc::{CatalogRpcDispatch, CatalogRpcDispatcher, CatalogRpcResponse};
#[cfg(any(windows, target_os = "macos"))]
pub use diagnostics::{DiagnosticsService, SharedApplicationLogBuffer};
#[cfg(any(windows, target_os = "macos"))]
pub use diagnostics_rpc::{
    DiagnosticsRpcDispatch, DiagnosticsRpcDispatcher, DiagnosticsRpcResponse,
};
#[cfg(any(windows, target_os = "macos"))]
pub use enrichment_rpc::{EnrichmentRpcDispatch, EnrichmentRpcDispatcher, EnrichmentRpcResponse};
#[cfg(any(windows, target_os = "macos"))]
pub use exit_rpc::{ExitRpcDispatch, ExitRpcDispatcher, ExitRpcResponse};
#[cfg(any(windows, target_os = "macos"))]
pub use external_stop::ExternalProcessStopService;
#[cfg(any(windows, target_os = "macos"))]
pub use history_rpc::{HistoryRpcDispatch, HistoryRpcDispatcher, HistoryRpcResponse};
#[cfg(any(windows, target_os = "macos"))]
pub use log_rpc::{LogRpcDispatch, LogRpcDispatcher, LogRpcResponse};
#[cfg(target_os = "macos")]
pub use macos_unix_socket::{
    AuthenticatedServerSocket, MacOsSocketServerError, MacOsUnixSocketListener,
};
#[cfg(any(windows, target_os = "macos"))]
pub use managed_runs::ManagedRunService;
pub use profile_credentials::{CredentialCleanupStatus, ProfileMutation, ProfileService};
#[cfg(any(windows, target_os = "macos"))]
pub use profile_rpc::{ProfileRpcDispatch, ProfileRpcDispatcher, ProfileRpcResponse};
pub use revision::{
    MAX_REVISION_DELTA_ENTITIES, MAX_REVISION_DELTA_PAYLOAD_BYTES, MAX_SNAPSHOT_CHUNK_ENTITIES,
    MAX_SNAPSHOT_CHUNK_PAYLOAD_BYTES, MAX_SNAPSHOT_CURSOR_BYTES, ManagedLogPublisher,
    REVISION_EVENT_CAPACITY, RevisionChange, RevisionEvent, RevisionEventPayload, RevisionState,
    RevisionStreamError, RevisionSubscription,
};
#[cfg(any(windows, target_os = "macos"))]
pub use stop_rpc::{StopRpcDispatch, StopRpcDispatcher, StopRpcResponse};
#[cfg(windows)]
pub use windows_named_pipe::{
    AuthenticatedServerPipe, WindowsNamedPipeListener, WindowsPipeServerError,
};

use std::fmt::{self, Debug, Formatter};
use std::fs::{File, TryLockError};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use domain::{AppError, ErrorCode};
use protocol::{
    AuthenticatedClientMessage, AuthenticatedClientMessageKind, CancelEnvelope, RequestEnvelope,
};
const SESSION_TOKEN_LENGTH: usize = 32;

/// An opaque process identity captured from an authenticated local transport.
///
/// The private field and constructor prevent request payloads or callers from
/// manufacturing the desktop process protection boundary.
struct AuthenticatedPeerProcessId {
    process_id: u32,
}

impl AuthenticatedPeerProcessId {
    fn from_transport(process_id: u32) -> Option<Self> {
        (process_id != 0 && process_id != std::process::id()).then_some(Self { process_id })
    }

    fn get(&self) -> u32 {
        self.process_id
    }
}

/// A validated client message that remains inseparably bound to the local
/// transport peer from which it was read.
pub struct AuthenticatedPeerMessage<'peer> {
    message: AuthenticatedClientMessage,
    peer_process_id: &'peer AuthenticatedPeerProcessId,
}

impl Debug for AuthenticatedPeerMessage<'_> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        self.message.fmt(formatter)
    }
}

impl<'peer> AuthenticatedPeerMessage<'peer> {
    fn bind(
        message: AuthenticatedClientMessage,
        peer_process_id: &'peer AuthenticatedPeerProcessId,
    ) -> Self {
        Self {
            message,
            peer_process_id,
        }
    }

    pub fn kind(&self) -> AuthenticatedClientMessageKind {
        self.message.kind()
    }

    pub fn request(&self) -> Option<AuthenticatedPeerRequest<'_>> {
        self.message
            .request()
            .map(|request| AuthenticatedPeerRequest {
                request,
                peer_process_id: self.peer_process_id,
            })
    }

    pub fn cancel(&self) -> Option<&CancelEnvelope> {
        self.message.cancel()
    }
}

/// A request and the authenticated transport peer that sent it. The private
/// fields prevent dispatch code from combining one connection's request with
/// another connection's process identity.
pub struct AuthenticatedPeerRequest<'message> {
    request: &'message RequestEnvelope,
    peer_process_id: &'message AuthenticatedPeerProcessId,
}

impl Debug for AuthenticatedPeerRequest<'_> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        self.request.fmt(formatter)
    }
}

impl AuthenticatedPeerRequest<'_> {
    pub fn envelope(&self) -> &RequestEnvelope {
        self.request
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimePaths {
    root: PathBuf,
    lock_file: PathBuf,
    session_token_file: PathBuf,
}

impl RuntimePaths {
    pub fn for_current_user() -> Result<Self, AppError> {
        let root = platform::current_user_runtime_root()
            .map_err(|error| io_app_error("resolve current-user runtime directory", None, error))?;
        Ok(Self::from_root(root))
    }

    fn from_root(root: PathBuf) -> Self {
        Self {
            lock_file: root.join("supervisor.lock"),
            session_token_file: root.join("session.token"),
            root,
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn lock_file(&self) -> &Path {
        &self.lock_file
    }

    pub fn session_token_file(&self) -> &Path {
        &self.session_token_file
    }

    fn prepare(&self) -> Result<(), AppError> {
        platform::prepare_runtime_directory(&self.root).map_err(|error| {
            io_app_error(
                "prepare private Supervisor runtime directory",
                Some(&self.root),
                error,
            )
        })
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct SessionToken([u8; SESSION_TOKEN_LENGTH]);

impl SessionToken {
    pub fn as_bytes(&self) -> &[u8; SESSION_TOKEN_LENGTH] {
        &self.0
    }

    fn generate() -> Result<Self, AppError> {
        let mut bytes = [0_u8; SESSION_TOKEN_LENGTH];
        getrandom::fill(&mut bytes).map_err(|error| {
            let mut app_error = AppError::new(
                ErrorCode::PlatformError,
                "failed to generate the Supervisor session token",
            );
            app_error
                .details
                .insert("operation".into(), "generate session token".into());
            app_error.details.insert("source".into(), error.to_string());
            app_error
        })?;
        Ok(Self(bytes))
    }
}

impl Debug for SessionToken {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionToken([REDACTED; 32])")
    }
}

pub struct SupervisorInstanceGuard {
    paths: RuntimePaths,
    lock_file: File,
    session_token: SessionToken,
}

impl SupervisorInstanceGuard {
    pub fn acquire(paths: RuntimePaths) -> Result<Self, AppError> {
        paths.prepare()?;

        let lock_file = platform::open_private_file(&paths.lock_file, false).map_err(|error| {
            io_app_error(
                "open Supervisor instance lock",
                Some(&paths.lock_file),
                error,
            )
        })?;

        match lock_file.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => {
                return Err(instance_conflict_error(&paths.lock_file));
            }
            Err(TryLockError::Error(error)) => {
                return Err(io_app_error(
                    "lock Supervisor instance file",
                    Some(&paths.lock_file),
                    error,
                ));
            }
        }

        let session_token = SessionToken::generate()?;
        write_session_token(&paths.session_token_file, &session_token)?;

        Ok(Self {
            paths,
            lock_file,
            session_token,
        })
    }

    pub fn paths(&self) -> &RuntimePaths {
        &self.paths
    }

    pub fn session_token(&self) -> &SessionToken {
        &self.session_token
    }
}

impl Drop for SupervisorInstanceGuard {
    fn drop(&mut self) {
        // Remove the token while the lock is still held so a successor cannot
        // create a new token that this instance then deletes.
        let _ = std::fs::remove_file(&self.paths.session_token_file);
        let _ = self.lock_file.unlock();
    }
}

fn write_session_token(path: &Path, token: &SessionToken) -> Result<(), AppError> {
    let temporary = path.with_extension("token.new");
    match std::fs::remove_file(&temporary) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(io_app_error(
                "remove stale session token temporary file",
                Some(&temporary),
                error,
            ));
        }
    }

    let result = (|| {
        let mut file = platform::open_private_file(&temporary, true).map_err(|error| {
            io_app_error("open session token temporary file", Some(&temporary), error)
        })?;
        file.write_all(token.as_bytes()).map_err(|error| {
            io_app_error(
                "write session token temporary file",
                Some(&temporary),
                error,
            )
        })?;
        file.sync_all().map_err(|error| {
            io_app_error(
                "flush session token temporary file",
                Some(&temporary),
                error,
            )
        })?;
        drop(file);
        platform::atomic_replace(&temporary, path)
            .map_err(|error| io_app_error("publish session token file", Some(path), error))
    })();

    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

fn instance_conflict_error(path: &Path) -> AppError {
    let mut error = AppError::new(
        ErrorCode::Conflict,
        "another Supervisor instance already holds the current-user lock",
    );
    error.retryable = true;
    error
        .details
        .insert("operation".into(), "acquire instance lock".into());
    error
        .details
        .insert("path".into(), path.display().to_string());
    error
}

fn io_app_error(operation: &'static str, path: Option<&Path>, source: io::Error) -> AppError {
    let code = if source.kind() == io::ErrorKind::PermissionDenied {
        ErrorCode::AccessDenied
    } else {
        ErrorCode::PlatformError
    };
    let mut error = AppError::new(code, format!("{operation} failed"));
    error.retryable = matches!(
        source.kind(),
        io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
    );
    error.details.insert("operation".into(), operation.into());
    error
        .details
        .insert("ioKind".into(), format!("{:?}", source.kind()));
    error.details.insert("source".into(), source.to_string());
    if let Some(path) = path {
        error
            .details
            .insert("path".into(), path.display().to_string());
    }
    error
}
