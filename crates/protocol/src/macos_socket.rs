use std::ffi::{CStr, OsStr};
use std::fmt::{self, Debug, Formatter};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr::null_mut;
use std::time::Duration;

use thiserror::Error;
use tokio::net::UnixStream;
use tokio::sync::watch;
use tokio::time::{sleep, timeout};

use crate::{
    AsyncProtocolError, AuthenticatedClientConnection, ConnectionState, DisconnectReason,
    SessionToken, TransportErrorKind, authenticate_client,
};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const INITIAL_RETRY_MS: u64 = 100;
const MAX_RETRY_MS: u64 = 5_000;

#[derive(Clone, Eq, PartialEq)]
pub struct MacOsSocketEndpoint(PathBuf);

impl MacOsSocketEndpoint {
    pub fn as_path(&self) -> &Path {
        &self.0
    }
}

impl Debug for MacOsSocketEndpoint {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("MacOsSocketEndpoint([REDACTED])")
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct CurrentMacOsIdentity {
    endpoint: MacOsSocketEndpoint,
    euid: libc::uid_t,
}

impl CurrentMacOsIdentity {
    pub fn for_current_process() -> Result<Self, MacOsIdentityError> {
        let euid = unsafe { libc::geteuid() };
        let home = current_user_home(euid).map_err(|source| MacOsIdentityError::Os {
            operation: "resolve the effective user's home directory",
            source,
        })?;
        let endpoint = MacOsSocketEndpoint(
            home.join("Library")
                .join("Application Support")
                .join("DevProcessManager")
                .join("runtime")
                .join("supervisor.sock"),
        );
        Ok(Self { endpoint, euid })
    }

    pub fn endpoint(&self) -> &MacOsSocketEndpoint {
        &self.endpoint
    }

    pub fn euid(&self) -> libc::uid_t {
        self.euid
    }
}

impl Debug for CurrentMacOsIdentity {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CurrentMacOsIdentity")
            .field("endpoint", &self.endpoint)
            .field("euid", &self.euid)
            .finish()
    }
}

#[derive(Debug, Error)]
pub enum MacOsIdentityError {
    #[error("{operation} failed")]
    Os {
        operation: &'static str,
        #[source]
        source: io::Error,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SocketConnectErrorKind {
    EndpointUnavailable,
    Other,
}

#[derive(Debug, Error)]
pub enum MacOsSocketClientError {
    #[error(transparent)]
    Identity(#[from] MacOsIdentityError),
    #[error("access to the Supervisor socket was denied")]
    AccessDenied { raw_os_error: Option<i32> },
    #[error("the Supervisor socket peer could not be inspected")]
    PeerInspection {
        raw_os_error: Option<i32>,
        #[source]
        source: io::Error,
    },
    #[error("the Supervisor socket belongs to another effective user")]
    PeerUserMismatch {
        expected: libc::uid_t,
        actual: libc::uid_t,
    },
    #[error("the Supervisor uses an incompatible protocol version")]
    IncompatibleVersion,
    #[error("the Supervisor handshake timed out")]
    HandshakeTimeout,
    #[error("the Supervisor handshake failed")]
    Handshake(#[source] AsyncProtocolError),
    #[error("connecting to the Supervisor socket failed ({kind:?})")]
    Connect {
        kind: SocketConnectErrorKind,
        raw_os_error: Option<i32>,
        #[source]
        source: io::Error,
    },
    #[error("the client is shutting down")]
    ShuttingDown,
    #[error("the connection generation counter was exhausted")]
    GenerationExhausted,
}

pub struct MacOsSocketClient {
    identity: CurrentMacOsIdentity,
    generation: u64,
    state_tx: watch::Sender<ConnectionState>,
}

impl MacOsSocketClient {
    pub fn for_current_process() -> Result<Self, MacOsIdentityError> {
        Ok(Self::new(CurrentMacOsIdentity::for_current_process()?))
    }

    pub fn new(identity: CurrentMacOsIdentity) -> Self {
        let (state_tx, _) = watch::channel(ConnectionState::Disconnected { reason: None });
        Self {
            identity,
            generation: 0,
            state_tx,
        }
    }

    pub fn endpoint(&self) -> &MacOsSocketEndpoint {
        self.identity.endpoint()
    }

    pub fn subscribe(&self) -> watch::Receiver<ConnectionState> {
        self.state_tx.subscribe()
    }

    pub fn state(&self) -> ConnectionState {
        self.state_tx.borrow().clone()
    }

    /// Connects and authenticates without replaying any business request.
    /// The generation is committed only after the complete handshake succeeds.
    pub async fn connect_authenticated(
        &mut self,
        token: SessionToken,
        shutdown: &mut watch::Receiver<bool>,
    ) -> Result<AuthenticatedClientConnection<UnixStream>, MacOsSocketClientError> {
        let mut attempt = 0_u32;
        loop {
            if shutdown_requested(shutdown) {
                self.set_state(ConnectionState::ShuttingDown);
                return Err(MacOsSocketClientError::ShuttingDown);
            }

            attempt = attempt.saturating_add(1);
            self.set_state(ConnectionState::Connecting { attempt });
            match UnixStream::connect(self.identity.endpoint().as_path()).await {
                Ok(stream) => {
                    let peer_uid = match peer_euid(&stream) {
                        Ok(peer_uid) => peer_uid,
                        Err(source) => {
                            let raw_os_error = source.raw_os_error();
                            self.set_state(ConnectionState::Disconnected {
                                reason: Some(DisconnectReason::Transport { raw_os_error }),
                            });
                            return Err(MacOsSocketClientError::PeerInspection {
                                raw_os_error,
                                source,
                            });
                        }
                    };
                    if peer_uid != self.identity.euid() {
                        self.set_state(ConnectionState::AccessDenied);
                        return Err(MacOsSocketClientError::PeerUserMismatch {
                            expected: self.identity.euid(),
                            actual: peer_uid,
                        });
                    }

                    self.set_state(ConnectionState::Authenticating);
                    let generation = self
                        .generation
                        .checked_add(1)
                        .ok_or(MacOsSocketClientError::GenerationExhausted)?;
                    let authentication = timeout(
                        HANDSHAKE_TIMEOUT,
                        authenticate_client(stream, token.clone(), generation),
                    )
                    .await;
                    let connection = match authentication {
                        Err(_) => {
                            self.set_state(ConnectionState::Disconnected {
                                reason: Some(DisconnectReason::HandshakeTimeout),
                            });
                            return Err(MacOsSocketClientError::HandshakeTimeout);
                        }
                        Ok(Err(error)) if error.is_incompatible_version() => {
                            self.set_state(ConnectionState::IncompatibleVersion);
                            return Err(MacOsSocketClientError::IncompatibleVersion);
                        }
                        Ok(Err(error)) => {
                            let reason = handshake_disconnect_reason(&error);
                            self.set_state(ConnectionState::Disconnected {
                                reason: Some(reason),
                            });
                            return Err(MacOsSocketClientError::Handshake(error));
                        }
                        Ok(Ok(connection)) => connection,
                    };
                    self.generation = generation;
                    self.set_state(ConnectionState::Connected {
                        version: connection.protocol_version(),
                        generation,
                    });
                    return Ok(connection);
                }
                Err(source) => {
                    let raw_os_error = source.raw_os_error();
                    if is_access_denied(&source) {
                        self.set_state(ConnectionState::AccessDenied);
                        return Err(MacOsSocketClientError::AccessDenied { raw_os_error });
                    }
                    let kind = classify_connect_error(&source);
                    if kind == SocketConnectErrorKind::Other {
                        self.set_state(ConnectionState::Disconnected {
                            reason: Some(DisconnectReason::Transport { raw_os_error }),
                        });
                        return Err(MacOsSocketClientError::Connect {
                            kind,
                            raw_os_error,
                            source,
                        });
                    }

                    self.set_state(ConnectionState::Disconnected {
                        reason: Some(DisconnectReason::EndpointUnavailable),
                    });
                    let retry_after_ms = retry_delay_ms(attempt);
                    self.set_state(ConnectionState::Backoff {
                        attempt,
                        retry_after_ms,
                    });
                    tokio::select! {
                        _ = sleep(Duration::from_millis(retry_after_ms)) => {}
                        changed = shutdown.changed() => {
                            if changed.is_err() || shutdown_requested(shutdown) {
                                self.set_state(ConnectionState::ShuttingDown);
                                return Err(MacOsSocketClientError::ShuttingDown);
                            }
                        }
                    }
                }
            }
        }
    }

    pub fn record_disconnected(&self, reason: DisconnectReason) {
        self.set_state(ConnectionState::Disconnected {
            reason: Some(reason),
        });
    }

    pub fn mark_shutting_down(&self) {
        self.set_state(ConnectionState::ShuttingDown);
    }

    fn set_state(&self, state: ConnectionState) {
        self.state_tx.send_replace(state);
    }
}

fn current_user_home(euid: libc::uid_t) -> io::Result<PathBuf> {
    const FALLBACK_BUFFER_BYTES: usize = 16 * 1024;
    const MAX_BUFFER_BYTES: usize = 1024 * 1024;

    let configured = unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
    let mut buffer_len = if configured > 0 {
        usize::try_from(configured)
            .unwrap_or(MAX_BUFFER_BYTES)
            .clamp(1, MAX_BUFFER_BYTES)
    } else {
        FALLBACK_BUFFER_BYTES
    };

    loop {
        let mut buffer = vec![0_u8; buffer_len];
        let mut entry = unsafe { std::mem::zeroed::<libc::passwd>() };
        let mut result = null_mut::<libc::passwd>();
        let status = unsafe {
            libc::getpwuid_r(
                euid,
                &mut entry,
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut result,
            )
        };
        if status == libc::ERANGE && buffer_len < MAX_BUFFER_BYTES {
            buffer_len = buffer_len.saturating_mul(2).min(MAX_BUFFER_BYTES);
            continue;
        }
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status));
        }
        if result.is_null() || entry.pw_dir.is_null() || entry.pw_uid != euid {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "the effective user's home directory is unavailable",
            ));
        }

        let home = PathBuf::from(OsStr::from_bytes(
            unsafe { CStr::from_ptr(entry.pw_dir) }.to_bytes(),
        ));
        if !home.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the effective user's home directory is not absolute",
            ));
        }
        return Ok(home);
    }
}

fn peer_euid(stream: &UnixStream) -> io::Result<libc::uid_t> {
    let mut euid = 0;
    let mut egid = 0;
    if unsafe { libc::getpeereid(stream.as_raw_fd(), &mut euid, &mut egid) } == 0 {
        Ok(euid)
    } else {
        Err(io::Error::last_os_error())
    }
}

fn handshake_disconnect_reason(error: &AsyncProtocolError) -> DisconnectReason {
    if error.is_authentication_failure() {
        return DisconnectReason::AuthenticationFailed;
    }
    match error.transport_kind() {
        Some(TransportErrorKind::PeerClosed) => DisconnectReason::PeerClosed,
        Some(_) => DisconnectReason::Transport {
            raw_os_error: match error {
                AsyncProtocolError::Transport { raw_os_error, .. } => *raw_os_error,
                AsyncProtocolError::Protocol(_) => None,
            },
        },
        None => DisconnectReason::ProtocolViolation,
    }
}

fn classify_connect_error(error: &io::Error) -> SocketConnectErrorKind {
    match error.raw_os_error() {
        Some(libc::ENOENT | libc::ECONNREFUSED) => SocketConnectErrorKind::EndpointUnavailable,
        _ if matches!(
            error.kind(),
            io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
        ) =>
        {
            SocketConnectErrorKind::EndpointUnavailable
        }
        _ => SocketConnectErrorKind::Other,
    }
}

fn is_access_denied(error: &io::Error) -> bool {
    matches!(error.raw_os_error(), Some(libc::EACCES | libc::EPERM))
        || error.kind() == io::ErrorKind::PermissionDenied
}

fn retry_delay_ms(attempt: u32) -> u64 {
    let shift = attempt.saturating_sub(1).min(6);
    INITIAL_RETRY_MS
        .saturating_mul(1_u64 << shift)
        .min(MAX_RETRY_MS)
}

fn shutdown_requested(shutdown: &watch::Receiver<bool>) -> bool {
    *shutdown.borrow()
}
