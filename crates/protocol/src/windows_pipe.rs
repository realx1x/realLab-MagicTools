use std::ffi::{OsStr, OsString, c_void};
use std::fmt::{self, Debug, Formatter};
use std::io;
use std::mem::size_of;
use std::os::windows::ffi::OsStringExt;
use std::time::Duration;

use thiserror::Error;
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient, PipeMode};
use tokio::sync::watch;
use tokio::time::{sleep, timeout};
use windows::Win32::Foundation::{
    CloseHandle, ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, ERROR_PIPE_BUSY,
    HANDLE, HLOCAL, LocalFree,
};
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::Security::{GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser};
use windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows::Win32::System::Threading::{GetCurrentProcess, GetCurrentProcessId, OpenProcessToken};
use windows::core::{Error as WindowsError, PWSTR};

use crate::{
    AsyncProtocolError, AuthenticatedClientConnection, ConnectionState, DisconnectReason,
    SessionToken, TransportErrorKind, authenticate_client,
};

const PIPE_PREFIX: &str = r"\\.\pipe\com.local.devprocessmanager.supervisor";
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const INITIAL_RETRY_MS: u64 = 100;
const MAX_RETRY_MS: u64 = 5_000;

#[derive(Clone, Eq, PartialEq)]
pub struct WindowsPipeEndpoint(OsString);

impl WindowsPipeEndpoint {
    pub fn as_os_str(&self) -> &OsStr {
        &self.0
    }
}

impl Debug for WindowsPipeEndpoint {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("WindowsPipeEndpoint([REDACTED])")
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct CurrentWindowsIdentity {
    endpoint: WindowsPipeEndpoint,
    sid: String,
    session_id: u32,
}

impl CurrentWindowsIdentity {
    pub fn for_current_process() -> Result<Self, WindowsIdentityError> {
        let sid = current_user_sid_string()?;
        if sid.is_empty()
            || sid.len() > 184
            || !sid
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(WindowsIdentityError::InvalidSid);
        }

        let mut session_id = 0_u32;
        unsafe { ProcessIdToSessionId(GetCurrentProcessId(), &mut session_id) }.map_err(
            |source| WindowsIdentityError::Windows {
                operation: "resolve current process session",
                source,
            },
        )?;
        let endpoint =
            WindowsPipeEndpoint(format!("{PIPE_PREFIX}.{sid}.session-{session_id}").into());
        Ok(Self {
            endpoint,
            sid,
            session_id,
        })
    }

    pub fn endpoint(&self) -> &WindowsPipeEndpoint {
        &self.endpoint
    }

    pub fn sid_sddl_fragment(&self) -> &str {
        &self.sid
    }

    pub fn session_id(&self) -> u32 {
        self.session_id
    }
}

impl Debug for CurrentWindowsIdentity {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CurrentWindowsIdentity")
            .field("endpoint", &self.endpoint)
            .field("sid", &"[REDACTED]")
            .field("session_id", &self.session_id)
            .finish()
    }
}

#[derive(Debug, Error)]
pub enum WindowsIdentityError {
    #[error("the current Windows user SID is invalid")]
    InvalidSid,
    #[error("{operation} failed")]
    Windows {
        operation: &'static str,
        #[source]
        source: WindowsError,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PipeOpenErrorKind {
    EndpointUnavailable,
    Busy,
    Other,
}

#[derive(Debug, Error)]
pub enum WindowsPipeClientError {
    #[error(transparent)]
    Identity(#[from] WindowsIdentityError),
    #[error("access to the Supervisor pipe was denied")]
    AccessDenied { raw_os_error: Option<i32> },
    #[error("the Supervisor uses an incompatible protocol version")]
    IncompatibleVersion,
    #[error("the Supervisor handshake timed out")]
    HandshakeTimeout,
    #[error("the Supervisor handshake failed")]
    Handshake(#[source] AsyncProtocolError),
    #[error("opening the Supervisor pipe failed ({kind:?})")]
    Open {
        kind: PipeOpenErrorKind,
        raw_os_error: Option<i32>,
        #[source]
        source: io::Error,
    },
    #[error("the client is shutting down")]
    ShuttingDown,
    #[error("the connection generation counter was exhausted")]
    GenerationExhausted,
}

pub struct WindowsPipeClient {
    endpoint: WindowsPipeEndpoint,
    generation: u64,
    state_tx: watch::Sender<ConnectionState>,
}

impl WindowsPipeClient {
    pub fn for_current_process() -> Result<Self, WindowsIdentityError> {
        let identity = CurrentWindowsIdentity::for_current_process()?;
        Ok(Self::new(identity.endpoint().clone()))
    }

    pub fn new(endpoint: WindowsPipeEndpoint) -> Self {
        let (state_tx, _) = watch::channel(ConnectionState::Disconnected { reason: None });
        Self {
            endpoint,
            generation: 0,
            state_tx,
        }
    }

    pub fn subscribe(&self) -> watch::Receiver<ConnectionState> {
        self.state_tx.subscribe()
    }

    pub fn state(&self) -> ConnectionState {
        self.state_tx.borrow().clone()
    }

    /// Opens and authenticates one connection. Reusing this connector after a
    /// disconnect increments the generation; no business request is replayed.
    pub async fn connect_authenticated(
        &mut self,
        token: SessionToken,
        shutdown: &mut watch::Receiver<bool>,
    ) -> Result<AuthenticatedClientConnection<NamedPipeClient>, WindowsPipeClientError> {
        let mut attempt = 0_u32;
        loop {
            if shutdown_requested(shutdown) {
                self.set_state(ConnectionState::ShuttingDown);
                return Err(WindowsPipeClientError::ShuttingDown);
            }

            attempt = attempt.saturating_add(1);
            self.set_state(ConnectionState::Connecting { attempt });
            match ClientOptions::new()
                .pipe_mode(PipeMode::Byte)
                .open(self.endpoint.as_os_str())
            {
                Ok(client) => {
                    self.set_state(ConnectionState::Authenticating);
                    let generation = self
                        .generation
                        .checked_add(1)
                        .ok_or(WindowsPipeClientError::GenerationExhausted)?;
                    let authentication = timeout(
                        HANDSHAKE_TIMEOUT,
                        authenticate_client(client, token.clone(), generation),
                    )
                    .await;
                    let connection = match authentication {
                        Err(_) => {
                            self.set_state(ConnectionState::Disconnected {
                                reason: Some(DisconnectReason::HandshakeTimeout),
                            });
                            return Err(WindowsPipeClientError::HandshakeTimeout);
                        }
                        Ok(Err(error)) if error.is_incompatible_version() => {
                            self.set_state(ConnectionState::IncompatibleVersion);
                            return Err(WindowsPipeClientError::IncompatibleVersion);
                        }
                        Ok(Err(error)) => {
                            let reason = handshake_disconnect_reason(&error);
                            self.set_state(ConnectionState::Disconnected {
                                reason: Some(reason),
                            });
                            return Err(WindowsPipeClientError::Handshake(error));
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
                    let kind = classify_open_error(&source);
                    if raw_os_error == Some(ERROR_ACCESS_DENIED.0 as i32) {
                        self.set_state(ConnectionState::AccessDenied);
                        return Err(WindowsPipeClientError::AccessDenied { raw_os_error });
                    }
                    let reason = match kind {
                        PipeOpenErrorKind::EndpointUnavailable => {
                            DisconnectReason::EndpointUnavailable
                        }
                        PipeOpenErrorKind::Busy => DisconnectReason::PipeBusy,
                        PipeOpenErrorKind::Other => {
                            self.set_state(ConnectionState::Disconnected {
                                reason: Some(DisconnectReason::Transport { raw_os_error }),
                            });
                            return Err(WindowsPipeClientError::Open {
                                kind,
                                raw_os_error,
                                source,
                            });
                        }
                    };
                    self.set_state(ConnectionState::Disconnected {
                        reason: Some(reason),
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
                                return Err(WindowsPipeClientError::ShuttingDown);
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

fn classify_open_error(error: &io::Error) -> PipeOpenErrorKind {
    match error.raw_os_error() {
        Some(code)
            if code == ERROR_FILE_NOT_FOUND.0 as i32 || code == ERROR_PATH_NOT_FOUND.0 as i32 =>
        {
            PipeOpenErrorKind::EndpointUnavailable
        }
        Some(code) if code == ERROR_PIPE_BUSY.0 as i32 => PipeOpenErrorKind::Busy,
        _ if error.kind() == io::ErrorKind::NotFound => PipeOpenErrorKind::EndpointUnavailable,
        _ => PipeOpenErrorKind::Other,
    }
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

fn current_user_sid_string() -> Result<String, WindowsIdentityError> {
    let mut token = HANDLE::default();
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }.map_err(
        |source| WindowsIdentityError::Windows {
            operation: "open current process token",
            source,
        },
    )?;
    let token = OwnedHandle(token);

    let mut required = 0_u32;
    let _ = unsafe { GetTokenInformation(token.0, TokenUser, None, 0, &mut required) };
    if required < size_of::<TOKEN_USER>() as u32 {
        return Err(WindowsIdentityError::Windows {
            operation: "size current user SID",
            source: WindowsError::from_win32(),
        });
    }
    let words = (required as usize).div_ceil(size_of::<usize>());
    let mut buffer = vec![0_usize; words];
    unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            Some(buffer.as_mut_ptr().cast()),
            required,
            &mut required,
        )
    }
    .map_err(|source| WindowsIdentityError::Windows {
        operation: "read current user SID",
        source,
    })?;
    let token_user = unsafe { &*(buffer.as_ptr().cast::<TOKEN_USER>()) };

    let mut sid_text = PWSTR::null();
    unsafe { ConvertSidToStringSidW(token_user.User.Sid, &mut sid_text) }.map_err(|source| {
        WindowsIdentityError::Windows {
            operation: "format current user SID",
            source,
        }
    })?;
    let sid_text = LocalWideString(sid_text);
    let wide = unsafe { sid_text.0.as_wide() };
    OsString::from_wide(wide)
        .into_string()
        .map_err(|_| WindowsIdentityError::InvalidSid)
}

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        let _ = unsafe { CloseHandle(self.0) };
    }
}

struct LocalWideString(PWSTR);

impl Drop for LocalWideString {
    fn drop(&mut self) {
        unsafe { LocalFree(Some(HLOCAL(self.0.0.cast::<c_void>()))) };
    }
}
