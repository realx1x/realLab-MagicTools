use std::ffi::{OsStr, c_void};
use std::fmt::{self, Debug, Formatter};
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::AsRawHandle;
use std::sync::Arc;
use std::time::Duration;

use domain::{AppError, Revision};
use protocol::windows_pipe::{CurrentWindowsIdentity, WindowsIdentityError, WindowsPipeEndpoint};
use protocol::{
    AsyncProtocolError, AuthenticatedServerConnection, SessionToken as ProtocolSessionToken,
    authenticate_server,
};
use serde::Serialize;
use thiserror::Error;
use tokio::net::windows::named_pipe::{NamedPipeServer, PipeMode, ServerOptions};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::timeout;
use windows::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_PIPE_BUSY, HANDLE, HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows::Win32::System::Pipes::{GetNamedPipeClientProcessId, GetNamedPipeClientSessionId};
use windows::core::{BOOL, Error as WindowsError, PCWSTR};

use crate::{AuthenticatedPeerMessage, AuthenticatedPeerProcessId, SessionToken};

const MAX_PIPE_INSTANCES: usize = 16;
const MAX_ACTIVE_CONNECTIONS: usize = MAX_PIPE_INSTANCES - 1;
const PIPE_BUFFER_BYTES: u32 = 64 * 1024;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Error)]
pub enum WindowsPipeServerError {
    #[error(transparent)]
    Identity(#[from] WindowsIdentityError),
    #[error("the Supervisor pipe endpoint is already occupied")]
    EndpointOccupied,
    #[error("creating a Supervisor pipe instance failed")]
    CreateInstance(#[source] std::io::Error),
    #[error("accepting a Supervisor pipe connection failed")]
    Accept(#[source] std::io::Error),
    #[error("the Named Pipe client session could not be verified")]
    ClientSessionInspection(#[source] WindowsError),
    #[error("the Named Pipe client belongs to another login session")]
    ClientSessionMismatch,
    #[error("the Named Pipe client process could not be verified")]
    ClientProcessInspection(#[source] WindowsError),
    #[error("the Named Pipe client process ID is invalid")]
    InvalidClientProcessId,
    #[error("the Supervisor pipe handshake timed out")]
    HandshakeTimeout,
    #[error("the Supervisor pipe handshake failed")]
    Handshake(#[source] AsyncProtocolError),
    #[error("the connection generation counter was exhausted")]
    GenerationExhausted,
    #[error("the connection limit was closed")]
    ConnectionLimitClosed,
    #[error("the pending Named Pipe instance is unavailable")]
    PendingInstanceUnavailable,
    #[error("constructing the current-user pipe DACL failed")]
    SecurityDescriptor(#[source] WindowsError),
    #[error("the current-user SID cannot be represented in SDDL")]
    InvalidSddl,
}

/// An authenticated server connection that also owns one active-connection
/// permit. Dropping it closes the pipe handle and releases the permit together.
pub struct AuthenticatedServerPipe {
    connection: AuthenticatedServerConnection<NamedPipeServer>,
    peer_process_id: AuthenticatedPeerProcessId,
    _permit: OwnedSemaphorePermit,
}

impl Debug for AuthenticatedServerPipe {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        self.connection.fmt(formatter)
    }
}

impl AuthenticatedServerPipe {
    pub fn protocol_version(&self) -> u16 {
        self.connection.protocol_version()
    }

    pub fn generation(&self) -> u64 {
        self.connection.generation()
    }

    pub async fn accept_client_payload(
        &mut self,
    ) -> Result<AuthenticatedPeerMessage<'_>, AsyncProtocolError> {
        let message = self.connection.accept_client_payload().await?;
        Ok(AuthenticatedPeerMessage::bind(
            message,
            &self.peer_process_id,
        ))
    }

    pub async fn send_response_success<T: Serialize>(
        &mut self,
        request_id: impl Into<String>,
        operation_id: Option<String>,
        result: &T,
    ) -> Result<(), AsyncProtocolError> {
        self.connection
            .send_response_success(request_id, operation_id, result)
            .await
    }

    pub async fn send_response_error(
        &mut self,
        request_id: impl Into<String>,
        operation_id: Option<String>,
        error: AppError,
    ) -> Result<(), AsyncProtocolError> {
        self.connection
            .send_response_error(request_id, operation_id, error)
            .await
    }

    pub async fn send_event<T: Serialize>(
        &mut self,
        revision: Revision,
        event: impl Into<String>,
        payload: &T,
    ) -> Result<(), AsyncProtocolError> {
        self.connection.send_event(revision, event, payload).await
    }
}

/// Current-user, current-session Named Pipe listener.
///
/// The first instance claims the stable endpoint. Each accept replenishes the
/// pending instance before the authenticated connection is returned.
pub struct WindowsNamedPipeListener {
    identity: CurrentWindowsIdentity,
    security_descriptor: LocalSecurityDescriptor,
    pending: Option<NamedPipeServer>,
    active_connections: Arc<Semaphore>,
    generation: u64,
}

impl WindowsNamedPipeListener {
    pub fn bind_current_process() -> Result<Self, WindowsPipeServerError> {
        let identity = CurrentWindowsIdentity::for_current_process()?;
        let security_descriptor =
            LocalSecurityDescriptor::for_current_sid(identity.sid_sddl_fragment())?;
        let pending = create_pipe_instance(identity.endpoint(), &security_descriptor, true)
            .map_err(|source| {
                if is_occupied_error(&source) {
                    WindowsPipeServerError::EndpointOccupied
                } else {
                    WindowsPipeServerError::CreateInstance(source)
                }
            })?;
        Ok(Self {
            identity,
            security_descriptor,
            pending: Some(pending),
            active_connections: Arc::new(Semaphore::new(MAX_ACTIVE_CONNECTIONS)),
            generation: 0,
        })
    }

    pub fn endpoint(&self) -> &WindowsPipeEndpoint {
        self.identity.endpoint()
    }

    pub async fn accept_authenticated(
        &mut self,
        token: &SessionToken,
    ) -> Result<AuthenticatedServerPipe, WindowsPipeServerError> {
        let permit = self
            .active_connections
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| WindowsPipeServerError::ConnectionLimitClosed)?;

        self.ensure_pending_instance()?;
        let accept_result = self
            .pending
            .as_mut()
            .ok_or(WindowsPipeServerError::PendingInstanceUnavailable)?
            .connect()
            .await;
        if let Err(source) = accept_result {
            self.reject_connected_instance()?;
            return Err(WindowsPipeServerError::Accept(source));
        }
        let pipe_handle = HANDLE(
            self.pending
                .as_ref()
                .ok_or(WindowsPipeServerError::PendingInstanceUnavailable)?
                .as_raw_handle(),
        );

        let mut client_session_id = 0_u32;
        if let Err(source) =
            unsafe { GetNamedPipeClientSessionId(pipe_handle, &mut client_session_id) }
        {
            self.reject_connected_instance()?;
            return Err(WindowsPipeServerError::ClientSessionInspection(source));
        }
        if client_session_id != self.identity.session_id() {
            self.reject_connected_instance()?;
            return Err(WindowsPipeServerError::ClientSessionMismatch);
        }
        let mut client_process_id = 0_u32;
        if let Err(source) =
            unsafe { GetNamedPipeClientProcessId(pipe_handle, &mut client_process_id) }
        {
            self.reject_connected_instance()?;
            return Err(WindowsPipeServerError::ClientProcessInspection(source));
        }
        let Some(peer_process_id) = AuthenticatedPeerProcessId::from_transport(client_process_id)
        else {
            self.reject_connected_instance()?;
            return Err(WindowsPipeServerError::InvalidClientProcessId);
        };

        let connected = self.take_connected_and_replenish()?;
        let generation = self
            .generation
            .checked_add(1)
            .ok_or(WindowsPipeServerError::GenerationExhausted)?;
        let protocol_token = ProtocolSessionToken::from_bytes(*token.as_bytes());
        let connection = match timeout(
            HANDSHAKE_TIMEOUT,
            authenticate_server(connected, protocol_token, generation),
        )
        .await
        {
            Err(_) => return Err(WindowsPipeServerError::HandshakeTimeout),
            Ok(Err(source)) => return Err(WindowsPipeServerError::Handshake(source)),
            Ok(Ok(connection)) => connection,
        };
        self.generation = generation;
        Ok(AuthenticatedServerPipe {
            connection,
            peer_process_id,
            _permit: permit,
        })
    }

    fn ensure_pending_instance(&mut self) -> Result<(), WindowsPipeServerError> {
        if self.pending.is_none() {
            self.pending = Some(
                create_pipe_instance(self.identity.endpoint(), &self.security_descriptor, false)
                    .map_err(WindowsPipeServerError::CreateInstance)?,
            );
        }
        Ok(())
    }

    fn take_connected_and_replenish(&mut self) -> Result<NamedPipeServer, WindowsPipeServerError> {
        let connected = self
            .pending
            .take()
            .ok_or(WindowsPipeServerError::PendingInstanceUnavailable)?;
        let replacement =
            create_pipe_instance(self.identity.endpoint(), &self.security_descriptor, false)
                .map_err(WindowsPipeServerError::CreateInstance)?;
        self.pending = Some(replacement);
        Ok(connected)
    }

    fn reject_connected_instance(&mut self) -> Result<(), WindowsPipeServerError> {
        drop(self.take_connected_and_replenish()?);
        Ok(())
    }
}

fn create_pipe_instance(
    endpoint: &WindowsPipeEndpoint,
    descriptor: &LocalSecurityDescriptor,
    first: bool,
) -> std::io::Result<NamedPipeServer> {
    let mut attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0.0,
        bInheritHandle: BOOL(0),
    };
    let mut options = ServerOptions::new();
    options
        .pipe_mode(PipeMode::Byte)
        .access_inbound(true)
        .access_outbound(true)
        .first_pipe_instance(first)
        .reject_remote_clients(true)
        .max_instances(MAX_PIPE_INSTANCES)
        .in_buffer_size(PIPE_BUFFER_BYTES)
        .out_buffer_size(PIPE_BUFFER_BYTES);

    unsafe {
        options.create_with_security_attributes_raw(
            endpoint.as_os_str(),
            (&mut attributes as *mut SECURITY_ATTRIBUTES).cast::<c_void>(),
        )
    }
}

fn is_occupied_error(error: &std::io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(code)
            if code == ERROR_ACCESS_DENIED.0 as i32 || code == ERROR_PIPE_BUSY.0 as i32
    )
}

struct LocalSecurityDescriptor(PSECURITY_DESCRIPTOR);

impl LocalSecurityDescriptor {
    fn for_current_sid(sid: &str) -> Result<Self, WindowsPipeServerError> {
        let sddl = format!("D:P(A;;GA;;;{sid})");
        let sddl = wide_nul(OsStr::new(&sddl))?;
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(sddl.as_ptr()),
                SDDL_REVISION_1,
                &mut descriptor,
                None,
            )
        }
        .map_err(WindowsPipeServerError::SecurityDescriptor)?;
        Ok(Self(descriptor))
    }
}

impl Drop for LocalSecurityDescriptor {
    fn drop(&mut self) {
        unsafe { LocalFree(Some(HLOCAL(self.0.0))) };
    }
}

fn wide_nul(value: &OsStr) -> Result<Vec<u16>, WindowsPipeServerError> {
    let mut wide = value.encode_wide().collect::<Vec<_>>();
    if wide.contains(&0) {
        return Err(WindowsPipeServerError::InvalidSddl);
    }
    wide.push(0);
    Ok(wide)
}
