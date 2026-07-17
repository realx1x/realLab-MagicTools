use std::ffi::{OsStr, c_void};
use std::fmt::{self, Debug, Formatter};
use std::fs::{self, Permissions};
use std::io;
use std::mem::size_of;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use domain::{AppError, Revision};
use protocol::{
    AsyncProtocolError, AuthenticatedServerConnection, SessionToken as ProtocolSessionToken,
    authenticate_server,
};
use serde::Serialize;
use thiserror::Error;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::timeout;

use crate::{
    AuthenticatedPeerMessage, AuthenticatedPeerProcessId, SupervisorInstanceGuard, platform,
};

const SOCKET_NAME: &str = "supervisor.sock";
const SOCKET_MODE: u32 = 0o600;
const MAX_ACTIVE_CONNECTIONS: usize = 16;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Error)]
pub enum MacOsSocketServerError {
    #[error("resolving the fixed current-user runtime root failed")]
    RuntimeRoot(#[source] io::Error),
    #[error("the instance guard does not own the fixed current-user runtime root")]
    RuntimeRootMismatch,
    #[error("the Supervisor socket path is outside the fixed runtime root")]
    EndpointOutsideRuntimeRoot,
    #[error("inspecting the stale Supervisor socket failed")]
    InspectStaleEndpoint(#[source] io::Error),
    #[error("refusing to remove a stale symbolic link")]
    StaleEndpointSymlink,
    #[error("refusing to remove a stale path that is not a Unix socket")]
    StaleEndpointNotSocket,
    #[error("refusing to remove a stale socket owned by another user")]
    StaleEndpointOwnerMismatch {
        expected: libc::uid_t,
        actual: libc::uid_t,
    },
    #[error("the stale Supervisor socket changed during inspection")]
    StaleEndpointChanged,
    #[error("removing the stale Supervisor socket failed")]
    RemoveStaleEndpoint(#[source] io::Error),
    #[error("binding the Supervisor socket failed")]
    Bind(#[source] io::Error),
    #[error("inspecting the bound Supervisor socket failed")]
    InspectBoundEndpoint(#[source] io::Error),
    #[error("the bound Supervisor endpoint is not a Unix socket")]
    BoundEndpointNotSocket,
    #[error("the bound Supervisor socket is owned by another user")]
    BoundEndpointOwnerMismatch {
        expected: libc::uid_t,
        actual: libc::uid_t,
    },
    #[error("restricting the Supervisor socket to mode 0600 failed")]
    RestrictEndpoint(#[source] io::Error),
    #[error("the bound Supervisor socket changed while it was being secured")]
    BoundEndpointChanged,
    #[error("the bound Supervisor socket does not have mode 0600")]
    BoundEndpointModeMismatch { actual: u32 },
    #[error("accepting a Supervisor socket connection failed")]
    Accept(#[source] io::Error),
    #[error("the Supervisor socket peer could not be inspected")]
    PeerInspection(#[source] io::Error),
    #[error("the Supervisor socket peer process could not be inspected")]
    PeerProcessInspection(#[source] io::Error),
    #[error("the Supervisor socket peer process ID is invalid")]
    InvalidPeerProcessId,
    #[error("the Supervisor socket peer belongs to another effective user")]
    PeerUserMismatch {
        expected: libc::uid_t,
        actual: libc::uid_t,
    },
    #[error("the Supervisor socket handshake timed out")]
    HandshakeTimeout,
    #[error("the Supervisor socket handshake failed")]
    Handshake(#[source] AsyncProtocolError),
    #[error("the connection generation counter was exhausted")]
    GenerationExhausted,
    #[error("the connection limit was closed")]
    ConnectionLimitClosed,
}

/// An authenticated connection that owns one of the 16 active-connection
/// permits. Dropping it closes the stream and releases the permit together.
pub struct AuthenticatedServerSocket {
    connection: AuthenticatedServerConnection<UnixStream>,
    peer_process_id: AuthenticatedPeerProcessId,
    _permit: OwnedSemaphorePermit,
}

impl Debug for AuthenticatedServerSocket {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        self.connection.fmt(formatter)
    }
}

impl AuthenticatedServerSocket {
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

/// A current-user Unix Socket listener tied to the live single-instance lock.
///
/// The guard borrow prevents the listener from outliving or releasing the lock
/// that authorizes stale endpoint cleanup.
pub struct MacOsUnixSocketListener<'guard> {
    instance_guard: &'guard SupervisorInstanceGuard,
    endpoint: PathBuf,
    listener: UnixListener,
    identity: SocketIdentity,
    active_connections: Arc<Semaphore>,
    generation: u64,
}

impl<'guard> MacOsUnixSocketListener<'guard> {
    pub fn bind(
        instance_guard: &'guard SupervisorInstanceGuard,
    ) -> Result<Self, MacOsSocketServerError> {
        let fixed_root =
            platform::current_user_runtime_root().map_err(MacOsSocketServerError::RuntimeRoot)?;
        if instance_guard.paths().root() != fixed_root {
            return Err(MacOsSocketServerError::RuntimeRootMismatch);
        }

        let endpoint = fixed_root.join(SOCKET_NAME);
        validate_endpoint_path(&fixed_root, &endpoint)?;
        let expected_uid = unsafe { libc::geteuid() };
        remove_stale_endpoint(&endpoint, expected_uid)?;

        let listener = UnixListener::bind(&endpoint).map_err(MacOsSocketServerError::Bind)?;
        let initial_identity = match inspect_bound_endpoint(&endpoint, expected_uid) {
            Ok(identity) => identity,
            Err(error) => return Err(error),
        };
        if let Err(source) = fs::set_permissions(&endpoint, Permissions::from_mode(SOCKET_MODE)) {
            remove_if_matching(&endpoint, initial_identity);
            return Err(MacOsSocketServerError::RestrictEndpoint(source));
        }

        let identity = match inspect_bound_endpoint(&endpoint, expected_uid) {
            Ok(identity) => identity,
            Err(error) => {
                remove_if_matching(&endpoint, initial_identity);
                return Err(error);
            }
        };
        if !identity.same_object(initial_identity) {
            return Err(MacOsSocketServerError::BoundEndpointChanged);
        }
        if identity.mode != SOCKET_MODE {
            remove_if_matching(&endpoint, identity);
            return Err(MacOsSocketServerError::BoundEndpointModeMismatch {
                actual: identity.mode,
            });
        }

        Ok(Self {
            instance_guard,
            endpoint,
            listener,
            identity,
            active_connections: Arc::new(Semaphore::new(MAX_ACTIVE_CONNECTIONS)),
            generation: 0,
        })
    }

    pub fn endpoint(&self) -> &Path {
        &self.endpoint
    }

    pub async fn accept_authenticated(
        &mut self,
    ) -> Result<AuthenticatedServerSocket, MacOsSocketServerError> {
        let permit = self
            .active_connections
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| MacOsSocketServerError::ConnectionLimitClosed)?;
        let (stream, _) = self
            .listener
            .accept()
            .await
            .map_err(MacOsSocketServerError::Accept)?;

        let expected_uid = self.identity.uid;
        let peer_uid = peer_euid(&stream).map_err(MacOsSocketServerError::PeerInspection)?;
        if peer_uid != expected_uid {
            return Err(MacOsSocketServerError::PeerUserMismatch {
                expected: expected_uid,
                actual: peer_uid,
            });
        }
        let peer_process_id = peer_pid(&stream)
            .map_err(MacOsSocketServerError::PeerProcessInspection)
            .and_then(|process_id| {
                u32::try_from(process_id).map_err(|_| MacOsSocketServerError::InvalidPeerProcessId)
            })
            .and_then(|process_id| {
                AuthenticatedPeerProcessId::from_transport(process_id)
                    .ok_or(MacOsSocketServerError::InvalidPeerProcessId)
            })?;

        let generation = self
            .generation
            .checked_add(1)
            .ok_or(MacOsSocketServerError::GenerationExhausted)?;
        let token =
            ProtocolSessionToken::from_bytes(*self.instance_guard.session_token().as_bytes());
        let connection = match timeout(
            HANDSHAKE_TIMEOUT,
            authenticate_server(stream, token, generation),
        )
        .await
        {
            Err(_) => return Err(MacOsSocketServerError::HandshakeTimeout),
            Ok(Err(source)) => return Err(MacOsSocketServerError::Handshake(source)),
            Ok(Ok(connection)) => connection,
        };
        self.generation = generation;
        Ok(AuthenticatedServerSocket {
            connection,
            peer_process_id,
            _permit: permit,
        })
    }
}

impl Drop for MacOsUnixSocketListener<'_> {
    fn drop(&mut self) {
        remove_if_matching(&self.endpoint, self.identity);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SocketIdentity {
    device: u64,
    inode: u64,
    uid: libc::uid_t,
    mode: u32,
}

impl SocketIdentity {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            uid: metadata.uid(),
            mode: metadata.mode() & 0o777,
        }
    }

    fn same_object(self, other: Self) -> bool {
        self.device == other.device && self.inode == other.inode && self.uid == other.uid
    }

    fn matches_metadata(self, metadata: &fs::Metadata) -> bool {
        metadata.file_type().is_socket()
            && metadata.dev() == self.device
            && metadata.ino() == self.inode
            && metadata.uid() == self.uid
    }
}

fn validate_endpoint_path(root: &Path, endpoint: &Path) -> Result<(), MacOsSocketServerError> {
    if endpoint.parent() != Some(root) || endpoint.file_name() != Some(OsStr::new(SOCKET_NAME)) {
        return Err(MacOsSocketServerError::EndpointOutsideRuntimeRoot);
    }
    Ok(())
}

fn remove_stale_endpoint(
    endpoint: &Path,
    expected_uid: libc::uid_t,
) -> Result<(), MacOsSocketServerError> {
    let metadata = match fs::symlink_metadata(endpoint) {
        Ok(metadata) => metadata,
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(source) => return Err(MacOsSocketServerError::InspectStaleEndpoint(source)),
    };
    if metadata.file_type().is_symlink() {
        return Err(MacOsSocketServerError::StaleEndpointSymlink);
    }
    if !metadata.file_type().is_socket() {
        return Err(MacOsSocketServerError::StaleEndpointNotSocket);
    }
    if metadata.uid() != expected_uid {
        return Err(MacOsSocketServerError::StaleEndpointOwnerMismatch {
            expected: expected_uid,
            actual: metadata.uid(),
        });
    }

    let identity = SocketIdentity::from_metadata(&metadata);
    let current =
        fs::symlink_metadata(endpoint).map_err(MacOsSocketServerError::InspectStaleEndpoint)?;
    if !identity.matches_metadata(&current) {
        return Err(MacOsSocketServerError::StaleEndpointChanged);
    }
    fs::remove_file(endpoint).map_err(MacOsSocketServerError::RemoveStaleEndpoint)
}

fn inspect_bound_endpoint(
    endpoint: &Path,
    expected_uid: libc::uid_t,
) -> Result<SocketIdentity, MacOsSocketServerError> {
    let metadata =
        fs::symlink_metadata(endpoint).map_err(MacOsSocketServerError::InspectBoundEndpoint)?;
    if !metadata.file_type().is_socket() {
        return Err(MacOsSocketServerError::BoundEndpointNotSocket);
    }
    if metadata.uid() != expected_uid {
        return Err(MacOsSocketServerError::BoundEndpointOwnerMismatch {
            expected: expected_uid,
            actual: metadata.uid(),
        });
    }
    Ok(SocketIdentity::from_metadata(&metadata))
}

fn remove_if_matching(endpoint: &Path, identity: SocketIdentity) {
    if matches!(
        fs::symlink_metadata(endpoint),
        Ok(metadata) if identity.matches_metadata(&metadata)
    ) {
        let _ = fs::remove_file(endpoint);
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

fn peer_pid(stream: &UnixStream) -> io::Result<libc::pid_t> {
    let mut process_id = 0;
    let mut length = size_of::<libc::pid_t>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERPID,
            (&mut process_id as *mut libc::pid_t).cast::<c_void>(),
            &mut length,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    if length as usize != size_of::<libc::pid_t>() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "LOCAL_PEERPID returned an invalid value length",
        ));
    }
    Ok(process_id)
}
