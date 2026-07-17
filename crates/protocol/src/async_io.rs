use std::fmt::{self, Debug, Formatter};
use std::io;
use std::marker::PhantomData;

use domain::{AppError, Revision};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{
    AuthenticatedClientMessage, AuthenticatedServerMessage, AuthenticatedSession, ClientHandshake,
    FRAME_HEADER_BYTES, MAX_FRAME_BYTES, ProtocolError, ServerHandshake, SessionToken,
    encode_frame,
};

pub const MAX_HANDSHAKE_FRAME_BYTES: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportErrorKind {
    PeerClosed,
    AccessDenied,
    Interrupted,
    TimedOut,
    Other,
}

#[derive(Debug, Error)]
pub enum AsyncProtocolError {
    #[error("{operation} failed ({kind:?})")]
    Transport {
        operation: &'static str,
        kind: TransportErrorKind,
        raw_os_error: Option<i32>,
        #[source]
        source: io::Error,
    },
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
}

impl AsyncProtocolError {
    pub fn transport_kind(&self) -> Option<TransportErrorKind> {
        match self {
            Self::Transport { kind, .. } => Some(*kind),
            Self::Protocol(_) => None,
        }
    }

    pub fn is_incompatible_version(&self) -> bool {
        match self {
            Self::Protocol(ProtocolError::IncompatibleVersion) => true,
            Self::Protocol(ProtocolError::HandshakeRejected { code }) => {
                *code == crate::HandshakeRejectCode::IncompatibleVersion
            }
            _ => false,
        }
    }

    pub fn is_authentication_failure(&self) -> bool {
        match self {
            Self::Protocol(ProtocolError::AuthenticationFailed) => true,
            Self::Protocol(ProtocolError::HandshakeRejected { code }) => {
                *code == crate::HandshakeRejectCode::AuthenticationFailed
            }
            _ => false,
        }
    }
}

/// Length-prefixed JSON transport over one asynchronous byte stream.
///
/// Each read consumes exactly one frame. The declared size is validated before
/// allocating its payload buffer.
pub struct FramedIo<S> {
    stream: S,
    read_state: FrameReadState,
}

enum FrameReadState {
    Header {
        bytes: [u8; FRAME_HEADER_BYTES],
        filled: usize,
    },
    Payload {
        bytes: Vec<u8>,
        filled: usize,
    },
}

impl FrameReadState {
    fn header() -> Self {
        Self::Header {
            bytes: [0; FRAME_HEADER_BYTES],
            filled: 0,
        }
    }
}

impl<S> FramedIo<S> {
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            read_state: FrameReadState::header(),
        }
    }
}

impl<S> Debug for FramedIo<S> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("FramedIo(..)")
    }
}

impl<S> FramedIo<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub async fn read_payload(&mut self) -> Result<Vec<u8>, AsyncProtocolError> {
        self.read_payload_with_limit(MAX_FRAME_BYTES).await
    }

    pub async fn read_payload_with_limit(
        &mut self,
        maximum: usize,
    ) -> Result<Vec<u8>, AsyncProtocolError> {
        let maximum = maximum.min(MAX_FRAME_BYTES);
        loop {
            match &mut self.read_state {
                FrameReadState::Header { bytes, filled } => {
                    let read = self
                        .stream
                        .read(&mut bytes[*filled..])
                        .await
                        .map_err(|source| transport_error("read frame header", source))?;
                    if read == 0 {
                        return Err(peer_closed("read frame header").into());
                    }
                    *filled += read;
                    if *filled < FRAME_HEADER_BYTES {
                        continue;
                    }

                    let payload_len = u32::from_be_bytes(*bytes) as usize;
                    if payload_len == 0 {
                        return Err(ProtocolError::EmptyFrame.into());
                    }
                    if payload_len > maximum {
                        return Err(ProtocolError::FrameTooLarge {
                            actual: payload_len,
                            maximum,
                        }
                        .into());
                    }
                    self.read_state = FrameReadState::Payload {
                        bytes: vec![0; payload_len],
                        filled: 0,
                    };
                }
                FrameReadState::Payload { bytes, filled } => {
                    let read = self
                        .stream
                        .read(&mut bytes[*filled..])
                        .await
                        .map_err(|source| transport_error("read frame payload", source))?;
                    if read == 0 {
                        return Err(peer_closed("read frame payload").into());
                    }
                    *filled += read;
                    if *filled < bytes.len() {
                        continue;
                    }

                    let payload = std::mem::take(bytes);
                    self.read_state = FrameReadState::header();
                    return Ok(payload);
                }
            }
        }
    }

    pub async fn write_message<T: Serialize>(
        &mut self,
        message: &T,
    ) -> Result<(), AsyncProtocolError> {
        let frame = encode_frame(message)?;
        self.stream
            .write_all(&frame)
            .await
            .map_err(|source| transport_error("write frame", source))?;
        self.stream
            .flush()
            .await
            .map_err(|source| transport_error("flush frame", source))
    }
}

/// Owns the stream and the non-cloneable authenticated session as one unit.
/// No raw transport or payload reader is exposed after authentication.
#[derive(Debug)]
pub enum ClientRole {}

#[derive(Debug)]
pub enum ServerRole {}

pub struct AuthenticatedConnection<S, Role> {
    framed: FramedIo<S>,
    session: AuthenticatedSession,
    generation: u64,
    _role: PhantomData<Role>,
}

pub type AuthenticatedClientConnection<S> = AuthenticatedConnection<S, ClientRole>;
pub type AuthenticatedServerConnection<S> = AuthenticatedConnection<S, ServerRole>;

impl<S, Role> Debug for AuthenticatedConnection<S, Role> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedConnection")
            .field("protocol_version", &self.session.protocol_version())
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}

impl<S, Role> AuthenticatedConnection<S, Role> {
    fn new(framed: FramedIo<S>, session: AuthenticatedSession, generation: u64) -> Self {
        Self {
            framed,
            session,
            generation,
            _role: PhantomData,
        }
    }

    pub fn protocol_version(&self) -> u16 {
        self.session.protocol_version()
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }
}

impl<S> AuthenticatedConnection<S, ServerRole>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub async fn accept_client_payload(
        &mut self,
    ) -> Result<AuthenticatedClientMessage, AsyncProtocolError> {
        let payload = self.framed.read_payload().await?;
        Ok(self.session.accept_client_payload(&payload)?)
    }

    pub async fn send_response_success<T: Serialize>(
        &mut self,
        request_id: impl Into<String>,
        operation_id: Option<String>,
        result: &T,
    ) -> Result<(), AsyncProtocolError> {
        let message = self
            .session
            .response_success(request_id, operation_id, result)?;
        self.framed.write_message(&message).await
    }

    pub async fn send_response_error(
        &mut self,
        request_id: impl Into<String>,
        operation_id: Option<String>,
        error: AppError,
    ) -> Result<(), AsyncProtocolError> {
        let message = self
            .session
            .response_error(request_id, operation_id, error)?;
        self.framed.write_message(&message).await
    }

    pub async fn send_event<T: Serialize>(
        &mut self,
        revision: Revision,
        event: impl Into<String>,
        payload: &T,
    ) -> Result<(), AsyncProtocolError> {
        let message = self.session.event(revision, event, payload)?;
        self.framed.write_message(&message).await
    }
}

impl<S> AuthenticatedConnection<S, ClientRole>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub async fn accept_server_payload(
        &mut self,
    ) -> Result<AuthenticatedServerMessage, AsyncProtocolError> {
        let payload = self.framed.read_payload().await?;
        Ok(self.session.accept_server_payload(&payload)?)
    }

    pub async fn send_request<T: Serialize>(
        &mut self,
        request_id: impl Into<String>,
        operation_id: Option<String>,
        timeout_ms: u32,
        method: impl Into<String>,
        params: &T,
    ) -> Result<(), AsyncProtocolError> {
        let message = self
            .session
            .request(request_id, operation_id, timeout_ms, method, params)?;
        self.framed.write_message(&message).await
    }

    pub async fn send_cancel(
        &mut self,
        request_id: impl Into<String>,
        target_request_id: impl Into<String>,
    ) -> Result<(), AsyncProtocolError> {
        let message = self.session.cancel(request_id, target_request_id)?;
        self.framed.write_message(&message).await
    }
}

pub async fn authenticate_client<S>(
    stream: S,
    token: SessionToken,
    generation: u64,
) -> Result<AuthenticatedClientConnection<S>, AsyncProtocolError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut framed = FramedIo::new(stream);
    let (handshake, hello) = ClientHandshake::start(token);
    framed.write_message(&hello).await?;

    let challenge_payload = framed
        .read_payload_with_limit(MAX_HANDSHAKE_FRAME_BYTES)
        .await?;
    let (awaiting_acceptance, proof) = handshake.accept_server_payload(&challenge_payload)?;
    framed.write_message(&proof).await?;

    let acceptance_payload = framed
        .read_payload_with_limit(MAX_HANDSHAKE_FRAME_BYTES)
        .await?;
    let session = awaiting_acceptance.accept_server_payload(&acceptance_payload)?;
    Ok(AuthenticatedConnection::<S, ClientRole>::new(
        framed, session, generation,
    ))
}

pub async fn authenticate_server<S>(
    stream: S,
    token: SessionToken,
    generation: u64,
) -> Result<AuthenticatedServerConnection<S>, AsyncProtocolError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let reject_token = token.clone();
    let mut framed = FramedIo::new(stream);
    let hello_payload = framed
        .read_payload_with_limit(MAX_HANDSHAKE_FRAME_BYTES)
        .await?;
    let (awaiting_proof, challenge) =
        match ServerHandshake::new(token).accept_client_payload(&hello_payload) {
            Ok(value) => value,
            Err(error) => {
                send_rejection(&mut framed, reject_token, rejection_code(&error)).await;
                return Err(error.into());
            }
        };
    framed.write_message(&challenge).await?;

    let proof_payload = framed
        .read_payload_with_limit(MAX_HANDSHAKE_FRAME_BYTES)
        .await?;
    let (session, accepted) = match awaiting_proof.accept_client_payload(&proof_payload) {
        Ok(value) => value,
        Err(error) => {
            send_rejection(&mut framed, reject_token, rejection_code(&error)).await;
            return Err(error.into());
        }
    };
    framed.write_message(&accepted).await?;
    Ok(AuthenticatedConnection::<S, ServerRole>::new(
        framed, session, generation,
    ))
}

async fn send_rejection<S>(
    framed: &mut FramedIo<S>,
    token: SessionToken,
    code: crate::HandshakeRejectCode,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let rejection = ServerHandshake::new(token).reject(code);
    let _ = framed.write_message(&rejection).await;
}

fn rejection_code(error: &ProtocolError) -> crate::HandshakeRejectCode {
    match error {
        ProtocolError::IncompatibleVersion | ProtocolError::TooManyVersions { .. } => {
            crate::HandshakeRejectCode::IncompatibleVersion
        }
        ProtocolError::AuthenticationFailed => crate::HandshakeRejectCode::AuthenticationFailed,
        _ => crate::HandshakeRejectCode::MalformedHandshake,
    }
}

fn transport_error(operation: &'static str, source: io::Error) -> AsyncProtocolError {
    let kind = match source.kind() {
        io::ErrorKind::UnexpectedEof
        | io::ErrorKind::BrokenPipe
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::ConnectionReset => TransportErrorKind::PeerClosed,
        io::ErrorKind::PermissionDenied => TransportErrorKind::AccessDenied,
        io::ErrorKind::Interrupted => TransportErrorKind::Interrupted,
        io::ErrorKind::TimedOut => TransportErrorKind::TimedOut,
        _ => TransportErrorKind::Other,
    };
    AsyncProtocolError::Transport {
        operation,
        kind,
        raw_os_error: source.raw_os_error(),
        source,
    }
}

fn peer_closed(operation: &'static str) -> AsyncProtocolError {
    transport_error(
        operation,
        io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "the IPC peer closed the stream",
        ),
    )
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub enum DisconnectReason {
    EndpointUnavailable,
    PipeBusy,
    PeerClosed,
    HandshakeTimeout,
    AuthenticationFailed,
    ProtocolViolation,
    Transport {
        #[serde(rename = "rawOsError")]
        raw_os_error: Option<i32>,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub enum ConnectionState {
    Disconnected {
        reason: Option<DisconnectReason>,
    },
    Connecting {
        attempt: u32,
    },
    Authenticating,
    Connected {
        version: u16,
        generation: u64,
    },
    Backoff {
        attempt: u32,
        #[serde(rename = "retryAfterMs")]
        retry_after_ms: u64,
    },
    IncompatibleVersion,
    AccessDenied,
    ShuttingDown,
}
