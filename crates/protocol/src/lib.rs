//! Authenticated, versioned local RPC contracts.

mod async_io;
mod envelope;
mod error;
mod frame;
mod handshake;
#[cfg(target_os = "macos")]
pub mod macos_socket;
pub mod names;
mod runtime_token;
mod session;
#[cfg(windows)]
pub mod windows_pipe;

pub use async_io::{
    AsyncProtocolError, AuthenticatedClientConnection, AuthenticatedConnection,
    AuthenticatedServerConnection, ClientRole, ConnectionState, DisconnectReason, FramedIo,
    MAX_HANDSHAKE_FRAME_BYTES, ServerRole, TransportErrorKind, authenticate_client,
    authenticate_server,
};

pub use envelope::{
    CancelDisposition, CancelEnvelope, CancelResult, ClientMessage, EventEnvelope, MAX_ID_BYTES,
    MAX_METHOD_BYTES, MAX_TIMEOUT_MS, MIN_TIMEOUT_MS, RequestEnvelope, ResponseEnvelope,
    ResponseOutcome, ServerMessage, validate_cancel_input, validate_request_input,
    validate_revision,
};
pub use error::ProtocolError;
pub use frame::{
    FRAME_HEADER_BYTES, FrameDecodeProgress, FrameDecoder, MAX_BUFFERED_BYTES, MAX_FRAME_BYTES,
    encode_frame,
};
pub use handshake::{
    ClientHello, ClientProof, HandshakeAccepted, HandshakeRejectCode, HandshakeRejected,
    MAX_NEGOTIATED_VERSIONS, PROTOCOL_MAX_VERSION, PROTOCOL_MIN_VERSION, ServerChallenge,
    SessionToken, create_server_challenge, negotiate_version, new_client_hello,
    verify_client_proof, verify_server_and_create_client_proof,
};
pub use runtime_token::{
    SessionTokenReadError, current_user_runtime_root, read_current_session_token,
};
pub use session::{
    AuthenticatedClientMessage, AuthenticatedClientMessageKind, AuthenticatedServerMessage,
    AuthenticatedServerMessageKind, AuthenticatedSession, ClientAwaitingAcceptance,
    ClientHandshake, ServerAwaitingProof, ServerHandshake,
};
