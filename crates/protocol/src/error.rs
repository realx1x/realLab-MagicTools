use thiserror::Error;

use crate::HandshakeRejectCode;

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("the peer offered {actual} protocol versions; the maximum is {maximum}")]
    TooManyVersions { actual: usize, maximum: usize },
    #[error("no compatible protocol version")]
    IncompatibleVersion,
    #[error("handshake proof did not match")]
    AuthenticationFailed,
    #[error("the peer rejected the handshake: {code:?}")]
    HandshakeRejected { code: HandshakeRejectCode },
    #[error("the session token must contain exactly {expected} bytes; received {actual}")]
    InvalidTokenLength { expected: usize, actual: usize },
    #[error("received protocol version {received}; negotiated version is {negotiated}")]
    InvalidProtocolVersion { received: u16, negotiated: u16 },
    #[error("unexpected {message_kind} message during the {phase} phase")]
    UnexpectedMessage {
        phase: &'static str,
        message_kind: String,
    },
    #[error("frame payload is {actual} bytes; the maximum is {maximum}")]
    FrameTooLarge { actual: usize, maximum: usize },
    #[error("zero-length frames are not valid JSON protocol messages")]
    EmptyFrame,
    #[error("frame declares {declared} payload bytes but contains {actual}")]
    FrameLengthMismatch { declared: usize, actual: usize },
    #[error("frame stream ended after {actual} bytes; {expected} bytes were required")]
    TruncatedFrame { expected: usize, actual: usize },
    #[error("invalid envelope field {field}: {reason}")]
    InvalidEnvelope {
        field: &'static str,
        reason: &'static str,
    },
    #[error("invalid JSON payload: {0}")]
    InvalidJson(#[from] serde_json::Error),
}
