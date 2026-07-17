#![forbid(unsafe_op_in_unsafe_fn)]

use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const PROTOCOL_MIN_VERSION: u16 = 1;
pub const PROTOCOL_MAX_VERSION: u16 = 1;
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;
pub const MAX_NEGOTIATED_VERSIONS: usize = 16;

const NONCE_BYTES: usize = 32;
const TOKEN_BYTES: usize = 32;
const PROOF_BYTES: usize = 32;
const HMAC_BLOCK_BYTES: usize = 64;
const HANDSHAKE_DOMAIN: &[u8] = b"dev-process-manager/ipc/v1\0";

#[derive(Clone)]
pub struct SessionToken([u8; TOKEN_BYTES]);

impl SessionToken {
    pub fn generate() -> Self {
        let mut value = [0_u8; TOKEN_BYTES];
        OsRng.fill_bytes(&mut value);
        Self(value)
    }

    pub fn from_bytes(value: [u8; TOKEN_BYTES]) -> Self {
        Self(value)
    }
}

impl std::fmt::Debug for SessionToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SessionToken([REDACTED])")
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClientHello {
    pub supported_versions: Vec<u16>,
    pub client_nonce: [u8; NONCE_BYTES],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServerChallenge {
    pub selected_version: u16,
    pub server_nonce: [u8; NONCE_BYTES],
    pub server_proof: [u8; PROOF_BYTES],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClientProof {
    pub proof: [u8; PROOF_BYTES],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RequestEnvelope<T> {
    pub protocol_version: u16,
    pub request_id: String,
    pub operation_id: Option<String>,
    pub timeout_ms: u32,
    pub method: String,
    pub params: T,
}

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("the peer offered too many protocol versions")]
    TooManyVersions,
    #[error("no compatible protocol version")]
    IncompatibleVersion,
    #[error("handshake proof did not match")]
    AuthenticationFailed,
    #[error("frame is shorter than its four-byte length prefix")]
    MissingLengthPrefix,
    #[error("frame payload exceeds the configured limit")]
    FrameTooLarge,
    #[error("frame length does not match the encoded payload")]
    FrameLengthMismatch,
    #[error("invalid JSON payload: {0}")]
    InvalidJson(#[from] serde_json::Error),
}

pub fn new_client_hello() -> ClientHello {
    let mut client_nonce = [0_u8; NONCE_BYTES];
    OsRng.fill_bytes(&mut client_nonce);
    ClientHello {
        supported_versions: (PROTOCOL_MIN_VERSION..=PROTOCOL_MAX_VERSION).collect(),
        client_nonce,
    }
}

pub fn create_server_challenge(
    token: &SessionToken,
    hello: &ClientHello,
) -> Result<ServerChallenge, ProtocolError> {
    let selected_version = negotiate_version(&hello.supported_versions)?;
    let mut server_nonce = [0_u8; NONCE_BYTES];
    OsRng.fill_bytes(&mut server_nonce);
    let server_proof = handshake_proof(
        token,
        b"server",
        selected_version,
        &hello.client_nonce,
        &server_nonce,
    );
    Ok(ServerChallenge {
        selected_version,
        server_nonce,
        server_proof,
    })
}

pub fn verify_server_and_create_client_proof(
    token: &SessionToken,
    hello: &ClientHello,
    challenge: &ServerChallenge,
) -> Result<ClientProof, ProtocolError> {
    if !hello
        .supported_versions
        .contains(&challenge.selected_version)
        || !(PROTOCOL_MIN_VERSION..=PROTOCOL_MAX_VERSION).contains(&challenge.selected_version)
    {
        return Err(ProtocolError::IncompatibleVersion);
    }
    let expected = handshake_proof(
        token,
        b"server",
        challenge.selected_version,
        &hello.client_nonce,
        &challenge.server_nonce,
    );
    if !constant_time_eq(&expected, &challenge.server_proof) {
        return Err(ProtocolError::AuthenticationFailed);
    }

    Ok(ClientProof {
        proof: handshake_proof(
            token,
            b"client",
            challenge.selected_version,
            &hello.client_nonce,
            &challenge.server_nonce,
        ),
    })
}

pub fn verify_client_proof(
    token: &SessionToken,
    hello: &ClientHello,
    challenge: &ServerChallenge,
    client_proof: &ClientProof,
) -> Result<(), ProtocolError> {
    let expected = handshake_proof(
        token,
        b"client",
        challenge.selected_version,
        &hello.client_nonce,
        &challenge.server_nonce,
    );
    if constant_time_eq(&expected, &client_proof.proof) {
        Ok(())
    } else {
        Err(ProtocolError::AuthenticationFailed)
    }
}

pub fn encode_frame<T: Serialize>(value: &T) -> Result<Vec<u8>, ProtocolError> {
    let payload = serde_json::to_vec(value)?;
    if payload.len() > MAX_FRAME_BYTES {
        return Err(ProtocolError::FrameTooLarge);
    }
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

pub fn decode_frame<T: DeserializeOwned>(frame: &[u8]) -> Result<T, ProtocolError> {
    let prefix: [u8; 4] = frame
        .get(..4)
        .ok_or(ProtocolError::MissingLengthPrefix)?
        .try_into()
        .expect("the slice length was checked");
    let payload_len = u32::from_be_bytes(prefix) as usize;
    if payload_len > MAX_FRAME_BYTES {
        return Err(ProtocolError::FrameTooLarge);
    }
    if frame.len() != 4 + payload_len {
        return Err(ProtocolError::FrameLengthMismatch);
    }
    Ok(serde_json::from_slice(&frame[4..])?)
}

fn negotiate_version(offered: &[u16]) -> Result<u16, ProtocolError> {
    if offered.len() > MAX_NEGOTIATED_VERSIONS {
        return Err(ProtocolError::TooManyVersions);
    }
    offered
        .iter()
        .copied()
        .filter(|version| (PROTOCOL_MIN_VERSION..=PROTOCOL_MAX_VERSION).contains(version))
        .max()
        .ok_or(ProtocolError::IncompatibleVersion)
}

fn handshake_proof(
    token: &SessionToken,
    role: &[u8],
    version: u16,
    client_nonce: &[u8; NONCE_BYTES],
    server_nonce: &[u8; NONCE_BYTES],
) -> [u8; PROOF_BYTES] {
    let mut transcript = Vec::with_capacity(
        HANDSHAKE_DOMAIN.len() + role.len() + 2 + client_nonce.len() + server_nonce.len(),
    );
    transcript.extend_from_slice(HANDSHAKE_DOMAIN);
    transcript.extend_from_slice(role);
    transcript.extend_from_slice(&version.to_be_bytes());
    transcript.extend_from_slice(client_nonce);
    transcript.extend_from_slice(server_nonce);
    hmac_sha256(&token.0, &transcript)
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; PROOF_BYTES] {
    let mut block = [0_u8; HMAC_BLOCK_BYTES];
    if key.len() > HMAC_BLOCK_BYTES {
        block[..PROOF_BYTES].copy_from_slice(&Sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }

    let mut inner_pad = [0x36_u8; HMAC_BLOCK_BYTES];
    let mut outer_pad = [0x5c_u8; HMAC_BLOCK_BYTES];
    for index in 0..HMAC_BLOCK_BYTES {
        inner_pad[index] ^= block[index];
        outer_pad[index] ^= block[index];
    }

    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(message);
    let inner_digest = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner_digest);
    outer.finalize().into()
}

fn constant_time_eq(left: &[u8; PROOF_BYTES], right: &[u8; PROOF_BYTES]) -> bool {
    let mut difference = 0_u8;
    for index in 0..PROOF_BYTES {
        difference |= left[index] ^ right[index];
    }
    difference == 0
}

#[cfg(windows)]
pub mod windows_pipe;

#[cfg(target_os = "macos")]
pub mod macos_socket;
