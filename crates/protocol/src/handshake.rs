use std::fmt;

use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::ProtocolError;

pub const PROTOCOL_MIN_VERSION: u16 = 1;
pub const PROTOCOL_MAX_VERSION: u16 = 1;
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

    pub fn from_slice(value: &[u8]) -> Result<Self, ProtocolError> {
        let bytes = value
            .try_into()
            .map_err(|_| ProtocolError::InvalidTokenLength {
                expected: TOKEN_BYTES,
                actual: value.len(),
            })?;
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; TOKEN_BYTES] {
        &self.0
    }
}

impl fmt::Debug for SessionToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionToken([REDACTED])")
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClientHello {
    pub supported_versions: Vec<u16>,
    pub client_nonce: [u8; NONCE_BYTES],
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServerChallenge {
    pub selected_version: u16,
    pub server_nonce: [u8; NONCE_BYTES],
    pub server_proof: [u8; PROOF_BYTES],
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClientProof {
    pub proof: [u8; PROOF_BYTES],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HandshakeAccepted {
    pub protocol_version: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HandshakeRejectCode {
    IncompatibleVersion,
    AuthenticationFailed,
    MalformedHandshake,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HandshakeRejected {
    pub code: HandshakeRejectCode,
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
        &hello.supported_versions,
        &hello.client_nonce,
        &server_nonce,
    )?;
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
    validate_selected_version(hello, challenge.selected_version)?;
    let expected = handshake_proof(
        token,
        b"server",
        challenge.selected_version,
        &hello.supported_versions,
        &hello.client_nonce,
        &challenge.server_nonce,
    )?;
    if !constant_time_eq(&expected, &challenge.server_proof) {
        return Err(ProtocolError::AuthenticationFailed);
    }

    Ok(ClientProof {
        proof: handshake_proof(
            token,
            b"client",
            challenge.selected_version,
            &hello.supported_versions,
            &hello.client_nonce,
            &challenge.server_nonce,
        )?,
    })
}

pub fn verify_client_proof(
    token: &SessionToken,
    hello: &ClientHello,
    challenge: &ServerChallenge,
    client_proof: &ClientProof,
) -> Result<(), ProtocolError> {
    validate_selected_version(hello, challenge.selected_version)?;
    let expected = handshake_proof(
        token,
        b"client",
        challenge.selected_version,
        &hello.supported_versions,
        &hello.client_nonce,
        &challenge.server_nonce,
    )?;
    if constant_time_eq(&expected, &client_proof.proof) {
        Ok(())
    } else {
        Err(ProtocolError::AuthenticationFailed)
    }
}

pub fn negotiate_version(offered: &[u16]) -> Result<u16, ProtocolError> {
    if offered.len() > MAX_NEGOTIATED_VERSIONS {
        return Err(ProtocolError::TooManyVersions {
            actual: offered.len(),
            maximum: MAX_NEGOTIATED_VERSIONS,
        });
    }

    offered
        .iter()
        .copied()
        .filter(|version| (PROTOCOL_MIN_VERSION..=PROTOCOL_MAX_VERSION).contains(version))
        .max()
        .ok_or(ProtocolError::IncompatibleVersion)
}

fn validate_selected_version(
    hello: &ClientHello,
    selected_version: u16,
) -> Result<(), ProtocolError> {
    if hello.supported_versions.contains(&selected_version)
        && (PROTOCOL_MIN_VERSION..=PROTOCOL_MAX_VERSION).contains(&selected_version)
    {
        Ok(())
    } else {
        Err(ProtocolError::IncompatibleVersion)
    }
}

fn handshake_proof(
    token: &SessionToken,
    role: &[u8],
    version: u16,
    supported_versions: &[u16],
    client_nonce: &[u8; NONCE_BYTES],
    server_nonce: &[u8; NONCE_BYTES],
) -> Result<[u8; PROOF_BYTES], ProtocolError> {
    if supported_versions.len() > MAX_NEGOTIATED_VERSIONS {
        return Err(ProtocolError::TooManyVersions {
            actual: supported_versions.len(),
            maximum: MAX_NEGOTIATED_VERSIONS,
        });
    }

    let mut transcript = Vec::with_capacity(
        HANDSHAKE_DOMAIN.len()
            + role.len()
            + 2
            + 2
            + supported_versions.len() * 2
            + client_nonce.len()
            + server_nonce.len(),
    );
    transcript.extend_from_slice(HANDSHAKE_DOMAIN);
    transcript.extend_from_slice(role);
    transcript.extend_from_slice(&version.to_be_bytes());
    transcript.extend_from_slice(&(supported_versions.len() as u16).to_be_bytes());
    for offered_version in supported_versions {
        transcript.extend_from_slice(&offered_version.to_be_bytes());
    }
    transcript.extend_from_slice(client_nonce);
    transcript.extend_from_slice(server_nonce);
    Ok(hmac_sha256(token.as_bytes(), &transcript))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completes_mutual_proof_without_exposing_the_token() {
        let token = SessionToken::from_bytes([7_u8; TOKEN_BYTES]);
        let hello = new_client_hello();
        let challenge = create_server_challenge(&token, &hello).expect("server challenge");
        let proof = verify_server_and_create_client_proof(&token, &hello, &challenge)
            .expect("client proof");

        verify_client_proof(&token, &hello, &challenge, &proof).expect("mutual proof");
        assert_eq!(format!("{token:?}"), "SessionToken([REDACTED])");
    }

    #[test]
    fn rejects_a_proof_created_with_another_token() {
        let server_token = SessionToken::from_bytes([1_u8; TOKEN_BYTES]);
        let client_token = SessionToken::from_bytes([2_u8; TOKEN_BYTES]);
        let hello = new_client_hello();
        let challenge = create_server_challenge(&server_token, &hello).expect("server challenge");

        assert!(matches!(
            verify_server_and_create_client_proof(&client_token, &hello, &challenge),
            Err(ProtocolError::AuthenticationFailed)
        ));
    }

    #[test]
    fn binds_the_complete_supported_version_offer() {
        let token = SessionToken::from_bytes([3_u8; TOKEN_BYTES]);
        let hello = ClientHello {
            supported_versions: vec![1, 2],
            client_nonce: [4_u8; NONCE_BYTES],
        };
        let challenge = create_server_challenge(&token, &hello).expect("server challenge");
        let downgraded_hello = ClientHello {
            supported_versions: vec![1],
            client_nonce: hello.client_nonce,
        };

        assert!(matches!(
            verify_server_and_create_client_proof(&token, &downgraded_hello, &challenge),
            Err(ProtocolError::AuthenticationFailed)
        ));
    }
}
