use std::{cell::Cell, marker::PhantomData};

use domain::AppError;
use serde::Serialize;

use crate::envelope::{
    WireClientMessage, WireServerMessage, decode_client_payload, decode_server_payload,
};
use crate::{
    CancelEnvelope, ClientHello, ClientMessage, EventEnvelope, HandshakeRejectCode,
    HandshakeRejected, PROTOCOL_MAX_VERSION, PROTOCOL_MIN_VERSION, ProtocolError, RequestEnvelope,
    ResponseEnvelope, ServerChallenge, ServerMessage, SessionToken, create_server_challenge,
    new_client_hello, verify_client_proof, verify_server_and_create_client_proof,
};

#[derive(Debug)]
pub struct ClientHandshake {
    token: SessionToken,
    hello: ClientHello,
}

impl ClientHandshake {
    pub fn start(token: SessionToken) -> (Self, ClientMessage) {
        let hello = new_client_hello();
        let message = ClientMessage::client_hello(hello.clone());
        (Self { token, hello }, message)
    }

    /// Consumes the current phase so it cannot process a second challenge.
    pub fn accept_server_payload(
        self,
        payload: &[u8],
    ) -> Result<(ClientAwaitingAcceptance, ClientMessage), ProtocolError> {
        match decode_server_payload(payload)? {
            WireServerMessage::ServerChallenge(challenge) => {
                let proof =
                    verify_server_and_create_client_proof(&self.token, &self.hello, &challenge)?;
                Ok((
                    ClientAwaitingAcceptance {
                        selected_version: challenge.selected_version,
                    },
                    ClientMessage::client_proof(proof),
                ))
            }
            WireServerMessage::HandshakeRejected(rejection) => Err(peer_rejection(rejection.code)),
            other => Err(unexpected("awaitingServerChallenge", other.kind())),
        }
    }
}

#[derive(Debug)]
pub struct ClientAwaitingAcceptance {
    selected_version: u16,
}

impl ClientAwaitingAcceptance {
    /// Consumes the final handshake phase and is the only client path that can
    /// create an authenticated session.
    pub fn accept_server_payload(
        self,
        payload: &[u8],
    ) -> Result<AuthenticatedSession, ProtocolError> {
        match decode_server_payload(payload)? {
            WireServerMessage::HandshakeAccepted(accepted) => {
                if accepted.protocol_version != self.selected_version {
                    return Err(ProtocolError::InvalidProtocolVersion {
                        received: accepted.protocol_version,
                        negotiated: self.selected_version,
                    });
                }
                AuthenticatedSession::new(self.selected_version)
            }
            WireServerMessage::HandshakeRejected(rejection) => Err(peer_rejection(rejection.code)),
            other => Err(unexpected("awaitingHandshakeAccepted", other.kind())),
        }
    }
}

#[derive(Debug)]
pub struct ServerHandshake {
    token: SessionToken,
}

impl ServerHandshake {
    pub fn new(token: SessionToken) -> Self {
        Self { token }
    }

    /// Consumes the initial server phase so it cannot process a second hello.
    pub fn accept_client_payload(
        self,
        payload: &[u8],
    ) -> Result<(ServerAwaitingProof, ServerMessage), ProtocolError> {
        match decode_client_payload(payload)? {
            WireClientMessage::ClientHello(hello) => {
                let challenge = create_server_challenge(&self.token, &hello)?;
                Ok((
                    ServerAwaitingProof {
                        token: self.token,
                        hello,
                        challenge: challenge.clone(),
                    },
                    ServerMessage::server_challenge(challenge),
                ))
            }
            other => Err(unexpected("awaitingClientHello", other.kind())),
        }
    }

    pub fn reject(self, code: HandshakeRejectCode) -> ServerMessage {
        ServerMessage::handshake_rejected(HandshakeRejected { code })
    }
}

#[derive(Debug)]
pub struct ServerAwaitingProof {
    token: SessionToken,
    hello: ClientHello,
    challenge: ServerChallenge,
}

impl ServerAwaitingProof {
    /// Consumes the proof phase and is the only server path that can create an
    /// authenticated session.
    pub fn accept_client_payload(
        self,
        payload: &[u8],
    ) -> Result<(AuthenticatedSession, ServerMessage), ProtocolError> {
        match decode_client_payload(payload)? {
            WireClientMessage::ClientProof(proof) => {
                verify_client_proof(&self.token, &self.hello, &self.challenge, &proof)?;
                let session = AuthenticatedSession::new(self.challenge.selected_version)?;
                let accepted = crate::HandshakeAccepted {
                    protocol_version: self.challenge.selected_version,
                };
                Ok((session, ServerMessage::handshake_accepted(accepted)))
            }
            other => Err(unexpected("awaitingClientProof", other.kind())),
        }
    }

    pub fn reject(self, code: HandshakeRejectCode) -> ServerMessage {
        ServerMessage::handshake_rejected(HandshakeRejected { code })
    }
}

/// A successfully authenticated protocol connection.
///
/// The P2-T03 connection adapter must exclusively own this value together with
/// its transport and frame decoder. The non-`Sync` marker prevents sharing one
/// session across unrelated connection tasks; the type is intentionally not
/// cloneable.
#[derive(Debug)]
pub struct AuthenticatedSession {
    protocol_version: u16,
    _exclusive_connection: PhantomData<Cell<()>>,
}

impl AuthenticatedSession {
    fn new(protocol_version: u16) -> Result<Self, ProtocolError> {
        if !(PROTOCOL_MIN_VERSION..=PROTOCOL_MAX_VERSION).contains(&protocol_version) {
            return Err(ProtocolError::IncompatibleVersion);
        }
        Ok(Self {
            protocol_version,
            _exclusive_connection: PhantomData,
        })
    }

    pub fn protocol_version(&self) -> u16 {
        self.protocol_version
    }

    pub fn request<T: Serialize>(
        &self,
        request_id: impl Into<String>,
        operation_id: Option<String>,
        timeout_ms: u32,
        method: impl Into<String>,
        params: &T,
    ) -> Result<ClientMessage, ProtocolError> {
        Ok(ClientMessage::request(RequestEnvelope::new(
            self.protocol_version,
            request_id,
            operation_id,
            timeout_ms,
            method,
            params,
        )?))
    }

    pub fn cancel(
        &self,
        request_id: impl Into<String>,
        target_request_id: impl Into<String>,
    ) -> Result<ClientMessage, ProtocolError> {
        Ok(ClientMessage::cancel(CancelEnvelope::new(
            self.protocol_version,
            request_id,
            target_request_id,
        )?))
    }

    pub fn response_success<T: Serialize>(
        &self,
        request_id: impl Into<String>,
        operation_id: Option<String>,
        result: &T,
    ) -> Result<ServerMessage, ProtocolError> {
        Ok(ServerMessage::response(ResponseEnvelope::success(
            self.protocol_version,
            request_id,
            operation_id,
            result,
        )?))
    }

    pub fn response_error(
        &self,
        request_id: impl Into<String>,
        operation_id: Option<String>,
        error: AppError,
    ) -> Result<ServerMessage, ProtocolError> {
        Ok(ServerMessage::response(ResponseEnvelope::error(
            self.protocol_version,
            request_id,
            operation_id,
            error,
        )?))
    }

    pub fn event<T: Serialize>(
        &self,
        revision: domain::Revision,
        event: impl Into<String>,
        payload: &T,
    ) -> Result<ServerMessage, ProtocolError> {
        Ok(ServerMessage::event(EventEnvelope::new(
            self.protocol_version,
            revision,
            event,
            payload,
        )?))
    }

    /// Strictly decodes and validates a client payload before exposing it to
    /// Supervisor dispatch code.
    pub fn accept_client_payload(
        &self,
        payload: &[u8],
    ) -> Result<AuthenticatedClientMessage, ProtocolError> {
        match decode_client_payload(payload)? {
            WireClientMessage::Request(request) => Ok(AuthenticatedClientMessage(
                AuthenticatedClientMessageInner::Request(
                    request.into_validated(self.protocol_version)?,
                ),
            )),
            WireClientMessage::Cancel(cancel) => Ok(AuthenticatedClientMessage(
                AuthenticatedClientMessageInner::Cancel(
                    cancel.into_validated(self.protocol_version)?,
                ),
            )),
            other => Err(unexpected("authenticated", other.kind())),
        }
    }

    /// Strictly decodes and validates a server payload before exposing it to
    /// bridge code.
    pub fn accept_server_payload(
        &self,
        payload: &[u8],
    ) -> Result<AuthenticatedServerMessage, ProtocolError> {
        match decode_server_payload(payload)? {
            WireServerMessage::Response(response) => Ok(AuthenticatedServerMessage(
                AuthenticatedServerMessageInner::Response(
                    response.into_validated(self.protocol_version)?,
                ),
            )),
            WireServerMessage::Event(event) => Ok(AuthenticatedServerMessage(
                AuthenticatedServerMessageInner::Event(
                    event.into_validated(self.protocol_version)?,
                ),
            )),
            other => Err(unexpected("authenticated", other.kind())),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthenticatedClientMessageKind {
    Request,
    Cancel,
}

#[derive(Debug, PartialEq)]
pub struct AuthenticatedClientMessage(AuthenticatedClientMessageInner);

#[derive(Debug, PartialEq)]
enum AuthenticatedClientMessageInner {
    Request(RequestEnvelope),
    Cancel(CancelEnvelope),
}

impl AuthenticatedClientMessage {
    pub fn kind(&self) -> AuthenticatedClientMessageKind {
        match self.0 {
            AuthenticatedClientMessageInner::Request(_) => AuthenticatedClientMessageKind::Request,
            AuthenticatedClientMessageInner::Cancel(_) => AuthenticatedClientMessageKind::Cancel,
        }
    }

    pub fn request(&self) -> Option<&RequestEnvelope> {
        match &self.0 {
            AuthenticatedClientMessageInner::Request(request) => Some(request),
            AuthenticatedClientMessageInner::Cancel(_) => None,
        }
    }

    pub fn cancel(&self) -> Option<&CancelEnvelope> {
        match &self.0 {
            AuthenticatedClientMessageInner::Request(_) => None,
            AuthenticatedClientMessageInner::Cancel(cancel) => Some(cancel),
        }
    }

    pub fn into_request(self) -> Result<RequestEnvelope, Self> {
        match self.0 {
            AuthenticatedClientMessageInner::Request(request) => Ok(request),
            other => Err(Self(other)),
        }
    }

    pub fn into_cancel(self) -> Result<CancelEnvelope, Self> {
        match self.0 {
            AuthenticatedClientMessageInner::Cancel(cancel) => Ok(cancel),
            other => Err(Self(other)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthenticatedServerMessageKind {
    Response,
    Event,
}

#[derive(Debug, PartialEq)]
pub struct AuthenticatedServerMessage(AuthenticatedServerMessageInner);

#[derive(Debug, PartialEq)]
enum AuthenticatedServerMessageInner {
    Response(ResponseEnvelope),
    Event(EventEnvelope),
}

impl AuthenticatedServerMessage {
    pub fn kind(&self) -> AuthenticatedServerMessageKind {
        match self.0 {
            AuthenticatedServerMessageInner::Response(_) => {
                AuthenticatedServerMessageKind::Response
            }
            AuthenticatedServerMessageInner::Event(_) => AuthenticatedServerMessageKind::Event,
        }
    }

    pub fn response(&self) -> Option<&ResponseEnvelope> {
        match &self.0 {
            AuthenticatedServerMessageInner::Response(response) => Some(response),
            AuthenticatedServerMessageInner::Event(_) => None,
        }
    }

    pub fn event(&self) -> Option<&EventEnvelope> {
        match &self.0 {
            AuthenticatedServerMessageInner::Response(_) => None,
            AuthenticatedServerMessageInner::Event(event) => Some(event),
        }
    }

    pub fn into_response(self) -> Result<ResponseEnvelope, Self> {
        match self.0 {
            AuthenticatedServerMessageInner::Response(response) => Ok(response),
            other => Err(Self(other)),
        }
    }

    pub fn into_event(self) -> Result<EventEnvelope, Self> {
        match self.0 {
            AuthenticatedServerMessageInner::Event(event) => Ok(event),
            other => Err(Self(other)),
        }
    }
}

fn unexpected(phase: &'static str, message_kind: &'static str) -> ProtocolError {
    ProtocolError::UnexpectedMessage {
        phase,
        message_kind: message_kind.to_owned(),
    }
}

fn peer_rejection(code: HandshakeRejectCode) -> ProtocolError {
    ProtocolError::HandshakeRejected { code }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::names;

    fn payload(message: &impl Serialize) -> Vec<u8> {
        serde_json::to_vec(message).expect("wire payload")
    }

    fn sessions() -> (AuthenticatedSession, AuthenticatedSession) {
        let token = SessionToken::from_bytes([9_u8; 32]);
        let (client, hello) = ClientHandshake::start(token.clone());
        let server = ServerHandshake::new(token);
        let (server, challenge) = server
            .accept_client_payload(&payload(&hello))
            .expect("challenge");
        let (client, proof) = client
            .accept_server_payload(&payload(&challenge))
            .expect("proof");
        let (server_session, accepted) = server
            .accept_client_payload(&payload(&proof))
            .expect("accept");
        let client_session = client
            .accept_server_payload(&payload(&accepted))
            .expect("client session");
        (client_session, server_session)
    }

    #[test]
    fn exposes_business_messages_only_after_payload_validation() {
        let (client, server) = sessions();
        let request = client
            .request(
                "request-1",
                None,
                5_000,
                names::method::SYSTEM_GET_SNAPSHOT,
                &json!({}),
            )
            .expect("request");
        let request = server
            .accept_client_payload(&payload(&request))
            .expect("validated request");

        assert_eq!(request.kind(), AuthenticatedClientMessageKind::Request);
        assert_eq!(
            request.request().map(RequestEnvelope::method),
            Some(names::method::SYSTEM_GET_SNAPSHOT)
        );
    }

    #[test]
    fn authenticated_phase_rejects_handshake_payloads() {
        let (client, _) = sessions();
        let (_, hello) = ClientHandshake::start(SessionToken::from_bytes([8_u8; 32]));
        let result = client.accept_client_payload(&payload(&hello));

        assert!(matches!(
            result,
            Err(ProtocolError::UnexpectedMessage {
                phase: "authenticated",
                ..
            })
        ));
    }
}
