use std::fmt;

use domain::{AppError, MAX_SAFE_REVISION, Revision};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;

use crate::{
    ClientHello, ClientProof, HandshakeAccepted, HandshakeRejected, PROTOCOL_MAX_VERSION,
    PROTOCOL_MIN_VERSION, ProtocolError, ServerChallenge, names,
};

pub const MAX_ID_BYTES: usize = 128;
pub const MAX_METHOD_BYTES: usize = 96;
pub const MIN_TIMEOUT_MS: u32 = 1;
pub const MAX_TIMEOUT_MS: u32 = 120_000;

/// An outbound client message. It can only be produced by a handshake state or
/// an authenticated session and intentionally cannot be deserialized directly.
#[derive(Serialize)]
#[serde(transparent)]
pub struct ClientMessage(WireClientMessage);

impl fmt::Debug for ClientMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClientMessage")
            .field("kind", &self.0.kind())
            .finish_non_exhaustive()
    }
}

impl ClientMessage {
    pub(crate) fn client_hello(hello: ClientHello) -> Self {
        Self(WireClientMessage::ClientHello(hello))
    }

    pub(crate) fn client_proof(proof: ClientProof) -> Self {
        Self(WireClientMessage::ClientProof(proof))
    }

    pub(crate) fn request(request: RequestEnvelope) -> Self {
        Self(WireClientMessage::Request(request.into()))
    }

    pub(crate) fn cancel(cancel: CancelEnvelope) -> Self {
        Self(WireClientMessage::Cancel(cancel.into()))
    }
}

/// An outbound server message. It can only be produced by a handshake state or
/// an authenticated session and intentionally cannot be deserialized directly.
#[derive(Serialize)]
#[serde(transparent)]
pub struct ServerMessage(WireServerMessage);

impl fmt::Debug for ServerMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServerMessage")
            .field("kind", &self.0.kind())
            .finish_non_exhaustive()
    }
}

impl ServerMessage {
    pub(crate) fn server_challenge(challenge: ServerChallenge) -> Self {
        Self(WireServerMessage::ServerChallenge(challenge))
    }

    pub(crate) fn handshake_accepted(accepted: HandshakeAccepted) -> Self {
        Self(WireServerMessage::HandshakeAccepted(accepted))
    }

    pub(crate) fn handshake_rejected(rejected: HandshakeRejected) -> Self {
        Self(WireServerMessage::HandshakeRejected(rejected))
    }

    pub(crate) fn response(response: ResponseEnvelope) -> Self {
        Self(WireServerMessage::Response(response.into()))
    }

    pub(crate) fn event(event: EventEnvelope) -> Self {
        Self(WireServerMessage::Event(event.into()))
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "payload",
    rename_all = "camelCase",
    deny_unknown_fields
)]
pub(crate) enum WireClientMessage {
    ClientHello(ClientHello),
    ClientProof(ClientProof),
    Request(RawRequestEnvelope),
    Cancel(RawCancelEnvelope),
}

impl WireClientMessage {
    pub(crate) fn kind(&self) -> &'static str {
        match self {
            Self::ClientHello(_) => "clientHello",
            Self::ClientProof(_) => "clientProof",
            Self::Request(_) => "request",
            Self::Cancel(_) => "cancel",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "payload",
    rename_all = "camelCase",
    deny_unknown_fields
)]
pub(crate) enum WireServerMessage {
    ServerChallenge(ServerChallenge),
    HandshakeAccepted(HandshakeAccepted),
    HandshakeRejected(HandshakeRejected),
    Response(RawResponseEnvelope),
    Event(RawEventEnvelope),
}

impl WireServerMessage {
    pub(crate) fn kind(&self) -> &'static str {
        match self {
            Self::ServerChallenge(_) => "serverChallenge",
            Self::HandshakeAccepted(_) => "handshakeAccepted",
            Self::HandshakeRejected(_) => "handshakeRejected",
            Self::Response(_) => "response",
            Self::Event(_) => "event",
        }
    }
}

pub(crate) fn decode_client_payload(payload: &[u8]) -> Result<WireClientMessage, ProtocolError> {
    Ok(serde_json::from_slice(payload)?)
}

pub(crate) fn decode_server_payload(payload: &[u8]) -> Result<WireServerMessage, ProtocolError> {
    Ok(serde_json::from_slice(payload)?)
}

#[derive(Clone, PartialEq)]
pub struct RequestEnvelope {
    protocol_version: u16,
    request_id: String,
    operation_id: Option<String>,
    timeout_ms: u32,
    method: String,
    params: Value,
}

impl fmt::Debug for RequestEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RequestEnvelope")
            .field("protocol_version", &self.protocol_version)
            .field("request_id", &self.request_id)
            .field("operation_id", &self.operation_id)
            .field("timeout_ms", &self.timeout_ms)
            .field("method", &self.method)
            .field("params", &"<redacted>")
            .finish()
    }
}

impl RequestEnvelope {
    pub fn protocol_version(&self) -> u16 {
        self.protocol_version
    }

    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    pub fn operation_id(&self) -> Option<&str> {
        self.operation_id.as_deref()
    }

    pub fn timeout_ms(&self) -> u32 {
        self.timeout_ms
    }

    pub fn method(&self) -> &str {
        &self.method
    }

    pub fn params(&self) -> &Value {
        &self.params
    }

    pub fn decode_params<T: DeserializeOwned>(&self) -> Result<T, ProtocolError> {
        Ok(serde_json::from_value(self.params.clone())?)
    }

    pub(crate) fn new<T: Serialize>(
        protocol_version: u16,
        request_id: impl Into<String>,
        operation_id: Option<String>,
        timeout_ms: u32,
        method: impl Into<String>,
        params: &T,
    ) -> Result<Self, ProtocolError> {
        let envelope = Self {
            protocol_version,
            request_id: request_id.into(),
            operation_id,
            timeout_ms,
            method: method.into(),
            params: serde_json::to_value(params)?,
        };
        envelope.validate(protocol_version)?;
        Ok(envelope)
    }

    fn validate(&self, negotiated_version: u16) -> Result<(), ProtocolError> {
        validate_protocol_version(self.protocol_version, negotiated_version)?;
        validate_request_input(
            &self.request_id,
            self.operation_id.as_deref(),
            self.timeout_ms,
            &self.method,
        )
    }
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RawRequestEnvelope {
    protocol_version: u16,
    request_id: String,
    operation_id: Option<String>,
    timeout_ms: u32,
    method: String,
    params: Value,
}

impl fmt::Debug for RawRequestEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RawRequestEnvelope")
            .field("protocol_version", &self.protocol_version)
            .field("request_id", &self.request_id)
            .field("operation_id", &self.operation_id)
            .field("timeout_ms", &self.timeout_ms)
            .field("method", &self.method)
            .field("params", &"<redacted>")
            .finish()
    }
}

impl RawRequestEnvelope {
    pub(crate) fn into_validated(
        self,
        negotiated_version: u16,
    ) -> Result<RequestEnvelope, ProtocolError> {
        let envelope = RequestEnvelope {
            protocol_version: self.protocol_version,
            request_id: self.request_id,
            operation_id: self.operation_id,
            timeout_ms: self.timeout_ms,
            method: self.method,
            params: self.params,
        };
        envelope.validate(negotiated_version)?;
        Ok(envelope)
    }
}

impl From<RequestEnvelope> for RawRequestEnvelope {
    fn from(envelope: RequestEnvelope) -> Self {
        Self {
            protocol_version: envelope.protocol_version,
            request_id: envelope.request_id,
            operation_id: envelope.operation_id,
            timeout_ms: envelope.timeout_ms,
            method: envelope.method,
            params: envelope.params,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ResponseEnvelope {
    protocol_version: u16,
    request_id: String,
    operation_id: Option<String>,
    outcome: ResponseOutcome,
}

impl ResponseEnvelope {
    pub fn protocol_version(&self) -> u16 {
        self.protocol_version
    }

    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    pub fn operation_id(&self) -> Option<&str> {
        self.operation_id.as_deref()
    }

    pub fn outcome(&self) -> &ResponseOutcome {
        &self.outcome
    }

    pub(crate) fn success<T: Serialize>(
        protocol_version: u16,
        request_id: impl Into<String>,
        operation_id: Option<String>,
        result: &T,
    ) -> Result<Self, ProtocolError> {
        let envelope = Self {
            protocol_version,
            request_id: request_id.into(),
            operation_id,
            outcome: ResponseOutcome::Success {
                result: serde_json::to_value(result)?,
            },
        };
        envelope.validate(protocol_version)?;
        Ok(envelope)
    }

    pub(crate) fn error(
        protocol_version: u16,
        request_id: impl Into<String>,
        operation_id: Option<String>,
        mut error: AppError,
    ) -> Result<Self, ProtocolError> {
        error.operation_id.clone_from(&operation_id);
        let envelope = Self {
            protocol_version,
            request_id: request_id.into(),
            operation_id,
            outcome: ResponseOutcome::Error { error },
        };
        envelope.validate(protocol_version)?;
        Ok(envelope)
    }

    fn validate(&self, negotiated_version: u16) -> Result<(), ProtocolError> {
        validate_protocol_version(self.protocol_version, negotiated_version)?;
        validate_id("requestId", &self.request_id)?;
        if let Some(operation_id) = &self.operation_id {
            validate_id("operationId", operation_id)?;
        }
        if let ResponseOutcome::Error { error } = &self.outcome
            && error.operation_id != self.operation_id
        {
            return Err(ProtocolError::InvalidEnvelope {
                field: "error.operationId",
                reason: "must match the response operationId",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum ResponseOutcome {
    Success { result: Value },
    Error { error: AppError },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "camelCase", deny_unknown_fields)]
enum RawResponseOutcome {
    Success { result: Value },
    Error { error: AppError },
}

impl From<ResponseOutcome> for RawResponseOutcome {
    fn from(outcome: ResponseOutcome) -> Self {
        match outcome {
            ResponseOutcome::Success { result } => Self::Success { result },
            ResponseOutcome::Error { error } => Self::Error { error },
        }
    }
}

impl From<RawResponseOutcome> for ResponseOutcome {
    fn from(outcome: RawResponseOutcome) -> Self {
        match outcome {
            RawResponseOutcome::Success { result } => Self::Success { result },
            RawResponseOutcome::Error { error } => Self::Error { error },
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RawResponseEnvelope {
    protocol_version: u16,
    request_id: String,
    operation_id: Option<String>,
    outcome: RawResponseOutcome,
}

impl RawResponseEnvelope {
    pub(crate) fn into_validated(
        self,
        negotiated_version: u16,
    ) -> Result<ResponseEnvelope, ProtocolError> {
        let envelope = ResponseEnvelope {
            protocol_version: self.protocol_version,
            request_id: self.request_id,
            operation_id: self.operation_id,
            outcome: self.outcome.into(),
        };
        envelope.validate(negotiated_version)?;
        Ok(envelope)
    }
}

impl From<ResponseEnvelope> for RawResponseEnvelope {
    fn from(envelope: ResponseEnvelope) -> Self {
        Self {
            protocol_version: envelope.protocol_version,
            request_id: envelope.request_id,
            operation_id: envelope.operation_id,
            outcome: envelope.outcome.into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct EventEnvelope {
    protocol_version: u16,
    revision: Revision,
    event: String,
    payload: Value,
}

impl EventEnvelope {
    pub fn protocol_version(&self) -> u16 {
        self.protocol_version
    }

    pub fn revision(&self) -> Revision {
        self.revision
    }

    pub fn event(&self) -> &str {
        &self.event
    }

    pub fn payload(&self) -> &Value {
        &self.payload
    }

    pub fn decode_payload<T: DeserializeOwned>(&self) -> Result<T, ProtocolError> {
        Ok(serde_json::from_value(self.payload.clone())?)
    }

    pub(crate) fn new<T: Serialize>(
        protocol_version: u16,
        revision: Revision,
        event: impl Into<String>,
        payload: &T,
    ) -> Result<Self, ProtocolError> {
        let envelope = Self {
            protocol_version,
            revision,
            event: event.into(),
            payload: serde_json::to_value(payload)?,
        };
        envelope.validate(protocol_version)?;
        Ok(envelope)
    }

    fn validate(&self, negotiated_version: u16) -> Result<(), ProtocolError> {
        validate_protocol_version(self.protocol_version, negotiated_version)?;
        validate_revision(self.revision)?;
        validate_event(&self.event)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RawEventEnvelope {
    protocol_version: u16,
    revision: Revision,
    event: String,
    payload: Value,
}

impl RawEventEnvelope {
    pub(crate) fn into_validated(
        self,
        negotiated_version: u16,
    ) -> Result<EventEnvelope, ProtocolError> {
        let envelope = EventEnvelope {
            protocol_version: self.protocol_version,
            revision: self.revision,
            event: self.event,
            payload: self.payload,
        };
        envelope.validate(negotiated_version)?;
        Ok(envelope)
    }
}

impl From<EventEnvelope> for RawEventEnvelope {
    fn from(envelope: EventEnvelope) -> Self {
        Self {
            protocol_version: envelope.protocol_version,
            revision: envelope.revision,
            event: envelope.event,
            payload: envelope.payload,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CancelEnvelope {
    protocol_version: u16,
    request_id: String,
    target_request_id: String,
}

impl CancelEnvelope {
    pub fn protocol_version(&self) -> u16 {
        self.protocol_version
    }

    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    pub fn target_request_id(&self) -> &str {
        &self.target_request_id
    }

    pub(crate) fn new(
        protocol_version: u16,
        request_id: impl Into<String>,
        target_request_id: impl Into<String>,
    ) -> Result<Self, ProtocolError> {
        let envelope = Self {
            protocol_version,
            request_id: request_id.into(),
            target_request_id: target_request_id.into(),
        };
        envelope.validate(protocol_version)?;
        Ok(envelope)
    }

    fn validate(&self, negotiated_version: u16) -> Result<(), ProtocolError> {
        validate_protocol_version(self.protocol_version, negotiated_version)?;
        validate_cancel_input(&self.request_id, &self.target_request_id)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RawCancelEnvelope {
    protocol_version: u16,
    request_id: String,
    target_request_id: String,
}

impl RawCancelEnvelope {
    pub(crate) fn into_validated(
        self,
        negotiated_version: u16,
    ) -> Result<CancelEnvelope, ProtocolError> {
        let envelope = CancelEnvelope {
            protocol_version: self.protocol_version,
            request_id: self.request_id,
            target_request_id: self.target_request_id,
        };
        envelope.validate(negotiated_version)?;
        Ok(envelope)
    }
}

impl From<CancelEnvelope> for RawCancelEnvelope {
    fn from(envelope: CancelEnvelope) -> Self {
        Self {
            protocol_version: envelope.protocol_version,
            request_id: envelope.request_id,
            target_request_id: envelope.target_request_id,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CancelDisposition {
    Accepted,
    NotFound,
    AlreadyCompleted,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CancelResult {
    pub target_request_id: String,
    pub disposition: CancelDisposition,
}

impl CancelResult {
    pub fn new(
        target_request_id: impl Into<String>,
        disposition: CancelDisposition,
    ) -> Result<Self, ProtocolError> {
        let result = Self {
            target_request_id: target_request_id.into(),
            disposition,
        };
        validate_id("targetRequestId", &result.target_request_id)?;
        Ok(result)
    }
}

fn validate_protocol_version(received: u16, negotiated: u16) -> Result<(), ProtocolError> {
    if !(PROTOCOL_MIN_VERSION..=PROTOCOL_MAX_VERSION).contains(&negotiated) {
        return Err(ProtocolError::IncompatibleVersion);
    }
    if received != negotiated {
        return Err(ProtocolError::InvalidProtocolVersion {
            received,
            negotiated,
        });
    }
    Ok(())
}

pub fn validate_request_input(
    request_id: &str,
    operation_id: Option<&str>,
    timeout_ms: u32,
    method: &str,
) -> Result<(), ProtocolError> {
    validate_id("requestId", request_id)?;
    if let Some(operation_id) = operation_id {
        validate_id("operationId", operation_id)?;
    }
    let metadata = validate_method(method)?;
    if !(MIN_TIMEOUT_MS..=MAX_TIMEOUT_MS).contains(&timeout_ms) {
        return Err(ProtocolError::InvalidEnvelope {
            field: "timeoutMs",
            reason: "must be between 1 and 120000 milliseconds",
        });
    }
    if metadata.mutating && operation_id.is_none() {
        return Err(ProtocolError::InvalidEnvelope {
            field: "operationId",
            reason: "is required for mutating methods",
        });
    }
    Ok(())
}

pub fn validate_cancel_input(
    request_id: &str,
    target_request_id: &str,
) -> Result<(), ProtocolError> {
    validate_id("requestId", request_id)?;
    validate_id("targetRequestId", target_request_id)?;
    if request_id == target_request_id {
        return Err(ProtocolError::InvalidEnvelope {
            field: "targetRequestId",
            reason: "must differ from the cancellation requestId",
        });
    }
    Ok(())
}

pub fn validate_revision(revision: Revision) -> Result<(), ProtocolError> {
    if (1..=MAX_SAFE_REVISION).contains(&revision) {
        Ok(())
    } else {
        Err(ProtocolError::InvalidEnvelope {
            field: "revision",
            reason: "must be between 1 and 9007199254740991",
        })
    }
}

fn validate_id(field: &'static str, value: &str) -> Result<(), ProtocolError> {
    if value.is_empty() {
        return Err(ProtocolError::InvalidEnvelope {
            field,
            reason: "must not be empty",
        });
    }
    if value.len() > MAX_ID_BYTES {
        return Err(ProtocolError::InvalidEnvelope {
            field,
            reason: "exceeds the 128-byte limit",
        });
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(ProtocolError::InvalidEnvelope {
            field,
            reason: "must contain only ASCII letters, digits, '-', '_', '.', or ':'",
        });
    }
    Ok(())
}

fn validate_method(value: &str) -> Result<&'static names::method::MethodMetadata, ProtocolError> {
    validate_name("method", value, MAX_METHOD_BYTES)?;
    names::method::metadata(value).ok_or(ProtocolError::InvalidEnvelope {
        field: "method",
        reason: "is not a supported RPC method",
    })
}

fn validate_event(value: &str) -> Result<(), ProtocolError> {
    validate_name("event", value, MAX_METHOD_BYTES)?;
    if names::event::is_known(value) {
        Ok(())
    } else {
        Err(ProtocolError::InvalidEnvelope {
            field: "event",
            reason: "is not a supported event",
        })
    }
}

fn validate_name(field: &'static str, value: &str, maximum: usize) -> Result<(), ProtocolError> {
    if value.is_empty() {
        return Err(ProtocolError::InvalidEnvelope {
            field,
            reason: "must not be empty",
        });
    }
    if value.len() > maximum {
        return Err(ProtocolError::InvalidEnvelope {
            field,
            reason: "exceeds the 96-byte limit",
        });
    }
    if !value.bytes().all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_')
    }) {
        return Err(ProtocolError::InvalidEnvelope {
            field,
            reason: "must contain only lowercase ASCII letters, digits, '.', or '_'",
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use domain::{AppError, ErrorCode};
    use serde_json::json;

    use super::*;

    #[test]
    fn raw_messages_reject_unknown_outer_fields() {
        let client_message = json!({
            "kind": "request",
            "payload": {
                "protocolVersion": 1,
                "requestId": "request-1",
                "operationId": null,
                "timeoutMs": 5000,
                "method": names::method::SYSTEM_GET_SNAPSHOT,
                "params": {}
            },
            "unexpected": true
        });
        let response_outcome = json!({
            "status": "success",
            "result": {},
            "unexpected": true
        });

        assert!(serde_json::from_value::<WireClientMessage>(client_message).is_err());
        assert!(serde_json::from_value::<RawResponseOutcome>(response_outcome).is_err());
    }

    #[test]
    fn mutating_methods_require_operation_ids_and_unknown_names_fail() {
        assert!(
            RequestEnvelope::new(
                1,
                "request-1",
                None,
                5_000,
                names::method::RUN_STOP,
                &json!({})
            )
            .is_err()
        );
        assert!(
            RequestEnvelope::new(1, "request-1", None, 5_000, "unknown.method", &json!({}))
                .is_err()
        );
        assert!(EventEnvelope::new(1, 1, "unknown.event", &json!({})).is_err());
    }

    #[test]
    fn error_responses_bind_the_operation_id() {
        let response = ResponseEnvelope::error(
            1,
            "request-1",
            Some("operation-1".to_owned()),
            AppError::new(ErrorCode::Conflict, "already stopping"),
        )
        .expect("response");

        let ResponseOutcome::Error { error } = response.outcome() else {
            panic!("expected error");
        };
        assert_eq!(error.operation_id.as_deref(), Some("operation-1"));
    }

    #[test]
    fn event_revisions_must_be_safe_positive_javascript_integers() {
        assert!(EventEnvelope::new(1, 0, names::event::PROCESS_DELTA, &json!({})).is_err());
        assert!(
            EventEnvelope::new(
                1,
                domain::MAX_SAFE_REVISION,
                names::event::PROCESS_DELTA,
                &json!({})
            )
            .is_ok()
        );
        assert!(
            EventEnvelope::new(
                1,
                domain::MAX_SAFE_REVISION + 1,
                names::event::PROCESS_DELTA,
                &json!({})
            )
            .is_err()
        );
    }
}
