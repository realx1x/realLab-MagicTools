use std::collections::HashMap;
use std::fmt;
use std::future::pending;
use std::io::{self, Write};
use std::time::Duration;

use domain::{AppError, ErrorCode};
use protocol::{
    AsyncProtocolError, AuthenticatedClientConnection, AuthenticatedServerMessageKind,
    ConnectionState, DisconnectReason, ResponseOutcome, SessionToken, SessionTokenReadError,
    TransportErrorKind, read_current_session_token, validate_cancel_input, validate_request_input,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::{Instant, sleep, sleep_until, timeout};

const COMMAND_QUEUE_CAPACITY: usize = 64;
const MAX_PENDING_REQUESTS: usize = 256;
const QUEUE_WAIT: Duration = Duration::from_secs(1);
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);
const CANCEL_TIMEOUT: Duration = Duration::from_secs(5);
const COMMAND_REPLY_GRACE: Duration = Duration::from_secs(2);
const TOKEN_READ_TIMEOUT: Duration = Duration::from_secs(2);
const TOKEN_RETRY: Duration = Duration::from_millis(500);
const CONNECTION_RETRY: Duration = Duration::from_secs(1);
const TERMINAL_CONNECTION_RETRY: Duration = Duration::from_secs(30);

const RPC_PARAMS_FRAME_HEADROOM_BYTES: usize = 256 * 1024;
const MAX_RPC_PARAMS_ENCODED_BYTES: usize = 768 * 1024;
const MAX_RPC_PARAMS_DEPTH: usize = 32;
const MAX_RPC_PARAMS_NODES: usize = 8_192;
const MAX_RPC_PARAMS_OBJECT_KEYS: usize = 1_024;
const MAX_RPC_PARAMS_ARRAY_ITEMS: usize = 4_096;
const MAX_RPC_PARAMS_STRING_BYTES: usize = 64 * 1024;
const MAX_RPC_PARAMS_KEY_BYTES: usize = 256;

const _: () = assert!(
    MAX_RPC_PARAMS_ENCODED_BYTES + RPC_PARAMS_FRAME_HEADROOM_BYTES <= protocol::MAX_FRAME_BYTES
);

const CONNECTION_STATE_EVENT: &str = "supervisor://connection-state";
const SUPERVISOR_EVENT: &str = "supervisor://event";

#[cfg(windows)]
type PlatformConnector = protocol::windows_pipe::WindowsPipeClient;
#[cfg(windows)]
type PlatformStream = tokio::net::windows::named_pipe::NamedPipeClient;

#[cfg(target_os = "macos")]
type PlatformConnector = protocol::macos_socket::MacOsSocketClient;
#[cfg(target_os = "macos")]
type PlatformStream = tokio::net::UnixStream;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct BridgeRpcRequest {
    request_id: String,
    operation_id: Option<String>,
    timeout_ms: u32,
    method: String,
    params: Value,
}

impl fmt::Debug for BridgeRpcRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BridgeRpcRequest")
            .field("request_id", &self.request_id)
            .field("operation_id", &self.operation_id)
            .field("timeout_ms", &self.timeout_ms)
            .field("method", &self.method)
            .field("params", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct BridgeCancelRequest {
    request_id: String,
    target_request_id: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RpcParamsViolation {
    EncodedBytes,
    Depth,
    Nodes,
    ObjectKeys,
    ArrayItems,
    StringBytes,
    KeyBytes,
    NonFiniteNumber,
    JsonEncoding,
}

impl RpcParamsViolation {
    fn validation(self) -> &'static str {
        match self {
            Self::EncodedBytes => "params exceeds the 786432-byte encoded JSON limit",
            Self::Depth => "params exceeds the 32-level nesting limit",
            Self::Nodes => "params exceeds the 8192-node limit",
            Self::ObjectKeys => "a params object exceeds the 1024-key limit",
            Self::ArrayItems => "a params array exceeds the 4096-item limit",
            Self::StringBytes => "a params string exceeds the 65536-byte UTF-8 limit",
            Self::KeyBytes => "a params object key exceeds the 256-byte UTF-8 limit",
            Self::NonFiniteNumber => "params contains a non-finite JSON number",
            Self::JsonEncoding => "params could not be encoded as JSON",
        }
    }
}

#[derive(Debug, Default)]
struct BoundedJsonByteCounter {
    encoded_bytes: usize,
    limit_exceeded: bool,
}

impl Write for BoundedJsonByteCounter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let Some(encoded_bytes) = self.encoded_bytes.checked_add(buffer.len()) else {
            self.limit_exceeded = true;
            return Err(io::Error::other("JSON byte count overflowed"));
        };
        if encoded_bytes > MAX_RPC_PARAMS_ENCODED_BYTES {
            self.limit_exceeded = true;
            return Err(io::Error::other("JSON byte limit exceeded"));
        }
        self.encoded_bytes = encoded_bytes;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SupervisorEventPayload {
    generation: u64,
    revision: domain::Revision,
    event: String,
    payload: Value,
}

pub(crate) struct BridgeHandle {
    commands: mpsc::Sender<BridgeCommand>,
    connection_state: watch::Receiver<ConnectionState>,
    shutdown: watch::Sender<bool>,
}

impl BridgeHandle {
    fn new(app: AppHandle) -> Self {
        let (commands, command_rx) = mpsc::channel(COMMAND_QUEUE_CAPACITY);
        let (connection_state_tx, connection_state) =
            watch::channel(ConnectionState::Disconnected { reason: None });
        let (shutdown, shutdown_rx) = watch::channel(false);
        tauri::async_runtime::spawn(run_bridge_actor(
            app,
            command_rx,
            connection_state_tx,
            shutdown_rx,
        ));
        Self {
            commands,
            connection_state,
            shutdown,
        }
    }

    fn state(&self) -> ConnectionState {
        self.connection_state.borrow().clone()
    }
}

impl Drop for BridgeHandle {
    fn drop(&mut self) {
        self.shutdown.send_replace(true);
    }
}

enum BridgeCommand {
    Rpc {
        request: BridgeRpcRequest,
        reply: oneshot::Sender<Result<Value, AppError>>,
    },
    Cancel {
        request: BridgeCancelRequest,
        reply: oneshot::Sender<Result<Value, AppError>>,
    },
    ResetConnection {
        reply: oneshot::Sender<()>,
    },
}

struct PendingRequest {
    operation_id: Option<String>,
    deadline: Instant,
    reply: oneshot::Sender<Result<Value, AppError>>,
}

pub(crate) fn setup(app: &mut tauri::App) -> Result<(), Box<dyn std::error::Error>> {
    let bridge = BridgeHandle::new(app.handle().clone());
    if !app.manage(bridge) {
        return Err("Supervisor Bridge state was already initialized".into());
    }
    Ok(())
}

#[tauri::command]
pub(crate) fn supervisor_connection_state(bridge: State<'_, BridgeHandle>) -> ConnectionState {
    bridge.state()
}

#[tauri::command]
pub(crate) async fn supervisor_forward_rpc(
    request: BridgeRpcRequest,
    bridge: State<'_, BridgeHandle>,
) -> Result<Value, AppError> {
    validate_request_input(
        &request.request_id,
        request.operation_id.as_deref(),
        request.timeout_ms,
        &request.method,
    )
    .map_err(invalid_request_error)?;
    validate_rpc_params(&request.params).map_err(invalid_rpc_params_error)?;

    let wait = Duration::from_millis(u64::from(request.timeout_ms)) + COMMAND_REPLY_GRACE;
    let (reply, receiver) = oneshot::channel();
    enqueue(&bridge.commands, BridgeCommand::Rpc { request, reply }).await?;
    await_reply(receiver, wait).await
}

#[tauri::command]
pub(crate) async fn supervisor_cancel_request(
    request: BridgeCancelRequest,
    bridge: State<'_, BridgeHandle>,
) -> Result<Value, AppError> {
    validate_cancel_input(&request.request_id, &request.target_request_id)
        .map_err(invalid_request_error)?;

    let (reply, receiver) = oneshot::channel();
    enqueue(&bridge.commands, BridgeCommand::Cancel { request, reply }).await?;
    await_reply(receiver, CANCEL_TIMEOUT + COMMAND_REPLY_GRACE).await
}

#[tauri::command]
pub(crate) async fn supervisor_reset_connection(
    bridge: State<'_, BridgeHandle>,
) -> Result<(), AppError> {
    let (reply, receiver) = oneshot::channel();
    enqueue(&bridge.commands, BridgeCommand::ResetConnection { reply }).await?;
    match timeout(COMMAND_REPLY_GRACE, receiver).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(_)) => Err(supervisor_unavailable_error(None)),
        Err(_) => Err(timeout_error(None)),
    }
}

async fn enqueue(
    commands: &mpsc::Sender<BridgeCommand>,
    command: BridgeCommand,
) -> Result<(), AppError> {
    match timeout(QUEUE_WAIT, commands.send(command)).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(_)) => Err(supervisor_unavailable_error(None)),
        Err(_) => Err(bridge_busy_error()),
    }
}

async fn await_reply(
    receiver: oneshot::Receiver<Result<Value, AppError>>,
    maximum: Duration,
) -> Result<Value, AppError> {
    match timeout(maximum, receiver).await {
        Ok(Ok(result)) => result,
        Ok(Err(_)) => Err(supervisor_unavailable_error(None)),
        Err(_) => Err(timeout_error(None)),
    }
}

fn validate_rpc_params(params: &Value) -> Result<(), RpcParamsViolation> {
    let mut stack = vec![(params, 1_usize)];
    let mut nodes = 1_usize;
    let mut encoded_bytes = 0_usize;

    while let Some((value, depth)) = stack.pop() {
        if depth > MAX_RPC_PARAMS_DEPTH {
            return Err(RpcParamsViolation::Depth);
        }

        match value {
            Value::Null => add_encoded_bytes(&mut encoded_bytes, 4)?,
            Value::Bool(value) => {
                add_encoded_bytes(&mut encoded_bytes, if *value { 4 } else { 5 })?
            }
            Value::Number(value) => {
                if !value.as_f64().is_some_and(f64::is_finite) {
                    return Err(RpcParamsViolation::NonFiniteNumber);
                }
                add_encoded_bytes(&mut encoded_bytes, value.to_string().len())?;
            }
            Value::String(value) => {
                if value.len() > MAX_RPC_PARAMS_STRING_BYTES {
                    return Err(RpcParamsViolation::StringBytes);
                }
                add_encoded_bytes(&mut encoded_bytes, encoded_json_string_bytes(value)?)?;
            }
            Value::Array(values) => {
                if values.len() > MAX_RPC_PARAMS_ARRAY_ITEMS {
                    return Err(RpcParamsViolation::ArrayItems);
                }
                add_encoded_bytes(
                    &mut encoded_bytes,
                    2_usize.saturating_add(values.len().saturating_sub(1)),
                )?;
                let child_depth = validate_child_depth(depth, values.len())?;
                add_nodes(&mut nodes, values.len())?;
                stack.extend(values.iter().map(|value| (value, child_depth)));
            }
            Value::Object(values) => {
                if values.len() > MAX_RPC_PARAMS_OBJECT_KEYS {
                    return Err(RpcParamsViolation::ObjectKeys);
                }
                add_encoded_bytes(
                    &mut encoded_bytes,
                    2_usize.saturating_add(values.len().saturating_sub(1)),
                )?;
                let child_depth = validate_child_depth(depth, values.len())?;
                add_nodes(&mut nodes, values.len())?;
                for (key, value) in values {
                    if key.len() > MAX_RPC_PARAMS_KEY_BYTES {
                        return Err(RpcParamsViolation::KeyBytes);
                    }
                    add_encoded_bytes(
                        &mut encoded_bytes,
                        encoded_json_string_bytes(key)?.saturating_add(1),
                    )?;
                    stack.push((value, child_depth));
                }
            }
        }
    }

    let mut exact_counter = BoundedJsonByteCounter::default();
    match serde_json::to_writer(&mut exact_counter, params) {
        Ok(()) => {
            debug_assert_eq!(encoded_bytes, exact_counter.encoded_bytes);
            Ok(())
        }
        Err(_) if exact_counter.limit_exceeded => Err(RpcParamsViolation::EncodedBytes),
        Err(_) => Err(RpcParamsViolation::JsonEncoding),
    }
}

fn validate_child_depth(
    parent_depth: usize,
    child_count: usize,
) -> Result<usize, RpcParamsViolation> {
    if child_count == 0 {
        return Ok(parent_depth);
    }
    parent_depth
        .checked_add(1)
        .filter(|depth| *depth <= MAX_RPC_PARAMS_DEPTH)
        .ok_or(RpcParamsViolation::Depth)
}

fn add_nodes(total: &mut usize, additional: usize) -> Result<(), RpcParamsViolation> {
    *total = total
        .checked_add(additional)
        .filter(|nodes| *nodes <= MAX_RPC_PARAMS_NODES)
        .ok_or(RpcParamsViolation::Nodes)?;
    Ok(())
}

fn encoded_json_string_bytes(value: &str) -> Result<usize, RpcParamsViolation> {
    let mut encoded_bytes = 2_usize;
    for byte in value.bytes() {
        let byte_length = match byte {
            b'"' | b'\\' | b'\x08' | b'\t' | b'\n' | b'\x0c' | b'\r' => 2,
            b'\x00'..=b'\x1f' => 6,
            _ => 1,
        };
        encoded_bytes = encoded_bytes
            .checked_add(byte_length)
            .ok_or(RpcParamsViolation::EncodedBytes)?;
    }
    Ok(encoded_bytes)
}

fn add_encoded_bytes(total: &mut usize, additional: usize) -> Result<(), RpcParamsViolation> {
    *total = total
        .checked_add(additional)
        .filter(|total| *total <= MAX_RPC_PARAMS_ENCODED_BYTES)
        .ok_or(RpcParamsViolation::EncodedBytes)?;
    Ok(())
}

async fn run_bridge_actor(
    app: AppHandle,
    mut commands: mpsc::Receiver<BridgeCommand>,
    state_tx: watch::Sender<ConnectionState>,
    mut shutdown: watch::Receiver<bool>,
) {
    publish_state(
        &app,
        &state_tx,
        ConnectionState::Disconnected { reason: None },
    );

    let mut connector = loop {
        match new_platform_connector() {
            Ok(connector) => break connector,
            Err(()) => {
                publish_state(
                    &app,
                    &state_tx,
                    ConnectionState::Disconnected {
                        reason: Some(DisconnectReason::EndpointUnavailable),
                    },
                );
                if !wait_while_unavailable(&mut commands, &mut shutdown, CONNECTION_RETRY).await {
                    publish_state(&app, &state_tx, ConnectionState::ShuttingDown);
                    return;
                }
            }
        }
    };
    let mut connector_state = connector.subscribe();

    loop {
        let token = match read_token_while_serving(&mut commands, &mut shutdown).await {
            TokenOutcome::Ready(token) => token,
            TokenOutcome::Unavailable { access_denied } => {
                let state = if access_denied {
                    ConnectionState::AccessDenied
                } else {
                    ConnectionState::Disconnected {
                        reason: Some(DisconnectReason::EndpointUnavailable),
                    }
                };
                publish_state(&app, &state_tx, state);
                let retry = if access_denied {
                    TERMINAL_CONNECTION_RETRY
                } else {
                    TOKEN_RETRY
                };
                if !wait_while_unavailable(&mut commands, &mut shutdown, retry).await {
                    connector.mark_shutting_down();
                    publish_state(&app, &state_tx, ConnectionState::ShuttingDown);
                    return;
                }
                continue;
            }
            TokenOutcome::Closed => {
                connector.mark_shutting_down();
                publish_state(&app, &state_tx, ConnectionState::ShuttingDown);
                return;
            }
        };

        let connection = match connect_while_serving(
            &mut connector,
            token,
            &mut connector_state,
            &mut commands,
            &mut shutdown,
            &app,
            &state_tx,
        )
        .await
        {
            ConnectOutcome::Connected(connection) => connection,
            ConnectOutcome::Retry => {
                let connector_state = connector.state();
                publish_state(&app, &state_tx, connector_state.clone());
                let retry = if matches!(
                    connector_state,
                    ConnectionState::AccessDenied | ConnectionState::IncompatibleVersion
                ) {
                    TERMINAL_CONNECTION_RETRY
                } else {
                    CONNECTION_RETRY
                };
                if !wait_while_unavailable(&mut commands, &mut shutdown, retry).await {
                    connector.mark_shutting_down();
                    publish_state(&app, &state_tx, ConnectionState::ShuttingDown);
                    return;
                }
                continue;
            }
            ConnectOutcome::Closed => {
                connector.mark_shutting_down();
                publish_state(&app, &state_tx, ConnectionState::ShuttingDown);
                return;
            }
        };
        publish_state(&app, &state_tx, connector.state());

        let ended = run_connected(connection, &mut commands, &mut shutdown, &app).await;
        connector.record_disconnected(ended.reason.clone());
        publish_state(&app, &state_tx, connector.state());
        if ended.closed {
            connector.mark_shutting_down();
            publish_state(&app, &state_tx, ConnectionState::ShuttingDown);
            return;
        }
    }
}

enum TokenOutcome {
    Ready(SessionToken),
    Unavailable { access_denied: bool },
    Closed,
}

async fn read_token_while_serving(
    commands: &mut mpsc::Receiver<BridgeCommand>,
    shutdown: &mut watch::Receiver<bool>,
) -> TokenOutcome {
    let task = tauri::async_runtime::spawn_blocking(read_current_session_token);
    tokio::pin!(task);
    let token_deadline = sleep(TOKEN_READ_TIMEOUT);
    tokio::pin!(token_deadline);
    loop {
        tokio::select! {
            result = &mut task => {
                return match result {
                    Ok(Ok(token)) => TokenOutcome::Ready(token),
                    Ok(Err(error)) => TokenOutcome::Unavailable {
                        access_denied: token_access_denied(&error),
                    },
                    Err(_) => TokenOutcome::Unavailable { access_denied: false },
                };
            }
            _ = &mut token_deadline => {
                task.abort();
                return TokenOutcome::Unavailable { access_denied: false };
            }
            command = commands.recv() => match command {
                Some(command) => fail_command(command, supervisor_unavailable_error(None)),
                None => return TokenOutcome::Closed,
            },
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return TokenOutcome::Closed;
                }
            }
        }
    }
}

enum ConnectOutcome {
    Connected(AuthenticatedClientConnection<PlatformStream>),
    Retry,
    Closed,
}

#[allow(clippy::too_many_arguments)]
async fn connect_while_serving(
    connector: &mut PlatformConnector,
    token: SessionToken,
    connector_state: &mut watch::Receiver<ConnectionState>,
    commands: &mut mpsc::Receiver<BridgeCommand>,
    shutdown: &mut watch::Receiver<bool>,
    app: &AppHandle,
    state_tx: &watch::Sender<ConnectionState>,
) -> ConnectOutcome {
    let connect = connector.connect_authenticated(token, shutdown);
    tokio::pin!(connect);
    loop {
        tokio::select! {
            result = &mut connect => {
                return match result {
                    Ok(connection) => ConnectOutcome::Connected(connection),
                    Err(_) => ConnectOutcome::Retry,
                };
            }
            changed = connector_state.changed() => {
                if changed.is_ok() {
                    publish_state(app, state_tx, connector_state.borrow().clone());
                }
            }
            command = commands.recv() => match command {
                Some(command) => fail_command(command, supervisor_unavailable_error(None)),
                None => return ConnectOutcome::Closed,
            },
        }
    }
}

struct ConnectionEnded {
    reason: DisconnectReason,
    closed: bool,
}

async fn run_connected<S>(
    mut connection: AuthenticatedClientConnection<S>,
    commands: &mut mpsc::Receiver<BridgeCommand>,
    shutdown: &mut watch::Receiver<bool>,
    app: &AppHandle,
) -> ConnectionEnded
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let generation = connection.generation();
    let mut pending_requests = HashMap::<String, PendingRequest>::new();
    loop {
        let deadline = pending_requests
            .values()
            .map(|pending| pending.deadline)
            .min();
        let deadline_wait = async move {
            match deadline {
                Some(deadline) => sleep_until(deadline).await,
                None => pending::<()>().await,
            }
        };
        tokio::pin!(deadline_wait);

        tokio::select! {
            incoming = connection.accept_server_payload() => match incoming {
                Ok(message) => {
                    if let Err(reason) =
                        handle_server_message(message, generation, &mut pending_requests, app)
                    {
                        fail_all_pending(&mut pending_requests);
                        return ConnectionEnded { reason, closed: false };
                    }
                }
                Err(error) => {
                    fail_all_pending(&mut pending_requests);
                    return ConnectionEnded {
                        reason: disconnect_reason(&error),
                        closed: false,
                    };
                }
            },
            command = commands.recv() => match command {
                Some(command) => {
                    if let Err(reason) = handle_connected_command(
                        command,
                        &mut connection,
                        &mut pending_requests,
                    ).await {
                        fail_all_pending(&mut pending_requests);
                        return ConnectionEnded { reason, closed: false };
                    }
                }
                None => {
                    fail_all_pending(&mut pending_requests);
                    return ConnectionEnded {
                        reason: DisconnectReason::PeerClosed,
                        closed: true,
                    };
                }
            },
            _ = &mut deadline_wait => expire_pending(&mut pending_requests),
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    fail_all_pending(&mut pending_requests);
                    return ConnectionEnded {
                        reason: DisconnectReason::PeerClosed,
                        closed: true,
                    };
                }
            }
        }
    }
}

async fn handle_connected_command<S>(
    command: BridgeCommand,
    connection: &mut AuthenticatedClientConnection<S>,
    pending_requests: &mut HashMap<String, PendingRequest>,
) -> Result<(), DisconnectReason>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let command = match command {
        BridgeCommand::ResetConnection { reply } => {
            let _ = reply.send(());
            return Err(DisconnectReason::ProtocolViolation);
        }
        command => command,
    };
    if pending_requests.len() >= MAX_PENDING_REQUESTS {
        fail_command(command, bridge_busy_error());
        return Ok(());
    }

    match command {
        BridgeCommand::Rpc { request, reply } => {
            if pending_requests.contains_key(&request.request_id) {
                let _ = reply.send(Err(duplicate_request_error(&request.request_id)));
                return Ok(());
            }
            let send = connection.send_request(
                request.request_id.clone(),
                request.operation_id.clone(),
                request.timeout_ms,
                request.method,
                &request.params,
            );
            match timeout(WRITE_TIMEOUT, send).await {
                Ok(Ok(())) => {
                    pending_requests.insert(
                        request.request_id,
                        PendingRequest {
                            operation_id: request.operation_id,
                            deadline: Instant::now()
                                + Duration::from_millis(u64::from(request.timeout_ms)),
                            reply,
                        },
                    );
                    Ok(())
                }
                Ok(Err(AsyncProtocolError::Protocol(error))) => {
                    let _ = reply.send(Err(invalid_request_error(error)));
                    Ok(())
                }
                Ok(Err(error)) => {
                    let _ = reply.send(Err(supervisor_unavailable_error(request.operation_id)));
                    Err(disconnect_reason(&error))
                }
                Err(_) => {
                    let _ = reply.send(Err(supervisor_unavailable_error(request.operation_id)));
                    Err(DisconnectReason::Transport { raw_os_error: None })
                }
            }
        }
        BridgeCommand::Cancel { request, reply } => {
            if pending_requests.contains_key(&request.request_id) {
                let _ = reply.send(Err(duplicate_request_error(&request.request_id)));
                return Ok(());
            }
            let send =
                connection.send_cancel(request.request_id.clone(), request.target_request_id);
            match timeout(WRITE_TIMEOUT, send).await {
                Ok(Ok(())) => {
                    pending_requests.insert(
                        request.request_id,
                        PendingRequest {
                            operation_id: None,
                            deadline: Instant::now() + CANCEL_TIMEOUT,
                            reply,
                        },
                    );
                    Ok(())
                }
                Ok(Err(AsyncProtocolError::Protocol(error))) => {
                    let _ = reply.send(Err(invalid_request_error(error)));
                    Ok(())
                }
                Ok(Err(error)) => {
                    let _ = reply.send(Err(supervisor_unavailable_error(None)));
                    Err(disconnect_reason(&error))
                }
                Err(_) => {
                    let _ = reply.send(Err(supervisor_unavailable_error(None)));
                    Err(DisconnectReason::Transport { raw_os_error: None })
                }
            }
        }
        BridgeCommand::ResetConnection { .. } => {
            unreachable!("reset commands return before pending request handling")
        }
    }
}

fn handle_server_message(
    message: protocol::AuthenticatedServerMessage,
    generation: u64,
    pending_requests: &mut HashMap<String, PendingRequest>,
    app: &AppHandle,
) -> Result<(), DisconnectReason> {
    match message.kind() {
        AuthenticatedServerMessageKind::Response => {
            let response = message
                .into_response()
                .expect("the authenticated response kind was checked");
            let Some(pending) = pending_requests.remove(response.request_id()) else {
                return Ok(());
            };
            if pending.operation_id.as_deref() != response.operation_id() {
                let _ = pending.reply.send(Err(protocol_violation_error(
                    pending.operation_id,
                    "response operationId did not match the pending request",
                )));
                return Err(DisconnectReason::ProtocolViolation);
            }
            let result = match response.outcome().clone() {
                ResponseOutcome::Success { result } => Ok(result),
                ResponseOutcome::Error { error } => Err(error),
            };
            let _ = pending.reply.send(result);
        }
        AuthenticatedServerMessageKind::Event => {
            let event = message
                .into_event()
                .expect("the authenticated event kind was checked");
            let payload = SupervisorEventPayload {
                generation,
                revision: event.revision(),
                event: event.event().to_owned(),
                payload: event.payload().clone(),
            };
            let _ = app.emit(SUPERVISOR_EVENT, payload);
        }
    }
    Ok(())
}

fn expire_pending(pending_requests: &mut HashMap<String, PendingRequest>) {
    let now = Instant::now();
    let expired = pending_requests
        .iter()
        .filter_map(|(request_id, pending)| (pending.deadline <= now).then(|| request_id.clone()))
        .collect::<Vec<_>>();
    for request_id in expired {
        if let Some(pending) = pending_requests.remove(&request_id) {
            let _ = pending.reply.send(Err(timeout_error(pending.operation_id)));
        }
    }
}

fn fail_all_pending(pending_requests: &mut HashMap<String, PendingRequest>) {
    for (_, pending) in pending_requests.drain() {
        let _ = pending
            .reply
            .send(Err(supervisor_unavailable_error(pending.operation_id)));
    }
}

async fn wait_while_unavailable(
    commands: &mut mpsc::Receiver<BridgeCommand>,
    shutdown: &mut watch::Receiver<bool>,
    duration: Duration,
) -> bool {
    let delay = sleep(duration);
    tokio::pin!(delay);
    loop {
        tokio::select! {
            _ = &mut delay => return true,
            command = commands.recv() => match command {
                Some(command) => fail_command(command, supervisor_unavailable_error(None)),
                None => return false,
            },
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return false;
                }
            }
        }
    }
}

fn fail_command(command: BridgeCommand, error: AppError) {
    match command {
        BridgeCommand::Rpc { reply, .. } | BridgeCommand::Cancel { reply, .. } => {
            let _ = reply.send(Err(error));
        }
        BridgeCommand::ResetConnection { reply } => {
            let _ = reply.send(());
        }
    }
}

fn publish_state(
    app: &AppHandle,
    state_tx: &watch::Sender<ConnectionState>,
    state: ConnectionState,
) {
    state_tx.send_replace(state.clone());
    let _ = app.emit(CONNECTION_STATE_EVENT, state);
}

fn disconnect_reason(error: &AsyncProtocolError) -> DisconnectReason {
    match error {
        AsyncProtocolError::Transport {
            kind: TransportErrorKind::PeerClosed,
            ..
        } => DisconnectReason::PeerClosed,
        AsyncProtocolError::Transport { raw_os_error, .. } => DisconnectReason::Transport {
            raw_os_error: *raw_os_error,
        },
        AsyncProtocolError::Protocol(_) => DisconnectReason::ProtocolViolation,
    }
}

fn token_access_denied(error: &SessionTokenReadError) -> bool {
    error.is_access_denied()
}

fn invalid_request_error(error: protocol::ProtocolError) -> AppError {
    let mut app_error = AppError::new(ErrorCode::InvalidArgument, "invalid Supervisor RPC input");
    app_error
        .details
        .insert("validation".into(), error.to_string());
    app_error
}

fn invalid_rpc_params_error(violation: RpcParamsViolation) -> AppError {
    let mut error = AppError::new(ErrorCode::InvalidArgument, "invalid Supervisor RPC input");
    error
        .details
        .insert("validation".into(), violation.validation().into());
    error
}

fn bridge_busy_error() -> AppError {
    let mut error = AppError::new(ErrorCode::Conflict, "the Supervisor Bridge is busy");
    error.retryable = true;
    error
}

fn duplicate_request_error(request_id: &str) -> AppError {
    let mut error = AppError::new(
        ErrorCode::Conflict,
        "the Supervisor requestId is already pending",
    );
    error
        .details
        .insert("requestId".into(), request_id.to_owned());
    error
}

fn supervisor_unavailable_error(operation_id: Option<String>) -> AppError {
    let mut error = AppError::new(
        ErrorCode::SupervisorUnavailable,
        "the Supervisor connection is unavailable",
    );
    error.retryable = true;
    error.operation_id = operation_id;
    error
}

fn timeout_error(operation_id: Option<String>) -> AppError {
    let mut error = AppError::new(ErrorCode::Timeout, "the Supervisor request timed out");
    error.retryable = true;
    error.operation_id = operation_id;
    error
}

fn protocol_violation_error(operation_id: Option<String>, reason: &'static str) -> AppError {
    let mut error = AppError::new(
        ErrorCode::Internal,
        "invalid Supervisor response correlation",
    );
    error.operation_id = operation_id;
    error.details.insert("reason".into(), reason.into());
    error
}

#[cfg(windows)]
fn new_platform_connector() -> Result<PlatformConnector, ()> {
    PlatformConnector::for_current_process().map_err(|_| ())
}

#[cfg(target_os = "macos")]
fn new_platform_connector() -> Result<PlatformConnector, ()> {
    PlatformConnector::for_current_process().map_err(|_| ())
}

#[cfg(not(any(windows, target_os = "macos")))]
compile_error!("the Supervisor Bridge supports only Windows and macOS");

#[cfg(test)]
mod tests {
    use serde_json::{Map, json};

    use super::*;

    #[test]
    fn accepts_bounded_rpc_params_and_counts_json_escapes() {
        let params = json!({
            "enabled": true,
            "items": [null, 42, "line one\nline two", "\u{4e2d}\u{6587}"],
        });

        assert_eq!(validate_rpc_params(&params), Ok(()));
        assert_eq!(
            encoded_json_string_bytes("\0\u{1}\"\\\n\u{4e2d}").expect("bounded string"),
            serde_json::to_vec("\0\u{1}\"\\\n\u{4e2d}")
                .expect("string serialization")
                .len()
        );
    }

    #[test]
    fn rejects_per_container_and_text_limits() {
        let array = Value::Array(vec![Value::Null; MAX_RPC_PARAMS_ARRAY_ITEMS + 1]);
        assert_eq!(
            validate_rpc_params(&array),
            Err(RpcParamsViolation::ArrayItems)
        );

        let mut object = Map::new();
        for index in 0..=MAX_RPC_PARAMS_OBJECT_KEYS {
            object.insert(format!("key{index}"), Value::Null);
        }
        assert_eq!(
            validate_rpc_params(&Value::Object(object)),
            Err(RpcParamsViolation::ObjectKeys)
        );

        let string = Value::String("x".repeat(MAX_RPC_PARAMS_STRING_BYTES + 1));
        assert_eq!(
            validate_rpc_params(&string),
            Err(RpcParamsViolation::StringBytes)
        );

        let mut object = Map::new();
        object.insert("k".repeat(MAX_RPC_PARAMS_KEY_BYTES + 1), Value::Null);
        assert_eq!(
            validate_rpc_params(&Value::Object(object)),
            Err(RpcParamsViolation::KeyBytes)
        );
    }

    #[test]
    fn rejects_aggregate_node_depth_and_encoded_size_limits() {
        let nodes = Value::Array(
            (0..3)
                .map(|_| Value::Array(vec![Value::Null; 3_000]))
                .collect(),
        );
        assert_eq!(validate_rpc_params(&nodes), Err(RpcParamsViolation::Nodes));

        let mut deep = Value::Null;
        for _ in 0..MAX_RPC_PARAMS_DEPTH {
            deep = Value::Array(vec![deep]);
        }
        assert_eq!(validate_rpc_params(&deep), Err(RpcParamsViolation::Depth));

        let encoded = Value::Array(
            (0..13)
                .map(|_| Value::String("x".repeat(MAX_RPC_PARAMS_STRING_BYTES)))
                .collect(),
        );
        assert_eq!(
            validate_rpc_params(&encoded),
            Err(RpcParamsViolation::EncodedBytes)
        );

        let escaped = Value::Array(vec![
            Value::String("\0".repeat(MAX_RPC_PARAMS_STRING_BYTES));
            2
        ]);
        assert_eq!(
            validate_rpc_params(&escaped),
            Err(RpcParamsViolation::EncodedBytes)
        );
    }
}
