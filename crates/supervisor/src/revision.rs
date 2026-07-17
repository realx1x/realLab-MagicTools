use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::ops::Range;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::sync::{Arc, Mutex as StdMutex, MutexGuard};
use std::time::{Duration, Instant};

use domain::{
    AddressFamily, AppError, ErrorCode, GetSnapshotRequest, MAX_SAFE_REVISION,
    MAX_SNAPSHOT_ENTITY_BYTES, MAX_SNAPSHOT_PORT_BINDINGS, MAX_SNAPSHOT_PROCESSES,
    MAX_SNAPSHOT_TOTAL_ENTITY_BYTES, ManagedLogBatch, PortBinding, PortBindingKey, PortDelta,
    PortProtocol, ProcessDelta, ProcessInstanceKey, ProcessRecord, Revision, SystemSnapshot,
};
use tokio::sync::broadcast;

pub const REVISION_EVENT_CAPACITY: usize = 256;
pub const MAX_SNAPSHOT_CHUNK_ENTITIES: usize = 1_024;
pub const MAX_SNAPSHOT_CHUNK_PAYLOAD_BYTES: usize = 768 * 1_024;
pub const MAX_SNAPSHOT_CURSOR_BYTES: usize = 128;
pub const MAX_REVISION_DELTA_ENTITIES: usize = 128;
pub const MAX_REVISION_DELTA_PAYLOAD_BYTES: usize = 512 * 1_024;

const MAX_SNAPSHOT_SESSIONS: usize = 4;
const MAX_SNAPSHOT_PINNED_ENTITY_BYTES: usize = 2 * MAX_SNAPSHOT_TOTAL_ENTITY_BYTES;
const SNAPSHOT_ENTITY_ACCOUNTING_SLACK_BYTES: usize = 64;
const SNAPSHOT_SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const COMPLETED_SNAPSHOT_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const SNAPSHOT_SESSION_MAX_LIFETIME: Duration = Duration::from_secs(5 * 60);

#[derive(Clone, Debug, PartialEq)]
pub struct RevisionEvent {
    revision: Revision,
    change: RevisionChange,
}

impl RevisionEvent {
    pub fn revision(&self) -> Revision {
        self.revision
    }

    pub fn change(&self) -> &RevisionChange {
        &self.change
    }

    pub fn event_name(&self) -> &'static str {
        self.change.event_name()
    }

    pub fn payload(&self) -> RevisionEventPayload<'_> {
        self.change.payload()
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum RevisionChange {
    Process(ProcessDelta),
    Port(PortDelta),
    Log(Arc<ManagedLogBatch>),
}

impl RevisionChange {
    pub fn event_name(&self) -> &'static str {
        match self {
            Self::Process(_) => protocol::names::event::PROCESS_DELTA,
            Self::Port(_) => protocol::names::event::PORT_DELTA,
            Self::Log(_) => protocol::names::event::LOG_CHUNK,
        }
    }

    pub fn payload(&self) -> RevisionEventPayload<'_> {
        match self {
            Self::Process(delta) => RevisionEventPayload::ProcessDelta(delta),
            Self::Port(delta) => RevisionEventPayload::PortDelta(delta),
            Self::Log(batch) => RevisionEventPayload::ManagedLogBatch(batch),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum RevisionEventPayload<'a> {
    ProcessDelta(&'a ProcessDelta),
    PortDelta(&'a PortDelta),
    ManagedLogBatch(&'a ManagedLogBatch),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RevisionStreamError {
    Lagged { skipped: u64 },
    Closed,
}

pub struct RevisionSubscription {
    receiver: broadcast::Receiver<RevisionEvent>,
}

impl RevisionSubscription {
    pub async fn recv(&mut self) -> Result<RevisionEvent, RevisionStreamError> {
        self.receiver.recv().await.map_err(|error| match error {
            broadcast::error::RecvError::Lagged(skipped) => RevisionStreamError::Lagged { skipped },
            broadcast::error::RecvError::Closed => RevisionStreamError::Closed,
        })
    }
}

struct RevisionPublisherInner {
    current_revision: AtomicU64,
    publication_lock: StdMutex<()>,
    event_sender: broadcast::Sender<RevisionEvent>,
}

impl RevisionPublisherInner {
    fn new() -> Self {
        let (event_sender, _) = broadcast::channel(REVISION_EVENT_CAPACITY);
        Self {
            current_revision: AtomicU64::new(0),
            publication_lock: StdMutex::new(()),
            event_sender,
        }
    }

    fn current_revision(&self) -> Revision {
        self.current_revision.load(AtomicOrdering::Acquire)
    }

    fn next_revision(&self) -> Result<Revision, AppError> {
        let current_revision = self.current_revision();
        current_revision
            .checked_add(1)
            .filter(|revision| *revision <= MAX_SAFE_REVISION)
            .ok_or_else(|| {
                let mut error = AppError::new(
                    ErrorCode::Conflict,
                    "Supervisor revision space is exhausted",
                );
                error
                    .details
                    .insert("currentRevision".into(), current_revision.to_string());
                error
                    .details
                    .insert("maximumSafeRevision".into(), MAX_SAFE_REVISION.to_string());
                error
            })
    }

    fn commit_revision(&self, revision: Revision, change: RevisionChange) {
        debug_assert_eq!(revision, self.current_revision() + 1);
        self.current_revision
            .store(revision, AtomicOrdering::Release);

        // A disconnected UI is valid. Its next connection starts with a fresh
        // subscription and snapshot, so the no-receiver send error is ignored.
        let _ = self.event_sender.send(RevisionEvent { revision, change });
    }
}

/// Cloneable, least-privilege capability for managed log workers.
///
/// It shares revision assignment and event publication with process and port
/// changes but cannot mutate either snapshot collection.
#[derive(Clone)]
pub struct ManagedLogPublisher {
    inner: Arc<RevisionPublisherInner>,
}

impl ManagedLogPublisher {
    pub fn publish(&self, batch: Arc<ManagedLogBatch>) -> Result<Revision, AppError> {
        lifecycle::validate_managed_log_batch(&batch)?;
        let _publication = lock_revision_publication(&self.inner)?;
        let revision = self.inner.next_revision()?;
        self.inner
            .commit_revision(revision, RevisionChange::Log(batch));
        Ok(revision)
    }
}

/// In-memory revision state owned and mutated by the Supervisor actor only.
///
/// The type is intentionally not cloneable. Every mutation requires exclusive
/// access so state changes, revision assignment, and event publication stay in
/// one serialized operation.
pub struct RevisionState {
    processes: HashMap<ProcessInstanceKey, SnapshotEntity<ProcessRecord>>,
    port_bindings: HashMap<PortBindingKey, SnapshotEntity<PortBinding>>,
    process_entity_bytes: usize,
    port_entity_bytes: usize,
    snapshot_sessions: HashMap<String, FrozenSnapshotSession>,
    publisher: Arc<RevisionPublisherInner>,
}

struct SnapshotEntity<T> {
    value: Arc<T>,
    encoded_bytes: usize,
}

struct FrozenSnapshotSession {
    snapshot_id: String,
    starting_revision: Revision,
    revision: Revision,
    processes: Vec<Arc<ProcessRecord>>,
    process_sizes: Vec<usize>,
    port_bindings: Vec<Arc<PortBinding>>,
    port_sizes: Vec<usize>,
    total_entity_bytes: usize,
    pages: Vec<SnapshotPage>,
    created_at: Instant,
    last_accessed_at: Instant,
}

struct SnapshotPage {
    process_range: Range<usize>,
    port_range: Range<usize>,
    has_more: bool,
}

impl RevisionState {
    pub fn new() -> Self {
        Self {
            processes: HashMap::new(),
            port_bindings: HashMap::new(),
            process_entity_bytes: 0,
            port_entity_bytes: 0,
            snapshot_sessions: HashMap::new(),
            publisher: Arc::new(RevisionPublisherInner::new()),
        }
    }

    pub fn current_revision(&self) -> Revision {
        self.publisher.current_revision()
    }

    pub fn subscribe(&self) -> RevisionSubscription {
        RevisionSubscription {
            receiver: self.publisher.event_sender.subscribe(),
        }
    }

    pub fn managed_log_publisher(&self) -> ManagedLogPublisher {
        ManagedLogPublisher {
            inner: Arc::clone(&self.publisher),
        }
    }

    pub fn get_snapshot(
        &mut self,
        request: &GetSnapshotRequest,
    ) -> Result<SystemSnapshot, AppError> {
        let now = Instant::now();
        self.purge_expired_snapshot_sessions(now);
        match request.cursor.as_deref() {
            None => self.start_snapshot_session(request.starting_revision, now),
            Some(cursor) => self.continue_snapshot_session(request.starting_revision, cursor, now),
        }
    }

    pub fn apply_process_delta(&mut self, mut delta: ProcessDelta) -> Result<Revision, AppError> {
        validate_process_delta(&delta)?;
        for process in &mut delta.upserted {
            process.last_seen_revision = MAX_SAFE_REVISION;
        }
        validate_delta_wire_budget(
            "process",
            delta.upserted.len().saturating_add(delta.removed.len()),
            &delta,
        )?;
        let process_sizes = delta
            .upserted
            .iter()
            .enumerate()
            .map(|(index, process)| validate_snapshot_entity("process", index, process))
            .collect::<Result<Vec<_>, _>>()?;
        let (projected_count, projected_bytes) =
            self.project_process_state(&delta, &process_sizes)?;
        self.purge_expired_snapshot_sessions(Instant::now());
        let publisher = Arc::clone(&self.publisher);
        let _publication = lock_revision_publication(&publisher)?;
        let revision = publisher.next_revision()?;

        for process in &mut delta.upserted {
            process.last_seen_revision = revision;
        }
        for key in &delta.removed {
            self.processes.remove(key);
        }
        for (process, encoded_bytes) in delta.upserted.iter().zip(process_sizes) {
            self.processes.insert(
                process.instance_key.clone(),
                SnapshotEntity {
                    value: Arc::new(process.clone()),
                    encoded_bytes,
                },
            );
        }
        self.process_entity_bytes = projected_bytes;
        debug_assert_eq!(self.processes.len(), projected_count);

        publisher.commit_revision(revision, RevisionChange::Process(delta));
        Ok(revision)
    }

    pub fn apply_port_delta(&mut self, delta: PortDelta) -> Result<Revision, AppError> {
        validate_port_delta(&delta)?;
        validate_delta_wire_budget(
            "port",
            delta.upserted.len().saturating_add(delta.removed.len()),
            &delta,
        )?;
        let port_sizes = delta
            .upserted
            .iter()
            .enumerate()
            .map(|(index, binding)| validate_snapshot_entity("port", index, binding))
            .collect::<Result<Vec<_>, _>>()?;
        let (projected_count, projected_bytes) = self.project_port_state(&delta, &port_sizes)?;
        self.purge_expired_snapshot_sessions(Instant::now());
        let publisher = Arc::clone(&self.publisher);
        let _publication = lock_revision_publication(&publisher)?;
        let revision = publisher.next_revision()?;

        for key in &delta.removed {
            self.port_bindings.remove(key);
        }
        for (binding, encoded_bytes) in delta.upserted.iter().zip(port_sizes) {
            self.port_bindings.insert(
                PortBindingKey::from(binding),
                SnapshotEntity {
                    value: Arc::new(binding.clone()),
                    encoded_bytes,
                },
            );
        }
        self.port_entity_bytes = projected_bytes;
        debug_assert_eq!(self.port_bindings.len(), projected_count);

        publisher.commit_revision(revision, RevisionChange::Port(delta));
        Ok(revision)
    }

    pub fn apply_log_batch(&mut self, batch: Arc<ManagedLogBatch>) -> Result<Revision, AppError> {
        self.managed_log_publisher().publish(batch)
    }

    fn project_process_state(
        &self,
        delta: &ProcessDelta,
        upserted_sizes: &[usize],
    ) -> Result<(usize, usize), AppError> {
        let mut count = self.processes.len();
        let mut bytes = self.process_entity_bytes;
        for key in &delta.removed {
            if let Some(existing) = self.processes.get(key) {
                count = count.saturating_sub(1);
                bytes = bytes.saturating_sub(existing.encoded_bytes);
            }
        }
        for (process, encoded_bytes) in delta.upserted.iter().zip(upserted_sizes) {
            if let Some(existing) = self.processes.get(&process.instance_key) {
                bytes = bytes.saturating_sub(existing.encoded_bytes);
            } else {
                count = count.saturating_add(1);
            }
            bytes = bytes
                .checked_add(*encoded_bytes)
                .ok_or_else(snapshot_state_capacity_overflow)?;
        }
        validate_snapshot_state_capacity(
            "process",
            count,
            MAX_SNAPSHOT_PROCESSES,
            bytes,
            self.port_entity_bytes,
        )?;
        Ok((count, bytes))
    }

    fn project_port_state(
        &self,
        delta: &PortDelta,
        upserted_sizes: &[usize],
    ) -> Result<(usize, usize), AppError> {
        let mut count = self.port_bindings.len();
        let mut bytes = self.port_entity_bytes;
        for key in &delta.removed {
            if let Some(existing) = self.port_bindings.get(key) {
                count = count.saturating_sub(1);
                bytes = bytes.saturating_sub(existing.encoded_bytes);
            }
        }
        for (binding, encoded_bytes) in delta.upserted.iter().zip(upserted_sizes) {
            let key = PortBindingKey::from(binding);
            if let Some(existing) = self.port_bindings.get(&key) {
                bytes = bytes.saturating_sub(existing.encoded_bytes);
            } else {
                count = count.saturating_add(1);
            }
            bytes = bytes
                .checked_add(*encoded_bytes)
                .ok_or_else(snapshot_state_capacity_overflow)?;
        }
        validate_snapshot_state_capacity(
            "port",
            count,
            MAX_SNAPSHOT_PORT_BINDINGS,
            bytes,
            self.process_entity_bytes,
        )?;
        Ok((count, bytes))
    }

    fn start_snapshot_session(
        &mut self,
        starting_revision: Revision,
        now: Instant,
    ) -> Result<SystemSnapshot, AppError> {
        let publisher = Arc::clone(&self.publisher);
        let publication = lock_revision_publication(&publisher)?;
        let current_revision = publisher.current_revision();
        self.validate_snapshot_start(starting_revision, current_revision)?;
        drop(publication);

        let total_entity_bytes = self
            .process_entity_bytes
            .checked_add(self.port_entity_bytes)
            .ok_or_else(snapshot_state_capacity_overflow)?;
        self.reserve_snapshot_session_slot(total_entity_bytes)?;
        let mut process_entries = self
            .processes
            .values()
            .map(|entry| (Arc::clone(&entry.value), entry.encoded_bytes))
            .collect::<Vec<_>>();
        process_entries.sort_by(|left, right| {
            compare_process_keys(&left.0.instance_key, &right.0.instance_key)
        });
        let (processes, process_sizes) =
            process_entries.into_iter().unzip::<_, _, Vec<_>, Vec<_>>();
        let mut port_entries = self
            .port_bindings
            .values()
            .map(|entry| (Arc::clone(&entry.value), entry.encoded_bytes))
            .collect::<Vec<_>>();
        port_entries.sort_by(|left, right| compare_port_bindings(&left.0, &right.0));
        let (port_bindings, port_sizes) = port_entries.into_iter().unzip::<_, _, Vec<_>, Vec<_>>();
        let snapshot_id = self.allocate_snapshot_id()?;
        let first_page = build_snapshot_page(
            &snapshot_id,
            current_revision,
            0,
            &processes,
            &process_sizes,
            &port_bindings,
            &port_sizes,
            total_entity_bytes,
            0,
            0,
        )?;
        let session = FrozenSnapshotSession {
            snapshot_id: snapshot_id.clone(),
            starting_revision,
            revision: current_revision,
            processes,
            process_sizes,
            port_bindings,
            port_sizes,
            total_entity_bytes,
            pages: vec![first_page],
            created_at: now,
            last_accessed_at: now,
        };
        let response = snapshot_page_response(&session, 0)?;
        self.snapshot_sessions.insert(snapshot_id, session);
        Ok(response)
    }

    fn continue_snapshot_session(
        &mut self,
        starting_revision: Revision,
        cursor: &str,
        now: Instant,
    ) -> Result<SystemSnapshot, AppError> {
        let (snapshot_id, chunk_index) = parse_snapshot_cursor(cursor)?;
        let Some(session) = self.snapshot_sessions.get_mut(snapshot_id) else {
            return Err(snapshot_session_unavailable_error(snapshot_id));
        };
        if session.starting_revision != starting_revision {
            return Err(invalid_snapshot_cursor(
                "does not belong to the requested startingRevision",
            ));
        }

        let chunk_index = usize::try_from(chunk_index)
            .map_err(|_| invalid_snapshot_cursor("contains an unsupported chunk index"))?;
        if chunk_index > session.pages.len() {
            return Err(invalid_snapshot_cursor("skips an unissued snapshot chunk"));
        }
        if chunk_index == session.pages.len() {
            let Some(previous) = session.pages.last() else {
                return Err(invalid_snapshot_cursor(
                    "does not identify a snapshot chunk",
                ));
            };
            if !previous.has_more {
                return Err(invalid_snapshot_cursor("continues a completed snapshot"));
            }
            let next_page = build_snapshot_page(
                &session.snapshot_id,
                session.revision,
                chunk_index,
                &session.processes,
                &session.process_sizes,
                &session.port_bindings,
                &session.port_sizes,
                session.total_entity_bytes,
                previous.process_range.end,
                previous.port_range.end,
            )?;
            session.pages.push(next_page);
        }
        session.last_accessed_at = now;
        snapshot_page_response(session, chunk_index)
    }

    fn purge_expired_snapshot_sessions(&mut self, now: Instant) {
        self.snapshot_sessions.retain(|_, session| {
            let idle_timeout = if session.pages.last().is_some_and(|page| !page.has_more) {
                COMPLETED_SNAPSHOT_IDLE_TIMEOUT
            } else {
                SNAPSHOT_SESSION_IDLE_TIMEOUT
            };
            now.duration_since(session.last_accessed_at) <= idle_timeout
                && now.duration_since(session.created_at) <= SNAPSHOT_SESSION_MAX_LIFETIME
        });
    }

    fn reserve_snapshot_session_slot(&self, required_entity_bytes: usize) -> Result<(), AppError> {
        if self.snapshot_sessions.len() < MAX_SNAPSHOT_SESSIONS {
            let pinned_entity_bytes = self
                .snapshot_sessions
                .values()
                .try_fold(required_entity_bytes, |total, session| {
                    total.checked_add(session.total_entity_bytes)
                });
            if pinned_entity_bytes.is_some_and(|total| total <= MAX_SNAPSHOT_PINNED_ENTITY_BYTES) {
                return Ok(());
            }
        }
        let mut error = AppError::new(
            ErrorCode::Conflict,
            "the frozen snapshot resource capacity is currently exhausted",
        );
        error.retryable = true;
        error
            .details
            .insert("maximumSessions".into(), MAX_SNAPSHOT_SESSIONS.to_string());
        error.details.insert(
            "maximumPinnedEntityBytes".into(),
            MAX_SNAPSHOT_PINNED_ENTITY_BYTES.to_string(),
        );
        Err(error)
    }

    fn allocate_snapshot_id(&mut self) -> Result<String, AppError> {
        for _ in 0..MAX_SNAPSHOT_SESSIONS {
            let mut random = [0_u8; 16];
            getrandom::fill(&mut random).map_err(|_| {
                snapshot_internal_error("failed to generate an opaque snapshot identifier")
            })?;
            let mut snapshot_id = String::with_capacity(random.len() * 2);
            for byte in random {
                write!(&mut snapshot_id, "{byte:02x}")
                    .expect("writing hexadecimal bytes to a String cannot fail");
            }
            if !self.snapshot_sessions.contains_key(&snapshot_id) {
                return Ok(snapshot_id);
            }
        }
        Err(snapshot_internal_error(
            "failed to allocate a unique snapshot identifier",
        ))
    }

    fn validate_snapshot_start(
        &self,
        starting_revision: Revision,
        current_revision: Revision,
    ) -> Result<(), AppError> {
        if starting_revision > MAX_SAFE_REVISION {
            let mut error = AppError::new(
                ErrorCode::InvalidArgument,
                "snapshot starting revision exceeds the JavaScript-safe limit",
            );
            error
                .details
                .insert("startingRevision".into(), starting_revision.to_string());
            error
                .details
                .insert("maximumSafeRevision".into(), MAX_SAFE_REVISION.to_string());
            return Err(error);
        }
        if starting_revision > current_revision {
            let mut error = AppError::new(
                ErrorCode::Conflict,
                "snapshot starting revision is ahead of Supervisor state",
            );
            error
                .details
                .insert("startingRevision".into(), starting_revision.to_string());
            error
                .details
                .insert("currentRevision".into(), current_revision.to_string());
            return Err(error);
        }
        Ok(())
    }
}

fn build_snapshot_page(
    snapshot_id: &str,
    revision: Revision,
    chunk_index: usize,
    processes: &[Arc<ProcessRecord>],
    process_sizes: &[usize],
    port_bindings: &[Arc<PortBinding>],
    port_sizes: &[usize],
    total_entity_bytes: usize,
    process_offset: usize,
    port_offset: usize,
) -> Result<SnapshotPage, AppError> {
    if process_offset > processes.len()
        || port_offset > port_bindings.len()
        || process_sizes.len() != processes.len()
        || port_sizes.len() != port_bindings.len()
    {
        return Err(snapshot_internal_error(
            "snapshot page offsets are outside the frozen collections",
        ));
    }
    let chunk_index = u32::try_from(chunk_index)
        .map_err(|_| snapshot_internal_error("snapshot chunk count exceeds u32"))?;
    let next_chunk_index = chunk_index
        .checked_add(1)
        .ok_or_else(|| snapshot_internal_error("snapshot chunk count is exhausted"))?;
    let baseline = SystemSnapshot {
        snapshot_id: snapshot_id.to_owned(),
        chunk_index,
        revision,
        process_count: snapshot_collection_count("process", processes.len())?,
        port_binding_count: snapshot_collection_count("port", port_bindings.len())?,
        total_entity_bytes: snapshot_total_entity_bytes(total_entity_bytes)?,
        processes: Vec::new(),
        port_bindings: Vec::new(),
        next_cursor: Some(format_snapshot_cursor(snapshot_id, next_chunk_index)),
    };
    let mut payload_bytes = snapshot_payload_size(&baseline)?;
    let mut entity_count = 0_usize;
    let mut process_end = process_offset;
    let mut port_end = port_offset;

    while process_end < processes.len() && entity_count < MAX_SNAPSHOT_CHUNK_ENTITIES {
        let entity_bytes = process_sizes[process_end];
        if payload_bytes.saturating_add(entity_bytes).saturating_add(1)
            > MAX_SNAPSHOT_CHUNK_PAYLOAD_BYTES
        {
            if entity_count == 0 {
                return Err(snapshot_entity_too_large(
                    "process",
                    process_end,
                    entity_bytes,
                ));
            }
            break;
        }
        payload_bytes += entity_bytes + 1;
        process_end += 1;
        entity_count += 1;
    }

    if process_end == processes.len() {
        while port_end < port_bindings.len() && entity_count < MAX_SNAPSHOT_CHUNK_ENTITIES {
            let entity_bytes = port_sizes[port_end];
            if payload_bytes.saturating_add(entity_bytes).saturating_add(1)
                > MAX_SNAPSHOT_CHUNK_PAYLOAD_BYTES
            {
                if entity_count == 0 {
                    return Err(snapshot_entity_too_large("port", port_end, entity_bytes));
                }
                break;
            }
            payload_bytes += entity_bytes + 1;
            port_end += 1;
            entity_count += 1;
        }
    }

    let page = SnapshotPage {
        process_range: process_offset..process_end,
        port_range: port_offset..port_end,
        has_more: process_end < processes.len() || port_end < port_bindings.len(),
    };
    let response = make_snapshot_page_response(
        snapshot_id,
        revision,
        chunk_index,
        &page,
        processes,
        port_bindings,
        total_entity_bytes,
    )?;
    let encoded_bytes = snapshot_payload_size(&response)?;
    if encoded_bytes > MAX_SNAPSHOT_CHUNK_PAYLOAD_BYTES {
        let mut error = snapshot_internal_error("snapshot chunk exceeds its encoded byte budget");
        error
            .details
            .insert("encodedBytes".into(), encoded_bytes.to_string());
        error.details.insert(
            "maximumBytes".into(),
            MAX_SNAPSHOT_CHUNK_PAYLOAD_BYTES.to_string(),
        );
        return Err(error);
    }
    Ok(page)
}

fn snapshot_page_response(
    session: &FrozenSnapshotSession,
    chunk_index: usize,
) -> Result<SystemSnapshot, AppError> {
    let page = session
        .pages
        .get(chunk_index)
        .ok_or_else(|| invalid_snapshot_cursor("does not identify an issued snapshot chunk"))?;
    let chunk_index = u32::try_from(chunk_index)
        .map_err(|_| snapshot_internal_error("snapshot chunk count exceeds u32"))?;
    let response = make_snapshot_page_response(
        &session.snapshot_id,
        session.revision,
        chunk_index,
        page,
        &session.processes,
        &session.port_bindings,
        session.total_entity_bytes,
    )?;
    let encoded_bytes = snapshot_payload_size(&response)?;
    if encoded_bytes > MAX_SNAPSHOT_CHUNK_PAYLOAD_BYTES {
        return Err(snapshot_internal_error(
            "stored snapshot chunk exceeds its encoded byte budget",
        ));
    }
    Ok(response)
}

fn make_snapshot_page_response(
    snapshot_id: &str,
    revision: Revision,
    chunk_index: u32,
    page: &SnapshotPage,
    processes: &[Arc<ProcessRecord>],
    port_bindings: &[Arc<PortBinding>],
    total_entity_bytes: usize,
) -> Result<SystemSnapshot, AppError> {
    Ok(SystemSnapshot {
        snapshot_id: snapshot_id.to_owned(),
        chunk_index,
        revision,
        process_count: snapshot_collection_count("process", processes.len())?,
        port_binding_count: snapshot_collection_count("port", port_bindings.len())?,
        total_entity_bytes: snapshot_total_entity_bytes(total_entity_bytes)?,
        processes: processes[page.process_range.clone()]
            .iter()
            .map(|process| process.as_ref().clone())
            .collect(),
        port_bindings: port_bindings[page.port_range.clone()]
            .iter()
            .map(|binding| binding.as_ref().clone())
            .collect(),
        next_cursor: page.has_more.then(|| {
            format_snapshot_cursor(
                snapshot_id,
                chunk_index
                    .checked_add(1)
                    .expect("a stored snapshot page cannot exceed u32"),
            )
        }),
    })
}

fn snapshot_collection_count(entity: &'static str, count: usize) -> Result<u32, AppError> {
    u32::try_from(count).map_err(|_| {
        let mut error = snapshot_internal_error("snapshot collection exceeds the wire count range");
        error.details.insert("entity".into(), entity.into());
        error.details.insert("count".into(), count.to_string());
        error
    })
}

fn snapshot_total_entity_bytes(total_entity_bytes: usize) -> Result<u64, AppError> {
    u64::try_from(total_entity_bytes)
        .map_err(|_| snapshot_internal_error("snapshot byte count exceeds the wire range"))
}

fn snapshot_entity_size<T: serde::Serialize>(value: &T) -> Result<usize, AppError> {
    serde_json::to_vec(value)
        .map(|encoded| encoded.len())
        .map_err(|_| snapshot_internal_error("snapshot entity serialization failed"))
}

fn validate_delta_wire_budget<T: serde::Serialize>(
    entity: &'static str,
    entity_count: usize,
    delta: &T,
) -> Result<(), AppError> {
    let encoded_bytes = snapshot_entity_size(delta)?;
    let accounting_bytes = encoded_bytes
        .checked_add(
            entity_count
                .checked_mul(SNAPSHOT_ENTITY_ACCOUNTING_SLACK_BYTES)
                .ok_or_else(snapshot_state_capacity_overflow)?,
        )
        .ok_or_else(snapshot_state_capacity_overflow)?;
    if entity_count <= MAX_REVISION_DELTA_ENTITIES
        && accounting_bytes <= MAX_REVISION_DELTA_PAYLOAD_BYTES
    {
        return Ok(());
    }
    let mut error = AppError::new(
        ErrorCode::InvalidArgument,
        "state delta exceeds the bounded revision event contract",
    );
    error.details.insert("entity".into(), entity.into());
    error
        .details
        .insert("entityCount".into(), entity_count.to_string());
    error.details.insert(
        "maximumEntities".into(),
        MAX_REVISION_DELTA_ENTITIES.to_string(),
    );
    error
        .details
        .insert("encodedBytes".into(), encoded_bytes.to_string());
    error
        .details
        .insert("accountingBytes".into(), accounting_bytes.to_string());
    error.details.insert(
        "maximumBytes".into(),
        MAX_REVISION_DELTA_PAYLOAD_BYTES.to_string(),
    );
    Err(error)
}

fn validate_snapshot_entity<T: serde::Serialize>(
    entity: &'static str,
    index: usize,
    value: &T,
) -> Result<usize, AppError> {
    let encoded_bytes = snapshot_entity_size(value)?;
    let accounting_bytes = encoded_bytes
        .checked_add(SNAPSHOT_ENTITY_ACCOUNTING_SLACK_BYTES)
        .ok_or_else(snapshot_state_capacity_overflow)?;
    if accounting_bytes <= MAX_SNAPSHOT_ENTITY_BYTES {
        return Ok(accounting_bytes);
    }
    let mut error = AppError::new(
        ErrorCode::InvalidArgument,
        "state entity exceeds the bounded snapshot contract",
    );
    error.details.insert("entity".into(), entity.into());
    error.details.insert("index".into(), index.to_string());
    error
        .details
        .insert("encodedBytes".into(), encoded_bytes.to_string());
    error
        .details
        .insert("accountingBytes".into(), accounting_bytes.to_string());
    error
        .details
        .insert("maximumBytes".into(), MAX_SNAPSHOT_ENTITY_BYTES.to_string());
    Err(error)
}

fn validate_snapshot_state_capacity(
    entity: &'static str,
    count: usize,
    maximum_count: usize,
    entity_bytes: usize,
    other_entity_bytes: usize,
) -> Result<(), AppError> {
    let total_entity_bytes = entity_bytes
        .checked_add(other_entity_bytes)
        .ok_or_else(snapshot_state_capacity_overflow)?;
    if count <= maximum_count && total_entity_bytes <= MAX_SNAPSHOT_TOTAL_ENTITY_BYTES {
        return Ok(());
    }
    let mut error = AppError::new(
        ErrorCode::InvalidArgument,
        "state delta exceeds the bounded snapshot collection contract",
    );
    error.details.insert("entity".into(), entity.into());
    error.details.insert("count".into(), count.to_string());
    error
        .details
        .insert("maximumCount".into(), maximum_count.to_string());
    error
        .details
        .insert("totalEntityBytes".into(), total_entity_bytes.to_string());
    error.details.insert(
        "maximumTotalEntityBytes".into(),
        MAX_SNAPSHOT_TOTAL_ENTITY_BYTES.to_string(),
    );
    Err(error)
}

fn snapshot_state_capacity_overflow() -> AppError {
    AppError::new(
        ErrorCode::InvalidArgument,
        "snapshot state byte accounting overflowed",
    )
}

fn snapshot_payload_size(value: &SystemSnapshot) -> Result<usize, AppError> {
    serde_json::to_vec(value)
        .map(|encoded| encoded.len())
        .map_err(|_| snapshot_internal_error("snapshot payload serialization failed"))
}

fn format_snapshot_cursor(snapshot_id: &str, chunk_index: u32) -> String {
    format!("{snapshot_id}:{chunk_index:08x}")
}

fn parse_snapshot_cursor(cursor: &str) -> Result<(&str, u32), AppError> {
    if cursor.is_empty() || cursor.len() > MAX_SNAPSHOT_CURSOR_BYTES || !cursor.is_ascii() {
        return Err(invalid_snapshot_cursor(
            "must be a bounded opaque ASCII continuation",
        ));
    }
    let Some((snapshot_id, chunk_index)) = cursor.rsplit_once(':') else {
        return Err(invalid_snapshot_cursor("has an invalid shape"));
    };
    if snapshot_id.is_empty() || chunk_index.len() != 8 {
        return Err(invalid_snapshot_cursor("has an invalid shape"));
    }
    let chunk_index = u32::from_str_radix(chunk_index, 16)
        .map_err(|_| invalid_snapshot_cursor("has an invalid chunk index"))?;
    if format_snapshot_cursor(snapshot_id, chunk_index) != cursor {
        return Err(invalid_snapshot_cursor("is not in canonical form"));
    }
    Ok((snapshot_id, chunk_index))
}

fn snapshot_entity_too_large(entity: &'static str, index: usize, encoded_bytes: usize) -> AppError {
    let mut error = snapshot_internal_error("one snapshot entity exceeds the chunk byte budget");
    error.details.insert("entity".into(), entity.into());
    error.details.insert("index".into(), index.to_string());
    error
        .details
        .insert("encodedBytes".into(), encoded_bytes.to_string());
    error.details.insert(
        "maximumBytes".into(),
        MAX_SNAPSHOT_CHUNK_PAYLOAD_BYTES.to_string(),
    );
    error
}

fn invalid_snapshot_cursor(reason: &'static str) -> AppError {
    let mut error = AppError::new(
        ErrorCode::InvalidArgument,
        "snapshot cursor does not match the frozen snapshot contract",
    );
    error.details.insert("field".into(), "cursor".into());
    error.details.insert("reason".into(), reason.into());
    error
}

fn snapshot_session_unavailable_error(snapshot_id: &str) -> AppError {
    let mut error = AppError::new(
        ErrorCode::Conflict,
        "the frozen snapshot session is no longer available",
    );
    error.retryable = true;
    error
        .details
        .insert("snapshotId".into(), snapshot_id.to_owned());
    error
}

fn snapshot_internal_error(message: &'static str) -> AppError {
    AppError::new(ErrorCode::Internal, message)
}

impl Default for RevisionState {
    fn default() -> Self {
        Self::new()
    }
}

fn lock_revision_publication(
    publisher: &RevisionPublisherInner,
) -> Result<MutexGuard<'_, ()>, AppError> {
    publisher.publication_lock.lock().map_err(|_| {
        AppError::new(
            ErrorCode::Internal,
            "Supervisor revision publisher is unavailable",
        )
    })
}

fn validate_process_delta(delta: &ProcessDelta) -> Result<(), AppError> {
    let mut upserted = HashSet::with_capacity(delta.upserted.len());
    for (index, process) in delta.upserted.iter().enumerate() {
        lifecycle::validate_process_instance_key(&process.instance_key)?;
        if let domain::FieldValue::Known(Some(parent)) = &process.parent_instance_key {
            lifecycle::validate_process_instance_key(parent)?;
        }
        lifecycle::validate_process_record_control(process)?;
        if !upserted.insert(process.instance_key.clone()) {
            return Err(invalid_delta_entry(
                "process",
                "upserted",
                index,
                "duplicate key",
            ));
        }
    }

    let mut removed = HashSet::with_capacity(delta.removed.len());
    for (index, key) in delta.removed.iter().enumerate() {
        if !removed.insert(key.clone()) {
            return Err(invalid_delta_entry(
                "process",
                "removed",
                index,
                "duplicate key",
            ));
        }
        if upserted.contains(key) {
            return Err(invalid_delta_entry(
                "process",
                "removed",
                index,
                "key is also upserted",
            ));
        }
    }
    Ok(())
}

fn validate_port_delta(delta: &PortDelta) -> Result<(), AppError> {
    let mut upserted = HashSet::with_capacity(delta.upserted.len());
    for (index, binding) in delta.upserted.iter().enumerate() {
        if !upserted.insert(PortBindingKey::from(binding)) {
            return Err(invalid_delta_entry(
                "port",
                "upserted",
                index,
                "duplicate key",
            ));
        }
    }

    let mut removed = HashSet::with_capacity(delta.removed.len());
    for (index, key) in delta.removed.iter().enumerate() {
        if !removed.insert(key.clone()) {
            return Err(invalid_delta_entry(
                "port",
                "removed",
                index,
                "duplicate key",
            ));
        }
        if upserted.contains(key) {
            return Err(invalid_delta_entry(
                "port",
                "removed",
                index,
                "key is also upserted",
            ));
        }
    }
    Ok(())
}

fn invalid_delta_entry(
    entity: &'static str,
    collection: &'static str,
    index: usize,
    reason: &'static str,
) -> AppError {
    let mut error = AppError::new(ErrorCode::InvalidArgument, "state delta is ambiguous");
    error.details.insert("entity".into(), entity.into());
    error.details.insert("collection".into(), collection.into());
    error.details.insert("index".into(), index.to_string());
    error.details.insert("reason".into(), reason.into());
    error
}

fn compare_process_keys(left: &ProcessInstanceKey, right: &ProcessInstanceKey) -> Ordering {
    left.boot_id
        .cmp(&right.boot_id)
        .then_with(|| left.pid.cmp(&right.pid))
        .then_with(|| left.native_start_time.cmp(&right.native_start_time))
}

fn compare_optional_process_keys(
    left: Option<&ProcessInstanceKey>,
    right: Option<&ProcessInstanceKey>,
) -> Ordering {
    match (left, right) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Less,
        (Some(_), None) => Ordering::Greater,
        (Some(left), Some(right)) => compare_process_keys(left, right),
    }
}

fn compare_port_bindings(left: &PortBinding, right: &PortBinding) -> Ordering {
    port_protocol_rank(left.protocol)
        .cmp(&port_protocol_rank(right.protocol))
        .then_with(|| {
            address_family_rank(left.address_family).cmp(&address_family_rank(right.address_family))
        })
        .then_with(|| left.local_address.cmp(&right.local_address))
        .then_with(|| left.local_port.cmp(&right.local_port))
        .then_with(|| {
            compare_optional_process_keys(
                left.process_instance_key.as_ref(),
                right.process_instance_key.as_ref(),
            )
        })
}

fn port_protocol_rank(protocol: PortProtocol) -> u8 {
    match protocol {
        PortProtocol::Tcp => 0,
        PortProtocol::Udp => 1,
    }
}

fn address_family_rank(address_family: AddressFamily) -> u8 {
    match address_family {
        AddressFamily::Ipv4 => 0,
        AddressFamily::Ipv6 => 1,
    }
}
