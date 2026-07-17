use std::cmp::Ordering;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use domain::{
    AddressFamily, AppError, ErrorCode, FieldValue, MAX_SNAPSHOT_PORT_BINDINGS,
    MAX_SNAPSHOT_PROCESSES, PortBinding, PortBindingKey, PortDelta, PortOwnershipConfidence,
    PortProtocol, ProcessDelta, ProcessInstanceKey, ProcessOwnership, ProcessRecord,
    ProjectEvidence,
};
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio::task::{Id as TaskId, JoinHandle, JoinSet};
use tokio::time::{Instant, MissedTickBehavior};

use crate::backend::{
    CancellationToken, DiscoveryBackend, EnrichmentDemand, FastProcessScan, PortScan,
    ProcessEnrichment,
};
use crate::classification::{
    ClassificationEngine, ClassificationRulesSnapshot, ProcessClassificationFacts,
};
use crate::project::{
    ProjectCatalog, ProjectContextSnapshot, ProjectScanRequest, ProjectScanResult,
};

const DEFAULT_FAST_SCAN_INTERVAL: Duration = Duration::from_secs(2);
const DEFAULT_PORT_SCAN_INTERVAL: Duration = Duration::from_secs(5);
const DEFAULT_PROCESS_CACHE_TTL: Duration = Duration::from_secs(10);
const DEFAULT_PORT_CACHE_TTL: Duration = Duration::from_secs(15);
const DEFAULT_ENRICHMENT_CACHE_TTL: Duration = Duration::from_secs(30);
const DEFAULT_PROJECT_CACHE_TTL: Duration = Duration::from_secs(30);
const DEFAULT_CACHE_SWEEP_INTERVAL: Duration = Duration::from_secs(1);
const DEFAULT_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_COMMAND_CAPACITY: usize = 256;
const DEFAULT_UPDATE_CAPACITY: usize = 64;
const DEFAULT_PROCESS_CAPACITY: usize = 16_384;
const DEFAULT_PORT_CAPACITY: usize = 65_536;
const DEFAULT_ENRICHMENT_CAPACITY: usize = 4_096;
const DEFAULT_ENRICHMENT_CONCURRENCY: usize = 4;
const DEFAULT_PROJECT_CAPACITY: usize = 4_096;
const DEFAULT_PROJECT_CONCURRENCY: usize = 4;
const MAX_CHANNEL_CAPACITY: usize = 65_536;
const MAX_CACHE_CAPACITY: usize = 1_000_000;
const MAX_ENRICHMENT_CONCURRENCY: usize = 16;
const MAX_PROJECT_CONCURRENCY: usize = 4;
const MAX_CLASSIFICATION_RULE_EVALUATIONS: usize = 4 * 1_024 * 1_024;
const MAX_CLASSIFICATION_PATTERN_WORK_BYTES: usize = 64 * 1_024 * 1_024;
const MAX_MANAGED_RUN_ID_BYTES: usize = 256;
const MAX_PROCESS_BOOT_ID_BYTES: usize = 256;
const MAX_PROCESS_NATIVE_START_TIME_BYTES: usize = 128;
const MAX_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
const MAX_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(60);
const EVENT_ACCUMULATION_INTERVAL: Duration = Duration::from_millis(16);
const ESTIMATED_EVENT_CONTAINER_BYTES: usize = 128;
const ESTIMATED_EVENT_ENTITY_OVERHEAD_BYTES: usize = 32;

pub const MAX_ENRICHMENT_BATCH_SIZE: usize = 64;
pub const MAX_DISCOVERY_EVENT_ENTITIES: usize = 128;
pub const MAX_DISCOVERY_EVENT_PAYLOAD_BYTES: usize = 512 * 1_024;
pub const DISCOVERY_LATENCY_WINDOW_CAPACITY: usize = 256;

#[derive(Clone, Debug)]
pub struct DiscoveryConfig {
    pub fast_scan_interval: Duration,
    pub port_scan_interval: Duration,
    pub process_cache_ttl: Duration,
    pub port_cache_ttl: Duration,
    pub enrichment_cache_ttl: Duration,
    pub project_cache_ttl: Duration,
    pub cache_sweep_interval: Duration,
    pub shutdown_timeout: Duration,
    pub command_capacity: usize,
    pub update_capacity: usize,
    pub process_cache_capacity: usize,
    pub port_cache_capacity: usize,
    pub enrichment_cache_capacity: usize,
    pub enrichment_concurrency: usize,
    pub project_cache_capacity: usize,
    pub project_concurrency: usize,
}

impl DiscoveryConfig {
    pub fn validate(&self) -> Result<(), AppError> {
        validate_duration("fastScanInterval", self.fast_scan_interval, MAX_INTERVAL)?;
        validate_duration("portScanInterval", self.port_scan_interval, MAX_INTERVAL)?;
        validate_duration("processCacheTtl", self.process_cache_ttl, MAX_INTERVAL)?;
        validate_duration("portCacheTtl", self.port_cache_ttl, MAX_INTERVAL)?;
        validate_duration(
            "enrichmentCacheTtl",
            self.enrichment_cache_ttl,
            MAX_INTERVAL,
        )?;
        validate_duration("projectCacheTtl", self.project_cache_ttl, MAX_INTERVAL)?;
        validate_duration(
            "cacheSweepInterval",
            self.cache_sweep_interval,
            MAX_INTERVAL,
        )?;
        validate_duration(
            "shutdownTimeout",
            self.shutdown_timeout,
            MAX_SHUTDOWN_TIMEOUT,
        )?;

        if self.process_cache_ttl < self.fast_scan_interval {
            return Err(invalid_config(
                "processCacheTtl",
                "must be at least fastScanInterval",
            ));
        }
        if self.port_cache_ttl < self.port_scan_interval {
            return Err(invalid_config(
                "portCacheTtl",
                "must be at least portScanInterval",
            ));
        }
        if self.cache_sweep_interval > self.process_cache_ttl
            || self.cache_sweep_interval > self.port_cache_ttl
            || self.cache_sweep_interval > self.enrichment_cache_ttl
            || self.cache_sweep_interval > self.project_cache_ttl
        {
            return Err(invalid_config(
                "cacheSweepInterval",
                "must not exceed any cache TTL",
            ));
        }

        validate_capacity(
            "commandCapacity",
            self.command_capacity,
            MAX_CHANNEL_CAPACITY,
        )?;
        validate_capacity("updateCapacity", self.update_capacity, MAX_CHANNEL_CAPACITY)?;
        validate_capacity(
            "processCacheCapacity",
            self.process_cache_capacity,
            MAX_SNAPSHOT_PROCESSES,
        )?;
        validate_capacity(
            "portCacheCapacity",
            self.port_cache_capacity,
            MAX_SNAPSHOT_PORT_BINDINGS,
        )?;
        validate_capacity(
            "enrichmentCacheCapacity",
            self.enrichment_cache_capacity,
            MAX_CACHE_CAPACITY,
        )?;
        validate_capacity(
            "enrichmentConcurrency",
            self.enrichment_concurrency,
            MAX_ENRICHMENT_CONCURRENCY,
        )?;
        validate_capacity(
            "projectCacheCapacity",
            self.project_cache_capacity,
            MAX_CACHE_CAPACITY,
        )?;
        validate_capacity(
            "projectConcurrency",
            self.project_concurrency,
            MAX_PROJECT_CONCURRENCY,
        )?;

        if self.enrichment_cache_capacity > self.process_cache_capacity {
            return Err(invalid_config(
                "enrichmentCacheCapacity",
                "must not exceed processCacheCapacity",
            ));
        }
        if self.project_cache_capacity > self.process_cache_capacity {
            return Err(invalid_config(
                "projectCacheCapacity",
                "must not exceed processCacheCapacity",
            ));
        }
        Ok(())
    }
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            fast_scan_interval: DEFAULT_FAST_SCAN_INTERVAL,
            port_scan_interval: DEFAULT_PORT_SCAN_INTERVAL,
            process_cache_ttl: DEFAULT_PROCESS_CACHE_TTL,
            port_cache_ttl: DEFAULT_PORT_CACHE_TTL,
            enrichment_cache_ttl: DEFAULT_ENRICHMENT_CACHE_TTL,
            project_cache_ttl: DEFAULT_PROJECT_CACHE_TTL,
            cache_sweep_interval: DEFAULT_CACHE_SWEEP_INTERVAL,
            shutdown_timeout: DEFAULT_SHUTDOWN_TIMEOUT,
            command_capacity: DEFAULT_COMMAND_CAPACITY,
            update_capacity: DEFAULT_UPDATE_CAPACITY,
            process_cache_capacity: DEFAULT_PROCESS_CAPACITY,
            port_cache_capacity: DEFAULT_PORT_CAPACITY,
            enrichment_cache_capacity: DEFAULT_ENRICHMENT_CAPACITY,
            enrichment_concurrency: DEFAULT_ENRICHMENT_CONCURRENCY,
            project_cache_capacity: DEFAULT_PROJECT_CAPACITY,
            project_concurrency: DEFAULT_PROJECT_CONCURRENCY,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RefreshScope {
    FastProcesses,
    Ports,
    All,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RefreshMode {
    /// Coalesce any number of requests received during a scan into one rerun.
    Merge,
    /// Cooperatively cancel the running scan and rerun after it converges.
    CancelAndRestart,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum EnrichmentPriority {
    New,
    ClassificationCandidate,
    Visible,
    Selected,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnrichmentRequestStatus {
    Cached,
    Running,
    Queued,
    Merged,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProjectRequestStatus {
    Cached,
    Running,
    Queued,
    Merged,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnrichmentBatchRequest {
    pub instance_key: ProcessInstanceKey,
    pub priority: EnrichmentPriority,
    pub demand: EnrichmentDemand,
}

#[derive(Clone, Debug, PartialEq)]
pub struct EnrichmentBatchResult {
    pub instance_key: ProcessInstanceKey,
    pub result: Result<EnrichmentRequestStatus, AppError>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveryLatencySnapshot {
    pub completed: u64,
    pub failed: u64,
    pub cancelled: u64,
    pub sample_count: usize,
    pub p50: Option<Duration>,
    pub p95: Option<Duration>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveryPerformanceSnapshot {
    pub fast_scan_interval: Duration,
    pub port_scan_interval: Duration,
    pub enrichment_concurrency: usize,
    pub project_concurrency: usize,
    pub latency_window_capacity: usize,
    pub fast: DiscoveryLatencySnapshot,
    pub port: DiscoveryLatencySnapshot,
    pub enrichment: DiscoveryLatencySnapshot,
    pub project: DiscoveryLatencySnapshot,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DiscoveryOperation {
    FastProcessScan,
    PortScan,
    Enrichment(ProcessInstanceKey),
    ProjectAssociation(ProcessInstanceKey),
    /// Publication can follow scans, enrichment, project association, rule
    /// changes, or managed-run reconciliation, so it is reported separately.
    ProcessPublication(ProcessInstanceKey),
}

#[derive(Clone, Debug, PartialEq)]
pub struct DiscoveryUpdate {
    pub sequence: u64,
    pub change: DiscoveryChange,
}

#[derive(Clone, Debug, PartialEq)]
pub enum DiscoveryChange {
    ProcessDelta(ProcessDelta),
    PortDelta(PortDelta),
    /// Changes in scan availability are separate from binding deltas so an
    /// empty successful scan cannot be mistaken for an unknown scan.
    PortAvailabilityChanged(FieldValue<()>),
    OperationFailed {
        operation: DiscoveryOperation,
        error: AppError,
    },
}

#[derive(Clone, Debug, PartialEq)]
pub struct DiscoverySnapshot {
    /// Last update included in this snapshot. Buffered updates at or below
    /// this value must be discarded during resynchronization.
    pub sequence: u64,
    pub processes: Vec<ProcessRecord>,
    pub port_bindings: FieldValue<Vec<PortBinding>>,
}

/// A trusted Supervisor association. Native discovery adapters cannot create
/// these bindings because visibility does not establish lifecycle control.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedProcessBinding {
    pub process_instance_key: ProcessInstanceKey,
    pub run_id: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubscriptionError {
    Lagged { skipped: u64 },
    Closed,
}

pub struct DiscoverySubscription {
    receiver: broadcast::Receiver<DiscoveryUpdate>,
}

impl DiscoverySubscription {
    pub async fn recv(&mut self) -> Result<DiscoveryUpdate, SubscriptionError> {
        self.receiver.recv().await.map_err(|error| match error {
            broadcast::error::RecvError::Lagged(skipped) => SubscriptionError::Lagged { skipped },
            broadcast::error::RecvError::Closed => SubscriptionError::Closed,
        })
    }
}

#[derive(Clone)]
pub struct DiscoverySchedulerHandle {
    commands: mpsc::Sender<Command>,
}

impl DiscoverySchedulerHandle {
    pub async fn refresh(&self, scope: RefreshScope, mode: RefreshMode) -> Result<(), AppError> {
        let (reply, receiver) = oneshot::channel();
        self.send(Command::Refresh { scope, mode, reply }).await?;
        receive_reply(receiver).await?
    }

    pub async fn request_enrichment(
        &self,
        instance_key: ProcessInstanceKey,
        priority: EnrichmentPriority,
        demand: EnrichmentDemand,
    ) -> Result<EnrichmentRequestStatus, AppError> {
        let mut results = self
            .request_enrichment_batch(vec![EnrichmentBatchRequest {
                instance_key,
                priority,
                demand,
            }])
            .await?;
        results
            .pop()
            .ok_or_else(|| {
                internal_error(
                    "discovery enrichment batch returned no result",
                    "one request must produce one result".into(),
                )
            })?
            .result
    }

    pub async fn request_enrichment_batch(
        &self,
        requests: Vec<EnrichmentBatchRequest>,
    ) -> Result<Vec<EnrichmentBatchResult>, AppError> {
        if requests.len() > MAX_ENRICHMENT_BATCH_SIZE {
            return Err(invalid_enrichment_batch_size(requests.len()));
        }
        let (reply, receiver) = oneshot::channel();
        self.send(Command::RequestEnrichmentBatch { requests, reply })
            .await?;
        receive_reply(receiver).await
    }

    pub async fn cancel_enrichment(
        &self,
        instance_key: ProcessInstanceKey,
    ) -> Result<bool, AppError> {
        let (reply, receiver) = oneshot::channel();
        self.send(Command::CancelEnrichment {
            instance_key,
            reply,
        })
        .await?;
        receive_reply(receiver).await
    }

    pub async fn request_project_evidence(
        &self,
        instance_key: ProcessInstanceKey,
        priority: EnrichmentPriority,
    ) -> Result<ProjectRequestStatus, AppError> {
        let (reply, receiver) = oneshot::channel();
        self.send(Command::RequestProjectEvidence {
            instance_key,
            priority,
            reply,
        })
        .await?;
        receive_reply(receiver).await?
    }

    pub async fn cancel_project_evidence(
        &self,
        instance_key: ProcessInstanceKey,
    ) -> Result<bool, AppError> {
        let (reply, receiver) = oneshot::channel();
        self.send(Command::CancelProjectEvidence {
            instance_key,
            reply,
        })
        .await?;
        receive_reply(receiver).await
    }

    pub async fn replace_classification_rules(
        &self,
        snapshot: ClassificationRulesSnapshot,
    ) -> Result<(), AppError> {
        let (reply, receiver) = oneshot::channel();
        self.send(Command::ReplaceClassificationRules { snapshot, reply })
            .await?;
        receive_reply(receiver).await?
    }

    pub async fn replace_project_context(
        &self,
        snapshot: ProjectContextSnapshot,
    ) -> Result<(), AppError> {
        let (reply, receiver) = oneshot::channel();
        self.send(Command::ReplaceProjectContext { snapshot, reply })
            .await?;
        receive_reply(receiver).await?
    }

    /// Atomically replaces all trusted managed root-process associations.
    /// Missing keys become external on the same actor turn.
    pub async fn replace_managed_process_bindings(
        &self,
        bindings: Vec<ManagedProcessBinding>,
    ) -> Result<(), AppError> {
        let (reply, receiver) = oneshot::channel();
        self.send(Command::ReplaceManagedProcessBindings { bindings, reply })
            .await?;
        receive_reply(receiver).await?
    }

    pub async fn snapshot(&self) -> Result<DiscoverySnapshot, AppError> {
        let (reply, receiver) = oneshot::channel();
        self.send(Command::Snapshot { reply }).await?;
        receive_reply(receiver).await
    }

    pub async fn subscribe(&self) -> Result<DiscoverySubscription, AppError> {
        let (reply, receiver) = oneshot::channel();
        self.send(Command::Subscribe { reply }).await?;
        Ok(DiscoverySubscription {
            receiver: receive_reply(receiver).await?,
        })
    }

    pub async fn performance_snapshot(&self) -> Result<DiscoveryPerformanceSnapshot, AppError> {
        let (reply, receiver) = oneshot::channel();
        self.send(Command::PerformanceSnapshot { reply }).await?;
        receive_reply(receiver).await
    }

    async fn send(&self, command: Command) -> Result<(), AppError> {
        self.commands
            .send(command)
            .await
            .map_err(|_| unavailable("discovery scheduler is closed"))
    }
}

pub struct DiscoveryScheduler {
    handle: DiscoverySchedulerHandle,
    shutdown_signal: CancellationToken,
    actor_task: Option<JoinHandle<()>>,
}

impl DiscoveryScheduler {
    pub fn start(
        backend: Arc<dyn DiscoveryBackend>,
        config: DiscoveryConfig,
    ) -> Result<Self, AppError> {
        config.validate()?;
        let runtime = tokio::runtime::Handle::try_current().map_err(|error| {
            internal_error(
                "discovery scheduler requires a Tokio runtime",
                error.to_string(),
            )
        })?;
        let (command_sender, command_receiver) = mpsc::channel(config.command_capacity);
        let (update_sender, _) = broadcast::channel(config.update_capacity);
        let shutdown_signal = CancellationToken::new();
        let actor = Actor::new(
            backend,
            config,
            command_receiver,
            update_sender,
            shutdown_signal.clone(),
        );
        let actor_task = runtime.spawn(actor.run());
        Ok(Self {
            handle: DiscoverySchedulerHandle {
                commands: command_sender,
            },
            shutdown_signal,
            actor_task: Some(actor_task),
        })
    }

    pub fn start_with_backend<B>(backend: B, config: DiscoveryConfig) -> Result<Self, AppError>
    where
        B: DiscoveryBackend,
    {
        Self::start(Arc::new(backend), config)
    }

    pub fn handle(&self) -> DiscoverySchedulerHandle {
        self.handle.clone()
    }

    pub async fn shutdown(mut self) -> Result<(), AppError> {
        let (reply, receiver) = oneshot::channel();
        let command_result = self.handle.send(Command::Shutdown { reply }).await;
        let reply_result = match command_result {
            Ok(()) => receive_reply(receiver).await,
            Err(error) => Err(error),
        };

        self.shutdown_signal.cancel();
        let join_result = match self.actor_task.take() {
            Some(task) => task.await.map_err(|error| {
                internal_error("discovery scheduler actor failed", error.to_string())
            }),
            None => Ok(()),
        };
        join_result?;
        reply_result
    }
}

impl Drop for DiscoveryScheduler {
    fn drop(&mut self) {
        self.shutdown_signal.cancel();
        if let Some(actor_task) = self.actor_task.take() {
            actor_task.abort();
        }
    }
}

enum Command {
    Refresh {
        scope: RefreshScope,
        mode: RefreshMode,
        reply: oneshot::Sender<Result<(), AppError>>,
    },
    RequestEnrichmentBatch {
        requests: Vec<EnrichmentBatchRequest>,
        reply: oneshot::Sender<Vec<EnrichmentBatchResult>>,
    },
    CancelEnrichment {
        instance_key: ProcessInstanceKey,
        reply: oneshot::Sender<bool>,
    },
    RequestProjectEvidence {
        instance_key: ProcessInstanceKey,
        priority: EnrichmentPriority,
        reply: oneshot::Sender<Result<ProjectRequestStatus, AppError>>,
    },
    CancelProjectEvidence {
        instance_key: ProcessInstanceKey,
        reply: oneshot::Sender<bool>,
    },
    ReplaceClassificationRules {
        snapshot: ClassificationRulesSnapshot,
        reply: oneshot::Sender<Result<(), AppError>>,
    },
    ReplaceProjectContext {
        snapshot: ProjectContextSnapshot,
        reply: oneshot::Sender<Result<(), AppError>>,
    },
    ReplaceManagedProcessBindings {
        bindings: Vec<ManagedProcessBinding>,
        reply: oneshot::Sender<Result<(), AppError>>,
    },
    Snapshot {
        reply: oneshot::Sender<DiscoverySnapshot>,
    },
    Subscribe {
        reply: oneshot::Sender<broadcast::Receiver<DiscoveryUpdate>>,
    },
    PerformanceSnapshot {
        reply: oneshot::Sender<DiscoveryPerformanceSnapshot>,
    },
    Shutdown {
        reply: oneshot::Sender<()>,
    },
}

struct ProcessCacheEntry {
    record: ProcessRecord,
    expires_at: Instant,
}

struct PortCacheEntry {
    binding: PortBinding,
    expires_at: Instant,
}

struct ProcessPortCacheEntry {
    value: FieldValue<Vec<PortBinding>>,
    expires_at: Instant,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct PortEndpointKey {
    protocol: PortProtocol,
    address_family: AddressFamily,
    local_address: String,
    local_port: u16,
}

struct EnrichmentCacheEntry {
    expires_at: Instant,
    demand: EnrichmentDemand,
}

struct ProjectCacheEntry {
    expires_at: Instant,
    expected_working_directory: String,
    catalog_generation: u64,
}

struct PendingEnrichment {
    priority: EnrichmentPriority,
    demand: EnrichmentDemand,
    sequence: u64,
}

struct PendingProjectScan {
    priority: EnrichmentPriority,
    sequence: u64,
    expected_working_directory: String,
    catalog_generation: u64,
}

struct RunningTask {
    cancellation: CancellationToken,
    task_id: TaskId,
    started_at: Instant,
}

struct RunningEnrichment {
    cancellation: CancellationToken,
    task_id: TaskId,
    started_at: Instant,
    priority: EnrichmentPriority,
    started_demand: EnrichmentDemand,
    desired_demand: EnrichmentDemand,
}

struct RunningProjectScan {
    cancellation: CancellationToken,
    task_id: TaskId,
    started_at: Instant,
    priority: EnrichmentPriority,
    expected_working_directory: String,
    catalog_generation: u64,
}

#[derive(Clone, Debug)]
enum TaskKind {
    Fast,
    Port,
    Enrichment(ProcessInstanceKey),
    ProjectAssociation(ProcessInstanceKey),
}

enum TaskOutput {
    Fast {
        result: Result<FastProcessScan, AppError>,
        cancelled: bool,
    },
    Port {
        result: Result<PortScan, AppError>,
        cancelled: bool,
    },
    Enrichment {
        instance_key: ProcessInstanceKey,
        demand: EnrichmentDemand,
        result: Result<ProcessEnrichment, AppError>,
        cancelled: bool,
    },
    ProjectAssociation {
        request: ProjectScanRequest,
        result: Result<ProjectScanResult, AppError>,
        cancelled: bool,
    },
}

#[derive(Clone, Copy)]
enum TaskCompletionStatus {
    Completed,
    Failed,
    Cancelled,
}

#[derive(Default)]
struct LatencyRecorder {
    samples: VecDeque<Duration>,
    completed: u64,
    failed: u64,
    cancelled: u64,
}

impl LatencyRecorder {
    fn record(&mut self, status: TaskCompletionStatus, latency: Duration) {
        match status {
            TaskCompletionStatus::Completed => {
                self.completed = self.completed.saturating_add(1);
            }
            TaskCompletionStatus::Failed => {
                self.failed = self.failed.saturating_add(1);
            }
            TaskCompletionStatus::Cancelled => {
                self.cancelled = self.cancelled.saturating_add(1);
                return;
            }
        }
        if self.samples.len() == DISCOVERY_LATENCY_WINDOW_CAPACITY {
            self.samples.pop_front();
        }
        self.samples.push_back(latency);
    }

    fn snapshot(&self) -> DiscoveryLatencySnapshot {
        let mut samples = self.samples.iter().copied().collect::<Vec<_>>();
        samples.sort_unstable();
        DiscoveryLatencySnapshot {
            completed: self.completed,
            failed: self.failed,
            cancelled: self.cancelled,
            sample_count: samples.len(),
            p50: nearest_rank(&samples, 50),
            p95: nearest_rank(&samples, 95),
        }
    }
}

#[derive(Default)]
struct PerformanceRecorder {
    fast: LatencyRecorder,
    port: LatencyRecorder,
    enrichment: LatencyRecorder,
    project: LatencyRecorder,
}

impl PerformanceRecorder {
    fn record(&mut self, kind: &TaskKind, status: TaskCompletionStatus, latency: Duration) {
        match kind {
            TaskKind::Fast => &mut self.fast,
            TaskKind::Port => &mut self.port,
            TaskKind::Enrichment(_) => &mut self.enrichment,
            TaskKind::ProjectAssociation(_) => &mut self.project,
        }
        .record(status, latency);
    }
}

enum PendingProcessMutation {
    Upsert {
        record: ProcessRecord,
        estimated_bytes: usize,
    },
    Remove {
        estimated_bytes: usize,
    },
}

impl PendingProcessMutation {
    fn estimated_bytes(&self) -> usize {
        match self {
            Self::Upsert {
                estimated_bytes, ..
            }
            | Self::Remove { estimated_bytes } => *estimated_bytes,
        }
    }
}

enum PendingPortMutation {
    Upsert {
        binding: PortBinding,
        estimated_bytes: usize,
    },
    Remove {
        estimated_bytes: usize,
    },
}

impl PendingPortMutation {
    fn estimated_bytes(&self) -> usize {
        match self {
            Self::Upsert {
                estimated_bytes, ..
            }
            | Self::Remove { estimated_bytes } => *estimated_bytes,
        }
    }
}

#[derive(Default)]
struct DiscoveryEventAccumulator {
    processes: HashMap<ProcessInstanceKey, PendingProcessMutation>,
    ports: HashMap<PortBindingKey, PendingPortMutation>,
    availability: Option<(FieldValue<()>, usize)>,
    process_order: Option<u64>,
    port_order: Option<u64>,
    availability_order: Option<u64>,
    next_order: u64,
    estimated_payload_bytes: usize,
}

impl DiscoveryEventAccumulator {
    fn is_empty(&self) -> bool {
        self.processes.is_empty() && self.ports.is_empty() && self.availability.is_none()
    }

    fn entity_count(&self) -> usize {
        self.processes.len().saturating_add(self.ports.len())
    }

    fn next_change_order(&mut self) -> u64 {
        let order = self.next_order;
        self.next_order = self.next_order.saturating_add(1);
        order
    }

    fn into_ordered_changes(self) -> Vec<DiscoveryChange> {
        let mut changes = Vec::with_capacity(3);
        if let Some(order) = self.process_order {
            let mut upserted = Vec::new();
            let mut removed = Vec::new();
            for (key, mutation) in self.processes {
                match mutation {
                    PendingProcessMutation::Upsert { record, .. } => upserted.push(record),
                    PendingProcessMutation::Remove { .. } => removed.push(key),
                }
            }
            upserted.sort_by(|left, right| {
                compare_process_keys(&left.instance_key, &right.instance_key)
            });
            removed.sort_by(compare_process_keys);
            changes.push((
                order,
                DiscoveryChange::ProcessDelta(ProcessDelta { upserted, removed }),
            ));
        }
        if let Some(order) = self.port_order {
            let mut upserted = Vec::new();
            let mut removed = Vec::new();
            for (key, mutation) in self.ports {
                match mutation {
                    PendingPortMutation::Upsert { binding, .. } => upserted.push(binding),
                    PendingPortMutation::Remove { .. } => removed.push(key),
                }
            }
            sort_port_bindings(&mut upserted);
            sort_port_keys(&mut removed);
            changes.push((
                order,
                DiscoveryChange::PortDelta(PortDelta { upserted, removed }),
            ));
        }
        if let (Some(order), Some((availability, _))) = (self.availability_order, self.availability)
        {
            changes.push((
                order,
                DiscoveryChange::PortAvailabilityChanged(availability),
            ));
        }
        changes.sort_by_key(|(order, _)| *order);
        changes.into_iter().map(|(_, change)| change).collect()
    }
}

struct Actor {
    backend: Arc<dyn DiscoveryBackend>,
    config: DiscoveryConfig,
    commands: mpsc::Receiver<Command>,
    updates: broadcast::Sender<DiscoveryUpdate>,
    shutdown_signal: CancellationToken,
    tasks: JoinSet<TaskOutput>,
    task_kinds: HashMap<TaskId, TaskKind>,
    fast_task: Option<RunningTask>,
    fast_pending: bool,
    port_task: Option<RunningTask>,
    port_pending: bool,
    running_enrichments: HashMap<ProcessInstanceKey, RunningEnrichment>,
    pending_enrichments: HashMap<ProcessInstanceKey, PendingEnrichment>,
    running_project_scans: HashMap<ProcessInstanceKey, RunningProjectScan>,
    pending_project_scans: HashMap<ProcessInstanceKey, PendingProjectScan>,
    processes: HashMap<ProcessInstanceKey, ProcessCacheEntry>,
    ports: HashMap<PortBindingKey, PortCacheEntry>,
    process_port_results: HashMap<ProcessInstanceKey, ProcessPortCacheEntry>,
    port_availability: FieldValue<()>,
    port_availability_expires_at: Option<Instant>,
    enrichment_cache: HashMap<ProcessInstanceKey, EnrichmentCacheEntry>,
    project_cache: HashMap<ProcessInstanceKey, ProjectCacheEntry>,
    project_catalog: Arc<ProjectCatalog>,
    project_catalog_generation: u64,
    classification_engine: ClassificationEngine,
    classification_facts: HashMap<ProcessInstanceKey, ProcessClassificationFacts>,
    managed_process_bindings: HashMap<ProcessInstanceKey, String>,
    pending_updates: DiscoveryEventAccumulator,
    performance: PerformanceRecorder,
    ordering_sequence: u64,
    update_sequence: u64,
}

impl Actor {
    fn new(
        backend: Arc<dyn DiscoveryBackend>,
        config: DiscoveryConfig,
        commands: mpsc::Receiver<Command>,
        updates: broadcast::Sender<DiscoveryUpdate>,
        shutdown_signal: CancellationToken,
    ) -> Self {
        Self {
            backend,
            config,
            commands,
            updates,
            shutdown_signal,
            tasks: JoinSet::new(),
            task_kinds: HashMap::new(),
            fast_task: None,
            fast_pending: false,
            port_task: None,
            port_pending: false,
            running_enrichments: HashMap::new(),
            pending_enrichments: HashMap::new(),
            running_project_scans: HashMap::new(),
            pending_project_scans: HashMap::new(),
            processes: HashMap::new(),
            ports: HashMap::new(),
            process_port_results: HashMap::new(),
            port_availability: FieldValue::Unknown,
            port_availability_expires_at: None,
            enrichment_cache: HashMap::new(),
            project_cache: HashMap::new(),
            project_catalog: ProjectCatalog::empty(),
            project_catalog_generation: 0,
            classification_engine: ClassificationEngine::default(),
            classification_facts: HashMap::new(),
            managed_process_bindings: HashMap::new(),
            pending_updates: DiscoveryEventAccumulator::default(),
            performance: PerformanceRecorder::default(),
            ordering_sequence: 0,
            update_sequence: 0,
        }
    }

    async fn run(mut self) {
        let mut fast_interval = tokio::time::interval(self.config.fast_scan_interval);
        fast_interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let mut port_interval = tokio::time::interval(self.config.port_scan_interval);
        port_interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let mut sweep_interval = tokio::time::interval(self.config.cache_sweep_interval);
        sweep_interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let mut event_flush_interval = tokio::time::interval_at(
            Instant::now() + EVENT_ACCUMULATION_INTERVAL,
            EVENT_ACCUMULATION_INTERVAL,
        );
        event_flush_interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let mut shutdown_reply = None;

        loop {
            tokio::select! {
                _ = self.shutdown_signal.cancelled() => break,
                command = self.commands.recv() => {
                    match command {
                        Some(Command::Shutdown { reply }) => {
                            shutdown_reply = Some(reply);
                            break;
                        }
                        Some(command) => self.handle_command(command),
                        None => break,
                    }
                }
                _ = fast_interval.tick() => self.request_fast_scan(RefreshMode::Merge),
                _ = port_interval.tick() => self.request_port_scan(RefreshMode::Merge),
                _ = sweep_interval.tick() => self.sweep_expired(),
                _ = event_flush_interval.tick() => self.flush_pending_updates(),
                task = self.tasks.join_next_with_id(), if !self.tasks.is_empty() => {
                    if let Some(task) = task {
                        self.handle_task_completion(task);
                    }
                }
            }
        }

        self.flush_pending_updates();
        self.commands.close();
        self.cancel_all_tasks();
        self.drain_tasks().await;
        self.flush_pending_updates();
        if let Some(reply) = shutdown_reply {
            let _ = reply.send(());
        }
    }

    fn handle_command(&mut self, command: Command) {
        match command {
            Command::Refresh { scope, mode, reply } => {
                match scope {
                    RefreshScope::FastProcesses => self.request_fast_scan(mode),
                    RefreshScope::Ports => self.request_port_scan(mode),
                    RefreshScope::All => {
                        self.request_fast_scan(mode);
                        self.request_port_scan(mode);
                    }
                }
                let _ = reply.send(Ok(()));
            }
            Command::RequestEnrichmentBatch { requests, reply } => {
                let results = requests
                    .into_iter()
                    .map(|request| {
                        let instance_key = request.instance_key;
                        let result = self.queue_enrichment(
                            instance_key.clone(),
                            request.priority,
                            request.demand,
                        );
                        if result.is_ok() && request.priority >= EnrichmentPriority::Visible {
                            self.queue_project_scan_background(
                                instance_key.clone(),
                                request.priority,
                            );
                        }
                        EnrichmentBatchResult {
                            instance_key,
                            result,
                        }
                    })
                    .collect();
                let _ = reply.send(results);
            }
            Command::CancelEnrichment {
                instance_key,
                reply,
            } => {
                let _ = reply.send(self.cancel_enrichment(&instance_key));
            }
            Command::RequestProjectEvidence {
                instance_key,
                priority,
                reply,
            } => {
                let result = self.queue_project_scan(instance_key, priority);
                let _ = reply.send(result);
            }
            Command::CancelProjectEvidence {
                instance_key,
                reply,
            } => {
                let _ = reply.send(self.cancel_project_scan(&instance_key));
            }
            Command::ReplaceClassificationRules { snapshot, reply } => {
                let _ = reply.send(self.replace_classification_rules(snapshot));
            }
            Command::ReplaceProjectContext { snapshot, reply } => {
                let _ = reply.send(self.replace_project_context(snapshot));
            }
            Command::ReplaceManagedProcessBindings { bindings, reply } => {
                let _ = reply.send(self.replace_managed_process_bindings(bindings));
            }
            Command::Snapshot { reply } => {
                self.sweep_expired();
                self.flush_pending_updates();
                let _ = reply.send(self.snapshot());
            }
            Command::Subscribe { reply } => {
                self.flush_pending_updates();
                let _ = reply.send(self.updates.subscribe());
            }
            Command::PerformanceSnapshot { reply } => {
                let _ = reply.send(self.performance_snapshot());
            }
            Command::Shutdown { .. } => unreachable!("shutdown is handled by the actor loop"),
        }
    }

    fn replace_classification_rules(
        &mut self,
        snapshot: ClassificationRulesSnapshot,
    ) -> Result<(), AppError> {
        validate_project_context_ids(self.project_catalog.as_ref(), &snapshot)?;
        let next_engine = ClassificationEngine::new(snapshot)?;
        validate_classification_workload(self.config.process_cache_capacity, &next_engine)?;
        let mut fact_keys = self
            .classification_facts
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        fact_keys.sort_by(compare_process_keys);
        for key in fact_keys {
            if let Some(facts) = self.classification_facts.get(&key) {
                next_engine.validate_facts(facts)?;
            }
        }
        self.classification_engine = next_engine;
        self.reclassify_all_processes();
        Ok(())
    }

    fn replace_project_context(
        &mut self,
        snapshot: ProjectContextSnapshot,
    ) -> Result<(), AppError> {
        let next_catalog = Arc::new(ProjectCatalog::new(snapshot.catalog)?);
        validate_project_context_ids(next_catalog.as_ref(), &snapshot.classification_rules)?;
        let next_engine = ClassificationEngine::new(snapshot.classification_rules)?;
        validate_classification_workload(self.config.process_cache_capacity, &next_engine)?;
        let next_generation = self
            .project_catalog_generation
            .checked_add(1)
            .ok_or_else(project_catalog_generation_exhausted)?;

        self.cancel_all_project_scans();
        self.project_cache.clear();
        self.classification_facts.clear();
        self.project_catalog = next_catalog;
        self.project_catalog_generation = next_generation;
        self.classification_engine = next_engine;

        let mut keys = self.processes.keys().cloned().collect::<Vec<_>>();
        keys.sort_by(compare_process_keys);
        let mut upserted = Vec::new();
        let mut rescan_keys = Vec::new();
        for key in keys {
            let Some(entry) = self.processes.get_mut(&key) else {
                continue;
            };
            let old = entry.record.clone();
            reset_project_evidence(&mut entry.record);
            apply_classification(&self.classification_engine, None, &mut entry.record);
            if matches!(entry.record.working_directory, FieldValue::Known(_)) {
                rescan_keys.push(key);
            }
            if process_semantically_equal(&old, &entry.record) {
                entry.record = old;
            } else {
                upserted.push(entry.record.clone());
            }
        }
        if !upserted.is_empty() {
            self.publish(DiscoveryChange::ProcessDelta(ProcessDelta {
                upserted,
                removed: Vec::new(),
            }));
        }
        for key in rescan_keys {
            self.queue_project_scan_background(key, EnrichmentPriority::New);
        }
        Ok(())
    }

    fn replace_managed_process_bindings(
        &mut self,
        bindings: Vec<ManagedProcessBinding>,
    ) -> Result<(), AppError> {
        if bindings.len() > self.config.process_cache_capacity {
            return Err(managed_binding_capacity_error(
                bindings.len(),
                self.config.process_cache_capacity,
            ));
        }
        let mut next = HashMap::with_capacity(bindings.len());
        let mut run_ids = HashSet::with_capacity(bindings.len());
        for binding in bindings {
            validate_instance_key(
                &binding.process_instance_key,
                "managedProcessBinding",
                ErrorCode::InvalidArgument,
            )?;
            validate_managed_run_id(&binding.run_id)?;
            if !run_ids.insert(binding.run_id.clone()) {
                return Err(duplicate_managed_binding_error(
                    "runId",
                    &binding.run_id,
                    binding.process_instance_key.pid,
                ));
            }
            if next
                .insert(binding.process_instance_key.clone(), binding.run_id.clone())
                .is_some()
            {
                return Err(duplicate_managed_binding_error(
                    "processInstanceKey",
                    &binding.run_id,
                    binding.process_instance_key.pid,
                ));
            }
        }
        if next == self.managed_process_bindings {
            return Ok(());
        }
        self.managed_process_bindings = next;

        let mut keys = self.processes.keys().cloned().collect::<Vec<_>>();
        keys.sort_by(compare_process_keys);
        let mut upserted = Vec::new();
        for key in keys {
            let Some(entry) = self.processes.get_mut(&key) else {
                continue;
            };
            let old = entry.record.clone();
            overlay_managed_process_binding(&self.managed_process_bindings, &mut entry.record);
            if classification_inputs_semantically_different(&old, &entry.record) {
                apply_classification(
                    &self.classification_engine,
                    self.classification_facts.get(&key),
                    &mut entry.record,
                );
            }
            if !process_semantically_equal(&old, &entry.record) {
                upserted.push(entry.record.clone());
            }
        }
        if !upserted.is_empty() {
            self.publish(DiscoveryChange::ProcessDelta(ProcessDelta {
                upserted,
                removed: Vec::new(),
            }));
        }
        Ok(())
    }

    fn clear_project_evidence(
        &mut self,
        instance_key: &ProcessInstanceKey,
    ) -> Option<ProcessRecord> {
        self.classification_facts.remove(instance_key);
        let entry = self.processes.get_mut(instance_key)?;
        let old = entry.record.clone();
        reset_project_evidence(&mut entry.record);
        apply_classification(&self.classification_engine, None, &mut entry.record);
        if process_semantically_equal(&old, &entry.record) {
            entry.record = old;
            None
        } else {
            Some(entry.record.clone())
        }
    }

    fn reclassify_all_processes(&mut self) {
        let mut keys = self.processes.keys().cloned().collect::<Vec<_>>();
        keys.sort_by(compare_process_keys);
        let mut upserted = Vec::new();
        for key in keys {
            let Some(entry) = self.processes.get_mut(&key) else {
                continue;
            };
            let old = entry.record.clone();
            apply_classification(
                &self.classification_engine,
                self.classification_facts.get(&key),
                &mut entry.record,
            );
            if process_semantically_equal(&old, &entry.record) {
                entry.record = old;
            } else {
                upserted.push(entry.record.clone());
            }
        }
        if !upserted.is_empty() {
            self.publish(DiscoveryChange::ProcessDelta(ProcessDelta {
                upserted,
                removed: Vec::new(),
            }));
        }
    }

    fn request_fast_scan(&mut self, mode: RefreshMode) {
        if let Some(running) = &self.fast_task {
            self.fast_pending = true;
            if mode == RefreshMode::CancelAndRestart {
                running.cancellation.cancel();
            }
            return;
        }
        self.spawn_fast_scan();
    }

    fn request_port_scan(&mut self, mode: RefreshMode) {
        if let Some(running) = &self.port_task {
            self.port_pending = true;
            if mode == RefreshMode::CancelAndRestart {
                running.cancellation.cancel();
            }
            return;
        }
        self.spawn_port_scan();
    }

    fn spawn_fast_scan(&mut self) {
        let backend = Arc::clone(&self.backend);
        let cancellation = CancellationToken::new();
        let task_cancellation = cancellation.clone();
        let started_at = Instant::now();
        let abort_handle = self.tasks.spawn(async move {
            let result = backend.scan_processes(task_cancellation.clone()).await;
            TaskOutput::Fast {
                result,
                cancelled: task_cancellation.is_cancelled(),
            }
        });
        let task_id = abort_handle.id();
        self.task_kinds.insert(task_id, TaskKind::Fast);
        self.fast_task = Some(RunningTask {
            cancellation,
            task_id,
            started_at,
        });
    }

    fn spawn_port_scan(&mut self) {
        let backend = Arc::clone(&self.backend);
        let cancellation = CancellationToken::new();
        let task_cancellation = cancellation.clone();
        let started_at = Instant::now();
        let abort_handle = self.tasks.spawn(async move {
            let result = backend.scan_ports(task_cancellation.clone()).await;
            TaskOutput::Port {
                result,
                cancelled: task_cancellation.is_cancelled(),
            }
        });
        let task_id = abort_handle.id();
        self.task_kinds.insert(task_id, TaskKind::Port);
        self.port_task = Some(RunningTask {
            cancellation,
            task_id,
            started_at,
        });
    }

    fn queue_enrichment(
        &mut self,
        instance_key: ProcessInstanceKey,
        priority: EnrichmentPriority,
        demand: EnrichmentDemand,
    ) -> Result<EnrichmentRequestStatus, AppError> {
        if !self.processes.contains_key(&instance_key) {
            let mut error = AppError::new(ErrorCode::NotFound, "process instance is not cached");
            error
                .details
                .insert("pid".into(), instance_key.pid.to_string());
            return Err(error);
        }

        let now = Instant::now();
        if self
            .enrichment_cache
            .get(&instance_key)
            .is_some_and(|entry| entry.expires_at > now && entry.demand >= demand)
        {
            return Ok(EnrichmentRequestStatus::Cached);
        }
        if self
            .enrichment_cache
            .get(&instance_key)
            .is_some_and(|entry| entry.expires_at <= now)
        {
            self.enrichment_cache.remove(&instance_key);
        }

        if let Some(running) = self.running_enrichments.get_mut(&instance_key) {
            if !running.cancellation.is_cancelled() {
                let upgraded = priority > running.priority || demand > running.desired_demand;
                if priority > running.priority {
                    running.priority = priority;
                }
                if demand > running.desired_demand {
                    running.desired_demand = demand;
                }
                return Ok(if upgraded {
                    EnrichmentRequestStatus::Merged
                } else {
                    EnrichmentRequestStatus::Running
                });
            }
        }

        if let Some(pending) = self.pending_enrichments.get_mut(&instance_key) {
            if priority > pending.priority {
                pending.priority = priority;
            }
            if demand > pending.demand {
                pending.demand = demand;
            }
            return Ok(EnrichmentRequestStatus::Merged);
        }

        let sequence = self.next_ordering_sequence();
        self.pending_enrichments.insert(
            instance_key,
            PendingEnrichment {
                priority,
                demand,
                sequence,
            },
        );
        self.pump_enrichments();
        Ok(EnrichmentRequestStatus::Queued)
    }

    fn pump_enrichments(&mut self) {
        while self.running_enrichments.len() < self.config.enrichment_concurrency {
            let Some(instance_key) = self.next_pending_enrichment() else {
                break;
            };
            let Some(pending) = self.pending_enrichments.remove(&instance_key) else {
                continue;
            };
            if !self.processes.contains_key(&instance_key) {
                continue;
            }
            let now = Instant::now();
            if self
                .enrichment_cache
                .get(&instance_key)
                .is_some_and(|entry| entry.expires_at > now && entry.demand >= pending.demand)
            {
                continue;
            }
            if self
                .enrichment_cache
                .get(&instance_key)
                .is_some_and(|entry| entry.expires_at <= now)
            {
                self.enrichment_cache.remove(&instance_key);
            }

            let backend = Arc::clone(&self.backend);
            let cancellation = CancellationToken::new();
            let task_cancellation = cancellation.clone();
            let task_key = instance_key.clone();
            let task_demand = pending.demand;
            let started_at = Instant::now();
            let abort_handle = self.tasks.spawn(async move {
                let result = backend
                    .enrich_process(task_key.clone(), task_demand, task_cancellation.clone())
                    .await;
                TaskOutput::Enrichment {
                    instance_key: task_key,
                    demand: task_demand,
                    result,
                    cancelled: task_cancellation.is_cancelled(),
                }
            });
            let task_id = abort_handle.id();
            self.task_kinds
                .insert(task_id, TaskKind::Enrichment(instance_key.clone()));
            self.running_enrichments.insert(
                instance_key,
                RunningEnrichment {
                    cancellation,
                    task_id,
                    started_at,
                    priority: pending.priority,
                    started_demand: pending.demand,
                    desired_demand: pending.demand,
                },
            );
        }
    }

    fn next_pending_enrichment(&self) -> Option<ProcessInstanceKey> {
        self.pending_enrichments
            .iter()
            .filter(|(key, _)| !self.running_enrichments.contains_key(*key))
            .max_by(|(_, left), (_, right)| {
                left.priority
                    .cmp(&right.priority)
                    .then_with(|| right.sequence.cmp(&left.sequence))
            })
            .map(|(key, _)| key.clone())
    }

    fn cancel_enrichment(&mut self, instance_key: &ProcessInstanceKey) -> bool {
        let pending = self.pending_enrichments.remove(instance_key).is_some();
        let running = self
            .running_enrichments
            .get(instance_key)
            .is_some_and(|running| {
                running.cancellation.cancel();
                true
            });
        pending || running
    }

    fn queue_project_scan(
        &mut self,
        instance_key: ProcessInstanceKey,
        priority: EnrichmentPriority,
    ) -> Result<ProjectRequestStatus, AppError> {
        let expected_working_directory = match self.processes.get(&instance_key) {
            Some(entry) => match &entry.record.working_directory {
                FieldValue::Known(value) => value.clone(),
                FieldValue::Unknown
                | FieldValue::AccessLimited { .. }
                | FieldValue::NotSupported => return Ok(ProjectRequestStatus::Cached),
            },
            None => {
                let mut error =
                    AppError::new(ErrorCode::NotFound, "process instance is not cached");
                error
                    .details
                    .insert("pid".into(), instance_key.pid.to_string());
                return Err(error);
            }
        };

        let now = Instant::now();
        if self.project_cache.get(&instance_key).is_some_and(|entry| {
            entry.expires_at > now
                && entry.catalog_generation == self.project_catalog_generation
                && entry.expected_working_directory == expected_working_directory
        }) {
            return Ok(ProjectRequestStatus::Cached);
        }
        self.project_cache.remove(&instance_key);

        if let Some(running) = self.running_project_scans.get_mut(&instance_key) {
            if !running.cancellation.is_cancelled()
                && running.catalog_generation == self.project_catalog_generation
                && running.expected_working_directory == expected_working_directory
            {
                if priority > running.priority {
                    running.priority = priority;
                    return Ok(ProjectRequestStatus::Merged);
                }
                return Ok(ProjectRequestStatus::Running);
            }
            running.cancellation.cancel();
        }

        if let Some(pending) = self.pending_project_scans.get_mut(&instance_key) {
            if pending.catalog_generation == self.project_catalog_generation
                && pending.expected_working_directory == expected_working_directory
            {
                if priority > pending.priority {
                    pending.priority = priority;
                }
                return Ok(ProjectRequestStatus::Merged);
            }
            self.pending_project_scans.remove(&instance_key);
        }

        let queued = self
            .pending_project_scans
            .len()
            .saturating_add(self.running_project_scans.len());
        if queued >= self.config.project_cache_capacity {
            return Err(scan_capacity_error(
                "projectAssociationTask",
                queued.saturating_add(1),
                self.config.project_cache_capacity,
            ));
        }

        let sequence = self.next_ordering_sequence();
        self.pending_project_scans.insert(
            instance_key,
            PendingProjectScan {
                priority,
                sequence,
                expected_working_directory,
                catalog_generation: self.project_catalog_generation,
            },
        );
        self.pump_project_scans();
        Ok(ProjectRequestStatus::Queued)
    }

    fn queue_project_scan_background(
        &mut self,
        instance_key: ProcessInstanceKey,
        priority: EnrichmentPriority,
    ) {
        if let Err(error) = self.queue_project_scan(instance_key.clone(), priority) {
            self.publish(DiscoveryChange::OperationFailed {
                operation: DiscoveryOperation::ProjectAssociation(instance_key),
                error,
            });
        }
    }

    fn pump_project_scans(&mut self) {
        while self.running_project_scans.len() < self.config.project_concurrency {
            let Some(instance_key) = self.next_pending_project_scan() else {
                break;
            };
            let Some(pending) = self.pending_project_scans.remove(&instance_key) else {
                continue;
            };
            let current_working_directory = self.processes.get(&instance_key).and_then(|entry| {
                match &entry.record.working_directory {
                    FieldValue::Known(value) => Some(value.as_str()),
                    FieldValue::Unknown
                    | FieldValue::AccessLimited { .. }
                    | FieldValue::NotSupported => None,
                }
            });
            if pending.catalog_generation != self.project_catalog_generation
                || current_working_directory != Some(pending.expected_working_directory.as_str())
            {
                continue;
            }

            let now = Instant::now();
            if self.project_cache.get(&instance_key).is_some_and(|entry| {
                entry.expires_at > now
                    && entry.catalog_generation == pending.catalog_generation
                    && entry.expected_working_directory == pending.expected_working_directory
            }) {
                continue;
            }
            self.project_cache.remove(&instance_key);

            let cancellation = CancellationToken::new();
            let request = match ProjectScanRequest::new(
                instance_key.clone(),
                pending.expected_working_directory.clone(),
                Arc::clone(&self.project_catalog),
                pending.catalog_generation,
                cancellation.clone(),
            ) {
                Ok(request) => request,
                Err(error) => {
                    self.publish(DiscoveryChange::OperationFailed {
                        operation: DiscoveryOperation::ProjectAssociation(instance_key),
                        error,
                    });
                    continue;
                }
            };
            let backend = Arc::clone(&self.backend);
            let backend_request = request.clone();
            let task_cancellation = cancellation.clone();
            let started_at = Instant::now();
            let abort_handle = self.tasks.spawn(async move {
                let result = backend.scan_project_evidence(backend_request).await;
                TaskOutput::ProjectAssociation {
                    request,
                    result,
                    cancelled: task_cancellation.is_cancelled(),
                }
            });
            let task_id = abort_handle.id();
            self.task_kinds
                .insert(task_id, TaskKind::ProjectAssociation(instance_key.clone()));
            self.running_project_scans.insert(
                instance_key,
                RunningProjectScan {
                    cancellation,
                    task_id,
                    started_at,
                    priority: pending.priority,
                    expected_working_directory: pending.expected_working_directory,
                    catalog_generation: pending.catalog_generation,
                },
            );
        }
    }

    fn next_pending_project_scan(&self) -> Option<ProcessInstanceKey> {
        self.pending_project_scans
            .iter()
            .filter(|(key, _)| !self.running_project_scans.contains_key(*key))
            .max_by(|(_, left), (_, right)| {
                left.priority
                    .cmp(&right.priority)
                    .then_with(|| right.sequence.cmp(&left.sequence))
            })
            .map(|(key, _)| key.clone())
    }

    fn cancel_project_scan(&mut self, instance_key: &ProcessInstanceKey) -> bool {
        let pending = self.pending_project_scans.remove(instance_key).is_some();
        let running = self
            .running_project_scans
            .get(instance_key)
            .is_some_and(|running| {
                running.cancellation.cancel();
                true
            });
        pending || running
    }

    fn cancel_all_project_scans(&mut self) {
        self.pending_project_scans.clear();
        for running in self.running_project_scans.values() {
            running.cancellation.cancel();
        }
    }

    fn handle_task_completion(
        &mut self,
        completion: Result<(TaskId, TaskOutput), tokio::task::JoinError>,
    ) {
        match completion {
            Ok((task_id, output)) => {
                let kind = self.task_kinds.remove(&task_id);
                let cancelled_by_actor = self.task_was_cancelled(task_id, kind.as_ref());
                let latency = self.task_elapsed(task_id, kind.as_ref());
                let completed_enrichment = self.clear_running_task(task_id, kind.as_ref());
                let enrichment_priority = completed_enrichment
                    .as_ref()
                    .map(|completed| completed.priority);
                let status =
                    self.apply_task_output(output, cancelled_by_actor, enrichment_priority);
                if let (Some(kind), Some(latency)) = (kind.as_ref(), latency) {
                    self.performance.record(kind, status, latency);
                }
                self.queue_enrichment_follow_up(
                    kind.as_ref(),
                    completed_enrichment,
                    cancelled_by_actor,
                );
                self.restart_after_task(kind);
            }
            Err(error) => {
                let task_id = error.id();
                let kind = self.task_kinds.remove(&task_id);
                let cancelled_by_actor = self.task_was_cancelled(task_id, kind.as_ref());
                let latency = self.task_elapsed(task_id, kind.as_ref());
                let completed_enrichment = self.clear_running_task(task_id, kind.as_ref());
                let status = if error.is_cancelled() || cancelled_by_actor {
                    TaskCompletionStatus::Cancelled
                } else {
                    let operation = operation_for_task(kind.as_ref());
                    self.publish(DiscoveryChange::OperationFailed {
                        operation,
                        error: internal_error("discovery backend task failed", error.to_string()),
                    });
                    TaskCompletionStatus::Failed
                };
                if let (Some(kind), Some(latency)) = (kind.as_ref(), latency) {
                    self.performance.record(kind, status, latency);
                }
                self.queue_enrichment_follow_up(
                    kind.as_ref(),
                    completed_enrichment,
                    cancelled_by_actor,
                );
                self.restart_after_task(kind);
            }
        }
    }

    fn task_was_cancelled(&self, task_id: TaskId, kind: Option<&TaskKind>) -> bool {
        match kind {
            Some(TaskKind::Fast) => self
                .fast_task
                .as_ref()
                .is_some_and(|task| task.task_id == task_id && task.cancellation.is_cancelled()),
            Some(TaskKind::Port) => self
                .port_task
                .as_ref()
                .is_some_and(|task| task.task_id == task_id && task.cancellation.is_cancelled()),
            Some(TaskKind::Enrichment(instance_key)) => self
                .running_enrichments
                .get(instance_key)
                .is_some_and(|task| task.task_id == task_id && task.cancellation.is_cancelled()),
            Some(TaskKind::ProjectAssociation(instance_key)) => self
                .running_project_scans
                .get(instance_key)
                .is_some_and(|task| task.task_id == task_id && task.cancellation.is_cancelled()),
            None => true,
        }
    }

    fn task_elapsed(&self, task_id: TaskId, kind: Option<&TaskKind>) -> Option<Duration> {
        let started_at = match kind? {
            TaskKind::Fast => self
                .fast_task
                .as_ref()
                .filter(|task| task.task_id == task_id)
                .map(|task| task.started_at),
            TaskKind::Port => self
                .port_task
                .as_ref()
                .filter(|task| task.task_id == task_id)
                .map(|task| task.started_at),
            TaskKind::Enrichment(instance_key) => self
                .running_enrichments
                .get(instance_key)
                .filter(|task| task.task_id == task_id)
                .map(|task| task.started_at),
            TaskKind::ProjectAssociation(instance_key) => self
                .running_project_scans
                .get(instance_key)
                .filter(|task| task.task_id == task_id)
                .map(|task| task.started_at),
        }?;
        Some(started_at.elapsed())
    }

    fn clear_running_task(
        &mut self,
        task_id: TaskId,
        kind: Option<&TaskKind>,
    ) -> Option<RunningEnrichment> {
        match kind {
            Some(TaskKind::Fast) => {
                debug_assert_eq!(
                    self.fast_task.as_ref().map(|task| task.task_id),
                    Some(task_id)
                );
                self.fast_task = None;
                None
            }
            Some(TaskKind::Port) => {
                debug_assert_eq!(
                    self.port_task.as_ref().map(|task| task.task_id),
                    Some(task_id)
                );
                self.port_task = None;
                None
            }
            Some(TaskKind::Enrichment(instance_key)) => {
                if self
                    .running_enrichments
                    .get(instance_key)
                    .is_some_and(|task| task.task_id == task_id)
                {
                    self.running_enrichments.remove(instance_key)
                } else {
                    None
                }
            }
            Some(TaskKind::ProjectAssociation(instance_key)) => {
                if self
                    .running_project_scans
                    .get(instance_key)
                    .is_some_and(|task| task.task_id == task_id)
                {
                    self.running_project_scans.remove(instance_key);
                }
                None
            }
            None => None,
        }
    }

    fn queue_enrichment_follow_up(
        &mut self,
        kind: Option<&TaskKind>,
        completed: Option<RunningEnrichment>,
        cancelled_by_actor: bool,
    ) {
        let (Some(TaskKind::Enrichment(instance_key)), Some(completed)) = (kind, completed) else {
            return;
        };
        if cancelled_by_actor || completed.started_demand >= completed.desired_demand {
            return;
        }
        let _ = self.queue_enrichment(
            instance_key.clone(),
            completed.priority,
            completed.desired_demand,
        );
    }

    fn apply_task_output(
        &mut self,
        output: TaskOutput,
        cancelled_by_actor: bool,
        enrichment_priority: Option<EnrichmentPriority>,
    ) -> TaskCompletionStatus {
        match output {
            TaskOutput::Fast { result, cancelled } => {
                if cancelled || cancelled_by_actor {
                    TaskCompletionStatus::Cancelled
                } else {
                    match result.and_then(|scan| self.apply_fast_scan(scan)) {
                        Ok(()) => TaskCompletionStatus::Completed,
                        Err(error) => {
                            self.publish(DiscoveryChange::OperationFailed {
                                operation: DiscoveryOperation::FastProcessScan,
                                error,
                            });
                            TaskCompletionStatus::Failed
                        }
                    }
                }
            }
            TaskOutput::Port { result, cancelled } => {
                if cancelled || cancelled_by_actor {
                    TaskCompletionStatus::Cancelled
                } else {
                    match result.and_then(|scan| self.apply_port_scan(scan)) {
                        Ok(()) => TaskCompletionStatus::Completed,
                        Err(error) => {
                            self.publish(DiscoveryChange::OperationFailed {
                                operation: DiscoveryOperation::PortScan,
                                error,
                            });
                            TaskCompletionStatus::Failed
                        }
                    }
                }
            }
            TaskOutput::Enrichment {
                instance_key,
                demand,
                result,
                cancelled,
            } => {
                if cancelled || cancelled_by_actor {
                    TaskCompletionStatus::Cancelled
                } else {
                    match result.and_then(|result| {
                        self.apply_enrichment(
                            &instance_key,
                            demand,
                            enrichment_priority.unwrap_or(EnrichmentPriority::New),
                            result,
                        )
                    }) {
                        Ok(()) => TaskCompletionStatus::Completed,
                        Err(error) => {
                            self.publish(DiscoveryChange::OperationFailed {
                                operation: DiscoveryOperation::Enrichment(instance_key),
                                error,
                            });
                            TaskCompletionStatus::Failed
                        }
                    }
                }
            }
            TaskOutput::ProjectAssociation {
                request,
                result,
                cancelled,
            } => {
                if cancelled || cancelled_by_actor {
                    TaskCompletionStatus::Cancelled
                } else {
                    let instance_key = request.instance_key.clone();
                    match result.and_then(|result| self.apply_project_scan(&request, result)) {
                        Ok(()) => TaskCompletionStatus::Completed,
                        Err(error) => {
                            self.publish(DiscoveryChange::OperationFailed {
                                operation: DiscoveryOperation::ProjectAssociation(instance_key),
                                error,
                            });
                            TaskCompletionStatus::Failed
                        }
                    }
                }
            }
        }
    }

    fn restart_after_task(&mut self, kind: Option<TaskKind>) {
        match kind {
            Some(TaskKind::Fast) if self.fast_pending => {
                self.fast_pending = false;
                self.spawn_fast_scan();
            }
            Some(TaskKind::Port) if self.port_pending => {
                self.port_pending = false;
                self.spawn_port_scan();
            }
            Some(TaskKind::Enrichment(_)) => self.pump_enrichments(),
            Some(TaskKind::ProjectAssociation(_)) => self.pump_project_scans(),
            _ => {}
        }
    }

    fn apply_fast_scan(&mut self, scan: FastProcessScan) -> Result<(), AppError> {
        if scan.processes.len() > self.config.process_cache_capacity {
            return Err(scan_capacity_error(
                "process",
                scan.processes.len(),
                self.config.process_cache_capacity,
            ));
        }

        let now = Instant::now();
        let expires_at = now + self.config.process_cache_ttl;
        let mut seen = HashSet::with_capacity(scan.processes.len());
        let mut next = HashMap::with_capacity(scan.processes.len());
        let mut upserted = Vec::new();
        let mut new_keys = Vec::new();
        let mut project_invalidated_keys = Vec::new();
        let mut project_rescan_keys = Vec::new();

        for mut record in scan.processes {
            validate_instance_key(&record.instance_key, "process", ErrorCode::PlatformError)?;
            if let FieldValue::Known(Some(parent)) = &record.parent_instance_key {
                validate_instance_key(parent, "parentProcess", ErrorCode::PlatformError)?;
            }
            if !seen.insert(record.instance_key.clone()) {
                return Err(duplicate_key_error("process", record.instance_key.pid));
            }
            let instance_key = record.instance_key.clone();
            let old = self
                .processes
                .get(&instance_key)
                .map(|entry| entry.record.clone());
            normalize_fast_record(&mut record, old.as_ref());
            overlay_managed_process_binding(&self.managed_process_bindings, &mut record);
            let working_directory_changed = old
                .as_ref()
                .is_some_and(|old| old.working_directory != record.working_directory);
            if old.is_none() {
                record.port_bindings = process_port_value(
                    &instance_key,
                    &self.port_availability,
                    &self.ports,
                    &self.process_port_results,
                );
                reset_project_evidence(&mut record);
            } else if working_directory_changed {
                project_invalidated_keys.push(instance_key.clone());
                reset_project_evidence(&mut record);
            }
            if old
                .as_ref()
                .is_none_or(|old| classification_inputs_semantically_different(old, &record))
            {
                apply_classification(
                    &self.classification_engine,
                    if working_directory_changed {
                        None
                    } else {
                        self.classification_facts.get(&instance_key)
                    },
                    &mut record,
                );
            }
            if old.is_none() {
                new_keys.push(instance_key.clone());
            }
            if (old.is_none() || working_directory_changed)
                && matches!(&record.working_directory, FieldValue::Known(_))
            {
                project_rescan_keys.push(instance_key.clone());
            }
            if old
                .as_ref()
                .is_none_or(|old| !process_semantically_equal(old, &record))
            {
                upserted.push(record.clone());
            } else if let Some(old) = old {
                record = old;
            }
            next.insert(
                record.instance_key.clone(),
                ProcessCacheEntry { record, expires_at },
            );
        }

        let mut removed = self
            .processes
            .keys()
            .filter(|key| !seen.contains(*key))
            .cloned()
            .collect::<Vec<_>>();
        removed.sort_by(compare_process_keys);
        for key in &project_invalidated_keys {
            self.cancel_project_scan(key);
            self.project_cache.remove(key);
            self.classification_facts.remove(key);
        }
        self.processes = next;

        for key in &removed {
            self.cancel_enrichment(key);
            self.cancel_project_scan(key);
            self.enrichment_cache.remove(key);
            self.project_cache.remove(key);
            self.classification_facts.remove(key);
        }

        upserted
            .sort_by(|left, right| compare_process_keys(&left.instance_key, &right.instance_key));
        if !upserted.is_empty() || !removed.is_empty() {
            self.publish(DiscoveryChange::ProcessDelta(ProcessDelta {
                upserted,
                removed: removed.clone(),
            }));
        }
        self.remove_ports_for_processes(&removed);

        new_keys.sort_by(compare_process_keys);
        for key in new_keys {
            let _ = self.queue_enrichment(key, EnrichmentPriority::New, EnrichmentDemand::Metadata);
        }
        project_rescan_keys.sort_by(compare_process_keys);
        for key in project_rescan_keys {
            self.queue_project_scan_background(key, EnrichmentPriority::New);
        }
        Ok(())
    }

    fn apply_port_scan(&mut self, scan: PortScan) -> Result<(), AppError> {
        let old_availability = self.port_availability.clone();
        let now = Instant::now();
        match scan.bindings {
            FieldValue::Known(bindings) => {
                if bindings.len() > self.config.port_cache_capacity {
                    return Err(scan_capacity_error(
                        "port",
                        bindings.len(),
                        self.config.port_cache_capacity,
                    ));
                }
                let expires_at = now + self.config.port_cache_ttl;
                let mut next = HashMap::with_capacity(bindings.len());
                let mut upserted = Vec::new();

                for mut binding in bindings {
                    if let Some(instance_key) = &binding.process_instance_key {
                        validate_instance_key(instance_key, "portOwner", ErrorCode::PlatformError)?;
                    }
                    let key = PortBindingKey::from(&binding);
                    if next.contains_key(&key) {
                        return Err(duplicate_port_error(&key));
                    }
                    if let Some(old) = self.ports.get(&key) {
                        if port_semantically_equal(&old.binding, &binding) {
                            binding = old.binding.clone();
                        } else {
                            upserted.push(binding.clone());
                        }
                    } else {
                        upserted.push(binding.clone());
                    }
                    next.insert(
                        binding_key(&binding),
                        PortCacheEntry {
                            binding,
                            expires_at,
                        },
                    );
                }

                let mut removed = self
                    .ports
                    .keys()
                    .filter(|key| !next.contains_key(*key))
                    .cloned()
                    .collect::<Vec<_>>();
                self.process_port_results.clear();
                self.ports = next;
                self.port_availability = FieldValue::Known(());
                self.port_availability_expires_at = Some(expires_at);
                sort_port_bindings(&mut upserted);
                sort_port_keys(&mut removed);
                if !upserted.is_empty() || !removed.is_empty() {
                    self.publish(DiscoveryChange::PortDelta(PortDelta { upserted, removed }));
                }
            }
            FieldValue::Unknown => {
                self.port_availability = FieldValue::Unknown;
                self.port_availability_expires_at = None;
            }
            FieldValue::AccessLimited { reason } => {
                self.port_availability = FieldValue::AccessLimited { reason };
                self.port_availability_expires_at = Some(now + self.config.port_cache_ttl);
            }
            FieldValue::NotSupported => {
                self.port_availability = FieldValue::NotSupported;
                self.port_availability_expires_at = Some(now + self.config.port_cache_ttl);
            }
        }

        self.publish_process_port_changes();
        if old_availability != self.port_availability {
            self.publish(DiscoveryChange::PortAvailabilityChanged(
                self.port_availability.clone(),
            ));
        }
        Ok(())
    }

    fn apply_enrichment(
        &mut self,
        requested_key: &ProcessInstanceKey,
        demand: EnrichmentDemand,
        priority: EnrichmentPriority,
        mut result: ProcessEnrichment,
    ) -> Result<(), AppError> {
        validate_instance_key(
            &result.instance_key,
            "enrichment",
            ErrorCode::IdentityMismatch,
        )?;
        if result.instance_key != *requested_key {
            let mut error = AppError::new(
                ErrorCode::IdentityMismatch,
                "enrichment returned a different process instance",
            );
            error
                .details
                .insert("requestedPid".into(), requested_key.pid.to_string());
            error
                .details
                .insert("returnedPid".into(), result.instance_key.pid.to_string());
            return Err(error);
        }
        validate_enrichment_ports(&result, self.config.port_cache_capacity)?;
        if let Some(FieldValue::Known(bindings)) = &mut result.port_bindings {
            sort_port_bindings(bindings);
        }
        if !self.processes.contains_key(requested_key) {
            return Ok(());
        }

        let working_directory_changed = self
            .processes
            .get(requested_key)
            .is_some_and(|entry| entry.record.working_directory != result.working_directory);
        let mut affected_processes = HashSet::new();
        affected_processes.insert(requested_key.clone());
        if let Some(port_bindings) = result.port_bindings.clone() {
            affected_processes
                .extend(self.apply_enrichment_port_result(requested_key, port_bindings)?);
        }
        if working_directory_changed {
            self.cancel_project_scan(requested_key);
            self.project_cache.remove(requested_key);
            self.classification_facts.remove(requested_key);
        }

        let mut updated_records = Vec::new();
        {
            let availability = &self.port_availability;
            let ports = &self.ports;
            let process_port_results = &self.process_port_results;
            let classification_engine = &self.classification_engine;
            let classification_facts = &self.classification_facts;
            for key in affected_processes {
                let Some(entry) = self.processes.get_mut(&key) else {
                    continue;
                };
                let old = entry.record.clone();
                if key == *requested_key {
                    entry.record.executable_path = result.executable_path.clone();
                    entry.record.command_line = result.command_line.clone();
                    entry.record.working_directory = result.working_directory.clone();
                    if working_directory_changed {
                        reset_project_evidence(&mut entry.record);
                    }
                    if let Some(access_level) = result.access_level {
                        entry.record.access_level = access_level;
                    }
                }
                entry.record.port_bindings =
                    process_port_value(&key, availability, ports, process_port_results);
                apply_classification(
                    classification_engine,
                    classification_facts.get(&key),
                    &mut entry.record,
                );
                if process_semantically_equal(&old, &entry.record) {
                    entry.record = old;
                } else {
                    updated_records.push(entry.record.clone());
                }
            }
        }
        updated_records
            .sort_by(|left, right| compare_process_keys(&left.instance_key, &right.instance_key));
        if !updated_records.is_empty() {
            self.publish(DiscoveryChange::ProcessDelta(ProcessDelta {
                upserted: updated_records,
                removed: Vec::new(),
            }));
        }

        self.insert_enrichment_cache(requested_key.clone(), demand);
        if matches!(result.working_directory, FieldValue::Known(_)) {
            self.queue_project_scan_background(requested_key.clone(), priority);
        }
        Ok(())
    }

    fn apply_project_scan(
        &mut self,
        request: &ProjectScanRequest,
        result: ProjectScanResult,
    ) -> Result<(), AppError> {
        result.validate_for(request)?;
        if request.catalog_generation != self.project_catalog_generation
            || !Arc::ptr_eq(&request.catalog, &self.project_catalog)
        {
            return Ok(());
        }
        let Some(entry) = self.processes.get_mut(&request.instance_key) else {
            return Ok(());
        };
        if entry.record.working_directory
            != FieldValue::Known(request.expected_working_directory.clone())
        {
            return Ok(());
        }

        let facts = result.classification_facts();
        self.classification_engine.validate_facts(&facts)?;
        let old = entry.record.clone();
        entry.record.project_association = result.association;
        entry.record.project_features = result.features;
        if facts == ProcessClassificationFacts::default() {
            self.classification_facts.remove(&request.instance_key);
        } else {
            self.classification_facts
                .insert(request.instance_key.clone(), facts);
        }
        apply_classification(
            &self.classification_engine,
            self.classification_facts.get(&request.instance_key),
            &mut entry.record,
        );
        let updated = if process_semantically_equal(&old, &entry.record) {
            entry.record = old;
            None
        } else {
            Some(entry.record.clone())
        };
        let evicted = self.insert_project_cache(
            request.instance_key.clone(),
            request.expected_working_directory.clone(),
            request.catalog_generation,
        );
        if let Some(record) = updated {
            self.publish(DiscoveryChange::ProcessDelta(ProcessDelta {
                upserted: vec![record],
                removed: Vec::new(),
            }));
        }
        if let Some(evicted) = evicted
            && let Some(record) = self.clear_project_evidence(&evicted)
        {
            self.publish(DiscoveryChange::ProcessDelta(ProcessDelta {
                upserted: vec![record],
                removed: Vec::new(),
            }));
        }
        Ok(())
    }

    fn apply_enrichment_port_result(
        &mut self,
        requested_key: &ProcessInstanceKey,
        result: FieldValue<Vec<PortBinding>>,
    ) -> Result<HashSet<ProcessInstanceKey>, AppError> {
        let incoming_count = match &result {
            FieldValue::Known(bindings) => bindings.len(),
            _ => 0,
        };
        let retained_count = self
            .ports
            .keys()
            .filter(|key| key.process_instance_key.as_ref() != Some(requested_key))
            .count();
        let combined_count = retained_count.checked_add(incoming_count).ok_or_else(|| {
            scan_capacity_error(
                "enrichmentPort",
                usize::MAX,
                self.config.port_cache_capacity,
            )
        })?;
        if combined_count > self.config.port_cache_capacity {
            return Err(scan_capacity_error(
                "enrichmentPort",
                combined_count,
                self.config.port_cache_capacity,
            ));
        }

        let mut affected_endpoints = self
            .ports
            .keys()
            .filter(|key| key.process_instance_key.as_ref() == Some(requested_key))
            .map(endpoint_key_from_port_key)
            .collect::<HashSet<_>>();
        if let FieldValue::Known(bindings) = &result {
            affected_endpoints.extend(bindings.iter().map(endpoint_key_from_binding));
        }
        let before = port_bindings_for_endpoints(&self.ports, &affected_endpoints);

        self.ports
            .retain(|key, _| key.process_instance_key.as_ref() != Some(requested_key));
        let expires_at = Instant::now() + self.config.port_cache_ttl;
        if let FieldValue::Known(bindings) = &result {
            for binding in bindings {
                let mut binding = binding.clone();
                binding.confidence = PortOwnershipConfidence::Exact;
                self.ports.insert(
                    PortBindingKey::from(&binding),
                    PortCacheEntry {
                        binding,
                        expires_at,
                    },
                );
            }
        }
        self.process_port_results.insert(
            requested_key.clone(),
            ProcessPortCacheEntry {
                value: result,
                expires_at,
            },
        );

        rebalance_port_confidence(&mut self.ports, &affected_endpoints);
        let after = port_bindings_for_endpoints(&self.ports, &affected_endpoints);
        let mut affected_processes = HashSet::new();
        affected_processes.insert(requested_key.clone());
        for binding in before.values().chain(after.values()) {
            if let Some(key) = &binding.process_instance_key {
                affected_processes.insert(key.clone());
            }
        }
        refresh_known_process_port_results(
            &mut self.process_port_results,
            &self.ports,
            &affected_processes,
        );
        self.publish_port_cache_diff(before, after);
        Ok(affected_processes)
    }

    fn publish_port_cache_diff(
        &mut self,
        before: HashMap<PortBindingKey, PortBinding>,
        after: HashMap<PortBindingKey, PortBinding>,
    ) {
        let mut removed = before
            .keys()
            .filter(|key| !after.contains_key(*key))
            .cloned()
            .collect::<Vec<_>>();
        let mut upserted = after
            .iter()
            .filter(|(key, binding)| {
                before
                    .get(*key)
                    .is_none_or(|old| !port_semantically_equal(old, binding))
            })
            .map(|(_, binding)| binding.clone())
            .collect::<Vec<_>>();
        sort_port_keys(&mut removed);
        sort_port_bindings(&mut upserted);
        if !removed.is_empty() || !upserted.is_empty() {
            self.publish(DiscoveryChange::PortDelta(PortDelta { upserted, removed }));
        }
    }

    fn insert_enrichment_cache(
        &mut self,
        instance_key: ProcessInstanceKey,
        demand: EnrichmentDemand,
    ) {
        if !self.enrichment_cache.contains_key(&instance_key)
            && self.enrichment_cache.len() >= self.config.enrichment_cache_capacity
            && let Some(oldest) = self
                .enrichment_cache
                .iter()
                .min_by_key(|(_, entry)| entry.expires_at)
                .map(|(key, _)| key.clone())
        {
            self.enrichment_cache.remove(&oldest);
        }
        let ttl = if demand == EnrichmentDemand::MetadataAndPorts {
            self.config
                .enrichment_cache_ttl
                .min(self.config.port_cache_ttl)
        } else {
            self.config.enrichment_cache_ttl
        };
        self.enrichment_cache.insert(
            instance_key,
            EnrichmentCacheEntry {
                expires_at: Instant::now() + ttl,
                demand,
            },
        );
    }

    fn insert_project_cache(
        &mut self,
        instance_key: ProcessInstanceKey,
        expected_working_directory: String,
        catalog_generation: u64,
    ) -> Option<ProcessInstanceKey> {
        let mut evicted = None;
        if !self.project_cache.contains_key(&instance_key)
            && self.project_cache.len() >= self.config.project_cache_capacity
            && let Some(oldest) = self
                .project_cache
                .iter()
                .min_by_key(|(_, entry)| entry.expires_at)
                .map(|(key, _)| key.clone())
        {
            self.project_cache.remove(&oldest);
            evicted = Some(oldest);
        }
        self.project_cache.insert(
            instance_key,
            ProjectCacheEntry {
                expires_at: Instant::now() + self.config.project_cache_ttl,
                expected_working_directory,
                catalog_generation,
            },
        );
        evicted
    }

    fn publish_process_port_changes(&mut self) {
        let port_availability = self.port_availability.clone();
        let ports = &self.ports;
        let process_port_results = &self.process_port_results;
        let classification_engine = &self.classification_engine;
        let classification_facts = &self.classification_facts;
        let mut upserted = Vec::new();
        for entry in self.processes.values_mut() {
            let next = process_port_value(
                &entry.record.instance_key,
                &port_availability,
                ports,
                process_port_results,
            );
            if !field_ports_semantically_different(&entry.record.port_bindings, &next) {
                continue;
            }
            let old = entry.record.clone();
            entry.record.port_bindings = next;
            apply_classification(
                classification_engine,
                classification_facts.get(&entry.record.instance_key),
                &mut entry.record,
            );
            if process_semantically_equal(&old, &entry.record) {
                entry.record = old;
            } else {
                upserted.push(entry.record.clone());
            }
        }
        upserted
            .sort_by(|left, right| compare_process_keys(&left.instance_key, &right.instance_key));
        if !upserted.is_empty() {
            self.publish(DiscoveryChange::ProcessDelta(ProcessDelta {
                upserted,
                removed: Vec::new(),
            }));
        }
    }

    fn remove_ports_for_processes(&mut self, removed_processes: &[ProcessInstanceKey]) {
        if removed_processes.is_empty() {
            return;
        }
        let removed_set = removed_processes.iter().collect::<HashSet<_>>();
        for key in removed_processes {
            self.process_port_results.remove(key);
        }
        let affected_endpoints = self
            .ports
            .keys()
            .filter(|key| {
                key.process_instance_key
                    .as_ref()
                    .is_some_and(|process| removed_set.contains(process))
            })
            .map(endpoint_key_from_port_key)
            .collect::<HashSet<_>>();
        if affected_endpoints.is_empty() {
            return;
        }
        let before = port_bindings_for_endpoints(&self.ports, &affected_endpoints);
        self.ports.retain(|key, _| {
            key.process_instance_key
                .as_ref()
                .is_none_or(|process| !removed_set.contains(process))
        });
        rebalance_port_confidence(&mut self.ports, &affected_endpoints);
        let after = port_bindings_for_endpoints(&self.ports, &affected_endpoints);
        let affected_processes = before
            .values()
            .chain(after.values())
            .filter_map(|binding| binding.process_instance_key.clone())
            .filter(|key| !removed_set.contains(key))
            .collect::<HashSet<_>>();
        refresh_known_process_port_results(
            &mut self.process_port_results,
            &self.ports,
            &affected_processes,
        );
        self.publish_port_cache_diff(before, after);
        if !affected_processes.is_empty() {
            self.publish_process_port_changes();
        }
    }

    fn sweep_expired(&mut self) {
        let now = Instant::now();
        let mut removed_processes = self
            .processes
            .iter()
            .filter(|(_, entry)| entry.expires_at <= now)
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>();
        removed_processes.sort_by(compare_process_keys);
        for key in &removed_processes {
            self.processes.remove(key);
            self.cancel_enrichment(key);
            self.cancel_project_scan(key);
            self.enrichment_cache.remove(key);
            self.project_cache.remove(key);
            self.classification_facts.remove(key);
        }
        if !removed_processes.is_empty() {
            self.publish(DiscoveryChange::ProcessDelta(ProcessDelta {
                upserted: Vec::new(),
                removed: removed_processes.clone(),
            }));
        }
        self.remove_ports_for_processes(&removed_processes);

        self.enrichment_cache
            .retain(|_, entry| entry.expires_at > now);

        let mut expired_project_keys = self
            .project_cache
            .iter()
            .filter(|(_, entry)| entry.expires_at <= now)
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>();
        expired_project_keys.sort_by(compare_process_keys);
        let mut expired_project_records = Vec::new();
        let mut project_rescan_keys = Vec::new();
        for key in expired_project_keys {
            self.project_cache.remove(&key);
            self.cancel_project_scan(&key);
            if let Some(record) = self.clear_project_evidence(&key) {
                if matches!(&record.working_directory, FieldValue::Known(_)) {
                    project_rescan_keys.push(key);
                }
                expired_project_records.push(record);
            } else if self.processes.get(&key).is_some_and(|entry| {
                matches!(&entry.record.working_directory, FieldValue::Known(_))
            }) {
                project_rescan_keys.push(key);
            }
        }
        if !expired_project_records.is_empty() {
            self.publish(DiscoveryChange::ProcessDelta(ProcessDelta {
                upserted: expired_project_records,
                removed: Vec::new(),
            }));
        }
        for key in project_rescan_keys {
            self.queue_project_scan_background(key, EnrichmentPriority::ClassificationCandidate);
        }

        let availability_expired = self
            .port_availability_expires_at
            .is_some_and(|expires_at| expires_at <= now);
        let expired_process_port_results = self
            .process_port_results
            .iter()
            .filter(|(_, entry)| entry.expires_at <= now)
            .map(|(key, _)| key.clone())
            .collect::<HashSet<_>>();
        for key in &expired_process_port_results {
            self.process_port_results.remove(key);
        }

        let expired_port_keys = self
            .ports
            .iter()
            .filter(|(_, entry)| entry.expires_at <= now)
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>();
        let affected_endpoints = expired_port_keys
            .iter()
            .map(endpoint_key_from_port_key)
            .collect::<HashSet<_>>();
        let before = port_bindings_for_endpoints(&self.ports, &affected_endpoints);
        for key in &expired_port_keys {
            self.ports.remove(key);
        }
        rebalance_port_confidence(&mut self.ports, &affected_endpoints);
        let after = port_bindings_for_endpoints(&self.ports, &affected_endpoints);
        let mut affected_processes = expired_process_port_results;
        for binding in before.values().chain(after.values()) {
            if let Some(key) = &binding.process_instance_key {
                affected_processes.insert(key.clone());
            }
        }
        refresh_known_process_port_results(
            &mut self.process_port_results,
            &self.ports,
            &affected_processes,
        );
        self.publish_port_cache_diff(before, after);
        if !affected_processes.is_empty() {
            self.publish_process_port_changes();
        }
        if availability_expired {
            self.port_availability = FieldValue::Unknown;
            self.port_availability_expires_at = None;
            self.publish_process_port_changes();
            self.publish(DiscoveryChange::PortAvailabilityChanged(
                FieldValue::Unknown,
            ));
        }
    }

    fn snapshot(&self) -> DiscoverySnapshot {
        let mut processes = self
            .processes
            .values()
            .map(|entry| entry.record.clone())
            .collect::<Vec<_>>();
        processes
            .sort_by(|left, right| compare_process_keys(&left.instance_key, &right.instance_key));
        let port_bindings = match &self.port_availability {
            FieldValue::Known(()) => {
                let mut bindings = self
                    .ports
                    .values()
                    .map(|entry| entry.binding.clone())
                    .collect::<Vec<_>>();
                sort_port_bindings(&mut bindings);
                FieldValue::Known(bindings)
            }
            FieldValue::Unknown => FieldValue::Unknown,
            FieldValue::AccessLimited { reason } => FieldValue::AccessLimited {
                reason: reason.clone(),
            },
            FieldValue::NotSupported => FieldValue::NotSupported,
        };
        DiscoverySnapshot {
            sequence: self.update_sequence,
            processes,
            port_bindings,
        }
    }

    fn performance_snapshot(&self) -> DiscoveryPerformanceSnapshot {
        DiscoveryPerformanceSnapshot {
            fast_scan_interval: self.config.fast_scan_interval,
            port_scan_interval: self.config.port_scan_interval,
            enrichment_concurrency: self.config.enrichment_concurrency,
            project_concurrency: self.config.project_concurrency,
            latency_window_capacity: DISCOVERY_LATENCY_WINDOW_CAPACITY,
            fast: self.performance.fast.snapshot(),
            port: self.performance.port.snapshot(),
            enrichment: self.performance.enrichment.snapshot(),
            project: self.performance.project.snapshot(),
        }
    }

    fn publish(&mut self, change: DiscoveryChange) {
        match change {
            DiscoveryChange::ProcessDelta(delta) => self.accumulate_process_delta(delta),
            DiscoveryChange::PortDelta(delta) => self.accumulate_port_delta(delta),
            DiscoveryChange::PortAvailabilityChanged(availability) => {
                self.accumulate_port_availability(availability);
            }
            change @ DiscoveryChange::OperationFailed { .. } => {
                self.flush_pending_updates();
                self.publish_immediate(change);
            }
        }
    }

    fn accumulate_process_delta(&mut self, delta: ProcessDelta) {
        for record in delta.upserted {
            let key = record.instance_key.clone();
            let estimated_bytes = estimated_process_record_bytes(&record);
            self.accumulate_process_mutation(
                key,
                PendingProcessMutation::Upsert {
                    record,
                    estimated_bytes,
                },
            );
        }
        for key in delta.removed {
            let estimated_bytes = estimated_process_key_bytes(&key);
            self.accumulate_process_mutation(
                key,
                PendingProcessMutation::Remove { estimated_bytes },
            );
        }
    }

    fn accumulate_process_mutation(
        &mut self,
        key: ProcessInstanceKey,
        mutation: PendingProcessMutation,
    ) {
        let estimated_entity_bytes = mutation.estimated_bytes();
        let estimated_payload_bytes =
            estimated_entity_bytes.saturating_add(ESTIMATED_EVENT_CONTAINER_BYTES);
        if estimated_payload_bytes > MAX_DISCOVERY_EVENT_PAYLOAD_BYTES {
            self.publish(DiscoveryChange::OperationFailed {
                operation: DiscoveryOperation::ProcessPublication(key.clone()),
                error: event_payload_capacity_error(
                    "process",
                    estimated_entity_bytes,
                    estimated_payload_bytes,
                ),
            });
            return;
        }
        let mut mutation = Some(mutation);
        loop {
            let mutation_bytes = mutation
                .as_ref()
                .map(PendingProcessMutation::estimated_bytes)
                .unwrap_or_default();
            let existing_bytes = self
                .pending_updates
                .processes
                .get(&key)
                .map(PendingProcessMutation::estimated_bytes)
                .unwrap_or_default();
            let new_entity = !self.pending_updates.processes.contains_key(&key);
            let container_bytes = if self.pending_updates.processes.is_empty() {
                ESTIMATED_EVENT_CONTAINER_BYTES
            } else {
                0
            };
            let projected_entities = self
                .pending_updates
                .entity_count()
                .saturating_add(if new_entity { 1 } else { 0 });
            let projected_bytes = self
                .pending_updates
                .estimated_payload_bytes
                .saturating_sub(existing_bytes)
                .saturating_add(mutation_bytes)
                .saturating_add(container_bytes);
            if !self.pending_updates.is_empty()
                && (projected_entities > MAX_DISCOVERY_EVENT_ENTITIES
                    || projected_bytes > MAX_DISCOVERY_EVENT_PAYLOAD_BYTES)
            {
                self.flush_pending_updates();
                continue;
            }
            if self.pending_updates.process_order.is_none() {
                let order = self.pending_updates.next_change_order();
                self.pending_updates.process_order = Some(order);
            }
            self.pending_updates.estimated_payload_bytes = projected_bytes;
            self.pending_updates
                .processes
                .insert(key, mutation.take().expect("mutation is inserted once"));
            self.flush_pending_updates_if_full();
            break;
        }
    }

    fn accumulate_port_delta(&mut self, delta: PortDelta) {
        for binding in delta.upserted {
            let key = PortBindingKey::from(&binding);
            let estimated_bytes = estimated_port_binding_bytes(&binding);
            self.accumulate_port_mutation(
                key,
                PendingPortMutation::Upsert {
                    binding,
                    estimated_bytes,
                },
            );
        }
        for key in delta.removed {
            let estimated_bytes = estimated_port_key_bytes(&key);
            self.accumulate_port_mutation(key, PendingPortMutation::Remove { estimated_bytes });
        }
    }

    fn accumulate_port_mutation(&mut self, key: PortBindingKey, mutation: PendingPortMutation) {
        let estimated_entity_bytes = mutation.estimated_bytes();
        let estimated_payload_bytes =
            estimated_entity_bytes.saturating_add(ESTIMATED_EVENT_CONTAINER_BYTES);
        if estimated_payload_bytes > MAX_DISCOVERY_EVENT_PAYLOAD_BYTES {
            self.publish(DiscoveryChange::OperationFailed {
                operation: DiscoveryOperation::PortScan,
                error: event_payload_capacity_error(
                    "port",
                    estimated_entity_bytes,
                    estimated_payload_bytes,
                ),
            });
            return;
        }
        let mut mutation = Some(mutation);
        loop {
            let mutation_bytes = mutation
                .as_ref()
                .map(PendingPortMutation::estimated_bytes)
                .unwrap_or_default();
            let existing_bytes = self
                .pending_updates
                .ports
                .get(&key)
                .map(PendingPortMutation::estimated_bytes)
                .unwrap_or_default();
            let new_entity = !self.pending_updates.ports.contains_key(&key);
            let container_bytes = if self.pending_updates.ports.is_empty() {
                ESTIMATED_EVENT_CONTAINER_BYTES
            } else {
                0
            };
            let projected_entities = self
                .pending_updates
                .entity_count()
                .saturating_add(if new_entity { 1 } else { 0 });
            let projected_bytes = self
                .pending_updates
                .estimated_payload_bytes
                .saturating_sub(existing_bytes)
                .saturating_add(mutation_bytes)
                .saturating_add(container_bytes);
            if !self.pending_updates.is_empty()
                && (projected_entities > MAX_DISCOVERY_EVENT_ENTITIES
                    || projected_bytes > MAX_DISCOVERY_EVENT_PAYLOAD_BYTES)
            {
                self.flush_pending_updates();
                continue;
            }
            if self.pending_updates.port_order.is_none() {
                let order = self.pending_updates.next_change_order();
                self.pending_updates.port_order = Some(order);
            }
            self.pending_updates.estimated_payload_bytes = projected_bytes;
            self.pending_updates
                .ports
                .insert(key, mutation.take().expect("mutation is inserted once"));
            self.flush_pending_updates_if_full();
            break;
        }
    }

    fn accumulate_port_availability(&mut self, availability: FieldValue<()>) {
        let estimated_entity_bytes = estimated_port_availability_bytes(&availability);
        let estimated_payload_bytes =
            estimated_entity_bytes.saturating_add(ESTIMATED_EVENT_CONTAINER_BYTES);
        if estimated_payload_bytes > MAX_DISCOVERY_EVENT_PAYLOAD_BYTES {
            self.publish(DiscoveryChange::OperationFailed {
                operation: DiscoveryOperation::PortScan,
                error: event_payload_capacity_error(
                    "portAvailability",
                    estimated_entity_bytes,
                    estimated_payload_bytes,
                ),
            });
            return;
        }
        let mut availability = Some(availability);
        loop {
            let estimated_bytes = availability
                .as_ref()
                .map(estimated_port_availability_bytes)
                .unwrap_or_default();
            let existing_bytes = self
                .pending_updates
                .availability
                .as_ref()
                .map(|(_, bytes)| *bytes)
                .unwrap_or_default();
            let container_bytes = if self.pending_updates.availability.is_none() {
                ESTIMATED_EVENT_CONTAINER_BYTES
            } else {
                0
            };
            let projected_bytes = self
                .pending_updates
                .estimated_payload_bytes
                .saturating_sub(existing_bytes)
                .saturating_add(estimated_bytes)
                .saturating_add(container_bytes);
            if !self.pending_updates.is_empty()
                && projected_bytes > MAX_DISCOVERY_EVENT_PAYLOAD_BYTES
            {
                self.flush_pending_updates();
                continue;
            }
            if self.pending_updates.availability_order.is_none() {
                let order = self.pending_updates.next_change_order();
                self.pending_updates.availability_order = Some(order);
            }
            self.pending_updates.estimated_payload_bytes = projected_bytes;
            self.pending_updates.availability = Some((
                availability.take().expect("availability is inserted once"),
                estimated_bytes,
            ));
            self.flush_pending_updates_if_full();
            break;
        }
    }

    fn flush_pending_updates_if_full(&mut self) {
        if self.pending_updates.entity_count() >= MAX_DISCOVERY_EVENT_ENTITIES
            || self.pending_updates.estimated_payload_bytes >= MAX_DISCOVERY_EVENT_PAYLOAD_BYTES
        {
            self.flush_pending_updates();
        }
    }

    fn flush_pending_updates(&mut self) {
        if self.pending_updates.is_empty() {
            return;
        }
        let pending = std::mem::take(&mut self.pending_updates);
        for change in pending.into_ordered_changes() {
            self.publish_immediate(change);
        }
    }

    fn publish_immediate(&mut self, change: DiscoveryChange) {
        let Some(sequence) = self.update_sequence.checked_add(1) else {
            // Closing is preferable to publishing a duplicate or decreasing
            // synchronization sequence after exhaustion.
            self.shutdown_signal.cancel();
            return;
        };
        self.update_sequence = sequence;
        let _ = self.updates.send(DiscoveryUpdate { sequence, change });
    }

    fn next_ordering_sequence(&mut self) -> u64 {
        let current = self.ordering_sequence;
        self.ordering_sequence = self.ordering_sequence.saturating_add(1);
        current
    }

    fn cancel_all_tasks(&mut self) {
        if let Some(task) = &self.fast_task {
            task.cancellation.cancel();
        }
        if let Some(task) = &self.port_task {
            task.cancellation.cancel();
        }
        for task in self.running_enrichments.values() {
            task.cancellation.cancel();
        }
        for task in self.running_project_scans.values() {
            task.cancellation.cancel();
        }
        self.fast_pending = false;
        self.port_pending = false;
        self.pending_enrichments.clear();
        self.pending_project_scans.clear();
    }

    async fn drain_tasks(&mut self) {
        let drained = tokio::time::timeout(self.config.shutdown_timeout, async {
            while let Some(task) = self.tasks.join_next_with_id().await {
                self.handle_task_completion(task);
            }
        })
        .await;
        if drained.is_err() {
            self.tasks.abort_all();
            while let Some(task) = self.tasks.join_next_with_id().await {
                self.handle_task_completion(task);
            }
        }
        self.task_kinds.clear();
        self.fast_task = None;
        self.port_task = None;
        self.running_enrichments.clear();
        self.running_project_scans.clear();
    }
}

fn nearest_rank(samples: &[Duration], percentile: usize) -> Option<Duration> {
    if samples.is_empty() {
        return None;
    }
    let rank = samples.len().saturating_mul(percentile).saturating_add(99) / 100;
    samples.get(rank.saturating_sub(1)).copied()
}

fn estimated_process_record_bytes(record: &ProcessRecord) -> usize {
    serde_json::to_vec(record)
        .map(|payload| payload.len())
        .unwrap_or(MAX_DISCOVERY_EVENT_PAYLOAD_BYTES)
        .saturating_add(ESTIMATED_EVENT_ENTITY_OVERHEAD_BYTES)
}

fn estimated_process_key_bytes(key: &ProcessInstanceKey) -> usize {
    serde_json::to_vec(key)
        .map(|payload| payload.len())
        .unwrap_or(MAX_DISCOVERY_EVENT_PAYLOAD_BYTES)
        .saturating_add(ESTIMATED_EVENT_ENTITY_OVERHEAD_BYTES)
}

fn estimated_port_binding_bytes(binding: &PortBinding) -> usize {
    serde_json::to_vec(binding)
        .map(|payload| payload.len())
        .unwrap_or(MAX_DISCOVERY_EVENT_PAYLOAD_BYTES)
        .saturating_add(ESTIMATED_EVENT_ENTITY_OVERHEAD_BYTES)
}

fn estimated_port_key_bytes(key: &PortBindingKey) -> usize {
    serde_json::to_vec(key)
        .map(|payload| payload.len())
        .unwrap_or(MAX_DISCOVERY_EVENT_PAYLOAD_BYTES)
        .saturating_add(ESTIMATED_EVENT_ENTITY_OVERHEAD_BYTES)
}

fn estimated_port_availability_bytes(availability: &FieldValue<()>) -> usize {
    serde_json::to_vec(availability)
        .map(|payload| payload.len())
        .unwrap_or(MAX_DISCOVERY_EVENT_PAYLOAD_BYTES)
        .saturating_add(ESTIMATED_EVENT_ENTITY_OVERHEAD_BYTES)
}

fn overlay_managed_process_binding(
    bindings: &HashMap<ProcessInstanceKey, String>,
    record: &mut ProcessRecord,
) {
    if let Some(run_id) = bindings.get(&record.instance_key) {
        record.ownership = ProcessOwnership::Managed;
        record.managed_run_id = Some(run_id.clone());
    } else {
        record.ownership = ProcessOwnership::External;
        record.managed_run_id = None;
    }
}

fn normalize_fast_record(record: &mut ProcessRecord, old: Option<&ProcessRecord>) {
    if let Some(old) = old {
        preserve_if_unknown(&mut record.executable_path, &old.executable_path);
        preserve_if_unknown(&mut record.command_line, &old.command_line);
        preserve_if_unknown(&mut record.working_directory, &old.working_directory);
        record.port_bindings = old.port_bindings.clone();
        record.project_association = old.project_association.clone();
        record.project_features = old.project_features.clone();
        record.project_id = old.project_id.clone();
        record.classification = old.classification.clone();
        record.last_seen_revision = old.last_seen_revision;
    } else {
        record.port_bindings = FieldValue::Unknown;
        record.last_seen_revision = 0;
    }
}

fn reset_project_evidence(record: &mut ProcessRecord) {
    match &record.working_directory {
        FieldValue::Known(_) | FieldValue::Unknown => {
            record.project_association = ProjectEvidence::Unknown;
            record.project_features = ProjectEvidence::Unknown;
        }
        FieldValue::AccessLimited { reason } => {
            record.project_association = ProjectEvidence::AccessLimited {
                reason: reason.clone(),
            };
            record.project_features = ProjectEvidence::AccessLimited {
                reason: reason.clone(),
            };
        }
        FieldValue::NotSupported => {
            record.project_association = ProjectEvidence::NotSupported;
            record.project_features = ProjectEvidence::NotSupported;
        }
    }
}

fn apply_classification(
    engine: &ClassificationEngine,
    facts: Option<&ProcessClassificationFacts>,
    record: &mut ProcessRecord,
) {
    let empty_facts = ProcessClassificationFacts::default();
    let decision = engine.classify(record, facts.unwrap_or(&empty_facts));
    record.classification = decision.result;
    record.project_id = decision.project_id;
}

fn process_port_value(
    instance_key: &ProcessInstanceKey,
    availability: &FieldValue<()>,
    ports: &HashMap<PortBindingKey, PortCacheEntry>,
    process_port_results: &HashMap<ProcessInstanceKey, ProcessPortCacheEntry>,
) -> FieldValue<Vec<PortBinding>> {
    if let Some(result) = process_port_results
        .get(instance_key)
        .filter(|entry| entry.expires_at > Instant::now())
    {
        return result.value.clone();
    }
    match availability {
        FieldValue::Known(()) => {
            let mut bindings = ports
                .values()
                .filter(|port| port.binding.process_instance_key.as_ref() == Some(instance_key))
                .map(|port| port.binding.clone())
                .collect::<Vec<_>>();
            sort_port_bindings(&mut bindings);
            FieldValue::Known(bindings)
        }
        FieldValue::Unknown => FieldValue::Unknown,
        FieldValue::AccessLimited { reason } => FieldValue::AccessLimited {
            reason: reason.clone(),
        },
        FieldValue::NotSupported => FieldValue::NotSupported,
    }
}

fn endpoint_key_from_binding(binding: &PortBinding) -> PortEndpointKey {
    PortEndpointKey {
        protocol: binding.protocol,
        address_family: binding.address_family,
        local_address: binding.local_address.clone(),
        local_port: binding.local_port,
    }
}

fn endpoint_key_from_port_key(key: &PortBindingKey) -> PortEndpointKey {
    PortEndpointKey {
        protocol: key.protocol,
        address_family: key.address_family,
        local_address: key.local_address.clone(),
        local_port: key.local_port,
    }
}

fn port_bindings_for_endpoints(
    ports: &HashMap<PortBindingKey, PortCacheEntry>,
    endpoints: &HashSet<PortEndpointKey>,
) -> HashMap<PortBindingKey, PortBinding> {
    ports
        .iter()
        .filter(|(key, _)| endpoints.contains(&endpoint_key_from_port_key(key)))
        .map(|(key, entry)| (key.clone(), entry.binding.clone()))
        .collect()
}

fn rebalance_port_confidence(
    ports: &mut HashMap<PortBindingKey, PortCacheEntry>,
    endpoints: &HashSet<PortEndpointKey>,
) {
    let mut groups = HashMap::<PortEndpointKey, (HashSet<ProcessInstanceKey>, bool)>::new();
    for key in ports.keys() {
        let endpoint = endpoint_key_from_port_key(key);
        if !endpoints.contains(&endpoint) {
            continue;
        }
        let group = groups.entry(endpoint).or_default();
        if let Some(owner) = &key.process_instance_key {
            group.0.insert(owner.clone());
        } else {
            group.1 = true;
        }
    }
    for (key, entry) in ports.iter_mut() {
        let endpoint = endpoint_key_from_port_key(key);
        let Some((owners, has_unknown_owner)) = groups.get(&endpoint) else {
            continue;
        };
        entry.binding.confidence = if key.process_instance_key.is_none() {
            PortOwnershipConfidence::Unknown
        } else if owners.len() > 1 || *has_unknown_owner {
            PortOwnershipConfidence::Shared
        } else {
            PortOwnershipConfidence::Exact
        };
    }
}

fn refresh_known_process_port_results(
    results: &mut HashMap<ProcessInstanceKey, ProcessPortCacheEntry>,
    ports: &HashMap<PortBindingKey, PortCacheEntry>,
    processes: &HashSet<ProcessInstanceKey>,
) {
    let known_processes = processes
        .iter()
        .filter(|process| {
            results
                .get(*process)
                .is_some_and(|result| matches!(result.value, FieldValue::Known(_)))
        })
        .cloned()
        .collect::<HashSet<_>>();
    let mut grouped = HashMap::<ProcessInstanceKey, Vec<PortBinding>>::new();
    for entry in ports.values() {
        let Some(owner) = &entry.binding.process_instance_key else {
            continue;
        };
        if known_processes.contains(owner) {
            grouped
                .entry(owner.clone())
                .or_default()
                .push(entry.binding.clone());
        }
    }
    for process in known_processes {
        let mut bindings = grouped.remove(&process).unwrap_or_default();
        sort_port_bindings(&mut bindings);
        if let Some(result) = results.get_mut(&process) {
            result.value = FieldValue::Known(bindings);
        }
    }
}

fn preserve_if_unknown<T: Clone>(value: &mut FieldValue<T>, old: &FieldValue<T>) {
    if matches!(value, FieldValue::Unknown) {
        *value = old.clone();
    }
}

fn process_semantically_equal(left: &ProcessRecord, right: &ProcessRecord) -> bool {
    let mut left = left.clone();
    let mut right = right.clone();
    left.last_seen_revision = 0;
    right.last_seen_revision = 0;
    normalize_observation_times(&mut left.port_bindings);
    normalize_observation_times(&mut right.port_bindings);
    left == right
}

fn classification_inputs_semantically_different(
    left: &ProcessRecord,
    right: &ProcessRecord,
) -> bool {
    left.ownership != right.ownership
        || left.executable_name != right.executable_name
        || left.executable_path != right.executable_path
        || left.command_line != right.command_line
        || left.working_directory != right.working_directory
        || field_ports_semantically_different(&left.port_bindings, &right.port_bindings)
}

fn field_ports_semantically_different(
    left: &FieldValue<Vec<PortBinding>>,
    right: &FieldValue<Vec<PortBinding>>,
) -> bool {
    let mut left = left.clone();
    let mut right = right.clone();
    normalize_observation_times(&mut left);
    normalize_observation_times(&mut right);
    left != right
}

fn normalize_observation_times(value: &mut FieldValue<Vec<PortBinding>>) {
    if let FieldValue::Known(bindings) = value {
        for binding in bindings {
            binding.observed_at.clear();
        }
    }
}

fn port_semantically_equal(left: &PortBinding, right: &PortBinding) -> bool {
    let mut left = left.clone();
    let mut right = right.clone();
    left.observed_at.clear();
    right.observed_at.clear();
    left == right
}

fn validate_enrichment_ports(
    enrichment: &ProcessEnrichment,
    capacity: usize,
) -> Result<(), AppError> {
    let Some(FieldValue::Known(bindings)) = &enrichment.port_bindings else {
        return Ok(());
    };
    if bindings.len() > capacity {
        return Err(scan_capacity_error(
            "enrichmentPort",
            bindings.len(),
            capacity,
        ));
    }
    let mut seen = HashSet::with_capacity(bindings.len());
    for binding in bindings {
        let Some(instance_key) = binding.process_instance_key.as_ref() else {
            let mut error = AppError::new(
                ErrorCode::IdentityMismatch,
                "enriched port has no process instance identity",
            );
            error.details.insert(
                "requestedPid".into(),
                enrichment.instance_key.pid.to_string(),
            );
            return Err(error);
        };
        validate_instance_key(
            instance_key,
            "enrichedPortOwner",
            ErrorCode::IdentityMismatch,
        )?;
        if instance_key != &enrichment.instance_key {
            let mut error = AppError::new(
                ErrorCode::IdentityMismatch,
                "enriched port belongs to a different process instance",
            );
            error.details.insert(
                "requestedPid".into(),
                enrichment.instance_key.pid.to_string(),
            );
            return Err(error);
        }
        let key = PortBindingKey::from(binding);
        if !seen.insert(key.clone()) {
            return Err(duplicate_port_error(&key));
        }
    }
    Ok(())
}

fn validate_instance_key(
    key: &ProcessInstanceKey,
    entity: &'static str,
    code: ErrorCode,
) -> Result<(), AppError> {
    let invalid = if key.pid == 0 {
        Some(("pid", "must be greater than zero"))
    } else if key.boot_id.trim().is_empty() {
        Some(("bootId", "must not be empty"))
    } else if key.boot_id.len() > MAX_PROCESS_BOOT_ID_BYTES {
        Some(("bootId", "exceeds the supported length"))
    } else if key.boot_id.contains('\0') {
        Some(("bootId", "must not contain NUL"))
    } else if key.native_start_time.trim().is_empty() {
        Some(("nativeStartTime", "must not be empty"))
    } else if key.native_start_time.len() > MAX_PROCESS_NATIVE_START_TIME_BYTES {
        Some(("nativeStartTime", "exceeds the supported length"))
    } else if key.native_start_time.contains('\0') {
        Some(("nativeStartTime", "must not contain NUL"))
    } else if key
        .native_start_time
        .parse::<u64>()
        .ok()
        .filter(|value| *value != 0)
        .is_none_or(|value| value.to_string() != key.native_start_time)
    {
        Some((
            "nativeStartTime",
            "must use canonical nonzero unsigned decimal form",
        ))
    } else {
        None
    };
    let Some((field, reason)) = invalid else {
        return Ok(());
    };

    let mut error = AppError::new(
        code,
        "discovery backend returned an invalid process identity",
    );
    error.details.insert("entity".into(), entity.into());
    error.details.insert("field".into(), field.into());
    error.details.insert("reason".into(), reason.into());
    Err(error)
}

fn validate_managed_run_id(run_id: &str) -> Result<(), AppError> {
    if run_id.trim().is_empty() {
        return Err(invalid_managed_binding("runId", "must not be empty"));
    }
    if run_id.len() > MAX_MANAGED_RUN_ID_BYTES {
        return Err(invalid_managed_binding(
            "runId",
            "exceeds the supported length",
        ));
    }
    if run_id.contains('\0') {
        return Err(invalid_managed_binding("runId", "must not contain NUL"));
    }
    Ok(())
}

fn validate_duration(
    field: &'static str,
    value: Duration,
    maximum: Duration,
) -> Result<(), AppError> {
    if value.is_zero() {
        return Err(invalid_config(field, "must be greater than zero"));
    }
    if value > maximum {
        return Err(invalid_config(field, "exceeds the supported maximum"));
    }
    Ok(())
}

fn validate_classification_workload(
    process_capacity: usize,
    engine: &ClassificationEngine,
) -> Result<(), AppError> {
    let evaluation_units = process_capacity
        .checked_mul(engine.enabled_rule_count().saturating_add(1))
        .unwrap_or(usize::MAX);
    let pattern_units = process_capacity
        .checked_mul(engine.pattern_bytes_per_classification().saturating_add(16))
        .unwrap_or(usize::MAX);
    if evaluation_units <= MAX_CLASSIFICATION_RULE_EVALUATIONS
        && pattern_units <= MAX_CLASSIFICATION_PATTERN_WORK_BYTES
    {
        return Ok(());
    }

    let mut error = AppError::new(
        ErrorCode::InvalidArgument,
        "classification rules exceed the scheduler work budget",
    );
    error
        .details
        .insert("processCapacity".into(), process_capacity.to_string());
    error.details.insert(
        "enabledRules".into(),
        engine.enabled_rule_count().to_string(),
    );
    error
        .details
        .insert("evaluationUnits".into(), evaluation_units.to_string());
    error
        .details
        .insert("patternUnits".into(), pattern_units.to_string());
    Err(error)
}

fn validate_project_context_ids(
    catalog: &ProjectCatalog,
    rules: &ClassificationRulesSnapshot,
) -> Result<(), AppError> {
    let catalog_ids = catalog.project_ids();
    let mut rule_ids = rules.known_project_ids.clone();
    rule_ids.sort();
    if catalog_ids == rule_ids {
        return Ok(());
    }
    let mut error = AppError::new(
        ErrorCode::InvalidArgument,
        "project catalog and classification rules identify different projects",
    );
    error
        .details
        .insert("catalogProjects".into(), catalog_ids.len().to_string());
    error
        .details
        .insert("ruleProjects".into(), rule_ids.len().to_string());
    Err(error)
}

fn project_catalog_generation_exhausted() -> AppError {
    AppError::new(
        ErrorCode::Internal,
        "project catalog generation is exhausted",
    )
}

fn validate_capacity(field: &'static str, value: usize, maximum: usize) -> Result<(), AppError> {
    if value == 0 {
        return Err(invalid_config(field, "must be greater than zero"));
    }
    if value > maximum {
        return Err(invalid_config(field, "exceeds the supported maximum"));
    }
    Ok(())
}

fn invalid_config(field: &'static str, reason: &'static str) -> AppError {
    let mut error = AppError::new(
        ErrorCode::InvalidArgument,
        "invalid discovery configuration",
    );
    error.details.insert("field".into(), field.into());
    error.details.insert("reason".into(), reason.into());
    error
}

fn invalid_enrichment_batch_size(actual: usize) -> AppError {
    let mut error = AppError::new(
        ErrorCode::InvalidArgument,
        "enrichment batch exceeds the supported size",
    );
    error.details.insert("actual".into(), actual.to_string());
    error
        .details
        .insert("maximum".into(), MAX_ENRICHMENT_BATCH_SIZE.to_string());
    error
}

fn invalid_managed_binding(field: &'static str, reason: &'static str) -> AppError {
    let mut error = AppError::new(
        ErrorCode::InvalidArgument,
        "invalid managed process binding snapshot",
    );
    error.details.insert("field".into(), field.into());
    error.details.insert("reason".into(), reason.into());
    error
}

fn duplicate_managed_binding_error(field: &'static str, run_id: &str, pid: u32) -> AppError {
    let mut error = invalid_managed_binding(field, "contains a duplicate association");
    error.details.insert("runId".into(), run_id.into());
    error.details.insert("pid".into(), pid.to_string());
    error
}

fn managed_binding_capacity_error(actual: usize, capacity: usize) -> AppError {
    let mut error = invalid_managed_binding("bindings", "exceeds process cache capacity");
    error.details.insert("actual".into(), actual.to_string());
    error
        .details
        .insert("capacity".into(), capacity.to_string());
    error
}

fn scan_capacity_error(entity: &'static str, actual: usize, capacity: usize) -> AppError {
    let mut error = AppError::new(
        ErrorCode::PlatformError,
        "discovery scan exceeds cache capacity",
    );
    error.details.insert("entity".into(), entity.into());
    error.details.insert("actual".into(), actual.to_string());
    error
        .details
        .insert("capacity".into(), capacity.to_string());
    error.retryable = true;
    error
}

fn event_payload_capacity_error(
    entity: &'static str,
    estimated_entity_bytes: usize,
    estimated_payload_bytes: usize,
) -> AppError {
    let mut error = AppError::new(
        ErrorCode::PlatformError,
        "discovery event entity exceeds payload capacity",
    );
    error.details.insert("entity".into(), entity.into());
    error.details.insert(
        "estimatedEntityBytes".into(),
        estimated_entity_bytes.to_string(),
    );
    error.details.insert(
        "estimatedPayloadBytes".into(),
        estimated_payload_bytes.to_string(),
    );
    error.details.insert(
        "maximumPayloadBytes".into(),
        MAX_DISCOVERY_EVENT_PAYLOAD_BYTES.to_string(),
    );
    error
}

fn duplicate_key_error(entity: &'static str, pid: u32) -> AppError {
    let mut error = AppError::new(
        ErrorCode::PlatformError,
        "discovery scan contains duplicate keys",
    );
    error.details.insert("entity".into(), entity.into());
    error.details.insert("pid".into(), pid.to_string());
    error
}

fn duplicate_port_error(key: &PortBindingKey) -> AppError {
    let mut error = AppError::new(
        ErrorCode::PlatformError,
        "discovery scan contains duplicate port keys",
    );
    error
        .details
        .insert("localAddress".into(), key.local_address.clone());
    error
        .details
        .insert("localPort".into(), key.local_port.to_string());
    error
}

fn unavailable(message: &'static str) -> AppError {
    let mut error = AppError::new(ErrorCode::SupervisorUnavailable, message);
    error.retryable = true;
    error
}

fn internal_error(message: &'static str, reason: String) -> AppError {
    let mut error = AppError::new(ErrorCode::Internal, message);
    error.details.insert("reason".into(), reason);
    error
}

fn operation_for_task(kind: Option<&TaskKind>) -> DiscoveryOperation {
    match kind {
        Some(TaskKind::Fast) => DiscoveryOperation::FastProcessScan,
        Some(TaskKind::Port) => DiscoveryOperation::PortScan,
        Some(TaskKind::Enrichment(key)) => DiscoveryOperation::Enrichment(key.clone()),
        Some(TaskKind::ProjectAssociation(key)) => {
            DiscoveryOperation::ProjectAssociation(key.clone())
        }
        None => DiscoveryOperation::FastProcessScan,
    }
}

async fn receive_reply<T>(receiver: oneshot::Receiver<T>) -> Result<T, AppError> {
    receiver
        .await
        .map_err(|_| unavailable("discovery scheduler stopped before replying"))
}

fn binding_key(binding: &PortBinding) -> PortBindingKey {
    PortBindingKey::from(binding)
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

fn compare_port_keys(left: &PortBindingKey, right: &PortBindingKey) -> Ordering {
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

fn sort_port_bindings(bindings: &mut [PortBinding]) {
    bindings.sort_by(compare_port_bindings);
}

fn sort_port_keys(keys: &mut [PortBindingKey]) {
    keys.sort_by(compare_port_keys);
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
