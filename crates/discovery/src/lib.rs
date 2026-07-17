//! Bounded process and port discovery scheduling.

mod backend;
mod classification;
mod project;
mod scheduler;

pub use backend::{
    BackendFuture, CancellationToken, DiscoveryBackend, EnrichmentDemand, FastProcessScan,
    PortScan, ProcessEnrichment,
};
pub use classification::{
    ALGORITHM_VERSION, COMMON_DEVELOPMENT_PORTS, ClassificationDecision, ClassificationEngine,
    ClassificationRule, ClassificationRuleAction, ClassificationRuleMatcher,
    ClassificationRulesSnapshot, DEFAULT_DEVELOPMENT_THRESHOLD, MAX_CLASSIFICATION_RULES,
    MAX_KNOWN_PROJECTS, ProcessClassificationFacts,
};
pub use project::{
    MAX_PROJECT_ANCESTOR_DEPTH, MAX_PROJECT_CATALOG_ENTRIES, MAX_PROJECT_FEATURES,
    MAX_PROJECT_PATH_BYTES, NormalizedPathKey, NormalizedPathRoot, NormalizedProjectRoot,
    PROJECT_MARKERS, ProjectCatalog, ProjectCatalogSnapshot, ProjectContextSnapshot, ProjectMarker,
    ProjectScanRequest, ProjectScanResult, RegisteredProject,
};
pub use scheduler::{
    DISCOVERY_LATENCY_WINDOW_CAPACITY, DiscoveryChange, DiscoveryConfig, DiscoveryLatencySnapshot,
    DiscoveryOperation, DiscoveryPerformanceSnapshot, DiscoveryScheduler, DiscoverySchedulerHandle,
    DiscoverySnapshot, DiscoverySubscription, DiscoveryUpdate, EnrichmentBatchRequest,
    EnrichmentBatchResult, EnrichmentPriority, EnrichmentRequestStatus,
    MAX_DISCOVERY_EVENT_ENTITIES, MAX_DISCOVERY_EVENT_PAYLOAD_BYTES, MAX_ENRICHMENT_BATCH_SIZE,
    ManagedProcessBinding, ProjectRequestStatus, RefreshMode, RefreshScope, SubscriptionError,
};
