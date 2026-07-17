use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use domain::{
    AccessLevel, AppError, ErrorCode, FieldValue, PortBinding, ProcessInstanceKey, ProcessRecord,
};
use tokio::sync::watch;

use crate::project::{NormalizedProjectRoot, ProjectScanRequest, ProjectScanResult};

/// A future returned by a platform discovery adapter.
pub type BackendFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, AppError>> + Send + 'a>>;

/// Cooperative cancellation shared between the scheduler and platform code.
///
/// Native adapters must check this token between bounded native API calls. The
/// scheduler can then merge or restart slow scans without detaching work.
#[derive(Clone, Debug)]
pub struct CancellationToken {
    sender: Arc<watch::Sender<bool>>,
}

impl CancellationToken {
    pub fn new() -> Self {
        let (sender, _) = watch::channel(false);
        Self {
            sender: Arc::new(sender),
        }
    }

    pub fn cancel(&self) {
        self.sender.send_replace(true);
    }

    pub fn is_cancelled(&self) -> bool {
        *self.sender.borrow()
    }

    pub async fn cancelled(&self) {
        let mut receiver = self.sender.subscribe();
        while !*receiver.borrow_and_update() {
            if receiver.changed().await.is_err() {
                return;
            }
        }
    }
}

impl Default for CancellationToken {
    fn default() -> Self {
        Self::new()
    }
}

/// One authoritative, platform-neutral fast process enumeration.
#[derive(Clone, Debug, PartialEq)]
pub struct FastProcessScan {
    pub processes: Vec<ProcessRecord>,
}

/// The availability of a complete port enumeration is explicit. In
/// particular, `Known(vec![])` is not interchangeable with `Unknown`.
#[derive(Clone, Debug, PartialEq)]
pub struct PortScan {
    pub bindings: FieldValue<Vec<PortBinding>>,
}

/// Expensive fields that can be filled independently of the fast scan.
#[derive(Clone, Debug, PartialEq)]
pub struct ProcessEnrichment {
    pub instance_key: ProcessInstanceKey,
    pub executable_path: FieldValue<String>,
    pub command_line: FieldValue<String>,
    pub working_directory: FieldValue<String>,
    /// `None` means this enrichment did not inspect ports. `Some(Unknown)` and
    /// `Some(Known(vec![]))` retain their distinct domain meanings.
    pub port_bindings: Option<FieldValue<Vec<PortBinding>>>,
    pub access_level: Option<AccessLevel>,
}

/// Fields requested from a delayed per-process enrichment.
///
/// Ordering is also the coverage ordering used by the scheduler cache.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum EnrichmentDemand {
    Metadata,
    MetadataAndPorts,
}

/// Platform adapter boundary used by the scheduler.
///
/// Implementations return structured domain errors and must never turn a
/// per-process access failure into an unstructured global failure.
pub trait DiscoveryBackend: Send + Sync + 'static {
    fn scan_processes(&self, cancellation: CancellationToken)
    -> BackendFuture<'_, FastProcessScan>;

    fn scan_ports(&self, cancellation: CancellationToken) -> BackendFuture<'_, PortScan>;

    fn enrich_process(
        &self,
        instance_key: ProcessInstanceKey,
        demand: EnrichmentDemand,
        cancellation: CancellationToken,
    ) -> BackendFuture<'_, ProcessEnrichment>;

    /// Resolves one already-known working directory and inspects only the
    /// fixed marker names in [`crate::PROJECT_MARKERS`]. Implementations must
    /// canonicalize losslessly, walk ancestors by components, ignore marker
    /// symlinks/reparse points, and return non-Known evidence after any partial
    /// or permission-limited scan.
    fn scan_project_evidence(
        &self,
        request: ProjectScanRequest,
    ) -> BackendFuture<'_, ProjectScanResult> {
        Box::pin(async move { Ok(ProjectScanResult::not_supported(&request)) })
    }

    /// Trusted project-save boundary. Clients never supply a normalized key.
    fn normalize_project_root(
        &self,
        _root_directory: String,
        _cancellation: CancellationToken,
    ) -> BackendFuture<'_, NormalizedProjectRoot> {
        Box::pin(async {
            Err(AppError::new(
                ErrorCode::NotSupported,
                "project root normalization is not supported by this backend",
            ))
        })
    }
}
