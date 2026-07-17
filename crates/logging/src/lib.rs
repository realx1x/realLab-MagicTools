//! Bounded UTF-8 collection and delivery for non-interactive managed process
//! pipes.
//!
//! Each stream owns an independent ordered writer. Disk capture happens before
//! the bounded in-memory tail is updated and does not depend on a UI consumer.
//! Raw events are coalesced behind a non-blocking dirty notification and disk
//! ranges remain available independently of event consumption. Pipe decoding
//! happens before the UTF-8 append boundary; PTY support remains outside this
//! crate's contract.

#![forbid(unsafe_op_in_unsafe_fn)]

mod application;
mod control_filter;
mod diagnostic_export;
mod redaction;
mod retention;
mod secure_directory;
mod text;

use std::collections::VecDeque;
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, TryRecvError, sync_channel};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use control_filter::is_printable_log_character;
use redaction::wipe_bytes;
use secure_directory::SecureRunDirectory;

pub use application::{
    APPLICATION_LOG_DIAGNOSTIC_CONTENT_ID, APPLICATION_LOG_SCHEMA_VERSION,
    ApplicationLogAppendReceipt, ApplicationLogBuffer, ApplicationLogError,
    ApplicationLogErrorKind, ApplicationLogEvent, ApplicationLogField, ApplicationLogFieldName,
    ApplicationLogLevel, ApplicationLogLimits, ApplicationLogOperation, ApplicationLogRead,
    ApplicationLogValue, DEFAULT_APPLICATION_LOG_RECORDS, DEFAULT_APPLICATION_LOG_RETAINED_BYTES,
    DEFAULT_DIAGNOSTIC_BYTE_BUDGET, DEFAULT_DIAGNOSTIC_CONTENT_ITEMS, DiagnosticByteBudget,
    DiagnosticContentInput, DiagnosticContentItem, DiagnosticContentManifest,
    DiagnosticContentProtection, DiagnosticManifestLimits, MAX_APPLICATION_LOG_FIELDS,
    MAX_APPLICATION_LOG_READ_BYTES, MAX_APPLICATION_LOG_RECORD_BYTES, MAX_APPLICATION_LOG_RECORDS,
    MAX_APPLICATION_LOG_RETAINED_BYTES, MAX_DIAGNOSTIC_BYTE_BUDGET, MAX_DIAGNOSTIC_CONTENT_BYTES,
    MAX_DIAGNOSTIC_CONTENT_ITEMS,
};
pub use diagnostic_export::{
    DIAGNOSTIC_EXPORT_SLOT_COUNT, DiagnosticExportReceipt, DiagnosticExportStore,
    MAX_DIAGNOSTIC_EXPORT_FILE_NAME_BYTES, diagnostic_export_slot_file_name,
};
pub use redaction::{LOG_REDACTION_MARKER, LogRedactionError, LogRedactionRules, LogRedactor};
pub use retention::{
    MAX_MANAGED_LOG_RUN_ID_BYTES, ManagedLogRetentionInspection, ManagedLogRetentionRemoval,
    ManagedLogRetentionStore,
};
pub use text::{
    LogEncodingPolicy, LogTextError, LogTextPipeline, LogTextStatus, ResolvedLogEncoding,
};

/// Default maximum size of each active or archived stream file: 10 MiB.
pub const DEFAULT_LOG_FILE_BYTES: u64 = 10 * 1024 * 1024;
/// Default number of files retained per stream, including the active file.
pub const DEFAULT_LOG_FILES_PER_STREAM: u8 = 5;
/// Default retained in-memory tail for each stream: 256 KiB.
pub const DEFAULT_MEMORY_BYTES_PER_STREAM: usize = 256 * 1024;
/// Default maximum retained disk bytes for one stream: 50 MiB.
pub const DEFAULT_DISK_BYTES_PER_STREAM: u64 =
    DEFAULT_LOG_FILE_BYTES * DEFAULT_LOG_FILES_PER_STREAM as u64;
/// Default maximum retained disk bytes for stdout and stderr together: 100 MiB.
pub const DEFAULT_DISK_BYTES_PER_RUN: u64 = DEFAULT_DISK_BYTES_PER_STREAM * 2;
/// Default maximum retained in-memory bytes for stdout and stderr together.
pub const DEFAULT_MEMORY_BYTES_PER_RUN: usize = DEFAULT_MEMORY_BYTES_PER_STREAM * 2;

/// Hard configuration bounds keep a caller from accidentally removing the
/// resource ceiling while allowing a future settings task to tune defaults.
pub const MAX_LOG_FILE_BYTES: u64 = 100 * 1024 * 1024;
pub const MAX_LOG_FILES_PER_STREAM: u8 = 10;
pub const MAX_MEMORY_BYTES_PER_STREAM: usize = 4 * 1024 * 1024;

/// Largest UTF-8 event body. Event delivery cannot allocate an unbounded chunk.
pub const MAX_LOG_EVENT_BYTES: usize = 64 * 1024;
/// Largest UTF-8 range-read body returned by one call.
pub const MAX_LOG_RANGE_BYTES: usize = 64 * 1024;
/// Dirty notifications are coalesced for this long before an event batch.
pub const LOG_EVENT_THROTTLE_MILLIS: u64 = 50;
/// Largest integer represented exactly by a JavaScript `number`.
pub const JS_MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

const PIPE_READ_BUFFER_BYTES: usize = 16 * 1024;
const DIRTY_NOTIFICATION_CAPACITY: usize = 1;
const MIN_UTF8_BOUNDARY_BYTES: usize = 4;

/// The two ordinary, non-interactive process output streams.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum LogStream {
    Stdout,
    Stderr,
}

impl Display for LogStream {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Stdout => "stdout",
            Self::Stderr => "stderr",
        })
    }
}

impl LogStream {
    fn active_file_name(self) -> &'static str {
        match self {
            Self::Stdout => "stdout.log",
            Self::Stderr => "stderr.log",
        }
    }

    fn archive_file_name(self, index: u8) -> String {
        format!("{}.{}", self.active_file_name(), index)
    }
}

/// Closed operation identifiers used by sanitized log errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LogOperation {
    ValidateLimits,
    ValidateRunDirectory,
    ValidateRetentionLogRoot,
    ValidateRetentionRunId,
    InspectRunDirectory,
    CreateRunDirectory,
    SecureRunDirectory,
    OpenLogFile,
    InspectLogFile,
    SecureLogFile,
    RemoveExpiredLogFile,
    InspectRetainedLogFile,
    RemoveRetainedLogFile,
    RemoveRetainedRunDirectory,
    RotateLogFile,
    ReadPipe,
    WriteLogFile,
    FlushLogFile,
    AccountBytes,
    AccountRetainedLogBytes,
    UseUnavailableStream,
    CoordinateLogIo,
    OpenExistingLogDirectory,
    ReadLogRange,
    SequenceLogEvent,
    ValidateDiagnosticExportRoot,
    ValidateDiagnosticExportFileName,
    InspectDiagnosticExportFile,
    CreateDiagnosticPartialFile,
    WriteDiagnosticPartialFile,
    FlushDiagnosticPartialFile,
    PublishDiagnosticFile,
    RemoveDiagnosticPartialFile,
    RemoveDiagnosticExportFile,
    SyncDiagnosticExportDirectory,
    CancelDiagnosticExport,
}

/// Sanitized failure categories. No path, log bytes, environment value, or OS
/// error text is retained in this public value or its `Debug` output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LogErrorKind {
    InvalidConfiguration,
    InvalidPath,
    NotFound,
    PermissionDenied,
    AlreadyExists,
    ResourceBusy,
    StorageFull,
    Interrupted,
    UnexpectedEof,
    InvalidData,
    LimitExceeded,
    WriteZero,
    Unavailable,
    OtherIo,
}

/// A structured, content-free logging error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LogError {
    stream: Option<LogStream>,
    operation: LogOperation,
    kind: LogErrorKind,
    accepted_input_bytes: usize,
}

impl LogError {
    pub fn stream(&self) -> Option<LogStream> {
        self.stream
    }

    pub fn operation(&self) -> LogOperation {
        self.operation
    }

    pub fn kind(&self) -> LogErrorKind {
        self.kind
    }

    /// Bytes from the current `append` call that reached the stream file before
    /// the failure. The value reveals no log content.
    pub fn accepted_input_bytes(&self) -> usize {
        self.accepted_input_bytes
    }

    fn configuration(operation: LogOperation, kind: LogErrorKind) -> Self {
        Self {
            stream: None,
            operation,
            kind,
            accepted_input_bytes: 0,
        }
    }

    fn io(stream: Option<LogStream>, operation: LogOperation, error: &io::Error) -> Self {
        Self {
            stream,
            operation,
            kind: sanitized_io_kind(error),
            accepted_input_bytes: 0,
        }
    }

    fn for_stream(stream: LogStream, operation: LogOperation, kind: LogErrorKind) -> Self {
        Self {
            stream: Some(stream),
            operation,
            kind,
            accepted_input_bytes: 0,
        }
    }

    fn with_accepted_input_bytes(mut self, accepted_input_bytes: usize) -> Self {
        self.accepted_input_bytes = accepted_input_bytes;
        self
    }
}

impl Display for LogError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self.stream {
            Some(stream) => write!(
                formatter,
                "{stream} log operation {:?} failed ({:?})",
                self.operation, self.kind
            ),
            None => write!(
                formatter,
                "log operation {:?} failed ({:?})",
                self.operation, self.kind
            ),
        }
    }
}

impl Error for LogError {}

fn sanitized_io_kind(error: &io::Error) -> LogErrorKind {
    match error.kind() {
        io::ErrorKind::NotFound => LogErrorKind::NotFound,
        io::ErrorKind::PermissionDenied => LogErrorKind::PermissionDenied,
        io::ErrorKind::AlreadyExists => LogErrorKind::AlreadyExists,
        io::ErrorKind::InvalidInput => LogErrorKind::InvalidPath,
        io::ErrorKind::InvalidData => LogErrorKind::InvalidData,
        io::ErrorKind::Interrupted => LogErrorKind::Interrupted,
        io::ErrorKind::UnexpectedEof => LogErrorKind::UnexpectedEof,
        io::ErrorKind::WriteZero => LogErrorKind::WriteZero,
        io::ErrorKind::StorageFull => LogErrorKind::StorageFull,
        io::ErrorKind::ResourceBusy => LogErrorKind::ResourceBusy,
        _ => LogErrorKind::OtherIo,
    }
}

/// Per-run resource limits. The file limit can hold any one UTF-8 scalar; every
/// field is nonzero and capped by the public hard limits above.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LogLimits {
    file_bytes: u64,
    files_per_stream: u8,
    memory_bytes_per_stream: usize,
}

impl LogLimits {
    pub fn new(
        file_bytes: u64,
        files_per_stream: u8,
        memory_bytes_per_stream: usize,
    ) -> Result<Self, LogError> {
        if file_bytes < MIN_UTF8_BOUNDARY_BYTES as u64
            || file_bytes > MAX_LOG_FILE_BYTES
            || files_per_stream == 0
            || files_per_stream > MAX_LOG_FILES_PER_STREAM
            || memory_bytes_per_stream == 0
            || memory_bytes_per_stream > MAX_MEMORY_BYTES_PER_STREAM
        {
            return Err(LogError::configuration(
                LogOperation::ValidateLimits,
                LogErrorKind::InvalidConfiguration,
            ));
        }
        Ok(Self {
            file_bytes,
            files_per_stream,
            memory_bytes_per_stream,
        })
    }

    pub fn file_bytes(self) -> u64 {
        self.file_bytes
    }

    /// Includes the active file and all numbered archives.
    pub fn files_per_stream(self) -> u8 {
        self.files_per_stream
    }

    pub fn memory_bytes_per_stream(self) -> usize {
        self.memory_bytes_per_stream
    }

    pub fn disk_bytes_per_stream(self) -> u64 {
        self.file_bytes * u64::from(self.files_per_stream)
    }

    pub fn disk_bytes_per_run(self) -> u64 {
        self.disk_bytes_per_stream() * 2
    }

    pub fn memory_bytes_per_run(self) -> usize {
        self.memory_bytes_per_stream * 2
    }
}

impl Default for LogLimits {
    fn default() -> Self {
        Self {
            file_bytes: DEFAULT_LOG_FILE_BYTES,
            files_per_stream: DEFAULT_LOG_FILES_PER_STREAM,
            memory_bytes_per_stream: DEFAULT_MEMORY_BYTES_PER_STREAM,
        }
    }
}

/// One successful ordered append. Existing retained files occupy the start of
/// the current reader generation, and stdout/stderr have independent offset
/// spaces.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LogAppendReceipt {
    pub stream: LogStream,
    pub first_byte_offset: u64,
    pub next_byte_offset: u64,
}

/// A bounded copy of the retained UTF-8 tail for one stream.
#[derive(Clone, Eq, PartialEq)]
pub struct BufferedLogSnapshot {
    pub stream: LogStream,
    pub first_byte_offset: u64,
    pub next_byte_offset: u64,
    pub text: String,
}

impl fmt::Debug for BufferedLogSnapshot {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BufferedLogSnapshot")
            .field("stream", &self.stream)
            .field("first_byte_offset", &self.first_byte_offset)
            .field("next_byte_offset", &self.next_byte_offset)
            .field("byte_count", &self.text.len())
            .finish()
    }
}

/// Result of draining one pipe to EOF.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LogCaptureSummary {
    pub stream: LogStream,
    pub captured_bytes: u64,
}

/// One throttled UTF-8 event. `text` is never larger than
/// [`MAX_LOG_EVENT_BYTES`]. `sequence` is assigned independently per stream
/// and never exceeds [`JS_MAX_SAFE_INTEGER`].
///
/// A false `complete` means either more bytes were present at the event's
/// snapshot (`has_more`) or bytes before `first` had already rotated away.
/// Terminal and disk/read-error flags are state snapshots, so an EOF event can
/// still carry the last bounded data chunk.
#[derive(Clone, Eq, PartialEq)]
pub struct RawLogEvent {
    pub stream: LogStream,
    pub sequence: u64,
    pub first_available: u64,
    pub first: u64,
    pub next: u64,
    pub end: u64,
    pub has_more: bool,
    pub complete: bool,
    pub text: String,
    pub end_of_file: bool,
    pub io_status_known: bool,
    pub disk_error: Option<LogErrorKind>,
    pub read_error: Option<LogErrorKind>,
    pub delivery_error: Option<LogErrorKind>,
    pub text_status: Option<LogTextStatus>,
}

impl fmt::Debug for RawLogEvent {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RawLogEvent")
            .field("stream", &self.stream)
            .field("sequence", &self.sequence)
            .field("first_available", &self.first_available)
            .field("first", &self.first)
            .field("next", &self.next)
            .field("end", &self.end)
            .field("has_more", &self.has_more)
            .field("complete", &self.complete)
            .field("byte_count", &self.text.len())
            .field("end_of_file", &self.end_of_file)
            .field("io_status_known", &self.io_status_known)
            .field("disk_error", &self.disk_error)
            .field("read_error", &self.read_error)
            .field("delivery_error", &self.delivery_error)
            .field("text_status", &self.text_status)
            .finish()
    }
}

/// A bounded disk-backed range result. The offset generation begins when its
/// reader is opened: retained files at that time occupy `0..end`. Absolute
/// offsets are not portable across Supervisor generations.
///
/// `complete` is true only when the requested offset was still retained and
/// this response reaches the observed `end`. The body is never larger than
/// [`MAX_LOG_RANGE_BYTES`].
#[derive(Clone, Eq, PartialEq)]
pub struct LogRangeRead {
    pub stream: LogStream,
    pub observed_sequence: u64,
    pub first_available: u64,
    pub first: u64,
    pub next: u64,
    pub end: u64,
    pub has_more: bool,
    pub complete: bool,
    pub text: String,
    pub end_of_file: bool,
    pub io_status_known: bool,
    pub disk_error: Option<LogErrorKind>,
    pub read_error: Option<LogErrorKind>,
    pub text_status: Option<LogTextStatus>,
}

impl fmt::Debug for LogRangeRead {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LogRangeRead")
            .field("stream", &self.stream)
            .field("observed_sequence", &self.observed_sequence)
            .field("first_available", &self.first_available)
            .field("first", &self.first)
            .field("next", &self.next)
            .field("end", &self.end)
            .field("has_more", &self.has_more)
            .field("complete", &self.complete)
            .field("byte_count", &self.text.len())
            .field("end_of_file", &self.end_of_file)
            .field("io_status_known", &self.io_status_known)
            .field("disk_error", &self.disk_error)
            .field("read_error", &self.read_error)
            .field("text_status", &self.text_status)
            .finish()
    }
}

/// Owns both ordinary managed-run streams before they are moved to independent
/// capture workers.
pub struct ManagedRunLogCollector {
    stdout: LogStreamCollector,
    stderr: LogStreamCollector,
    event_source: ManagedRunLogEventSource,
    range_reader: ManagedRunLogRangeReader,
}

impl ManagedRunLogCollector {
    /// Creates or reopens exactly one Supervisor-selected run directory.
    ///
    /// `run_log_directory` must be an absolute lexical path without `.` or
    /// `..`. Its parent must already exist as a private current-user directory;
    /// only the final run directory and fixed stream filenames are created.
    /// The active files are `stdout.log` and `stderr.log`; archive `.1` is the
    /// newest and the highest retained suffix is the oldest. The configured
    /// file count includes the active file. Rotation happens before the next
    /// complete UTF-8 scalar would exceed the per-file limit.
    pub fn open(run_log_directory: impl AsRef<Path>, limits: LogLimits) -> Result<Self, LogError> {
        let directory = Arc::new(SecureRunDirectory::prepare(run_log_directory.as_ref())?);
        let (dirty_sender, dirty_receiver) = sync_channel(DIRTY_NOTIFICATION_CAPACITY);
        let stdout = LogStreamCollector::open(
            directory.clone(),
            LogStream::Stdout,
            limits,
            dirty_sender.clone(),
        )?;
        let stderr = LogStreamCollector::open(directory, LogStream::Stderr, limits, dirty_sender)?;
        let range_reader = ManagedRunLogRangeReader {
            stdout: stdout.shared.clone(),
            stderr: stderr.shared.clone(),
        };
        let event_source = ManagedRunLogEventSource::new(
            dirty_receiver,
            range_reader.clone(),
            stdout.next_byte_offset,
            stderr.next_byte_offset,
        );
        Ok(Self {
            stdout,
            stderr,
            event_source,
            range_reader,
        })
    }

    pub fn stdout_mut(&mut self) -> &mut LogStreamCollector {
        &mut self.stdout
    }

    pub fn stderr_mut(&mut self) -> &mut LogStreamCollector {
        &mut self.stderr
    }

    pub fn into_streams(self) -> ManagedRunLogStreams {
        ManagedRunLogStreams {
            stdout: self.stdout,
            stderr: self.stderr,
            event_source: self.event_source,
            range_reader: self.range_reader,
        }
    }
}

impl fmt::Debug for ManagedRunLogCollector {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManagedRunLogCollector")
            .field("stdout", &self.stdout)
            .field("stderr", &self.stderr)
            .finish()
    }
}

/// Named result of splitting stdout and stderr for independent ordered capture.
pub struct ManagedRunLogStreams {
    pub stdout: LogStreamCollector,
    pub stderr: LogStreamCollector,
    pub event_source: ManagedRunLogEventSource,
    pub range_reader: ManagedRunLogRangeReader,
}

/// Cloneable bounded reader for both retained rolling-file windows.
///
/// Each call opens at most [`MAX_LOG_FILES_PER_STREAM`] fixed-name file
/// handles while holding a per-stream IO gate, releases that gate, and then
/// reads at most [`MAX_LOG_RANGE_BYTES`] bytes. This prevents a slow consumer
/// from holding up pipe capture while keeping rotations coherent with the
/// opened snapshot.
#[derive(Clone)]
pub struct ManagedRunLogRangeReader {
    stdout: Arc<StreamShared>,
    stderr: Arc<StreamShared>,
}

impl ManagedRunLogRangeReader {
    /// Opens a new absolute-offset generation over an existing run directory.
    /// This operation never creates a directory or file and never changes
    /// ownership, permissions, or ACLs. Retained files at open time are mapped
    /// contiguously to `0..end`; offsets from another reader generation are not
    /// accepted as stable identifiers.
    pub fn open_existing(
        run_log_directory: impl AsRef<Path>,
        limits: LogLimits,
    ) -> Result<Self, LogError> {
        let directory = Arc::new(
            SecureRunDirectory::open_existing(run_log_directory.as_ref()).map_err(|error| {
                LogError {
                    operation: LogOperation::OpenExistingLogDirectory,
                    ..error
                }
            })?,
        );
        let stdout = StreamShared::open_existing(directory.clone(), LogStream::Stdout, limits)?;
        let stderr = StreamShared::open_existing(directory, LogStream::Stderr, limits)?;
        Ok(Self { stdout, stderr })
    }

    /// Reads a retained UTF-8 range. An omitted offset starts at the first byte
    /// retained by the same atomic snapshot. `max_bytes` must be in
    /// `4..=MAX_LOG_RANGE_BYTES`, and a supplied offset must be JavaScript-safe
    /// and point at a UTF-8 scalar boundary while it is retained.
    pub fn read_range(
        &self,
        stream: LogStream,
        offset: Option<u64>,
        max_bytes: usize,
    ) -> Result<LogRangeRead, LogError> {
        if offset.is_some_and(|offset| offset > JS_MAX_SAFE_INTEGER)
            || max_bytes < MIN_UTF8_BOUNDARY_BYTES
            || max_bytes > MAX_LOG_RANGE_BYTES
        {
            return Err(LogError::for_stream(
                stream,
                LogOperation::ReadLogRange,
                LogErrorKind::LimitExceeded,
            ));
        }
        self.shared(stream)
            .read_snapshot(offset, max_bytes)
            .map(|snapshot| snapshot.range)
    }

    fn shared(&self, stream: LogStream) -> &Arc<StreamShared> {
        match stream {
            LogStream::Stdout => &self.stdout,
            LogStream::Stderr => &self.stderr,
        }
    }

    fn read_event_snapshot(
        &self,
        stream: LogStream,
        offset: u64,
    ) -> Result<RangeSnapshot, LogError> {
        self.shared(stream)
            .read_snapshot(Some(offset), MAX_LOG_EVENT_BYTES)
    }
}

impl fmt::Debug for ManagedRunLogRangeReader {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManagedRunLogRangeReader")
            .finish_non_exhaustive()
    }
}

/// Single-consumer blocking source for throttled raw log events.
///
/// Capture workers only perform a capacity-one `try_send`; they never wait for
/// this source or any downstream UI. `recv_batch` coalesces dirty notifications for
/// 50 ms and emits at most one 64 KiB chunk per stream in each batch. A slow
/// caller therefore applies backpressure only to this event source, never to
/// process pipes or disk collection.
pub struct ManagedRunLogEventSource {
    dirty_receiver: Receiver<()>,
    range_reader: ManagedRunLogRangeReader,
    stdout: EventCursor,
    stderr: EventCursor,
    pending: VecDeque<RawLogEvent>,
    disconnected: bool,
    backlog: bool,
    last_batch: Option<Instant>,
}

impl ManagedRunLogEventSource {
    fn new(
        dirty_receiver: Receiver<()>,
        range_reader: ManagedRunLogRangeReader,
        stdout_end: u64,
        stderr_end: u64,
    ) -> Self {
        Self {
            dirty_receiver,
            range_reader,
            stdout: EventCursor::new(stdout_end),
            stderr: EventCursor::new(stderr_end),
            pending: VecDeque::with_capacity(2),
            disconnected: false,
            backlog: false,
            last_batch: None,
        }
    }

    /// Blocks until the next throttled batch is available. A batch contains at
    /// most one event per stream, so its length is always one or two.
    /// `Ok(None)` means both collectors were dropped and every retained event
    /// chunk was emitted.
    pub fn recv_batch(&mut self) -> Result<Option<Vec<RawLogEvent>>, LogError> {
        loop {
            if !self.pending.is_empty() {
                return Ok(Some(self.pending.drain(..).collect()));
            }
            if !self.wait_for_batch() {
                return Ok(None);
            }
            self.fill_batch()?;
        }
    }

    /// Blocks until the next event is available. Callers that publish UI
    /// updates should prefer [`Self::recv_batch`] so both streams observed in
    /// one throttle window share one downstream batch.
    pub fn recv(&mut self) -> Result<Option<RawLogEvent>, LogError> {
        loop {
            if let Some(event) = self.pending.pop_front() {
                return Ok(Some(event));
            }
            if !self.wait_for_batch() {
                return Ok(None);
            }
            self.fill_batch()?;
        }
    }

    fn wait_for_batch(&mut self) -> bool {
        if self.backlog {
            self.wait_until_throttle_deadline();
            self.drain_dirty_notifications();
            return true;
        }
        if self.disconnected {
            return false;
        }

        match self.dirty_receiver.recv() {
            Ok(()) => {}
            Err(_) => {
                self.disconnected = true;
                return false;
            }
        }

        let deadline = Instant::now() + Duration::from_millis(LOG_EVENT_THROTTLE_MILLIS);
        while !self.disconnected {
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            match self.dirty_receiver.recv_timeout(deadline - now) {
                Ok(()) => {}
                Err(RecvTimeoutError::Timeout) => break,
                Err(RecvTimeoutError::Disconnected) => self.disconnected = true,
            }
        }
        self.wait_until_throttle_deadline();
        true
    }

    fn wait_until_throttle_deadline(&mut self) {
        let Some(last_batch) = self.last_batch else {
            return;
        };
        let deadline = last_batch + Duration::from_millis(LOG_EVENT_THROTTLE_MILLIS);
        loop {
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            if self.disconnected {
                std::thread::sleep(deadline - now);
                break;
            }
            match self.dirty_receiver.recv_timeout(deadline - now) {
                Ok(()) => {}
                Err(RecvTimeoutError::Timeout) => break,
                Err(RecvTimeoutError::Disconnected) => self.disconnected = true,
            }
        }
    }

    fn drain_dirty_notifications(&mut self) {
        while !self.disconnected {
            match self.dirty_receiver.try_recv() {
                Ok(()) => {}
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => self.disconnected = true,
            }
        }
    }

    fn fill_batch(&mut self) -> Result<(), LogError> {
        self.backlog = false;
        self.fill_stream(LogStream::Stdout)?;
        self.fill_stream(LogStream::Stderr)?;
        self.last_batch = Some(Instant::now());
        Ok(())
    }

    fn fill_stream(&mut self, stream: LogStream) -> Result<(), LogError> {
        let cursor = match stream {
            LogStream::Stdout => &mut self.stdout,
            LogStream::Stderr => &mut self.stderr,
        };
        let snapshot = match self
            .range_reader
            .read_event_snapshot(stream, cursor.next_offset)
        {
            Ok(snapshot) => snapshot,
            Err(error) => {
                let state = self.range_reader.shared(stream).event_state()?;
                let status_changed = cursor.end_of_file != state.status.end_of_file
                    || cursor.disk_error != state.status.disk_error
                    || cursor.read_error != state.status.read_error
                    || cursor.text_status != state.status.text_status
                    || cursor.delivery_error != Some(error.kind());
                if !status_changed {
                    return Ok(());
                }
                let sequence = self.range_reader.shared(stream).next_event_sequence()?;
                let first = cursor.next_offset.max(state.first_available).min(state.end);
                cursor.next_offset = first;
                cursor.end_of_file = state.status.end_of_file;
                cursor.disk_error = state.status.disk_error;
                cursor.read_error = state.status.read_error;
                cursor.text_status = state.status.text_status;
                cursor.delivery_error = Some(error.kind());
                self.pending.push_back(RawLogEvent {
                    stream,
                    sequence,
                    first_available: state.first_available,
                    first,
                    next: first,
                    end: state.end,
                    has_more: first < state.end,
                    complete: false,
                    text: String::new(),
                    end_of_file: state.status.end_of_file,
                    io_status_known: state.status.io_status_known,
                    disk_error: state.status.disk_error,
                    read_error: state.status.read_error,
                    delivery_error: Some(error.kind()),
                    text_status: state.status.text_status,
                });
                return Ok(());
            }
        };
        let status_changed = cursor.end_of_file != snapshot.status.end_of_file
            || cursor.disk_error != snapshot.status.disk_error
            || cursor.read_error != snapshot.status.read_error
            || cursor.text_status != snapshot.status.text_status
            || cursor.delivery_error.is_some();
        let offset_changed = snapshot.range.first != cursor.next_offset;
        self.backlog |= snapshot.range.has_more;

        if snapshot.range.text.is_empty() && !status_changed && !offset_changed {
            return Ok(());
        }

        let sequence = self.range_reader.shared(stream).next_event_sequence()?;
        cursor.next_offset = snapshot.range.next;
        cursor.end_of_file = snapshot.status.end_of_file;
        cursor.disk_error = snapshot.status.disk_error;
        cursor.read_error = snapshot.status.read_error;
        cursor.text_status = snapshot.status.text_status;
        cursor.delivery_error = None;
        self.pending.push_back(RawLogEvent {
            stream,
            sequence,
            first_available: snapshot.range.first_available,
            first: snapshot.range.first,
            next: snapshot.range.next,
            end: snapshot.range.end,
            has_more: snapshot.range.has_more,
            complete: snapshot.range.complete,
            text: snapshot.range.text,
            end_of_file: snapshot.status.end_of_file,
            io_status_known: snapshot.status.io_status_known,
            disk_error: snapshot.status.disk_error,
            read_error: snapshot.status.read_error,
            delivery_error: None,
            text_status: snapshot.status.text_status,
        });
        Ok(())
    }
}

impl fmt::Debug for ManagedRunLogEventSource {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManagedRunLogEventSource")
            .field("pending_events", &self.pending.len())
            .field("disconnected", &self.disconnected)
            .field("backlog", &self.backlog)
            .finish_non_exhaustive()
    }
}

struct EventCursor {
    next_offset: u64,
    end_of_file: bool,
    disk_error: Option<LogErrorKind>,
    read_error: Option<LogErrorKind>,
    delivery_error: Option<LogErrorKind>,
    text_status: Option<LogTextStatus>,
}

impl EventCursor {
    fn new(next_offset: u64) -> Self {
        Self {
            next_offset,
            end_of_file: false,
            disk_error: None,
            read_error: None,
            delivery_error: None,
            text_status: None,
        }
    }
}

/// A single-stream UTF-8 collector. `&mut self` serialization preserves
/// order within the stream; no cross-stream ordering is invented.
pub struct LogStreamCollector {
    stream: LogStream,
    rolling_file: RollingFile,
    memory: BoundedByteTail,
    next_byte_offset: u64,
    unavailable: bool,
    shared: Arc<StreamShared>,
    dirty_sender: SyncSender<()>,
}

impl LogStreamCollector {
    fn open(
        directory: Arc<SecureRunDirectory>,
        stream: LogStream,
        limits: LogLimits,
        dirty_sender: SyncSender<()>,
    ) -> Result<Self, LogError> {
        let rolling_file = RollingFile::open(directory.clone(), stream, limits)?;
        let next_byte_offset = rolling_file.initial_retained_bytes();
        let shared = Arc::new(StreamShared::new(
            directory,
            stream,
            limits,
            next_byte_offset,
            true,
        ));
        Ok(Self {
            stream,
            rolling_file,
            memory: BoundedByteTail::new(limits.memory_bytes_per_stream, next_byte_offset),
            next_byte_offset,
            unavailable: false,
            shared,
            dirty_sender,
        })
    }

    pub fn stream(&self) -> LogStream {
        self.stream
    }

    pub fn next_byte_offset(&self) -> u64 {
        self.next_byte_offset
    }

    pub fn retained_memory_bytes(&self) -> usize {
        self.memory.len()
    }

    fn append_utf8_with_status(
        &mut self,
        text: &str,
        text_status: Option<LogTextStatus>,
    ) -> Result<LogAppendReceipt, LogError> {
        validate_safe_log_text(self.stream, text, LogOperation::WriteLogFile)?;
        if self.unavailable {
            if let Some(text_status) = text_status {
                self.update_text_status(text_status)?;
            }
            return Err(LogError::for_stream(
                self.stream,
                LogOperation::UseUnavailableStream,
                LogErrorKind::Unavailable,
            ));
        }

        let input_len = u64::try_from(text.len()).map_err(|_| {
            LogError::for_stream(
                self.stream,
                LogOperation::AccountBytes,
                LogErrorKind::LimitExceeded,
            )
        })?;
        let first_byte_offset = self.next_byte_offset;
        let next_byte_offset = first_byte_offset.checked_add(input_len).ok_or_else(|| {
            LogError::for_stream(
                self.stream,
                LogOperation::AccountBytes,
                LogErrorKind::LimitExceeded,
            )
        })?;
        if next_byte_offset > JS_MAX_SAFE_INTEGER {
            return Err(LogError::for_stream(
                self.stream,
                LogOperation::AccountBytes,
                LogErrorKind::LimitExceeded,
            ));
        }

        let shared = self.shared.clone();
        let mut state = shared.lock_state()?;
        if let Some(text_status) = text_status {
            state.text_status = Some(text_status);
        }
        let result = self.append_utf8_under_gate(text, first_byte_offset, &mut state);
        drop(state);
        self.notify_dirty();
        result
    }

    fn append_utf8_under_gate(
        &mut self,
        text: &str,
        first_byte_offset: u64,
        state: &mut StreamRuntime,
    ) -> Result<LogAppendReceipt, LogError> {
        let mut accepted = 0;
        while accepted < text.len() {
            let remaining = &text[accepted..];
            let next_scalar_bytes = remaining
                .chars()
                .next()
                .expect("non-empty UTF-8 remainder")
                .len_utf8();
            if self.rolling_file.available_bytes() < next_scalar_bytes as u64 {
                match self.rolling_file.rotate() {
                    Ok(removed_bytes) => {
                        state.first_available = state
                            .first_available
                            .checked_add(removed_bytes)
                            .ok_or_else(|| {
                                LogError::for_stream(
                                    self.stream,
                                    LogOperation::AccountBytes,
                                    LogErrorKind::LimitExceeded,
                                )
                            })?;
                    }
                    Err(error) => {
                        self.unavailable = true;
                        state.disk_error = Some(error.kind());
                        self.reconcile_retained_window(state);
                        return Err(error.with_accepted_input_bytes(accepted));
                    }
                }
            }

            let available = self.rolling_file.available_bytes();
            let available = usize::try_from(available)
                .unwrap_or(usize::MAX)
                .min(remaining.len());
            let chunk_bytes = utf8_prefix_len(remaining, available);
            debug_assert!(chunk_bytes >= next_scalar_bytes);
            let chunk = &remaining[..chunk_bytes];
            match self.rolling_file.write_utf8_chunk(chunk.as_bytes()) {
                Ok(()) => {
                    self.memory.append_utf8(chunk, self.next_byte_offset);
                    self.next_byte_offset += chunk_bytes as u64;
                    state.end = self.next_byte_offset;
                    accepted += chunk_bytes;
                }
                Err(error) => {
                    self.unavailable = true;
                    let error = LogError::io(Some(self.stream), LogOperation::WriteLogFile, &error)
                        .with_accepted_input_bytes(accepted);
                    state.disk_error = Some(error.kind());
                    self.reconcile_retained_window(state);
                    return Err(error);
                }
            }
        }

        debug_assert_eq!(state.end, self.next_byte_offset);
        Ok(LogAppendReceipt {
            stream: self.stream,
            first_byte_offset,
            next_byte_offset: self.next_byte_offset,
        })
    }

    /// Drains and normalizes raw pipe bytes using the supplied per-stream text
    /// pipeline. The pipeline owns the stream redactor; only its redacted
    /// output reaches this collector. It must be constructed before process
    /// resume so an invalid encoding or redaction policy fails preparation.
    pub fn capture_with_pipeline<R: Read>(
        &mut self,
        reader: &mut R,
        mut pipeline: LogTextPipeline,
    ) -> Result<LogCaptureSummary, LogError> {
        let first_offset = self.next_byte_offset;
        let mut buffer = [0_u8; PIPE_READ_BUFFER_BYTES];
        let mut output = String::with_capacity(PIPE_READ_BUFFER_BYTES);
        let mut first_error = self.update_text_status(pipeline.status()).err();
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => {
                    output.clear();
                    pipeline.finish(&mut output);
                    self.accept_pipeline_output(&output, pipeline.status(), &mut first_error);
                    if let Err(error) = self.mark_end_of_file() {
                        return Err(first_error.unwrap_or(error));
                    }
                    break;
                }
                Ok(read) => {
                    output.clear();
                    pipeline.push(&buffer[..read], &mut output);
                    wipe_bytes(&mut buffer[..read]);
                    self.accept_pipeline_output(&output, pipeline.status(), &mut first_error);
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    output.clear();
                    pipeline.finish(&mut output);
                    self.accept_pipeline_output(&output, pipeline.status(), &mut first_error);
                    let read_error =
                        LogError::io(Some(self.stream), LogOperation::ReadPipe, &error);
                    if let Err(state_error) = self.mark_read_error(read_error.kind()) {
                        return Err(first_error.unwrap_or(state_error));
                    }
                    return Err(first_error.unwrap_or(read_error));
                }
            }
        }
        if let Some(error) = first_error {
            return Err(error);
        }
        self.flush()?;
        Ok(LogCaptureSummary {
            stream: self.stream,
            captured_bytes: self.next_byte_offset - first_offset,
        })
    }

    fn accept_pipeline_output(
        &mut self,
        output: &str,
        text_status: LogTextStatus,
        first_error: &mut Option<LogError>,
    ) {
        if first_error.is_none() {
            if let Err(error) = self.append_utf8_with_status(output, Some(text_status)) {
                *first_error = Some(error);
            }
        } else {
            let _ = self.update_text_status(text_status);
        }
    }

    fn update_text_status(&self, text_status: LogTextStatus) -> Result<(), LogError> {
        let mut state = self.shared.lock_state()?;
        if state.text_status == Some(text_status) {
            return Ok(());
        }
        state.text_status = Some(text_status);
        drop(state);
        self.notify_dirty();
        Ok(())
    }

    pub fn flush(&mut self) -> Result<(), LogError> {
        if self.unavailable {
            return Err(LogError::for_stream(
                self.stream,
                LogOperation::UseUnavailableStream,
                LogErrorKind::Unavailable,
            ));
        }
        let shared = self.shared.clone();
        let mut state = shared.lock_state()?;
        if let Err(error) = self.rolling_file.flush() {
            self.unavailable = true;
            let error = LogError::io(Some(self.stream), LogOperation::FlushLogFile, &error);
            state.disk_error = Some(error.kind());
            self.reconcile_retained_window(&mut state);
            drop(state);
            self.notify_dirty();
            return Err(error);
        }
        Ok(())
    }

    fn mark_end_of_file(&self) -> Result<(), LogError> {
        let mut state = self.shared.lock_state()?;
        state.end_of_file = true;
        drop(state);
        self.notify_dirty();
        Ok(())
    }

    fn mark_read_error(&self, kind: LogErrorKind) -> Result<(), LogError> {
        let mut state = self.shared.lock_state()?;
        state.read_error = Some(kind);
        drop(state);
        self.notify_dirty();
        Ok(())
    }

    fn notify_dirty(&self) {
        let _ = self.dirty_sender.try_send(());
    }

    fn reconcile_retained_window(&self, state: &mut StreamRuntime) {
        let Ok(files) =
            open_retained_files(&self.shared.directory, self.stream, self.shared.limits, 0)
        else {
            return;
        };
        let Some(retained_bytes) = files
            .iter()
            .try_fold(0_u64, |total, file| total.checked_add(file.len))
        else {
            return;
        };
        if retained_bytes <= state.end {
            state.first_available = state.end - retained_bytes;
        }
    }

    pub fn buffered_snapshot(&self) -> BufferedLogSnapshot {
        let bytes: Vec<u8> = self.memory.bytes.iter().copied().collect();
        BufferedLogSnapshot {
            stream: self.stream,
            first_byte_offset: self.memory.first_byte_offset,
            next_byte_offset: self.next_byte_offset,
            text: String::from_utf8(bytes).expect("the bounded log tail contains valid UTF-8"),
        }
    }
}

impl fmt::Debug for LogStreamCollector {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LogStreamCollector")
            .field("stream", &self.stream)
            .field("retained_memory_bytes", &self.memory.len())
            .field("next_byte_offset", &self.next_byte_offset)
            .field("unavailable", &self.unavailable)
            .finish_non_exhaustive()
    }
}

struct StreamShared {
    directory: Arc<SecureRunDirectory>,
    stream: LogStream,
    limits: LogLimits,
    state: Mutex<StreamRuntime>,
}

impl StreamShared {
    fn new(
        directory: Arc<SecureRunDirectory>,
        stream: LogStream,
        limits: LogLimits,
        retained_bytes: u64,
        io_status_known: bool,
    ) -> Self {
        Self {
            directory,
            stream,
            limits,
            state: Mutex::new(StreamRuntime {
                first_available: 0,
                end: retained_bytes,
                event_sequence: 0,
                end_of_file: false,
                io_status_known,
                disk_error: None,
                read_error: None,
                text_status: None,
            }),
        }
    }

    fn open_existing(
        directory: Arc<SecureRunDirectory>,
        stream: LogStream,
        limits: LogLimits,
    ) -> Result<Arc<Self>, LogError> {
        let mut files = open_retained_files(&directory, stream, limits, 0)?;
        validate_opened_files_utf8(stream, &mut files, LogOperation::ReadLogRange)?;
        let retained_bytes = files.iter().try_fold(0_u64, |total, file| {
            total.checked_add(file.len).ok_or_else(|| {
                LogError::for_stream(
                    stream,
                    LogOperation::AccountBytes,
                    LogErrorKind::LimitExceeded,
                )
            })
        })?;
        if retained_bytes > limits.disk_bytes_per_stream() || retained_bytes > JS_MAX_SAFE_INTEGER {
            return Err(LogError::for_stream(
                stream,
                LogOperation::AccountBytes,
                LogErrorKind::LimitExceeded,
            ));
        }
        Ok(Arc::new(Self::new(
            directory,
            stream,
            limits,
            retained_bytes,
            false,
        )))
    }

    fn lock_state(&self) -> Result<MutexGuard<'_, StreamRuntime>, LogError> {
        self.state.lock().map_err(|_| {
            LogError::for_stream(
                self.stream,
                LogOperation::CoordinateLogIo,
                LogErrorKind::Unavailable,
            )
        })
    }

    fn next_event_sequence(&self) -> Result<u64, LogError> {
        let mut state = self.lock_state()?;
        let sequence = state
            .event_sequence
            .checked_add(1)
            .filter(|sequence| *sequence <= JS_MAX_SAFE_INTEGER)
            .ok_or_else(|| {
                LogError::for_stream(
                    self.stream,
                    LogOperation::SequenceLogEvent,
                    LogErrorKind::LimitExceeded,
                )
            })?;
        state.event_sequence = sequence;
        Ok(sequence)
    }

    fn event_state(&self) -> Result<EventState, LogError> {
        let state = self.lock_state()?;
        Ok(EventState {
            first_available: state.first_available,
            end: state.end,
            status: StreamStatus {
                end_of_file: state.end_of_file,
                io_status_known: state.io_status_known,
                disk_error: state.disk_error,
                read_error: state.read_error,
                text_status: state.text_status,
            },
        })
    }

    fn read_snapshot(
        &self,
        offset: Option<u64>,
        max_bytes: usize,
    ) -> Result<RangeSnapshot, LogError> {
        if offset.is_some_and(|offset| offset > JS_MAX_SAFE_INTEGER)
            || max_bytes < MIN_UTF8_BOUNDARY_BYTES
            || max_bytes > MAX_LOG_RANGE_BYTES
        {
            return Err(LogError::for_stream(
                self.stream,
                LogOperation::ReadLogRange,
                LogErrorKind::LimitExceeded,
            ));
        }

        let state = self.lock_state()?;
        let requested_offset = offset.unwrap_or(state.first_available);
        let files = open_retained_files(
            &self.directory,
            self.stream,
            self.limits,
            state.first_available,
        )?;
        let retained_bytes = files.iter().try_fold(0_u64, |total, file| {
            total.checked_add(file.len).ok_or_else(|| {
                LogError::for_stream(
                    self.stream,
                    LogOperation::AccountBytes,
                    LogErrorKind::LimitExceeded,
                )
            })
        })?;
        let expected_retained_bytes =
            state
                .end
                .checked_sub(state.first_available)
                .ok_or_else(|| {
                    LogError::for_stream(
                        self.stream,
                        LogOperation::ReadLogRange,
                        LogErrorKind::InvalidData,
                    )
                })?;
        if retained_bytes != expected_retained_bytes {
            return Err(LogError::for_stream(
                self.stream,
                LogOperation::ReadLogRange,
                LogErrorKind::InvalidData,
            ));
        }

        let first_available = state.first_available;
        let end = state.end;
        let observed_sequence = state.event_sequence;
        let status = StreamStatus {
            end_of_file: state.end_of_file,
            io_status_known: state.io_status_known,
            disk_error: state.disk_error,
            read_error: state.read_error,
            text_status: state.text_status,
        };
        drop(state);

        let first = requested_offset.max(first_available).min(end);
        let mut bytes = Vec::with_capacity(max_bytes.min((end - first) as usize));
        for mut opened in files {
            if bytes.len() == max_bytes || first + bytes.len() as u64 >= end {
                break;
            }
            let requested = first + bytes.len() as u64;
            let file_end = opened.start.checked_add(opened.len).ok_or_else(|| {
                LogError::for_stream(
                    self.stream,
                    LogOperation::ReadLogRange,
                    LogErrorKind::LimitExceeded,
                )
            })?;
            if requested >= file_end {
                continue;
            }
            let within_file = requested.saturating_sub(opened.start);
            if within_file >= opened.len {
                continue;
            }
            opened
                .file
                .seek(SeekFrom::Start(within_file))
                .map_err(|error| {
                    LogError::io(Some(self.stream), LogOperation::ReadLogRange, &error)
                })?;
            let available_in_file = opened.len - within_file;
            let remaining_capacity = max_bytes - bytes.len();
            let to_read = usize::try_from(available_in_file)
                .unwrap_or(usize::MAX)
                .min(remaining_capacity);
            read_exact_bounded(self.stream, &mut opened.file, &mut bytes, to_read)?;
        }

        truncate_incomplete_utf8(self.stream, &mut bytes)?;

        let next = first + bytes.len() as u64;
        let has_more = next < end;
        let complete = requested_offset >= first_available && requested_offset <= end && !has_more;
        let text = String::from_utf8(bytes).map_err(|_| {
            LogError::for_stream(
                self.stream,
                LogOperation::ReadLogRange,
                LogErrorKind::InvalidData,
            )
        })?;
        Ok(RangeSnapshot {
            range: LogRangeRead {
                stream: self.stream,
                observed_sequence,
                first_available,
                first,
                next,
                end,
                has_more,
                complete,
                text,
                end_of_file: status.end_of_file,
                io_status_known: status.io_status_known,
                disk_error: status.disk_error,
                read_error: status.read_error,
                text_status: status.text_status,
            },
            status,
        })
    }
}

struct StreamRuntime {
    first_available: u64,
    end: u64,
    event_sequence: u64,
    end_of_file: bool,
    io_status_known: bool,
    disk_error: Option<LogErrorKind>,
    read_error: Option<LogErrorKind>,
    text_status: Option<LogTextStatus>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct StreamStatus {
    end_of_file: bool,
    io_status_known: bool,
    disk_error: Option<LogErrorKind>,
    read_error: Option<LogErrorKind>,
    text_status: Option<LogTextStatus>,
}

struct RangeSnapshot {
    range: LogRangeRead,
    status: StreamStatus,
}

struct EventState {
    first_available: u64,
    end: u64,
    status: StreamStatus,
}

struct OpenedLogFile {
    file: File,
    start: u64,
    len: u64,
}

fn open_retained_files(
    directory: &SecureRunDirectory,
    stream: LogStream,
    limits: LogLimits,
    first_available: u64,
) -> Result<Vec<OpenedLogFile>, LogError> {
    let mut files = Vec::with_capacity(usize::from(limits.files_per_stream));
    let mut next_start = first_available;
    for index in (1..limits.files_per_stream).rev() {
        open_retained_file(
            directory,
            stream,
            limits,
            &stream.archive_file_name(index),
            &mut next_start,
            &mut files,
        )?;
    }
    open_retained_file(
        directory,
        stream,
        limits,
        stream.active_file_name(),
        &mut next_start,
        &mut files,
    )?;
    Ok(files)
}

fn open_retained_file(
    directory: &SecureRunDirectory,
    stream: LogStream,
    limits: LogLimits,
    file_name: &str,
    next_start: &mut u64,
    files: &mut Vec<OpenedLogFile>,
) -> Result<(), LogError> {
    let Some(file) =
        directory.open_existing_file(file_name, Some(stream), LogOperation::ReadLogRange)?
    else {
        return Ok(());
    };
    let len = file
        .metadata()
        .map_err(|error| LogError::io(Some(stream), LogOperation::ReadLogRange, &error))?
        .len();
    if len > limits.file_bytes {
        return Err(LogError::for_stream(
            stream,
            LogOperation::ReadLogRange,
            LogErrorKind::LimitExceeded,
        ));
    }
    let start = *next_start;
    *next_start = next_start.checked_add(len).ok_or_else(|| {
        LogError::for_stream(
            stream,
            LogOperation::ReadLogRange,
            LogErrorKind::LimitExceeded,
        )
    })?;
    files.push(OpenedLogFile { file, start, len });
    Ok(())
}

fn read_exact_bounded(
    stream: LogStream,
    file: &mut File,
    destination: &mut Vec<u8>,
    count: usize,
) -> Result<(), LogError> {
    let first = destination.len();
    destination.resize(first + count, 0);
    let mut read = 0;
    while read < count {
        match file.read(&mut destination[first + read..first + count]) {
            Ok(0) => {
                destination.truncate(first + read);
                return Err(LogError::for_stream(
                    stream,
                    LogOperation::ReadLogRange,
                    LogErrorKind::UnexpectedEof,
                ));
            }
            Ok(bytes) => read += bytes,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => {
                destination.truncate(first + read);
                return Err(LogError::io(
                    Some(stream),
                    LogOperation::ReadLogRange,
                    &error,
                ));
            }
        }
    }
    Ok(())
}

fn validate_opened_files_utf8(
    stream: LogStream,
    files: &mut [OpenedLogFile],
    operation: LogOperation,
) -> Result<(), LogError> {
    for opened in files {
        validate_utf8_file(stream, &mut opened.file, opened.len, operation)?;
    }
    Ok(())
}

fn validate_utf8_file(
    stream: LogStream,
    file: &mut File,
    len: u64,
    operation: LogOperation,
) -> Result<(), LogError> {
    file.seek(SeekFrom::Start(0))
        .map_err(|error| LogError::io(Some(stream), operation, &error))?;
    let mut buffer = vec![0_u8; PIPE_READ_BUFFER_BYTES + MIN_UTF8_BOUNDARY_BYTES - 1];
    let mut pending = 0_usize;
    let mut remaining = len;
    while remaining > 0 {
        let read = usize::try_from(remaining)
            .unwrap_or(usize::MAX)
            .min(PIPE_READ_BUFFER_BYTES);
        file.read_exact(&mut buffer[pending..pending + read])
            .map_err(|error| LogError::io(Some(stream), operation, &error))?;
        remaining -= read as u64;
        let available = pending + read;
        match std::str::from_utf8(&buffer[..available]) {
            Ok(text) => {
                validate_safe_log_text(stream, text, operation)?;
                pending = 0;
            }
            Err(error) if error.error_len().is_none() => {
                let valid = error.valid_up_to();
                let text = std::str::from_utf8(&buffer[..valid])
                    .expect("from_utf8 reported this prefix as valid");
                validate_safe_log_text(stream, text, operation)?;
                pending = available - valid;
                if pending >= MIN_UTF8_BOUNDARY_BYTES {
                    return Err(invalid_utf8_error(stream, operation));
                }
                buffer.copy_within(valid..available, 0);
            }
            Err(_) => return Err(invalid_utf8_error(stream, operation)),
        }
    }
    if pending != 0 {
        return Err(invalid_utf8_error(stream, operation));
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|error| LogError::io(Some(stream), operation, &error))?;
    Ok(())
}

fn invalid_utf8_error(stream: LogStream, operation: LogOperation) -> LogError {
    LogError::for_stream(stream, operation, LogErrorKind::InvalidData)
}

fn validate_safe_log_text(
    stream: LogStream,
    text: &str,
    operation: LogOperation,
) -> Result<(), LogError> {
    if text.chars().all(is_printable_log_character) {
        Ok(())
    } else {
        Err(LogError::for_stream(
            stream,
            operation,
            LogErrorKind::InvalidData,
        ))
    }
}

fn utf8_prefix_len(text: &str, maximum: usize) -> usize {
    let mut end = text.len().min(maximum);
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    end
}

fn truncate_incomplete_utf8(stream: LogStream, bytes: &mut Vec<u8>) -> Result<(), LogError> {
    match std::str::from_utf8(bytes) {
        Ok(_) => Ok(()),
        Err(error) if error.error_len().is_none() => {
            bytes.truncate(error.valid_up_to());
            Ok(())
        }
        Err(_) => Err(invalid_utf8_error(stream, LogOperation::ReadLogRange)),
    }
}

struct RollingFile {
    directory: Arc<SecureRunDirectory>,
    stream: LogStream,
    limits: LogLimits,
    file: Option<File>,
    file_bytes: u64,
    initial_retained_bytes: u64,
}

impl RollingFile {
    fn open(
        directory: Arc<SecureRunDirectory>,
        stream: LogStream,
        limits: LogLimits,
    ) -> Result<Self, LogError> {
        for index in limits.files_per_stream..MAX_LOG_FILES_PER_STREAM {
            directory.remove_file_if_exists(
                &stream.archive_file_name(index),
                Some(stream),
                LogOperation::RemoveExpiredLogFile,
            )?;
        }
        let mut retained_files = open_retained_files(&directory, stream, limits, 0)?;
        validate_opened_files_utf8(stream, &mut retained_files, LogOperation::InspectLogFile)?;
        let mut initial_retained_bytes = 0_u64;
        for index in (1..limits.files_per_stream).rev() {
            if let Some(length) = directory.inspect_file(
                &stream.archive_file_name(index),
                Some(stream),
                LogOperation::InspectLogFile,
            )? {
                if length > limits.file_bytes {
                    return Err(LogError::for_stream(
                        stream,
                        LogOperation::InspectLogFile,
                        LogErrorKind::LimitExceeded,
                    ));
                }
                initial_retained_bytes =
                    initial_retained_bytes.checked_add(length).ok_or_else(|| {
                        LogError::for_stream(
                            stream,
                            LogOperation::AccountBytes,
                            LogErrorKind::LimitExceeded,
                        )
                    })?;
            }
        }

        let file = directory.open_file(
            stream.active_file_name(),
            false,
            Some(stream),
            LogOperation::OpenLogFile,
        )?;
        let file_bytes = file
            .metadata()
            .map_err(|error| LogError::io(Some(stream), LogOperation::InspectLogFile, &error))?
            .len();
        if file_bytes > limits.file_bytes {
            return Err(LogError::for_stream(
                stream,
                LogOperation::InspectLogFile,
                LogErrorKind::LimitExceeded,
            ));
        }
        initial_retained_bytes = initial_retained_bytes
            .checked_add(file_bytes)
            .filter(|total| {
                *total <= limits.disk_bytes_per_stream() && *total <= JS_MAX_SAFE_INTEGER
            })
            .ok_or_else(|| {
                LogError::for_stream(
                    stream,
                    LogOperation::AccountBytes,
                    LogErrorKind::LimitExceeded,
                )
            })?;
        Ok(Self {
            directory,
            stream,
            limits,
            file: Some(file),
            file_bytes,
            initial_retained_bytes,
        })
    }

    fn initial_retained_bytes(&self) -> u64 {
        self.initial_retained_bytes
    }

    fn available_bytes(&self) -> u64 {
        self.limits.file_bytes - self.file_bytes
    }

    fn write_utf8_chunk(&mut self, bytes: &[u8]) -> io::Result<()> {
        debug_assert!(std::str::from_utf8(bytes).is_ok());
        debug_assert!(bytes.len() as u64 <= self.available_bytes());
        let initial_file_bytes = self.file_bytes;
        let mut written = 0;
        while written < bytes.len() {
            let result = self
                .file
                .as_mut()
                .expect("active log file")
                .write(&bytes[written..]);
            match result {
                Ok(0) => {
                    let error = io::Error::new(io::ErrorKind::WriteZero, "log write returned zero");
                    return Err(self.rollback_partial_write(initial_file_bytes, written, error));
                }
                Ok(count) => written += count,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => {
                    return Err(self.rollback_partial_write(initial_file_bytes, written, error));
                }
            }
        }
        self.file_bytes = initial_file_bytes + bytes.len() as u64;
        Ok(())
    }

    fn rollback_partial_write(
        &mut self,
        initial_file_bytes: u64,
        written: usize,
        write_error: io::Error,
    ) -> io::Error {
        if written == 0 {
            return write_error;
        }
        let file = self.file.as_mut().expect("active log file");
        if let Err(error) = file.set_len(initial_file_bytes) {
            self.file_bytes = initial_file_bytes.saturating_add(written as u64);
            return error;
        }
        self.file_bytes = initial_file_bytes;
        if let Err(error) = file.seek(SeekFrom::End(0)) {
            return error;
        }
        write_error
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.as_mut().expect("active log file").flush()
    }

    fn rotate(&mut self) -> Result<u64, LogError> {
        debug_assert!(self.file_bytes > 0);
        self.flush()
            .map_err(|error| LogError::io(Some(self.stream), LogOperation::FlushLogFile, &error))?;

        if self.limits.files_per_stream == 1 {
            let removed_bytes = self.file_bytes;
            drop(self.file.take());
            self.directory.remove_file_if_exists(
                self.stream.active_file_name(),
                Some(self.stream),
                LogOperation::RotateLogFile,
            )?;
            self.directory
                .sync(Some(self.stream), LogOperation::RotateLogFile)?;
            self.file = Some(self.directory.open_file(
                self.stream.active_file_name(),
                true,
                Some(self.stream),
                LogOperation::RotateLogFile,
            )?);
            self.file_bytes = 0;
            return Ok(removed_bytes);
        }

        drop(self.file.take());
        let oldest = self
            .stream
            .archive_file_name(self.limits.files_per_stream - 1);
        let removed_bytes = self
            .directory
            .inspect_file(&oldest, Some(self.stream), LogOperation::RotateLogFile)?
            .unwrap_or(0);
        self.directory.remove_file_if_exists(
            &oldest,
            Some(self.stream),
            LogOperation::RotateLogFile,
        )?;

        for index in (1..self.limits.files_per_stream - 1).rev() {
            self.directory.replace_file_if_exists(
                &self.stream.archive_file_name(index),
                &self.stream.archive_file_name(index + 1),
                Some(self.stream),
                LogOperation::RotateLogFile,
            )?;
        }
        self.directory.replace_file_if_exists(
            self.stream.active_file_name(),
            &self.stream.archive_file_name(1),
            Some(self.stream),
            LogOperation::RotateLogFile,
        )?;
        self.directory
            .sync(Some(self.stream), LogOperation::RotateLogFile)?;
        self.file = Some(self.directory.open_file(
            self.stream.active_file_name(),
            true,
            Some(self.stream),
            LogOperation::RotateLogFile,
        )?);
        self.file_bytes = 0;
        Ok(removed_bytes)
    }
}

struct BoundedByteTail {
    capacity: usize,
    bytes: VecDeque<u8>,
    first_byte_offset: u64,
}

impl BoundedByteTail {
    fn new(capacity: usize, first_byte_offset: u64) -> Self {
        Self {
            capacity,
            bytes: VecDeque::with_capacity(capacity),
            first_byte_offset,
        }
    }

    fn len(&self) -> usize {
        self.bytes.len()
    }

    fn append_utf8(&mut self, text: &str, first_input_offset: u64) {
        let bytes = text.as_bytes();
        if bytes.len() >= self.capacity {
            self.bytes.clear();
            let mut retained_start = bytes.len() - self.capacity;
            while retained_start < bytes.len() && is_utf8_continuation(bytes[retained_start]) {
                retained_start += 1;
            }
            let retained = &bytes[retained_start..];
            self.bytes.extend(retained.iter().copied());
            self.first_byte_offset = first_input_offset + retained_start as u64;
            return;
        }

        let evicted = self
            .bytes
            .len()
            .saturating_add(bytes.len())
            .saturating_sub(self.capacity);
        if evicted > 0 {
            self.bytes.drain(..evicted);
            self.first_byte_offset += evicted as u64;
            while self
                .bytes
                .front()
                .is_some_and(|byte| is_utf8_continuation(*byte))
            {
                self.bytes.pop_front();
                self.first_byte_offset += 1;
            }
        } else if self.bytes.is_empty() {
            self.first_byte_offset = first_input_offset;
        }
        self.bytes.extend(bytes.iter().copied());
        debug_assert!(self.bytes.len() <= self.capacity);
        debug_assert!(std::str::from_utf8(self.bytes.make_contiguous()).is_ok());
    }
}

fn is_utf8_continuation(byte: u8) -> bool {
    byte & 0b1100_0000 == 0b1000_0000
}

#[cfg(test)]
mod tests {
    use super::{
        BoundedByteTail, LogErrorKind, LogOperation, LogStream, truncate_incomplete_utf8,
        utf8_prefix_len, validate_safe_log_text,
    };

    #[test]
    fn utf8_prefix_never_splits_a_four_byte_scalar() {
        let text = "A\u{1f642}B";

        assert_eq!(utf8_prefix_len(text, 1), 1);
        assert_eq!(utf8_prefix_len(text, 4), 1);
        assert_eq!(utf8_prefix_len(text, 5), 5);
        assert_eq!(utf8_prefix_len(text, 6), 6);
    }

    #[test]
    fn bounded_tail_evicts_only_at_scalar_boundaries() {
        for capacity in 1..=4 {
            let mut tail = BoundedByteTail::new(capacity, 0);
            tail.append_utf8("A\u{1f642}B", 0);
            assert_eq!(tail.bytes.make_contiguous(), b"B");
            assert_eq!(tail.first_byte_offset, 5);
        }

        let mut tail = BoundedByteTail::new(4, 0);
        tail.append_utf8("\u{1f642}", 0);
        assert_eq!(tail.bytes.make_contiguous(), "\u{1f642}".as_bytes());
        tail.append_utf8("B", 4);
        assert_eq!(tail.bytes.make_contiguous(), b"B");
        assert_eq!(tail.first_byte_offset, 4);
    }

    #[test]
    fn range_boundary_truncation_rejects_a_continuation_start() {
        let mut incomplete_end = b"A\xf0\x9f".to_vec();
        truncate_incomplete_utf8(LogStream::Stdout, &mut incomplete_end).unwrap();
        assert_eq!(incomplete_end, b"A");

        let mut continuation_start = b"\x9f".to_vec();
        let error = truncate_incomplete_utf8(LogStream::Stdout, &mut continuation_start)
            .expect_err("a retained continuation-byte offset must be rejected");
        assert_eq!(error.kind(), LogErrorKind::InvalidData);
    }

    #[test]
    fn storage_boundary_rejects_unfiltered_text() {
        for text in ["carriage\rreturn", "\u{001b}[31m", "\u{202e}", "\u{2028}"] {
            let error = validate_safe_log_text(LogStream::Stderr, text, LogOperation::WriteLogFile)
                .expect_err("unfiltered text must not enter rolling storage");
            assert_eq!(error.kind(), LogErrorKind::InvalidData);
        }
    }
}
