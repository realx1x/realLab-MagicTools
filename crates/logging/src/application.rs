use std::collections::{BTreeMap, VecDeque};
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::{JS_MAX_SAFE_INTEGER, LogRedactionRules};

/// Schema version written into every application-log JSON line.
pub const APPLICATION_LOG_SCHEMA_VERSION: u8 = 1;
/// Stable manifest identifier for the structured application-log excerpt.
pub const APPLICATION_LOG_DIAGNOSTIC_CONTENT_ID: &str = "application.logs";

/// Default retained application-log record count.
pub const DEFAULT_APPLICATION_LOG_RECORDS: usize = 4_096;
/// Default retained application-log JSONL bytes: 4 MiB.
pub const DEFAULT_APPLICATION_LOG_RETAINED_BYTES: usize = 4 * 1_024 * 1_024;
/// Hard retained application-log record count.
pub const MAX_APPLICATION_LOG_RECORDS: usize = 65_536;
/// Hard retained application-log JSONL bytes: 32 MiB.
pub const MAX_APPLICATION_LOG_RETAINED_BYTES: usize = 32 * 1_024 * 1_024;
/// Hard size of one serialized application-log JSON line, including LF.
pub const MAX_APPLICATION_LOG_RECORD_BYTES: usize = 16 * 1_024;
/// Hard size of one application-log range read: 64 KiB.
pub const MAX_APPLICATION_LOG_READ_BYTES: usize = 64 * 1_024;
/// Hard number of structured fields in one application-log record.
pub const MAX_APPLICATION_LOG_FIELDS: usize = 24;

/// Default number of entries in a diagnostic content checklist.
pub const DEFAULT_DIAGNOSTIC_CONTENT_ITEMS: usize = 16;
/// Hard number of entries in a diagnostic content checklist.
pub const MAX_DIAGNOSTIC_CONTENT_ITEMS: usize = 64;
/// Hard declared size of one diagnostic content item: 64 MiB.
pub const MAX_DIAGNOSTIC_CONTENT_BYTES: u64 = 64 * 1_024 * 1_024;
/// Default exact output budget for one diagnostic export: 64 MiB.
pub const DEFAULT_DIAGNOSTIC_BYTE_BUDGET: u64 = 64 * 1_024 * 1_024;
/// Hard exact output budget for one diagnostic export: 128 MiB.
pub const MAX_DIAGNOSTIC_BYTE_BUDGET: u64 = 128 * 1_024 * 1_024;

const MAX_APPLICATION_LOG_IDENTIFIER_BYTES: usize = 96;
const MAX_DIAGNOSTIC_CONTENT_ID_BYTES: usize = 96;
const MAX_APPLICATION_LOG_SEQUENCE: u64 = JS_MAX_SAFE_INTEGER - 1;

/// Resource bounds for one application-log ring.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApplicationLogLimits {
    records: usize,
    retained_bytes: usize,
}

impl ApplicationLogLimits {
    pub fn new(records: usize, retained_bytes: usize) -> Result<Self, ApplicationLogError> {
        if records == 0
            || records > MAX_APPLICATION_LOG_RECORDS
            || !(MAX_APPLICATION_LOG_RECORD_BYTES..=MAX_APPLICATION_LOG_RETAINED_BYTES)
                .contains(&retained_bytes)
        {
            return Err(ApplicationLogError::new(
                ApplicationLogOperation::ValidateLimits,
                ApplicationLogErrorKind::InvalidConfiguration,
            ));
        }
        Ok(Self {
            records,
            retained_bytes,
        })
    }

    pub fn records(self) -> usize {
        self.records
    }

    pub fn retained_bytes(self) -> usize {
        self.retained_bytes
    }
}

impl Default for ApplicationLogLimits {
    fn default() -> Self {
        Self {
            records: DEFAULT_APPLICATION_LOG_RECORDS,
            retained_bytes: DEFAULT_APPLICATION_LOG_RETAINED_BYTES,
        }
    }
}

/// Closed severity values for structured application events.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ApplicationLogLevel {
    Debug,
    Info,
    Warn,
    Error,
}

/// Closed application-log fields. The list intentionally excludes paths,
/// commands, arguments, environment values, user identifiers, and arbitrary
/// details.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ApplicationLogFieldName {
    Attempt,
    ByteCount,
    Count,
    DurationMillis,
    ErrorCode,
    ExitCode,
    Generation,
    Operation,
    Outcome,
    Phase,
    Platform,
    ProtocolVersion,
    RetryCount,
    Revision,
    Status,
    Success,
    Transport,
    Truncated,
}

impl ApplicationLogFieldName {
    fn as_str(self) -> &'static str {
        match self {
            Self::Attempt => "attempt",
            Self::ByteCount => "byteCount",
            Self::Count => "count",
            Self::DurationMillis => "durationMillis",
            Self::ErrorCode => "errorCode",
            Self::ExitCode => "exitCode",
            Self::Generation => "generation",
            Self::Operation => "operation",
            Self::Outcome => "outcome",
            Self::Phase => "phase",
            Self::Platform => "platform",
            Self::ProtocolVersion => "protocolVersion",
            Self::RetryCount => "retryCount",
            Self::Revision => "revision",
            Self::Status => "status",
            Self::Success => "success",
            Self::Transport => "transport",
            Self::Truncated => "truncated",
        }
    }

    fn accepts(self, value: ApplicationLogValue) -> bool {
        match self {
            Self::Attempt
            | Self::ByteCount
            | Self::Count
            | Self::DurationMillis
            | Self::Generation
            | Self::ProtocolVersion
            | Self::RetryCount
            | Self::Revision => matches!(value, ApplicationLogValue::Unsigned(_)),
            Self::ExitCode => matches!(value, ApplicationLogValue::Signed(_)),
            Self::ErrorCode
            | Self::Operation
            | Self::Outcome
            | Self::Phase
            | Self::Platform
            | Self::Status
            | Self::Transport => matches!(value, ApplicationLogValue::Code(_)),
            Self::Success | Self::Truncated => matches!(value, ApplicationLogValue::Boolean(_)),
        }
    }
}

/// One structured value. `Code` accepts only trusted static identifiers, not
/// runtime text; it is validated and redacted again before serialization.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum ApplicationLogValue {
    Boolean(bool),
    Signed(i64),
    Unsigned(u64),
    Code(&'static str),
}

impl fmt::Debug for ApplicationLogValue {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Boolean(value) => formatter.debug_tuple("Boolean").field(value).finish(),
            Self::Signed(value) => formatter.debug_tuple("Signed").field(value).finish(),
            Self::Unsigned(value) => formatter.debug_tuple("Unsigned").field(value).finish(),
            Self::Code(value) => formatter
                .debug_struct("Code")
                .field("byte_count", &value.len())
                .finish(),
        }
    }
}

/// One field for an application event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApplicationLogField {
    name: ApplicationLogFieldName,
    value: ApplicationLogValue,
}

impl ApplicationLogField {
    pub const fn new(name: ApplicationLogFieldName, value: ApplicationLogValue) -> Self {
        Self { name, value }
    }

    pub const fn name(self) -> ApplicationLogFieldName {
        self.name
    }
}

/// One structured application event before filtering, redaction, and JSONL
/// serialization. `component`, `event_code`, and code values are stable ASCII
/// identifiers. Free-form messages, paths, commands, environment values, and
/// RPC parameters cannot be represented by this type.
pub struct ApplicationLogEvent<'a> {
    pub timestamp_unix_millis: u64,
    pub level: ApplicationLogLevel,
    pub component: &'static str,
    pub event_code: &'static str,
    pub fields: &'a [ApplicationLogField],
}

/// Content-free operation identifiers for application-log failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplicationLogOperation {
    ValidateLimits,
    ValidateEvent,
    SanitizeEvent,
    SerializeEvent,
    SequenceEvent,
    ReadRange,
    BuildDiagnosticManifest,
    ConsumeDiagnosticBudget,
}

/// Sanitized application-log and diagnostic-budget failure categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplicationLogErrorKind {
    InvalidConfiguration,
    InvalidTimestamp,
    InvalidIdentifier,
    InvalidFieldValue,
    NumericValueNotJsonSafe,
    TooManyFields,
    DuplicateField,
    RecordTooLarge,
    ReadLimitInvalid,
    CursorAhead,
    SequenceExhausted,
    SerializationFailed,
    TooManyContentItems,
    DuplicateContentItem,
    InvalidContentSize,
    ArithmeticOverflow,
    BudgetExceeded,
    ClockBeforeUnixEpoch,
}

/// A structured error which never retains event text, field names, paths, or
/// secret values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApplicationLogError {
    operation: ApplicationLogOperation,
    kind: ApplicationLogErrorKind,
}

impl ApplicationLogError {
    fn new(operation: ApplicationLogOperation, kind: ApplicationLogErrorKind) -> Self {
        Self { operation, kind }
    }

    pub fn operation(self) -> ApplicationLogOperation {
        self.operation
    }

    pub fn kind(self) -> ApplicationLogErrorKind {
        self.kind
    }
}

impl Display for ApplicationLogError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "application log operation {:?} failed ({:?})",
            self.operation, self.kind
        )
    }
}

impl Error for ApplicationLogError {}

/// Sequence and retention state after one successful append.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApplicationLogAppendReceipt {
    pub sequence: u64,
    pub retained_records: usize,
    pub retained_bytes: usize,
    pub dropped_records: u64,
}

/// One bounded JSONL range. `next_sequence` is the cursor for the next call;
/// `end_sequence` is the ring's next sequence at the read snapshot.
#[derive(Clone, Eq, PartialEq)]
pub struct ApplicationLogRead {
    pub requested_sequence: u64,
    pub first_available_sequence: Option<u64>,
    pub first_sequence: Option<u64>,
    pub next_sequence: u64,
    pub end_sequence: u64,
    pub has_more: bool,
    pub complete: bool,
    pub dropped_records: u64,
    pub json_lines: String,
}

impl fmt::Debug for ApplicationLogRead {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApplicationLogRead")
            .field("requested_sequence", &self.requested_sequence)
            .field("first_available_sequence", &self.first_available_sequence)
            .field("first_sequence", &self.first_sequence)
            .field("next_sequence", &self.next_sequence)
            .field("end_sequence", &self.end_sequence)
            .field("has_more", &self.has_more)
            .field("complete", &self.complete)
            .field("dropped_records", &self.dropped_records)
            .field("byte_count", &self.json_lines.len())
            .finish()
    }
}

/// Single-owner bounded structured application-log ring.
pub struct ApplicationLogBuffer {
    limits: ApplicationLogLimits,
    redaction_rules: LogRedactionRules,
    records: VecDeque<StoredApplicationLogLine>,
    retained_bytes: usize,
    next_sequence: u64,
    dropped_records: u64,
}

impl ApplicationLogBuffer {
    pub fn new(limits: ApplicationLogLimits, redaction_rules: LogRedactionRules) -> Self {
        Self {
            limits,
            redaction_rules,
            records: VecDeque::new(),
            retained_bytes: 0,
            next_sequence: 1,
            dropped_records: 0,
        }
    }

    pub fn append(
        &mut self,
        event: ApplicationLogEvent<'_>,
    ) -> Result<ApplicationLogAppendReceipt, ApplicationLogError> {
        if event.timestamp_unix_millis > JS_MAX_SAFE_INTEGER {
            return Err(ApplicationLogError::new(
                ApplicationLogOperation::ValidateEvent,
                ApplicationLogErrorKind::InvalidTimestamp,
            ));
        }
        if self.next_sequence > MAX_APPLICATION_LOG_SEQUENCE {
            return Err(ApplicationLogError::new(
                ApplicationLogOperation::SequenceEvent,
                ApplicationLogErrorKind::SequenceExhausted,
            ));
        }
        validate_identifier(event.component, MAX_APPLICATION_LOG_IDENTIFIER_BYTES)?;
        validate_identifier(event.event_code, MAX_APPLICATION_LOG_IDENTIFIER_BYTES)?;
        if event.fields.len() > MAX_APPLICATION_LOG_FIELDS {
            return Err(ApplicationLogError::new(
                ApplicationLogOperation::ValidateEvent,
                ApplicationLogErrorKind::TooManyFields,
            ));
        }

        let sequence = self.next_sequence;
        let component = redact_code(event.component, &self.redaction_rules);
        let event_code = redact_code(event.event_code, &self.redaction_rules);
        let mut fields = BTreeMap::new();
        let mut redactions_applied = component.redactions_applied || event_code.redactions_applied;
        for field in event.fields {
            if !field.name.accepts(field.value) {
                return Err(ApplicationLogError::new(
                    ApplicationLogOperation::ValidateEvent,
                    ApplicationLogErrorKind::InvalidFieldValue,
                ));
            }

            let value = match field.value {
                ApplicationLogValue::Boolean(value) => StoredApplicationLogValue::Boolean(value),
                ApplicationLogValue::Signed(value) => {
                    if !(-(JS_MAX_SAFE_INTEGER as i64)..=JS_MAX_SAFE_INTEGER as i64)
                        .contains(&value)
                    {
                        return Err(ApplicationLogError::new(
                            ApplicationLogOperation::ValidateEvent,
                            ApplicationLogErrorKind::NumericValueNotJsonSafe,
                        ));
                    }
                    StoredApplicationLogValue::Signed(value)
                }
                ApplicationLogValue::Unsigned(value) => {
                    if value > JS_MAX_SAFE_INTEGER {
                        return Err(ApplicationLogError::new(
                            ApplicationLogOperation::ValidateEvent,
                            ApplicationLogErrorKind::NumericValueNotJsonSafe,
                        ));
                    }
                    StoredApplicationLogValue::Unsigned(value)
                }
                ApplicationLogValue::Code(value) => {
                    validate_identifier(value, MAX_APPLICATION_LOG_IDENTIFIER_BYTES)?;
                    let code = redact_code(value, &self.redaction_rules);
                    redactions_applied |= code.redactions_applied;
                    StoredApplicationLogValue::Code(code.value)
                }
            };
            if fields.insert(field.name.as_str(), value).is_some() {
                return Err(ApplicationLogError::new(
                    ApplicationLogOperation::ValidateEvent,
                    ApplicationLogErrorKind::DuplicateField,
                ));
            }
        }

        let record = StoredApplicationLogRecord {
            schema_version: APPLICATION_LOG_SCHEMA_VERSION,
            sequence,
            timestamp_unix_millis: event.timestamp_unix_millis,
            level: event.level,
            component: component.value,
            event_code: event_code.value,
            fields,
            redactions_applied,
        };
        let mut json_line = serde_json::to_vec(&record).map_err(|_| {
            ApplicationLogError::new(
                ApplicationLogOperation::SerializeEvent,
                ApplicationLogErrorKind::SerializationFailed,
            )
        })?;
        json_line.push(b'\n');
        if json_line.len() > MAX_APPLICATION_LOG_RECORD_BYTES {
            return Err(ApplicationLogError::new(
                ApplicationLogOperation::SerializeEvent,
                ApplicationLogErrorKind::RecordTooLarge,
            ));
        }

        while self.records.len() >= self.limits.records
            || self
                .retained_bytes
                .checked_add(json_line.len())
                .is_none_or(|bytes| bytes > self.limits.retained_bytes)
        {
            self.drop_oldest()?;
        }

        self.retained_bytes = self
            .retained_bytes
            .checked_add(json_line.len())
            .ok_or_else(|| {
                ApplicationLogError::new(
                    ApplicationLogOperation::SequenceEvent,
                    ApplicationLogErrorKind::ArithmeticOverflow,
                )
            })?;
        self.records.push_back(StoredApplicationLogLine {
            sequence,
            json_line,
        });
        self.next_sequence += 1;
        Ok(ApplicationLogAppendReceipt {
            sequence,
            retained_records: self.records.len(),
            retained_bytes: self.retained_bytes,
            dropped_records: self.dropped_records,
        })
    }

    pub fn append_now(
        &mut self,
        level: ApplicationLogLevel,
        component: &'static str,
        event_code: &'static str,
        fields: &[ApplicationLogField],
    ) -> Result<ApplicationLogAppendReceipt, ApplicationLogError> {
        let timestamp_unix_millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| {
                ApplicationLogError::new(
                    ApplicationLogOperation::ValidateEvent,
                    ApplicationLogErrorKind::ClockBeforeUnixEpoch,
                )
            })?
            .as_millis()
            .try_into()
            .map_err(|_| {
                ApplicationLogError::new(
                    ApplicationLogOperation::ValidateEvent,
                    ApplicationLogErrorKind::InvalidTimestamp,
                )
            })?;
        self.append(ApplicationLogEvent {
            timestamp_unix_millis,
            level,
            component,
            event_code,
            fields,
        })
    }

    /// Reads complete JSON lines starting at `sequence`. An omitted sequence
    /// starts at the first retained line. `max_bytes` must be at least one
    /// maximum record so a valid cursor always makes progress.
    pub fn read_json_lines(
        &self,
        sequence: Option<u64>,
        max_bytes: usize,
    ) -> Result<ApplicationLogRead, ApplicationLogError> {
        if !(MAX_APPLICATION_LOG_RECORD_BYTES..=MAX_APPLICATION_LOG_READ_BYTES).contains(&max_bytes)
        {
            return Err(ApplicationLogError::new(
                ApplicationLogOperation::ReadRange,
                ApplicationLogErrorKind::ReadLimitInvalid,
            ));
        }

        let first_available_sequence = self.records.front().map(|record| record.sequence);
        let requested_sequence =
            sequence.unwrap_or(first_available_sequence.unwrap_or(self.next_sequence));
        if requested_sequence == 0 || requested_sequence > self.next_sequence {
            return Err(ApplicationLogError::new(
                ApplicationLogOperation::ReadRange,
                ApplicationLogErrorKind::CursorAhead,
            ));
        }
        let start_sequence =
            requested_sequence.max(first_available_sequence.unwrap_or(self.next_sequence));
        let missed_retained_prefix = requested_sequence < start_sequence;
        let mut json_lines = Vec::with_capacity(max_bytes.min(self.retained_bytes));
        let mut first_sequence = None;
        let mut next_sequence = start_sequence;
        for record in self
            .records
            .iter()
            .filter(|record| record.sequence >= start_sequence)
        {
            let Some(next_len) = json_lines.len().checked_add(record.json_line.len()) else {
                break;
            };
            if next_len > max_bytes {
                break;
            }
            first_sequence.get_or_insert(record.sequence);
            json_lines.extend_from_slice(&record.json_line);
            next_sequence = record.sequence + 1;
        }
        let has_more = next_sequence < self.next_sequence;
        let json_lines = String::from_utf8(json_lines)
            .expect("application log JSON serialization always emits UTF-8");
        Ok(ApplicationLogRead {
            requested_sequence,
            first_available_sequence,
            first_sequence,
            next_sequence,
            end_sequence: self.next_sequence,
            has_more,
            complete: !missed_retained_prefix && !has_more,
            dropped_records: self.dropped_records,
            json_lines,
        })
    }

    pub fn retained_records(&self) -> usize {
        self.records.len()
    }

    pub fn retained_bytes(&self) -> usize {
        self.retained_bytes
    }

    pub fn dropped_records(&self) -> u64 {
        self.dropped_records
    }

    /// Describes this ring for a caller-owned diagnostic content checklist.
    pub fn diagnostic_content(&self, selected: bool) -> DiagnosticContentInput<'static> {
        DiagnosticContentInput {
            content_id: APPLICATION_LOG_DIAGNOSTIC_CONTENT_ID,
            selected,
            estimated_bytes: self.retained_bytes as u64,
            maximum_bytes: self.limits.retained_bytes as u64,
            protection: DiagnosticContentProtection::SanitizedText,
            truncated: self.dropped_records != 0,
        }
    }

    fn drop_oldest(&mut self) -> Result<(), ApplicationLogError> {
        let Some(record) = self.records.pop_front() else {
            return Err(ApplicationLogError::new(
                ApplicationLogOperation::SequenceEvent,
                ApplicationLogErrorKind::RecordTooLarge,
            ));
        };
        self.retained_bytes -= record.json_line.len();
        self.dropped_records = self.dropped_records.checked_add(1).ok_or_else(|| {
            ApplicationLogError::new(
                ApplicationLogOperation::SequenceEvent,
                ApplicationLogErrorKind::ArithmeticOverflow,
            )
        })?;
        Ok(())
    }
}

impl fmt::Debug for ApplicationLogBuffer {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApplicationLogBuffer")
            .field("limits", &self.limits)
            .field("retained_records", &self.records.len())
            .field("retained_bytes", &self.retained_bytes)
            .field("next_sequence", &self.next_sequence)
            .field("dropped_records", &self.dropped_records)
            .finish()
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StoredApplicationLogRecord {
    schema_version: u8,
    sequence: u64,
    timestamp_unix_millis: u64,
    level: ApplicationLogLevel,
    component: String,
    event_code: String,
    fields: BTreeMap<&'static str, StoredApplicationLogValue>,
    redactions_applied: bool,
}

#[derive(Serialize)]
#[serde(untagged)]
enum StoredApplicationLogValue {
    Boolean(bool),
    Signed(i64),
    Unsigned(u64),
    Code(String),
}

struct StoredApplicationLogLine {
    sequence: u64,
    json_line: Vec<u8>,
}

struct RedactedCode {
    value: String,
    redactions_applied: bool,
}

fn redact_code(input: &str, rules: &LogRedactionRules) -> RedactedCode {
    let mut redactor = rules.stream();
    let mut value = String::with_capacity(input.len());
    redactor.push(input, &mut value);
    redactor.finish(&mut value);
    RedactedCode {
        value,
        redactions_applied: redactor.redactions_applied(),
    }
}

fn validate_identifier(value: &str, maximum_bytes: usize) -> Result<(), ApplicationLogError> {
    let bytes = value.as_bytes();
    let valid = !bytes.is_empty()
        && bytes.len() <= maximum_bytes
        && bytes.first().is_some_and(u8::is_ascii_lowercase)
        && bytes
            .last()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && bytes.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        });
    if !valid {
        return Err(ApplicationLogError::new(
            ApplicationLogOperation::ValidateEvent,
            ApplicationLogErrorKind::InvalidIdentifier,
        ));
    }
    Ok(())
}

/// How one diagnostic item prevents raw sensitive content from entering an
/// export. There is deliberately no unprotected-content variant.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum DiagnosticContentProtection {
    SanitizedText,
    MetadataOnly,
}

/// Borrowed input for one container-independent diagnostic checklist item.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DiagnosticContentInput<'a> {
    content_id: &'a str,
    selected: bool,
    estimated_bytes: u64,
    maximum_bytes: u64,
    protection: DiagnosticContentProtection,
    truncated: bool,
}

impl<'a> DiagnosticContentInput<'a> {
    pub const fn new(
        content_id: &'a str,
        selected: bool,
        estimated_bytes: u64,
        maximum_bytes: u64,
        protection: DiagnosticContentProtection,
        truncated: bool,
    ) -> Self {
        Self {
            content_id,
            selected,
            estimated_bytes,
            maximum_bytes,
            protection,
            truncated,
        }
    }
}

/// Owned, serializable diagnostic checklist item.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticContentItem {
    content_id: String,
    selected: bool,
    estimated_bytes: u64,
    maximum_bytes: u64,
    protection: DiagnosticContentProtection,
    truncated: bool,
}

impl DiagnosticContentItem {
    pub fn content_id(&self) -> &str {
        &self.content_id
    }

    pub fn selected(&self) -> bool {
        self.selected
    }

    pub fn estimated_bytes(&self) -> u64 {
        self.estimated_bytes
    }

    pub fn maximum_bytes(&self) -> u64 {
        self.maximum_bytes
    }

    pub fn protection(&self) -> DiagnosticContentProtection {
        self.protection
    }

    pub fn truncated(&self) -> bool {
        self.truncated
    }
}

/// Limits for a caller-composed diagnostic content checklist.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DiagnosticManifestLimits {
    content_items: usize,
    byte_budget: u64,
}

impl DiagnosticManifestLimits {
    pub fn new(content_items: usize, byte_budget: u64) -> Result<Self, ApplicationLogError> {
        if content_items == 0
            || content_items > MAX_DIAGNOSTIC_CONTENT_ITEMS
            || byte_budget == 0
            || byte_budget > MAX_DIAGNOSTIC_BYTE_BUDGET
        {
            return Err(ApplicationLogError::new(
                ApplicationLogOperation::ValidateLimits,
                ApplicationLogErrorKind::InvalidConfiguration,
            ));
        }
        Ok(Self {
            content_items,
            byte_budget,
        })
    }

    pub fn content_items(self) -> usize {
        self.content_items
    }

    pub fn byte_budget(self) -> u64 {
        self.byte_budget
    }
}

impl Default for DiagnosticManifestLimits {
    fn default() -> Self {
        Self {
            content_items: DEFAULT_DIAGNOSTIC_CONTENT_ITEMS,
            byte_budget: DEFAULT_DIAGNOSTIC_BYTE_BUDGET,
        }
    }
}

/// A format-neutral content checklist and conservative budget estimate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticContentManifest {
    items: Vec<DiagnosticContentItem>,
    selected_estimated_bytes: u64,
    selected_maximum_bytes: u64,
    byte_budget: u64,
    estimated_bytes_fit: bool,
    maximum_bytes_fit: bool,
}

impl DiagnosticContentManifest {
    pub fn build<'a>(
        limits: DiagnosticManifestLimits,
        inputs: impl IntoIterator<Item = DiagnosticContentInput<'a>>,
    ) -> Result<Self, ApplicationLogError> {
        let mut items = Vec::with_capacity(limits.content_items);
        let mut selected_estimated_bytes = 0_u64;
        let mut selected_maximum_bytes = 0_u64;
        for input in inputs {
            if items.len() >= limits.content_items {
                return Err(ApplicationLogError::new(
                    ApplicationLogOperation::BuildDiagnosticManifest,
                    ApplicationLogErrorKind::TooManyContentItems,
                ));
            }
            validate_diagnostic_content_id(input.content_id)?;
            if input.estimated_bytes > input.maximum_bytes
                || input.maximum_bytes > MAX_DIAGNOSTIC_CONTENT_BYTES
            {
                return Err(ApplicationLogError::new(
                    ApplicationLogOperation::BuildDiagnosticManifest,
                    ApplicationLogErrorKind::InvalidContentSize,
                ));
            }
            if items
                .iter()
                .any(|item: &DiagnosticContentItem| item.content_id == input.content_id)
            {
                return Err(ApplicationLogError::new(
                    ApplicationLogOperation::BuildDiagnosticManifest,
                    ApplicationLogErrorKind::DuplicateContentItem,
                ));
            }
            if input.selected {
                selected_estimated_bytes = selected_estimated_bytes
                    .checked_add(input.estimated_bytes)
                    .ok_or_else(|| {
                        ApplicationLogError::new(
                            ApplicationLogOperation::BuildDiagnosticManifest,
                            ApplicationLogErrorKind::ArithmeticOverflow,
                        )
                    })?;
                selected_maximum_bytes = selected_maximum_bytes
                    .checked_add(input.maximum_bytes)
                    .ok_or_else(|| {
                        ApplicationLogError::new(
                            ApplicationLogOperation::BuildDiagnosticManifest,
                            ApplicationLogErrorKind::ArithmeticOverflow,
                        )
                    })?;
            }
            items.push(DiagnosticContentItem {
                content_id: input.content_id.to_owned(),
                selected: input.selected,
                estimated_bytes: input.estimated_bytes,
                maximum_bytes: input.maximum_bytes,
                protection: input.protection,
                truncated: input.truncated,
            });
        }
        Ok(Self {
            items,
            selected_estimated_bytes,
            selected_maximum_bytes,
            byte_budget: limits.byte_budget,
            estimated_bytes_fit: selected_estimated_bytes <= limits.byte_budget,
            maximum_bytes_fit: selected_maximum_bytes <= limits.byte_budget,
        })
    }

    /// Creates an exact output budget only when every selected item's declared
    /// maximum fits. Container framing must also be consumed from this budget.
    pub fn exact_budget(&self) -> Result<DiagnosticByteBudget, ApplicationLogError> {
        if !self.maximum_bytes_fit {
            return Err(ApplicationLogError::new(
                ApplicationLogOperation::ConsumeDiagnosticBudget,
                ApplicationLogErrorKind::BudgetExceeded,
            ));
        }
        DiagnosticByteBudget::new(self.byte_budget)
    }

    pub fn items(&self) -> &[DiagnosticContentItem] {
        &self.items
    }

    pub fn selected_estimated_bytes(&self) -> u64 {
        self.selected_estimated_bytes
    }

    pub fn selected_maximum_bytes(&self) -> u64 {
        self.selected_maximum_bytes
    }

    pub fn byte_budget(&self) -> u64 {
        self.byte_budget
    }

    pub fn estimated_bytes_fit(&self) -> bool {
        self.estimated_bytes_fit
    }

    pub fn maximum_bytes_fit(&self) -> bool {
        self.maximum_bytes_fit
    }
}

/// Exact byte accounting for a caller-owned diagnostic encoder or writer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DiagnosticByteBudget {
    limit: u64,
    consumed: u64,
}

impl DiagnosticByteBudget {
    pub fn new(limit: u64) -> Result<Self, ApplicationLogError> {
        if limit == 0 || limit > MAX_DIAGNOSTIC_BYTE_BUDGET {
            return Err(ApplicationLogError::new(
                ApplicationLogOperation::ValidateLimits,
                ApplicationLogErrorKind::InvalidConfiguration,
            ));
        }
        Ok(Self { limit, consumed: 0 })
    }

    /// Accounts bytes before they are written. Failure leaves the budget
    /// unchanged, so callers can stop without reporting a partial reservation.
    pub fn consume(&mut self, bytes: u64) -> Result<(), ApplicationLogError> {
        let consumed = self.consumed.checked_add(bytes).ok_or_else(|| {
            ApplicationLogError::new(
                ApplicationLogOperation::ConsumeDiagnosticBudget,
                ApplicationLogErrorKind::ArithmeticOverflow,
            )
        })?;
        if consumed > self.limit {
            return Err(ApplicationLogError::new(
                ApplicationLogOperation::ConsumeDiagnosticBudget,
                ApplicationLogErrorKind::BudgetExceeded,
            ));
        }
        self.consumed = consumed;
        Ok(())
    }

    pub fn limit(self) -> u64 {
        self.limit
    }

    pub fn consumed(self) -> u64 {
        self.consumed
    }

    pub fn remaining(self) -> u64 {
        self.limit - self.consumed
    }
}

fn validate_diagnostic_content_id(content_id: &str) -> Result<(), ApplicationLogError> {
    validate_identifier(content_id, MAX_DIAGNOSTIC_CONTENT_ID_BYTES).map_err(|_| {
        ApplicationLogError::new(
            ApplicationLogOperation::BuildDiagnosticManifest,
            ApplicationLogErrorKind::InvalidIdentifier,
        )
    })
}

#[cfg(test)]
mod tests {
    use super::{
        ApplicationLogBuffer, ApplicationLogErrorKind, ApplicationLogEvent, ApplicationLogField,
        ApplicationLogFieldName, ApplicationLogLevel, ApplicationLogLimits, ApplicationLogValue,
        DiagnosticContentManifest, DiagnosticManifestLimits, MAX_APPLICATION_LOG_READ_BYTES,
    };
    use crate::{LOG_REDACTION_MARKER, LogRedactionRules};

    #[test]
    fn application_json_lines_are_closed_and_redacted() {
        let rules = LogRedactionRules::from_secrets(["private-value"]).unwrap();
        let mut buffer = ApplicationLogBuffer::new(ApplicationLogLimits::default(), rules);
        buffer
            .append(ApplicationLogEvent {
                timestamp_unix_millis: 1,
                level: ApplicationLogLevel::Info,
                component: "supervisor",
                event_code: "connection.ready",
                fields: &[ApplicationLogField::new(
                    ApplicationLogFieldName::ErrorCode,
                    ApplicationLogValue::Code("private-value"),
                )],
            })
            .unwrap();

        let read = buffer
            .read_json_lines(None, MAX_APPLICATION_LOG_READ_BYTES)
            .unwrap();
        assert!(!read.json_lines.contains("private-value"));
        assert!(read.json_lines.contains(LOG_REDACTION_MARKER));
        assert!(read.complete);
    }

    #[test]
    fn free_form_command_text_is_not_a_valid_code() {
        let mut buffer =
            ApplicationLogBuffer::new(ApplicationLogLimits::default(), LogRedactionRules::empty());
        let error = buffer
            .append(ApplicationLogEvent {
                timestamp_unix_millis: 1,
                level: ApplicationLogLevel::Info,
                component: "supervisor",
                event_code: "launch.failed",
                fields: &[ApplicationLogField::new(
                    ApplicationLogFieldName::Operation,
                    ApplicationLogValue::Code("cargo run --release"),
                )],
            })
            .unwrap_err();
        assert_eq!(error.kind(), ApplicationLogErrorKind::InvalidIdentifier);
    }

    #[test]
    fn record_ring_reports_a_gap_after_count_eviction() {
        let limits = ApplicationLogLimits::new(1, 16 * 1_024).unwrap();
        let mut buffer = ApplicationLogBuffer::new(limits, LogRedactionRules::empty());
        for timestamp in 1..=2 {
            buffer
                .append(ApplicationLogEvent {
                    timestamp_unix_millis: timestamp,
                    level: ApplicationLogLevel::Debug,
                    component: "desktop",
                    event_code: "state.changed",
                    fields: &[],
                })
                .unwrap();
        }

        let read = buffer
            .read_json_lines(Some(1), MAX_APPLICATION_LOG_READ_BYTES)
            .unwrap();
        assert_eq!(read.first_available_sequence, Some(2));
        assert!(!read.complete);
        assert_eq!(read.dropped_records, 1);
    }

    #[test]
    fn manifest_and_exact_budget_share_the_declared_ceiling() {
        let buffer =
            ApplicationLogBuffer::new(ApplicationLogLimits::default(), LogRedactionRules::empty());
        let manifest = DiagnosticContentManifest::build(
            DiagnosticManifestLimits::default(),
            [buffer.diagnostic_content(true)],
        )
        .unwrap();
        let mut budget = manifest.exact_budget().unwrap();
        budget.consume(128).unwrap();
        assert_eq!(budget.consumed(), 128);
    }
}
