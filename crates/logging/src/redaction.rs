use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::sync::Arc;
use std::sync::atomic::{Ordering, compiler_fence};

use crate::control_filter::ControlSequenceFilter;

/// The replacement is deliberately fixed and contains no secret metadata.
pub const LOG_REDACTION_MARKER: &str = "[REDACTED]";

/// These limits mirror the bounded launch-environment contract. They also
/// keep a caller from accidentally constructing an unbounded matcher.
pub const MAX_REDACTION_PATTERNS: usize = 256;
pub const MAX_REDACTION_PATTERN_BYTES: usize = 2_560;
pub const MAX_REDACTION_TOTAL_BYTES: usize = 256 * 1_024;

/// A configuration error which never carries a pattern or its value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LogRedactionError {
    PatternTooLong,
    TooManyPatterns,
    TotalPatternBytesExceeded,
}

impl Display for LogRedactionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::PatternTooLong => "log redaction pattern is too long",
            Self::TooManyPatterns => "log redaction has too many patterns",
            Self::TotalPatternBytesExceeded => "log redaction patterns exceed the byte limit",
        })
    }
}

impl Error for LogRedactionError {}

/// Shared immutable rules. Cloning this value only clones an `Arc`; secret
/// bytes are not copied. Each call to [`Self::stream`] creates independent
/// carry state for one output stream.
#[derive(Clone)]
pub struct LogRedactionRules {
    inner: Arc<RedactionRulesInner>,
}

impl LogRedactionRules {
    pub fn empty() -> Self {
        Self {
            inner: Arc::new(RedactionRulesInner::empty()),
        }
    }

    /// Builds literal rules from UTF-8 secrets. Each secret is projected
    /// through the same terminal filter used for logs before it is indexed.
    /// Empty projections are ignored and duplicate projections are removed.
    pub fn from_secrets<'a, I>(secrets: I) -> Result<Self, LogRedactionError>
    where
        I: IntoIterator<Item = &'a str>,
    {
        let mut normalized = Vec::with_capacity(MAX_REDACTION_PATTERNS);
        let mut total_bytes = 0_usize;

        for secret in secrets {
            if secret.is_empty() {
                continue;
            }
            if secret.len() > MAX_REDACTION_PATTERN_BYTES {
                return Err(LogRedactionError::PatternTooLong);
            }

            let projected = normalize_secret(secret);
            if projected.is_empty()
                || normalized
                    .iter()
                    .any(|candidate: &SensitiveString| candidate.as_str() == projected.as_str())
            {
                continue;
            }
            if normalized.len() >= MAX_REDACTION_PATTERNS {
                return Err(LogRedactionError::TooManyPatterns);
            }
            total_bytes = total_bytes
                .checked_add(projected.len())
                .filter(|total| *total <= MAX_REDACTION_TOTAL_BYTES)
                .ok_or(LogRedactionError::TotalPatternBytesExceeded)?;
            normalized.push(projected);
        }

        let mut inner = RedactionRulesInner::with_capacity(total_bytes);
        for pattern in &normalized {
            inner.insert(pattern.as_bytes());
        }
        // The trie is the only retained copy. SensitiveString clears its
        // backing allocation when this temporary vector is dropped.
        drop(normalized);
        Ok(Self {
            inner: Arc::new(inner),
        })
    }

    pub fn stream(&self) -> LogRedactor {
        LogRedactor {
            rules: Arc::clone(&self.inner),
            pending: SensitiveBytes::with_capacity(self.inner.max_pattern_bytes.saturating_sub(1)),
            finished: false,
            redactions_applied: false,
        }
    }
}

impl Default for LogRedactionRules {
    fn default() -> Self {
        Self::empty()
    }
}

/// Stateful redactor for one stdout, stderr, or PTY stream.
pub struct LogRedactor {
    rules: Arc<RedactionRulesInner>,
    pending: SensitiveBytes,
    finished: bool,
    redactions_applied: bool,
}

impl LogRedactor {
    /// Appends filtered UTF-8 text. A suffix which could still become a
    /// pattern after the next call is retained and never exposed to the
    /// caller's output.
    pub fn push(&mut self, input: &str, output: &mut String) {
        if self.finished || input.is_empty() {
            return;
        }
        if self.rules.max_pattern_bytes == 0 {
            output.push_str(input);
            return;
        }
        self.pending.extend_from_slice(input.as_bytes());
        self.process(false, output);
    }

    /// Flushes the final carry. Calls after the first one are ignored.
    pub fn finish(&mut self, output: &mut String) {
        if self.finished {
            return;
        }
        self.process(true, output);
        self.pending.clear_sensitive();
        self.finished = true;
    }

    /// Reports whether this stream replaced at least one pattern. It carries
    /// no count, value, name, or length information.
    pub fn redactions_applied(&self) -> bool {
        self.redactions_applied
    }

    fn process(&mut self, end_of_stream: bool, output: &mut String) {
        let bytes = self.pending.as_slice();
        let mut safe_end = if end_of_stream {
            bytes.len()
        } else {
            bytes
                .len()
                .saturating_sub(self.rules.max_pattern_bytes.saturating_sub(1))
        };
        while safe_end > 0
            && !std::str::from_utf8(bytes)
                .expect("redaction input is UTF-8")
                .is_char_boundary(safe_end)
        {
            safe_end -= 1;
        }

        let mut cursor = 0_usize;
        while cursor < safe_end {
            if let Some(length) = self.rules.longest_match_at(bytes, cursor) {
                output.push_str(LOG_REDACTION_MARKER);
                self.redactions_applied = true;
                cursor += length;
                continue;
            }

            let text = std::str::from_utf8(&bytes[cursor..]).expect("redaction input is UTF-8");
            let character = text.chars().next().expect("non-empty redaction input");
            let length = character.len_utf8();
            output.push_str(&text[..length]);
            cursor += length;
        }
        self.pending.remove_prefix(cursor);
    }
}

struct RedactionRulesInner {
    nodes: Vec<TrieNode>,
    edges: Vec<TrieEdge>,
    max_pattern_bytes: usize,
}

impl RedactionRulesInner {
    fn empty() -> Self {
        Self::with_capacity(0)
    }

    fn with_capacity(total_pattern_bytes: usize) -> Self {
        let mut nodes = Vec::with_capacity(total_pattern_bytes.saturating_add(1));
        nodes.push(TrieNode::default());
        Self {
            nodes,
            edges: Vec::with_capacity(total_pattern_bytes),
            max_pattern_bytes: 0,
        }
    }

    fn insert(&mut self, pattern: &[u8]) {
        debug_assert!(!pattern.is_empty());
        self.max_pattern_bytes = self.max_pattern_bytes.max(pattern.len());
        let mut node = 0_usize;
        for &byte in pattern {
            let next = self.child(node, byte).unwrap_or_else(|| {
                let child = self.nodes.len();
                self.nodes.push(TrieNode::default());
                let edge = self.edges.len();
                self.edges.push(TrieEdge {
                    byte,
                    child,
                    next: self.nodes[node].first_edge,
                });
                self.nodes[node].first_edge = Some(edge);
                child
            });
            node = next;
        }
        self.nodes[node].terminal = true;
    }

    fn child(&self, node: usize, byte: u8) -> Option<usize> {
        let mut edge = self.nodes[node].first_edge;
        while let Some(index) = edge {
            let candidate = &self.edges[index];
            if candidate.byte == byte {
                return Some(candidate.child);
            }
            edge = candidate.next;
        }
        None
    }

    fn longest_match_at(&self, bytes: &[u8], start: usize) -> Option<usize> {
        let mut node = 0_usize;
        let mut cursor = start;
        let mut longest = None;
        while cursor < bytes.len() {
            let Some(next) = self.child(node, bytes[cursor]) else {
                break;
            };
            node = next;
            cursor += 1;
            if self.nodes[node].terminal {
                longest = Some(cursor - start);
            }
        }
        longest
    }
}

#[derive(Default)]
struct TrieNode {
    first_edge: Option<usize>,
    terminal: bool,
}

struct TrieEdge {
    byte: u8,
    child: usize,
    next: Option<usize>,
}

impl Drop for TrieEdge {
    fn drop(&mut self) {
        wipe_bytes(std::slice::from_mut(&mut self.byte));
        self.child = 0;
        self.next = None;
    }
}

/// UTF-8 scratch storage which clears its initialized bytes before release.
pub(crate) struct SensitiveString {
    value: String,
}

impl SensitiveString {
    pub(crate) fn with_capacity(capacity: usize) -> Self {
        Self {
            value: String::with_capacity(capacity),
        }
    }

    pub(crate) fn as_mut_string(&mut self) -> &mut String {
        &mut self.value
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.value
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.value.as_bytes()
    }

    pub(crate) fn len(&self) -> usize {
        self.value.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.value.is_empty()
    }
}

impl Drop for SensitiveString {
    fn drop(&mut self) {
        wipe_bytes(unsafe { self.value.as_mut_vec() });
    }
}

struct SensitiveBytes {
    bytes: Vec<u8>,
}

impl SensitiveBytes {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(capacity),
        }
    }

    fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    fn extend_from_slice(&mut self, bytes: &[u8]) {
        let required = self.bytes.len().saturating_add(bytes.len());
        if required > self.bytes.capacity() {
            let mut replacement = Vec::with_capacity(required);
            replacement.extend_from_slice(&self.bytes);
            replacement.extend_from_slice(bytes);
            self.clear_sensitive();
            self.bytes = replacement;
        } else {
            self.bytes.extend_from_slice(bytes);
        }
    }

    fn remove_prefix(&mut self, count: usize) {
        if count == 0 {
            return;
        }
        let length = self.bytes.len();
        debug_assert!(count <= length);
        self.bytes.copy_within(count..length, 0);
        let remaining = length - count;
        wipe_bytes(&mut self.bytes[remaining..length]);
        self.bytes.truncate(remaining);
    }

    fn clear_sensitive(&mut self) {
        wipe_bytes(&mut self.bytes);
        self.bytes.clear();
    }
}

impl Drop for SensitiveBytes {
    fn drop(&mut self) {
        wipe_bytes(&mut self.bytes);
    }
}

pub(crate) fn wipe_bytes(bytes: &mut [u8]) {
    for byte in bytes {
        // Volatile writes provide a best-effort clear for owned scratch and
        // matcher buffers. Copies made by decoders or OS APIs are separate.
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

fn normalize_secret(secret: &str) -> SensitiveString {
    let mut filter = ControlSequenceFilter::new();
    let mut projected = SensitiveString::with_capacity(secret.len());
    filter.push(secret, projected.as_mut_string());
    filter.finish(projected.as_mut_string());
    projected
}

#[cfg(test)]
mod tests {
    use super::{LOG_REDACTION_MARKER, LogRedactionRules};
    use crate::{LogEncodingPolicy, LogTextPipeline};

    fn redact(chunks: &[&str], secrets: &[&str]) -> String {
        let rules = LogRedactionRules::from_secrets(secrets.iter().copied()).unwrap();
        let mut redactor = rules.stream();
        let mut output = String::new();
        for chunk in chunks {
            redactor.push(chunk, &mut output);
        }
        redactor.finish(&mut output);
        output
    }

    #[test]
    fn matches_leftmost_longest_across_chunks() {
        assert_eq!(
            redact(&["xxab", "cdefyy"], &["abc", "bc", "abcdef"]),
            format!("xx{LOG_REDACTION_MARKER}yy")
        );
    }

    #[test]
    fn redacts_short_values_and_ignores_empty_values() {
        assert_eq!(
            redact(&["axa"], &["", "x"]),
            format!("a{LOG_REDACTION_MARKER}a")
        );
    }

    #[test]
    fn patterns_use_the_log_filter_projection() {
        let rules = LogRedactionRules::from_secrets(["a\nb"]).unwrap();
        let mut pipeline =
            LogTextPipeline::with_redactor(LogEncodingPolicy::Utf8, rules.stream()).unwrap();
        let mut output = String::new();
        pipeline.push(b"a\r", &mut output);
        pipeline.push(b"\nb", &mut output);
        pipeline.finish(&mut output);
        assert_eq!(output, LOG_REDACTION_MARKER);
    }
}
