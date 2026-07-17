use std::error::Error;
use std::fmt::{self, Display, Formatter};

use encoding_rs::{CoderResult, Decoder, Encoding, UTF_8, UTF_16BE, UTF_16LE};
use oem_cp::code_table::DECODING_TABLE_CP_MAP;
use oem_cp::code_table_type::TableType;

use crate::control_filter::ControlSequenceFilter;
#[cfg(test)]
use crate::redaction::LogRedactionRules;
use crate::redaction::{LogRedactor, SensitiveString, wipe_bytes};

const AUTO_PROBE_BYTES: usize = 4;
const DECODE_BUFFER_BYTES: usize = 4096;

/// Per-stream encoding policy selected before pipe capture starts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LogEncodingPolicy {
    /// Decode as UTF-8 and replace malformed or truncated input.
    Utf8,
    /// Prefer a Unicode BOM or valid UTF-8, otherwise replay the initial bytes
    /// through the supplied Windows code page.
    WindowsAuto { fallback_code_page: u16 },
    /// Decode the complete stream with one explicit Windows code page.
    WindowsCodePage(u16),
}

/// Encoding fixed for this stream after policy resolution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolvedLogEncoding {
    Utf8,
    Utf16LittleEndian,
    Utf16BigEndian,
    WindowsCodePage(u16),
}

/// Monotonic observations collected while one stream is decoded and filtered.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LogTextStatus {
    /// `None` is possible only while auto mode has seen ASCII exclusively.
    pub resolved_encoding: Option<ResolvedLogEncoding>,
    pub replacement_used: bool,
    pub controls_filtered: bool,
    pub fallback_unavailable: bool,
    pub auto_fallback_used: bool,
    pub finished: bool,
}

/// Invalid explicit encoding configuration. Stream data never produces this
/// error; malformed input is represented with U+FFFD instead.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LogTextError {
    UnsupportedWindowsCodePage { code_page: u16 },
}

impl Display for LogTextError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedWindowsCodePage { code_page } => {
                write!(formatter, "unsupported Windows code page {code_page}")
            }
        }
    }
}

impl Error for LogTextError {}

/// Fixed-state streaming decoder and terminal-control filter for one log
/// stream. A pipeline must not be shared by stdout and stderr.
pub struct LogTextPipeline {
    decoder: DecoderState,
    filter: ControlSequenceFilter,
    redactor: LogRedactor,
    status: LogTextStatus,
}

impl LogTextPipeline {
    #[cfg(test)]
    pub(crate) fn new(policy: LogEncodingPolicy) -> Result<Self, LogTextError> {
        Self::with_redactor(policy, LogRedactionRules::empty().stream())
    }

    /// Builds a pipeline with a stateful redactor dedicated to this stream.
    /// The terminal filter runs before the redactor so normalized output and
    /// text joined across removed control sequences are covered.
    pub fn with_redactor(
        policy: LogEncodingPolicy,
        redactor: LogRedactor,
    ) -> Result<Self, LogTextError> {
        let mut status = LogTextStatus {
            resolved_encoding: None,
            replacement_used: false,
            controls_filtered: false,
            fallback_unavailable: false,
            auto_fallback_used: false,
            finished: false,
        };

        let decoder = match policy {
            LogEncodingPolicy::Utf8 => {
                let specification = DecoderSpecification::utf8();
                status.resolved_encoding = Some(specification.resolved);
                specification.instantiate()
            }
            LogEncodingPolicy::WindowsAuto { fallback_code_page } => {
                let fallback = DecoderSpecification::for_code_page(fallback_code_page);
                DecoderState::Detecting(AutoDetector::new(fallback))
            }
            LogEncodingPolicy::WindowsCodePage(code_page) => {
                let specification = DecoderSpecification::for_code_page(code_page)
                    .ok_or(LogTextError::UnsupportedWindowsCodePage { code_page })?;
                status.resolved_encoding = Some(specification.resolved);
                specification.instantiate()
            }
        };

        Ok(Self {
            decoder,
            filter: ControlSequenceFilter::new(),
            redactor,
            status,
        })
    }

    /// Appends safe UTF-8 text decoded from the next raw pipe chunk.
    ///
    /// Calls after [`Self::finish`] are ignored so a late capture callback
    /// cannot revive a finalized decoder or terminal parser.
    pub fn push(&mut self, input: &[u8], output: &mut String) {
        if self.status.finished || input.is_empty() {
            return;
        }

        let mut filtered =
            SensitiveString::with_capacity(input.len().saturating_mul(4).saturating_add(16));
        if matches!(self.decoder, DecoderState::Detecting(_)) {
            self.push_detecting(input, filtered.as_mut_string());
        } else {
            self.decode_resolved(input, false, filtered.as_mut_string());
        }
        self.redactor.push(filtered.as_str(), output);
    }

    /// Flushes a partial code point as U+FFFD and discards any unterminated
    /// terminal control sequence. This operation is idempotent.
    pub fn finish(&mut self, output: &mut String) {
        if self.status.finished {
            return;
        }

        let mut filtered = SensitiveString::with_capacity(16);
        if matches!(self.decoder, DecoderState::Detecting(_)) {
            self.finish_detecting(filtered.as_mut_string());
        } else {
            self.decode_resolved(&[], true, filtered.as_mut_string());
        }

        self.filter.finish(filtered.as_mut_string());
        self.redactor.push(filtered.as_str(), output);
        self.redactor.finish(output);
        self.decoder = DecoderState::Finished;
        self.status.finished = true;
    }

    pub fn status(&self) -> LogTextStatus {
        LogTextStatus {
            controls_filtered: self.filter.controls_filtered(),
            ..self.status
        }
    }

    fn push_detecting(&mut self, input: &[u8], output: &mut String) {
        let DecoderState::Detecting(mut detector) =
            std::mem::replace(&mut self.decoder, DecoderState::Finished)
        else {
            unreachable!("auto decoder state checked by caller");
        };

        let mut cursor = 0;
        while cursor < input.len() {
            if detector.probe_len == 0 && input[cursor].is_ascii() {
                let first = cursor;
                while cursor < input.len() && input[cursor].is_ascii() {
                    cursor += 1;
                }
                detector.bom_allowed = false;
                let ascii = std::str::from_utf8(&input[first..cursor])
                    .expect("an ASCII byte range is valid UTF-8");
                self.filter.push(ascii, output);
                continue;
            }

            detector.push_probe(input[cursor]);
            cursor += 1;
            match classify_probe(detector.probe(), detector.bom_allowed) {
                ProbeDecision::Pending => {}
                ProbeDecision::Utf8 => {
                    let mut probe = detector.probe;
                    let probe_len = detector.probe_len;
                    self.activate(DecoderSpecification::utf8());
                    self.decode_resolved(&probe[..probe_len], false, output);
                    self.decode_resolved(&input[cursor..], false, output);
                    wipe_bytes(&mut probe[..probe_len]);
                    return;
                }
                ProbeDecision::Bom(specification) => {
                    self.activate(specification);
                    self.decode_resolved(&input[cursor..], false, output);
                    return;
                }
                ProbeDecision::Invalid => {
                    let mut probe = detector.probe;
                    let probe_len = detector.probe_len;
                    self.activate_auto_fallback(detector.fallback);
                    self.decode_resolved(&probe[..probe_len], false, output);
                    self.decode_resolved(&input[cursor..], false, output);
                    wipe_bytes(&mut probe[..probe_len]);
                    return;
                }
            }
        }

        self.decoder = DecoderState::Detecting(detector);
    }

    fn finish_detecting(&mut self, output: &mut String) {
        let DecoderState::Detecting(detector) =
            std::mem::replace(&mut self.decoder, DecoderState::Finished)
        else {
            unreachable!("auto decoder state checked by caller");
        };

        if detector.probe_len == 0 {
            self.status.resolved_encoding = Some(ResolvedLogEncoding::Utf8);
            return;
        }

        let mut probe = detector.probe;
        let probe_len = detector.probe_len;
        match classify_probe(&probe[..probe_len], false) {
            ProbeDecision::Invalid => self.activate_auto_fallback(detector.fallback),
            ProbeDecision::Pending | ProbeDecision::Utf8 | ProbeDecision::Bom(_) => {
                self.activate(DecoderSpecification::utf8());
            }
        }
        self.decode_resolved(&probe[..probe_len], true, output);
        wipe_bytes(&mut probe[..probe_len]);
    }

    fn activate_auto_fallback(&mut self, fallback: Option<DecoderSpecification>) {
        match fallback {
            Some(specification) => {
                self.status.auto_fallback_used = true;
                self.activate(specification);
            }
            None => {
                self.status.fallback_unavailable = true;
                self.activate(DecoderSpecification::utf8());
            }
        }
    }

    fn activate(&mut self, specification: DecoderSpecification) {
        self.status.resolved_encoding = Some(specification.resolved);
        self.decoder = specification.instantiate();
    }

    fn decode_resolved(&mut self, input: &[u8], last: bool, output: &mut String) {
        let Self {
            decoder,
            filter,
            redactor: _,
            status,
        } = self;
        match decoder {
            DecoderState::EncodingRs(decoder) => decode_with_encoding_rs(
                decoder,
                input,
                last,
                filter,
                output,
                &mut status.replacement_used,
            ),
            DecoderState::Oem(table) => {
                decode_with_oem(table, input, filter, output, &mut status.replacement_used)
            }
            DecoderState::Detecting(_) | DecoderState::Finished => {}
        }
    }
}

enum DecoderState {
    Detecting(AutoDetector),
    EncodingRs(Decoder),
    Oem(&'static TableType),
    Finished,
}

struct AutoDetector {
    fallback: Option<DecoderSpecification>,
    probe: [u8; AUTO_PROBE_BYTES],
    probe_len: usize,
    bom_allowed: bool,
}

impl Drop for AutoDetector {
    fn drop(&mut self) {
        wipe_bytes(&mut self.probe);
    }
}

impl AutoDetector {
    fn new(fallback: Option<DecoderSpecification>) -> Self {
        Self {
            fallback,
            probe: [0; AUTO_PROBE_BYTES],
            probe_len: 0,
            bom_allowed: true,
        }
    }

    fn push_probe(&mut self, byte: u8) {
        debug_assert!(self.probe_len < self.probe.len());
        self.probe[self.probe_len] = byte;
        self.probe_len += 1;
    }

    fn probe(&self) -> &[u8] {
        &self.probe[..self.probe_len]
    }
}

#[derive(Clone, Copy)]
struct DecoderSpecification {
    kind: DecoderKind,
    resolved: ResolvedLogEncoding,
}

impl DecoderSpecification {
    fn utf8() -> Self {
        Self {
            kind: DecoderKind::EncodingRs(UTF_8),
            resolved: ResolvedLogEncoding::Utf8,
        }
    }

    fn for_code_page(code_page: u16) -> Option<Self> {
        if let Some(encoding) = codepage::to_encoding_no_replacement(code_page) {
            let resolved = if encoding == UTF_8 {
                ResolvedLogEncoding::Utf8
            } else if encoding == UTF_16LE {
                ResolvedLogEncoding::Utf16LittleEndian
            } else if encoding == UTF_16BE {
                ResolvedLogEncoding::Utf16BigEndian
            } else {
                ResolvedLogEncoding::WindowsCodePage(code_page)
            };
            return Some(Self {
                kind: DecoderKind::EncodingRs(encoding),
                resolved,
            });
        }

        DECODING_TABLE_CP_MAP.get(&code_page).map(|table| Self {
            kind: DecoderKind::Oem(table),
            resolved: ResolvedLogEncoding::WindowsCodePage(code_page),
        })
    }

    fn instantiate(self) -> DecoderState {
        match self.kind {
            DecoderKind::EncodingRs(encoding) => {
                DecoderState::EncodingRs(encoding.new_decoder_with_bom_removal())
            }
            DecoderKind::Oem(table) => DecoderState::Oem(table),
        }
    }
}

#[derive(Clone, Copy)]
enum DecoderKind {
    EncodingRs(&'static Encoding),
    Oem(&'static TableType),
}

enum ProbeDecision {
    Pending,
    Utf8,
    Bom(DecoderSpecification),
    Invalid,
}

fn classify_probe(probe: &[u8], bom_allowed: bool) -> ProbeDecision {
    const UTF8_BOM: &[u8] = b"\xef\xbb\xbf";
    const UTF16LE_BOM: &[u8] = b"\xff\xfe";
    const UTF16BE_BOM: &[u8] = b"\xfe\xff";

    if bom_allowed {
        if probe == UTF8_BOM {
            return ProbeDecision::Bom(DecoderSpecification::utf8());
        }
        if probe == UTF16LE_BOM {
            return ProbeDecision::Bom(DecoderSpecification {
                kind: DecoderKind::EncodingRs(UTF_16LE),
                resolved: ResolvedLogEncoding::Utf16LittleEndian,
            });
        }
        if probe == UTF16BE_BOM {
            return ProbeDecision::Bom(DecoderSpecification {
                kind: DecoderKind::EncodingRs(UTF_16BE),
                resolved: ResolvedLogEncoding::Utf16BigEndian,
            });
        }
        if UTF8_BOM.starts_with(probe)
            || UTF16LE_BOM.starts_with(probe)
            || UTF16BE_BOM.starts_with(probe)
        {
            return ProbeDecision::Pending;
        }
    }

    match std::str::from_utf8(probe) {
        Ok(_) => ProbeDecision::Utf8,
        Err(error) if error.error_len().is_some() => ProbeDecision::Invalid,
        Err(_) if probe.len() < AUTO_PROBE_BYTES => ProbeDecision::Pending,
        Err(_) => ProbeDecision::Invalid,
    }
}

fn decode_with_encoding_rs(
    decoder: &mut Decoder,
    mut input: &[u8],
    last: bool,
    filter: &mut ControlSequenceFilter,
    output: &mut String,
    replacement_used: &mut bool,
) {
    loop {
        let mut decoded = [0_u8; DECODE_BUFFER_BYTES];
        let (result, read, written, replaced) = decoder.decode_to_utf8(input, &mut decoded, last);
        *replacement_used |= replaced;

        if written != 0 {
            let text = std::str::from_utf8(&decoded[..written])
                .expect("encoding_rs emits valid UTF-8 with replacement");
            filter.push(text, output);
            wipe_bytes(&mut decoded[..written]);
        }
        input = &input[read..];

        match result {
            CoderResult::InputEmpty => break,
            CoderResult::OutputFull => {
                debug_assert!(read != 0 || written != 0);
            }
        }
    }
}

fn decode_with_oem(
    table: &&'static TableType,
    input: &[u8],
    filter: &mut ControlSequenceFilter,
    output: &mut String,
    replacement_used: &mut bool,
) {
    for &byte in input {
        let character = if byte.is_ascii() {
            char::from(byte)
        } else {
            match table {
                TableType::Complete(decoding) => decoding[usize::from(byte - 0x80)],
                TableType::Incomplete(decoding) => decoding[usize::from(byte - 0x80)]
                    .unwrap_or_else(|| {
                        *replacement_used = true;
                        '\u{fffd}'
                    }),
            }
        };
        let mut encoded = [0_u8; 4];
        let encoded_text = character.encode_utf8(&mut encoded);
        let encoded_len = encoded_text.len();
        filter.push(encoded_text, output);
        wipe_bytes(&mut encoded[..encoded_len]);
    }
}

#[cfg(test)]
mod tests {
    use super::{LogEncodingPolicy, LogTextError, LogTextPipeline, ResolvedLogEncoding};

    #[test]
    fn utf8_decoder_joins_chunks_and_replaces_truncated_input() {
        let mut pipeline = LogTextPipeline::new(LogEncodingPolicy::Utf8).unwrap();
        let mut output = String::new();
        pipeline.push(b"a\xf0\x9f", &mut output);
        assert_eq!(output, "a");
        pipeline.finish(&mut output);

        assert_eq!(output, "a\u{fffd}");
        assert!(pipeline.status().replacement_used);
    }

    #[test]
    fn auto_mode_emits_ascii_before_resolving_and_prefers_a_split_utf16_bom() {
        let mut ascii = LogTextPipeline::new(LogEncodingPolicy::WindowsAuto {
            fallback_code_page: 1252,
        })
        .unwrap();
        let mut ascii_output = String::new();
        ascii.push(b"plain", &mut ascii_output);
        assert_eq!(ascii_output, "plain");
        assert_eq!(ascii.status().resolved_encoding, None);
        ascii.finish(&mut ascii_output);
        assert_eq!(
            ascii.status().resolved_encoding,
            Some(ResolvedLogEncoding::Utf8)
        );

        let mut utf16 = LogTextPipeline::new(LogEncodingPolicy::WindowsAuto {
            fallback_code_page: 1252,
        })
        .unwrap();
        let mut utf16_output = String::new();
        utf16.push(b"\xff", &mut utf16_output);
        utf16.push(b"\xfeA", &mut utf16_output);
        utf16.push(b"\0", &mut utf16_output);
        utf16.finish(&mut utf16_output);
        assert_eq!(utf16_output, "A");
        assert_eq!(
            utf16.status().resolved_encoding,
            Some(ResolvedLogEncoding::Utf16LittleEndian)
        );
    }

    #[test]
    fn auto_mode_locks_valid_utf8_or_replays_invalid_bytes_to_fallback() {
        let mut utf8 = LogTextPipeline::new(LogEncodingPolicy::WindowsAuto {
            fallback_code_page: 1252,
        })
        .unwrap();
        let mut utf8_output = String::new();
        utf8.push(b"\xe2\x82", &mut utf8_output);
        utf8.push(b"\xac", &mut utf8_output);
        assert_eq!(utf8_output, "\u{20ac}");
        assert_eq!(
            utf8.status().resolved_encoding,
            Some(ResolvedLogEncoding::Utf8)
        );
        assert!(!utf8.status().auto_fallback_used);

        let mut fallback = LogTextPipeline::new(LogEncodingPolicy::WindowsAuto {
            fallback_code_page: 1252,
        })
        .unwrap();
        let mut fallback_output = String::new();
        fallback.push(b"\x80", &mut fallback_output);
        assert_eq!(fallback_output, "\u{20ac}");
        assert!(fallback.status().auto_fallback_used);
        assert_eq!(
            fallback.status().resolved_encoding,
            Some(ResolvedLogEncoding::WindowsCodePage(1252))
        );
    }

    #[test]
    fn unavailable_auto_fallback_uses_utf8_replacement() {
        let mut pipeline = LogTextPipeline::new(LogEncodingPolicy::WindowsAuto {
            fallback_code_page: 42,
        })
        .unwrap();
        assert!(!pipeline.status().fallback_unavailable);

        let mut output = String::new();
        pipeline.push(b"\x80", &mut output);
        pipeline.finish(&mut output);
        assert_eq!(output, "\u{fffd}");
        assert!(pipeline.status().fallback_unavailable);
        assert!(pipeline.status().replacement_used);
        assert!(!pipeline.status().auto_fallback_used);
        assert_eq!(
            pipeline.status().resolved_encoding,
            Some(ResolvedLogEncoding::Utf8)
        );
    }

    #[test]
    fn auto_mode_treats_an_incomplete_utf8_prefix_at_eof_as_utf8() {
        let mut pipeline = LogTextPipeline::new(LogEncodingPolicy::WindowsAuto {
            fallback_code_page: 1252,
        })
        .unwrap();
        let mut output = String::new();
        pipeline.push(b"\xef\xbb", &mut output);
        pipeline.finish(&mut output);

        assert_eq!(output, "\u{fffd}");
        assert!(!pipeline.status().auto_fallback_used);
        assert!(pipeline.status().replacement_used);
    }

    #[test]
    fn explicit_multibyte_and_oem_code_pages_stream_across_chunks() {
        let mut gbk = LogTextPipeline::new(LogEncodingPolicy::WindowsCodePage(936)).unwrap();
        let mut gbk_output = String::new();
        gbk.push(b"\xd6", &mut gbk_output);
        gbk.push(b"\xd0\xce", &mut gbk_output);
        gbk.push(b"\xc4", &mut gbk_output);
        gbk.finish(&mut gbk_output);
        assert_eq!(gbk_output, "\u{4e2d}\u{6587}");

        let mut cp437 = LogTextPipeline::new(LogEncodingPolicy::WindowsCodePage(437)).unwrap();
        let mut cp437_output = String::new();
        cp437.push(b"\x82", &mut cp437_output);
        cp437.finish(&mut cp437_output);
        assert_eq!(cp437_output, "\u{00e9}");
    }

    #[test]
    fn explicit_unsupported_code_page_is_a_configuration_error() {
        assert_eq!(
            LogTextPipeline::new(LogEncodingPolicy::WindowsCodePage(42))
                .err()
                .unwrap(),
            LogTextError::UnsupportedWindowsCodePage { code_page: 42 }
        );
    }

    #[test]
    fn pipeline_filters_osc_52_and_osc_8_from_plain_text() {
        let mut pipeline = LogTextPipeline::new(LogEncodingPolicy::Utf8).unwrap();
        let mut output = String::new();
        pipeline.push(b"a\x1b]52;c;secret\x07b", &mut output);
        pipeline.push(
            b"\x1b]8;;https://example.invalid\x1b\\c\x1b]8;;\x1b\\d",
            &mut output,
        );
        pipeline.finish(&mut output);

        assert_eq!(output, "abcd");
        assert!(pipeline.status().controls_filtered);
    }
}
