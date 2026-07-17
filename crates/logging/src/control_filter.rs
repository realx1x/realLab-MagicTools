use unicode_general_category::{GeneralCategory, get_general_category};
use vte::{Params, Parser, Perform};

pub(crate) const OSC_BUFFER_BYTES: usize = 1024;

/// Stateful plain-text projection of terminal output.
///
/// The parser retains only VTE's fixed-size state, including a 1024-byte OSC
/// buffer. All terminal commands are discarded. Printable characters, LF,
/// and TAB are retained, while CRLF and lone CR are normalized to LF.
pub(crate) struct ControlSequenceFilter {
    parser: Parser<OSC_BUFFER_BYTES>,
    pending_carriage_return: bool,
    controls_filtered: bool,
    sequence_state: SequenceState,
}

impl ControlSequenceFilter {
    pub(crate) fn new() -> Self {
        Self {
            parser: Parser::new_with_size(),
            pending_carriage_return: false,
            controls_filtered: false,
            sequence_state: SequenceState::Ground,
        }
    }

    pub(crate) fn push(&mut self, input: &str, output: &mut String) {
        let Self {
            parser,
            pending_carriage_return,
            controls_filtered,
            sequence_state,
        } = self;

        // VTE recognizes seven-bit ESC forms. Normalize the string-oriented
        // C1 introducers so their payload cannot fall back into printable text.
        for character in input.chars() {
            let was_in_sequence = sequence_state.is_active();
            let c1_sequence = c1_escape_form(character);
            sequence_state.advance(character);
            if (character != '\r' && !is_printable_log_character(character))
                || c1_sequence.is_some()
            {
                *controls_filtered = true;
            }
            let mut performer = PlainTextPerformer {
                output,
                pending_carriage_return,
                controls_filtered,
                suppress_output: was_in_sequence
                    || character == '\u{001b}'
                    || c1_sequence.is_some(),
            };
            if let Some(sequence) = c1_sequence {
                parser.advance(&mut performer, sequence);
            } else {
                let mut encoded = [0_u8; 4];
                let encoded = character.encode_utf8(&mut encoded);
                parser.advance(&mut performer, encoded.as_bytes());
            }
        }
    }

    pub(crate) fn finish(&mut self, output: &mut String) {
        // Replacing the parser discards any unterminated OSC, CSI, DCS, APC,
        // PM, SOS, or ESC state without replaying its buffered bytes.
        self.parser = Parser::new_with_size();
        self.sequence_state = SequenceState::Ground;
        if self.pending_carriage_return {
            output.push('\n');
            self.pending_carriage_return = false;
        }
    }

    pub(crate) fn controls_filtered(&self) -> bool {
        self.controls_filtered
    }
}

impl Default for ControlSequenceFilter {
    fn default() -> Self {
        Self::new()
    }
}

struct PlainTextPerformer<'a> {
    output: &'a mut String,
    pending_carriage_return: &'a mut bool,
    controls_filtered: &'a mut bool,
    suppress_output: bool,
}

impl PlainTextPerformer<'_> {
    fn flush_carriage_return(&mut self) {
        if *self.pending_carriage_return {
            self.output.push('\n');
            *self.pending_carriage_return = false;
        }
    }
}

impl Perform for PlainTextPerformer<'_> {
    fn print(&mut self, character: char) {
        if self.suppress_output || !is_printable_log_character(character) {
            *self.controls_filtered = true;
            return;
        }
        self.flush_carriage_return();
        self.output.push(character);
    }

    fn execute(&mut self, byte: u8) {
        if self.suppress_output {
            *self.controls_filtered = true;
            return;
        }
        match byte {
            b'\r' => {
                self.flush_carriage_return();
                *self.pending_carriage_return = true;
            }
            b'\n' => {
                self.output.push('\n');
                *self.pending_carriage_return = false;
            }
            b'\t' => {
                self.flush_carriage_return();
                self.output.push('\t');
            }
            _ => *self.controls_filtered = true,
        }
    }

    fn hook(&mut self, _params: &Params, _intermediates: &[u8], _ignore: bool, _action: char) {
        *self.controls_filtered = true;
    }

    fn unhook(&mut self) {
        *self.controls_filtered = true;
    }

    fn osc_dispatch(&mut self, _params: &[&[u8]], _bell_terminated: bool) {
        *self.controls_filtered = true;
    }

    fn csi_dispatch(
        &mut self,
        _params: &Params,
        _intermediates: &[u8],
        _ignore: bool,
        _action: char,
    ) {
        *self.controls_filtered = true;
    }

    fn esc_dispatch(&mut self, _intermediates: &[u8], _ignore: bool, _byte: u8) {
        *self.controls_filtered = true;
    }
}

pub(crate) fn is_printable_log_character(character: char) -> bool {
    matches!(character, '\n' | '\t')
        || !matches!(
            get_general_category(character),
            GeneralCategory::Control
                | GeneralCategory::Format
                | GeneralCategory::LineSeparator
                | GeneralCategory::ParagraphSeparator
                | GeneralCategory::Surrogate
                | GeneralCategory::Unassigned
        )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SequenceState {
    Ground,
    Escape,
    Csi,
    DcsEntry,
    DcsString,
    Osc,
    String,
}

impl SequenceState {
    fn is_active(self) -> bool {
        self != Self::Ground
    }

    fn advance(&mut self, character: char) {
        match character {
            '\u{0090}' => *self = Self::DcsEntry,
            '\u{0098}' | '\u{009e}' | '\u{009f}' => *self = Self::String,
            '\u{009b}' => *self = Self::Csi,
            '\u{009c}' => *self = Self::Ground,
            '\u{009d}' => *self = Self::Osc,
            '\u{0018}' | '\u{001a}' => *self = Self::Ground,
            '\u{001b}' => *self = Self::Escape,
            _ => match *self {
                Self::Ground => {}
                Self::Escape => match character {
                    '[' => *self = Self::Csi,
                    'P' => *self = Self::DcsEntry,
                    ']' => *self = Self::Osc,
                    'X' | '^' | '_' => *self = Self::String,
                    '\u{0030}'..='\u{007e}' => *self = Self::Ground,
                    _ => {}
                },
                Self::Csi => {
                    if matches!(character, '\u{0040}'..='\u{007e}') {
                        *self = Self::Ground;
                    }
                }
                Self::DcsEntry => {
                    if matches!(character, '\u{0040}'..='\u{007e}') {
                        *self = Self::DcsString;
                    }
                }
                Self::Osc if character == '\u{0007}' => *self = Self::Ground,
                Self::DcsString | Self::Osc | Self::String => {}
            },
        }
    }
}

fn c1_escape_form(character: char) -> Option<&'static [u8]> {
    match character {
        '\u{0090}' => Some(b"\x1bP"),
        '\u{0098}' => Some(b"\x1bX"),
        '\u{009b}' => Some(b"\x1b["),
        '\u{009c}' => Some(b"\x1b\\"),
        '\u{009d}' => Some(b"\x1b]"),
        '\u{009e}' => Some(b"\x1b^"),
        '\u{009f}' => Some(b"\x1b_"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::ControlSequenceFilter;

    #[test]
    fn retains_plain_text_and_normalizes_newlines() {
        let mut filter = ControlSequenceFilter::new();
        let mut output = String::new();
        filter.push("one\r", &mut output);
        filter.push("\ntwo\rthree\tfour", &mut output);
        filter.finish(&mut output);

        assert_eq!(output, "one\ntwo\nthree\tfour");
        assert!(!filter.controls_filtered());
    }

    #[test]
    fn discards_osc_clipboard_and_hyperlink_sequences_across_chunks() {
        let mut filter = ControlSequenceFilter::new();
        let mut output = String::new();
        filter.push("before\x1b]52;c;", &mut output);
        filter.push(
            "c2VjcmV0\x07middle\x1b]8;;https://example.invalid",
            &mut output,
        );
        filter.push("\x1b\\link\x1b]8;;\x1b\\after", &mut output);
        filter.finish(&mut output);

        assert_eq!(output, "beforemiddlelinkafter");
        assert!(filter.controls_filtered());
    }

    #[test]
    fn discards_csi_dcs_apc_pm_sos_esc_and_unterminated_payloads() {
        let mut filter = ControlSequenceFilter::new();
        let mut output = String::new();
        filter.push("a\x1b[31mb\x1bPdata\x1b\\c", &mut output);
        filter.push("\x1b_apc\x1b\\d\x1b^pm\x1b\\e\x1bXsos\x1b\\f", &mut output);
        filter.push("\x1b(0g\x1b]52;c;unterminated", &mut output);
        filter.finish(&mut output);

        assert_eq!(output, "abcdefg");
        assert!(filter.controls_filtered());
    }

    #[test]
    fn treats_utf8_c1_introducers_as_terminal_sequences() {
        let mut filter = ControlSequenceFilter::new();
        let mut output = String::new();
        filter.push("a\u{009b}31mb\u{009d}52;c;secret\u{009c}c", &mut output);
        filter.finish(&mut output);

        assert_eq!(output, "abc");
        assert!(filter.controls_filtered());
    }

    #[test]
    fn drops_c0_controls_embedded_in_csi_and_escape_sequences() {
        let mut filter = ControlSequenceFilter::new();
        let mut output = String::new();
        filter.push("a\x1b[\tb\x1b[\nc\x1b[\rd\x1b(\teZ", &mut output);
        filter.finish(&mut output);

        assert_eq!(output, "aZ");
        assert!(filter.controls_filtered());
    }

    #[test]
    fn drops_non_printing_unicode_and_marks_del_as_filtered() {
        let mut filter = ControlSequenceFilter::new();
        let mut output = String::new();
        filter.push(
            "a\u{202e}b\u{200b}c\u{2028}d\u{fdd0}e\u{007f}f",
            &mut output,
        );
        filter.finish(&mut output);

        assert_eq!(output, "abcdef");
        assert!(filter.controls_filtered());
    }
}
