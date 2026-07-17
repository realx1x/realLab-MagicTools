use std::io::Write;
use std::thread;
use std::time::Duration;

use super::FixtureError;
use super::config::{EncodingConfig, EncodingScenario};

const MAX_PAYLOAD_BYTES: usize = 64 * 1024;
const CHUNK_DELAY: Duration = Duration::from_millis(15);

const UTF8_SPLIT: &[&[u8]] = &[b"UTF-8 split: ", &[0xf0], &[0x9f, 0xa7], &[0xaa, b'\n']];
const UTF8_TRUNCATED: &[&[u8]] = &[b"UTF-8 truncated: ", &[0xe4], &[0xb8]];
const INVALID_UTF8: &[&[u8]] = &[
    b"Invalid UTF-8: ",
    &[0xff],
    &[0xf0, 0x28],
    &[0x8c, 0x28, b'\n'],
];
const UTF16LE_BOM_SPLIT: &[&[u8]] = &[
    &[0xff],
    &[0xfe],
    &[0x4d, 0x00, 0x61],
    &[
        0x00, 0x67, 0x00, 0x69, 0x00, 0x63, 0x00, 0x54, 0x00, 0x6f, 0x00, 0x6f, 0x00, 0x6c, 0x00,
        0x73, 0x00, 0x20, 0x00, 0x4c, 0x00, 0x45, 0x00, 0x20, 0x00, 0x2d, 0x4e, 0x0a, 0x00,
    ],
];
const UTF16BE_BOM_SPLIT: &[&[u8]] = &[
    &[0xfe],
    &[0xff],
    &[0x00, 0x4d, 0x00],
    &[
        0x61, 0x00, 0x67, 0x00, 0x69, 0x00, 0x63, 0x00, 0x54, 0x00, 0x6f, 0x00, 0x6f, 0x00, 0x6c,
        0x00, 0x73, 0x00, 0x20, 0x00, 0x42, 0x00, 0x45, 0x00, 0x20, 0x4e, 0x2d, 0x00, 0x0a,
    ],
];
const WINDOWS_1252: &[&[u8]] = &[
    &[0x93],
    b"Windows-1252 quote",
    &[0x94, b' ', 0x80, b' ', b'c', b'a', b'f'],
    &[0xe9, b'\n'],
];
const ANSI_OSC: &[&[u8]] = &[
    b"\x1b[",
    b"31mANSI red\x1b[0",
    b"m\n\x1b]0;MagicTools fixture",
    b"\x07OSC title\n",
];

pub(crate) fn run(config: EncodingConfig) -> Result<(), FixtureError> {
    let chunks = payload(config.scenario);
    let payload_bytes = chunks
        .iter()
        .try_fold(0_usize, |total, chunk| total.checked_add(chunk.len()));
    let payload_bytes = payload_bytes
        .filter(|bytes| *bytes != 0 && *bytes <= MAX_PAYLOAD_BYTES)
        .ok_or(FixtureError::Runtime)?;

    let mut readiness = std::io::stderr().lock();
    writeln!(
        readiness,
        "MAGICTOOLS_TEST_FIXTURE_ENCODING_READY scenario={} payload_bytes={payload_bytes}",
        scenario_name(config.scenario)
    )
    .map_err(|_| FixtureError::Runtime)?;
    readiness.flush().map_err(|_| FixtureError::Runtime)?;
    drop(readiness);

    let mut output = std::io::stdout().lock();
    for (index, chunk) in chunks.iter().enumerate() {
        output
            .write_all(chunk)
            .and_then(|()| output.flush())
            .map_err(|_| FixtureError::Runtime)?;
        if index + 1 < chunks.len() {
            thread::sleep(CHUNK_DELAY);
        }
    }
    Ok(())
}

fn payload(scenario: EncodingScenario) -> &'static [&'static [u8]] {
    match scenario {
        EncodingScenario::Utf8Split => UTF8_SPLIT,
        EncodingScenario::Utf8Truncated => UTF8_TRUNCATED,
        EncodingScenario::InvalidUtf8 => INVALID_UTF8,
        EncodingScenario::Utf16LeBomSplit => UTF16LE_BOM_SPLIT,
        EncodingScenario::Utf16BeBomSplit => UTF16BE_BOM_SPLIT,
        EncodingScenario::Windows1252 => WINDOWS_1252,
        EncodingScenario::AnsiOsc => ANSI_OSC,
    }
}

fn scenario_name(scenario: EncodingScenario) -> &'static str {
    match scenario {
        EncodingScenario::Utf8Split => "utf8-split",
        EncodingScenario::Utf8Truncated => "utf8-truncated",
        EncodingScenario::InvalidUtf8 => "invalid-utf8",
        EncodingScenario::Utf16LeBomSplit => "utf16le-bom-split",
        EncodingScenario::Utf16BeBomSplit => "utf16be-bom-split",
        EncodingScenario::Windows1252 => "windows-1252",
        EncodingScenario::AnsiOsc => "ansi-osc",
    }
}
