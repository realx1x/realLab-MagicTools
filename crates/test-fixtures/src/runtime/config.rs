use std::collections::BTreeMap;
use std::str::FromStr;

use super::authorization::{AuthorizedInvocation, InternalAuthorization};
use super::{FixtureError, MAX_HOLD_MS};

const DEFAULT_HOLD_MS: u64 = 30_000;
const DEFAULT_BYTES_PER_STREAM: u64 = 12 * 1024 * 1024;
const MAX_BYTES_PER_STREAM: u64 = 32 * 1024 * 1024;
const MAX_AGGREGATE_BYTES: u64 = 64 * 1024 * 1024;
const DEFAULT_BYTES_PER_SECOND: u64 = 8 * 1024 * 1024;
const MAX_BYTES_PER_SECOND: u64 = 8 * 1024 * 1024;
const DEFAULT_LINE_BYTES: usize = 4 * 1024;
const MAX_LINE_BYTES: usize = 256 * 1024;
const MAX_LOG_DURATION_MS: u64 = 50_000;
const INTERNAL_SCENARIO_ENV: &str = "MAGICTOOLS_TEST_FIXTURE_INTERNAL_SCENARIO";
const INTERNAL_HOLD_MS_ENV: &str = "MAGICTOOLS_TEST_FIXTURE_INTERNAL_HOLD_MS";

#[derive(Debug)]
pub(crate) enum Invocation {
    ProcessTree(ProcessTreeConfig),
    Network(NetworkConfig),
    LogFlood(LogFloodConfig),
    Encoding(EncodingConfig),
    InternalProcess(InternalProcessConfig),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProcessTreeConfig {
    pub(crate) scenario: ProcessTreeScenario,
    pub(crate) hold_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProcessTreeScenario {
    Stable,
    ChildExitsAfterSpawn,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NetworkConfig {
    pub(crate) address: NetworkAddress,
    pub(crate) hold_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NetworkAddress {
    Ipv4Loopback,
    Ipv4Unspecified,
    Ipv6Loopback,
    Ipv6Unspecified,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LogFloodConfig {
    pub(crate) bytes_per_stream: u64,
    pub(crate) bytes_per_second: u64,
    pub(crate) line_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct EncodingConfig {
    pub(crate) scenario: EncodingScenario,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EncodingScenario {
    Utf8Split,
    Utf8Truncated,
    InvalidUtf8,
    Utf16LeBomSplit,
    Utf16BeBomSplit,
    Windows1252,
    AnsiOsc,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct InternalProcessConfig {
    pub(crate) role: InternalAuthorization,
    pub(crate) scenario: ProcessTreeScenario,
    pub(crate) hold_ms: u64,
}

pub(crate) fn parse(authorized: AuthorizedInvocation) -> Result<Invocation, FixtureError> {
    match authorized {
        AuthorizedInvocation::External(arguments) => parse_external(&arguments),
        AuthorizedInvocation::Internal(role) => parse_internal(role),
    }
}

fn parse_external(arguments: &[String]) -> Result<Invocation, FixtureError> {
    let (command, remaining) = arguments
        .split_first()
        .ok_or(FixtureError::InvalidArguments)?;
    let options = parse_options(remaining)?;

    match command.as_str() {
        "process-tree" => parse_process_tree(options).map(Invocation::ProcessTree),
        "network" => parse_network(options).map(Invocation::Network),
        "log-flood" => parse_log_flood(options).map(Invocation::LogFlood),
        "encoding" => parse_encoding(options).map(Invocation::Encoding),
        _ => Err(FixtureError::InvalidArguments),
    }
}

fn parse_options(arguments: &[String]) -> Result<BTreeMap<&str, &str>, FixtureError> {
    if !arguments.len().is_multiple_of(2) {
        return Err(FixtureError::InvalidArguments);
    }

    let mut options = BTreeMap::new();
    for pair in arguments.chunks_exact(2) {
        let name = pair[0].as_str();
        let value = pair[1].as_str();
        if !name.starts_with("--")
            || value.starts_with("--")
            || options.insert(name, value).is_some()
        {
            return Err(FixtureError::InvalidArguments);
        }
    }
    Ok(options)
}

fn parse_process_tree(
    mut options: BTreeMap<&str, &str>,
) -> Result<ProcessTreeConfig, FixtureError> {
    let scenario = match options.remove("--scenario").unwrap_or("stable") {
        "stable" => ProcessTreeScenario::Stable,
        "child-exits-after-spawn" => ProcessTreeScenario::ChildExitsAfterSpawn,
        _ => return Err(FixtureError::InvalidArguments),
    };
    let hold_ms = match options.remove("--hold-ms") {
        Some(value) => parse_bounded_u64(value, 1, MAX_HOLD_MS)?,
        None => DEFAULT_HOLD_MS,
    };
    reject_unknown(options)?;
    Ok(ProcessTreeConfig { scenario, hold_ms })
}

fn parse_network(mut options: BTreeMap<&str, &str>) -> Result<NetworkConfig, FixtureError> {
    let address = match options.remove("--address").unwrap_or("127.0.0.1") {
        "127.0.0.1" => NetworkAddress::Ipv4Loopback,
        "0.0.0.0" => NetworkAddress::Ipv4Unspecified,
        "::1" => NetworkAddress::Ipv6Loopback,
        "::" => NetworkAddress::Ipv6Unspecified,
        _ => return Err(FixtureError::InvalidArguments),
    };
    let hold_ms = match options.remove("--hold-ms") {
        Some(value) => parse_bounded_u64(value, 1, MAX_HOLD_MS)?,
        None => DEFAULT_HOLD_MS,
    };
    reject_unknown(options)?;
    Ok(NetworkConfig { address, hold_ms })
}

fn parse_log_flood(mut options: BTreeMap<&str, &str>) -> Result<LogFloodConfig, FixtureError> {
    let bytes_per_stream = match options.remove("--bytes-per-stream") {
        Some(value) => parse_bounded_u64(value, 1, MAX_BYTES_PER_STREAM)?,
        None => DEFAULT_BYTES_PER_STREAM,
    };
    let bytes_per_second = match options.remove("--bytes-per-second") {
        Some(value) => parse_bounded_u64(value, 1, MAX_BYTES_PER_SECOND)?,
        None => DEFAULT_BYTES_PER_SECOND,
    };
    let line_bytes = match options.remove("--line-bytes") {
        Some(value) => parse_bounded_u64(value, 1, MAX_LINE_BYTES as u64)? as usize,
        None => DEFAULT_LINE_BYTES,
    };
    reject_unknown(options)?;

    let aggregate_bytes = bytes_per_stream
        .checked_mul(2)
        .filter(|total| *total <= MAX_AGGREGATE_BYTES)
        .ok_or(FixtureError::InvalidArguments)?;
    let expected_duration_ms = aggregate_bytes
        .checked_mul(1_000)
        .and_then(|bytes| bytes.checked_add(bytes_per_second - 1))
        .map(|bytes| bytes / bytes_per_second)
        .ok_or(FixtureError::InvalidArguments)?;
    if expected_duration_ms > MAX_LOG_DURATION_MS {
        return Err(FixtureError::InvalidArguments);
    }

    Ok(LogFloodConfig {
        bytes_per_stream,
        bytes_per_second,
        line_bytes,
    })
}

fn parse_encoding(mut options: BTreeMap<&str, &str>) -> Result<EncodingConfig, FixtureError> {
    let scenario = match options.remove("--scenario").unwrap_or("utf8-split") {
        "utf8-split" => EncodingScenario::Utf8Split,
        "utf8-truncated" => EncodingScenario::Utf8Truncated,
        "invalid-utf8" => EncodingScenario::InvalidUtf8,
        "utf16le-bom-split" => EncodingScenario::Utf16LeBomSplit,
        "utf16be-bom-split" => EncodingScenario::Utf16BeBomSplit,
        "windows-1252" => EncodingScenario::Windows1252,
        "ansi-osc" => EncodingScenario::AnsiOsc,
        _ => return Err(FixtureError::InvalidArguments),
    };
    reject_unknown(options)?;
    Ok(EncodingConfig { scenario })
}

fn parse_internal(role: InternalAuthorization) -> Result<Invocation, FixtureError> {
    let scenario = match std::env::var(INTERNAL_SCENARIO_ENV).as_deref() {
        Ok("stable") => ProcessTreeScenario::Stable,
        Ok("child-exits-after-spawn") => ProcessTreeScenario::ChildExitsAfterSpawn,
        _ => return Err(FixtureError::Authorization),
    };
    let hold_ms = std::env::var(INTERNAL_HOLD_MS_ENV)
        .map_err(|_| FixtureError::Authorization)
        .and_then(|value| parse_bounded_u64(&value, 1, MAX_HOLD_MS))?;
    Ok(Invocation::InternalProcess(InternalProcessConfig {
        role,
        scenario,
        hold_ms,
    }))
}

fn parse_bounded_u64(value: &str, minimum: u64, maximum: u64) -> Result<u64, FixtureError> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(FixtureError::InvalidArguments);
    }
    let value = u64::from_str(value).map_err(|_| FixtureError::InvalidArguments)?;
    if !(minimum..=maximum).contains(&value) {
        return Err(FixtureError::InvalidArguments);
    }
    Ok(value)
}

fn reject_unknown(options: BTreeMap<&str, &str>) -> Result<(), FixtureError> {
    if options.is_empty() {
        Ok(())
    } else {
        Err(FixtureError::InvalidArguments)
    }
}

pub(crate) const fn internal_scenario_env() -> &'static str {
    INTERNAL_SCENARIO_ENV
}

pub(crate) const fn internal_hold_ms_env() -> &'static str {
    INTERNAL_HOLD_MS_ENV
}

pub(crate) const fn process_tree_scenario_name(scenario: ProcessTreeScenario) -> &'static str {
    match scenario {
        ProcessTreeScenario::Stable => "stable",
        ProcessTreeScenario::ChildExitsAfterSpawn => "child-exits-after-spawn",
    }
}
