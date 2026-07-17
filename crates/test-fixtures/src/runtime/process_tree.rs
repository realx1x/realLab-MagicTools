use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use super::FixtureError;
use super::authorization::{
    InternalAuthorization, external_authorization_env, external_authorization_flag,
    external_authorization_value, internal_authorization_env, internal_child_arg,
    internal_grandchild_arg,
};
use super::config::{
    InternalProcessConfig, ProcessTreeConfig, ProcessTreeScenario, internal_hold_ms_env,
    internal_scenario_env, process_tree_scenario_name,
};

const SESSION_NONCE_BYTES: usize = 32;
const READINESS_TIMEOUT: Duration = Duration::from_secs(5);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const MAX_READINESS_BYTES: u64 = 256;
const CHILD_READY_PREFIX: &str = "MAGICTOOLS_TEST_FIXTURE_CHILD_READY:";
const GRANDCHILD_READY_PREFIX: &str = "MAGICTOOLS_TEST_FIXTURE_GRANDCHILD_READY:";

pub(crate) fn run_root(config: ProcessTreeConfig) -> Result<(), FixtureError> {
    let mut child = spawn_internal(
        InternalAuthorization::ProcessChild,
        config.scenario,
        config.hold_ms,
    )?;

    let result = run_root_scenario(&mut child, config);
    if result.is_err() {
        let _ = terminate_child(&mut child);
    }
    result
}

pub(crate) fn run_internal(config: InternalProcessConfig) -> Result<(), FixtureError> {
    match config.role {
        InternalAuthorization::ProcessChild => run_child(config.scenario, config.hold_ms),
        InternalAuthorization::ProcessGrandchild => run_grandchild(config.hold_ms),
    }
}

fn run_root_scenario(child: &mut Child, config: ProcessTreeConfig) -> Result<(), FixtureError> {
    let expected_child_pid = child.id();
    let readiness = read_readiness(child)?;
    let (child_pid, grandchild_pid) = parse_child_readiness(&readiness)?;
    if child_pid != expected_child_pid {
        return Err(FixtureError::Runtime);
    }

    match config.scenario {
        ProcessTreeScenario::Stable => {
            if child
                .try_wait()
                .map_err(|_| FixtureError::Runtime)?
                .is_some()
            {
                return Err(FixtureError::Runtime);
            }
        }
        ProcessTreeScenario::ChildExitsAfterSpawn => {
            expect_successful_exit(child, CLEANUP_TIMEOUT)?;
        }
    }

    announce_root_readiness(config, child_pid, grandchild_pid)?;
    thread::sleep(Duration::from_millis(config.hold_ms));
    if config.scenario == ProcessTreeScenario::Stable {
        expect_successful_exit(child, CLEANUP_TIMEOUT)?;
    }
    Ok(())
}

fn announce_root_readiness(
    config: ProcessTreeConfig,
    child_pid: u32,
    grandchild_pid: u32,
) -> Result<(), FixtureError> {
    let mut output = std::io::stdout().lock();
    writeln!(
        output,
        "MAGICTOOLS_TEST_FIXTURE_PROCESS_TREE_READY:{}:{}:{}:{}",
        std::process::id(),
        child_pid,
        grandchild_pid,
        process_tree_scenario_name(config.scenario)
    )
    .map_err(|_| FixtureError::Runtime)?;
    output.flush().map_err(|_| FixtureError::Runtime)
}

fn run_child(scenario: ProcessTreeScenario, hold_ms: u64) -> Result<(), FixtureError> {
    let mut grandchild =
        spawn_internal(InternalAuthorization::ProcessGrandchild, scenario, hold_ms)?;
    let result = announce_child_readiness(&mut grandchild);
    if result.is_err() {
        let _ = terminate_child(&mut grandchild);
        return result;
    }

    if scenario == ProcessTreeScenario::ChildExitsAfterSpawn {
        return Ok(());
    }

    thread::sleep(Duration::from_millis(hold_ms));
    expect_successful_exit(&mut grandchild, CLEANUP_TIMEOUT)
}

fn announce_child_readiness(grandchild: &mut Child) -> Result<(), FixtureError> {
    let expected_grandchild_pid = grandchild.id();
    let readiness = read_readiness(grandchild)?;
    let grandchild_pid = parse_grandchild_readiness(&readiness)?;
    if grandchild_pid != expected_grandchild_pid {
        return Err(FixtureError::Runtime);
    }

    let mut output = std::io::stdout().lock();
    writeln!(
        output,
        "{CHILD_READY_PREFIX}{}:{grandchild_pid}",
        std::process::id()
    )
    .map_err(|_| FixtureError::Runtime)?;
    output.flush().map_err(|_| FixtureError::Runtime)
}

fn run_grandchild(hold_ms: u64) -> Result<(), FixtureError> {
    let mut output = std::io::stdout().lock();
    writeln!(output, "{GRANDCHILD_READY_PREFIX}{}", std::process::id())
        .map_err(|_| FixtureError::Runtime)?;
    output.flush().map_err(|_| FixtureError::Runtime)?;
    drop(output);

    thread::sleep(Duration::from_millis(hold_ms));
    Ok(())
}

fn spawn_internal(
    role: InternalAuthorization,
    scenario: ProcessTreeScenario,
    hold_ms: u64,
) -> Result<Child, FixtureError> {
    let executable = std::env::current_exe().map_err(|_| FixtureError::Runtime)?;
    let nonce = new_session_nonce()?;
    let role_argument = match role {
        InternalAuthorization::ProcessChild => internal_child_arg(),
        InternalAuthorization::ProcessGrandchild => internal_grandchild_arg(),
    };

    let mut command = Command::new(executable);
    command
        .arg(external_authorization_flag())
        .arg(role_argument)
        .env_clear()
        .env(external_authorization_env(), external_authorization_value())
        .env(internal_authorization_env(), nonce)
        .env(
            internal_scenario_env(),
            process_tree_scenario_name(scenario),
        )
        .env(internal_hold_ms_env(), hold_ms.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    command.spawn().map_err(|_| FixtureError::Runtime)
}

fn new_session_nonce() -> Result<String, FixtureError> {
    let mut bytes = [0_u8; SESSION_NONCE_BYTES];
    getrandom::fill(&mut bytes).map_err(|_| FixtureError::Runtime)?;

    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(SESSION_NONCE_BYTES * 2);
    for byte in bytes {
        encoded.push(HEX[usize::from(byte >> 4)] as char);
        encoded.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    Ok(encoded)
}

fn read_readiness(child: &mut Child) -> Result<Vec<u8>, FixtureError> {
    let stdout = child.stdout.take().ok_or(FixtureError::Runtime)?;
    let (sender, receiver) = mpsc::channel();
    let reader = match thread::Builder::new()
        .name("fixture-readiness".to_owned())
        .spawn(move || {
            let _ = sender.send(read_bounded_line(stdout));
        }) {
        Ok(reader) => reader,
        Err(_) => {
            let _ = terminate_child(child);
            return Err(FixtureError::Runtime);
        }
    };

    let result = match receiver.recv_timeout(READINESS_TIMEOUT) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Timeout) => {
            let _ = terminate_child(child);
            let _ = reader.join();
            return Err(FixtureError::TimedOut);
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(FixtureError::Runtime),
    };
    reader.join().map_err(|_| FixtureError::Runtime)?;
    if result.is_err() {
        let _ = terminate_child(child);
    }
    result
}

fn read_bounded_line(stdout: ChildStdout) -> Result<Vec<u8>, FixtureError> {
    let mut reader = BufReader::new(stdout).take(MAX_READINESS_BYTES + 1);
    let mut line = Vec::new();
    let read = reader
        .read_until(b'\n', &mut line)
        .map_err(|_| FixtureError::Runtime)?;
    if read == 0
        || line.len() as u64 > MAX_READINESS_BYTES
        || line.last() != Some(&b'\n')
        || line.contains(&b'\r')
        || !line.is_ascii()
    {
        return Err(FixtureError::Runtime);
    }
    line.pop();
    Ok(line)
}

fn parse_child_readiness(line: &[u8]) -> Result<(u32, u32), FixtureError> {
    let line = std::str::from_utf8(line).map_err(|_| FixtureError::Runtime)?;
    let payload = line
        .strip_prefix(CHILD_READY_PREFIX)
        .ok_or(FixtureError::Runtime)?;
    let (child_pid, grandchild_pid) = payload.split_once(':').ok_or(FixtureError::Runtime)?;
    if grandchild_pid.contains(':') {
        return Err(FixtureError::Runtime);
    }
    Ok((parse_pid(child_pid)?, parse_pid(grandchild_pid)?))
}

fn parse_grandchild_readiness(line: &[u8]) -> Result<u32, FixtureError> {
    let line = std::str::from_utf8(line).map_err(|_| FixtureError::Runtime)?;
    let payload = line
        .strip_prefix(GRANDCHILD_READY_PREFIX)
        .ok_or(FixtureError::Runtime)?;
    parse_pid(payload)
}

fn parse_pid(value: &str) -> Result<u32, FixtureError> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(FixtureError::Runtime);
    }
    value
        .parse::<u32>()
        .ok()
        .filter(|pid| *pid != 0)
        .ok_or(FixtureError::Runtime)
}

fn expect_successful_exit(child: &mut Child, timeout: Duration) -> Result<(), FixtureError> {
    match wait_for_exit(child, timeout)? {
        Some(status) if status.success() => Ok(()),
        Some(_) => Err(FixtureError::Runtime),
        None => {
            let _ = terminate_child(child);
            Err(FixtureError::Runtime)
        }
    }
}

fn terminate_child(child: &mut Child) -> Result<(), FixtureError> {
    if child
        .try_wait()
        .map_err(|_| FixtureError::Runtime)?
        .is_some()
    {
        return Ok(());
    }
    if child.kill().is_err()
        && child
            .try_wait()
            .map_err(|_| FixtureError::Runtime)?
            .is_none()
    {
        return Err(FixtureError::Runtime);
    }
    wait_for_exit(child, CLEANUP_TIMEOUT)?
        .map(|_| ())
        .ok_or(FixtureError::Runtime)
}

fn wait_for_exit(
    child: &mut Child,
    timeout: Duration,
) -> Result<Option<std::process::ExitStatus>, FixtureError> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().map_err(|_| FixtureError::Runtime)? {
            return Ok(Some(status));
        }
        if Instant::now() >= deadline {
            return Ok(None);
        }
        thread::sleep(POLL_INTERVAL);
    }
}
