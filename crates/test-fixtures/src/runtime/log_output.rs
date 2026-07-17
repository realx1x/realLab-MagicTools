use std::io::{ErrorKind, Write};
use std::thread;
use std::time::{Duration, Instant};

use super::FixtureError;
use super::config::LogFloodConfig;

const MAX_WRITE_BYTES: usize = 64 * 1024;
const NANOS_PER_SECOND: u128 = 1_000_000_000;
const STDOUT_PREFIX: &[u8] = b"\x1b[32mMAGICTOOLS_TEST_FIXTURE_STDOUT\x1b[0m ";
const STDERR_PREFIX: &[u8] =
    b"\x1b]0;MagicTools fixture\x07\x1b[31mMAGICTOOLS_TEST_FIXTURE_STDERR\x1b[0m ";

pub(crate) fn run_flood(config: LogFloodConfig) -> Result<(), FixtureError> {
    let stdout_line = build_line(config.line_bytes, STDOUT_PREFIX, b'S');
    let stderr_line = build_line(config.line_bytes, STDERR_PREFIX, b'E');
    let mut stdout_state = StreamState::new(config.bytes_per_stream, stdout_line);
    let mut stderr_state = StreamState::new(config.bytes_per_stream, stderr_line);
    let mut stdout = std::io::stdout().lock();
    let mut stderr = std::io::stderr().lock();
    let started = Instant::now();
    let mut aggregate_attempted = 0_u64;

    while !stdout_state.is_complete() || !stderr_state.is_complete() {
        if let Some(chunk) = stdout_state.next_chunk() {
            pace(
                started,
                aggregate_attempted + chunk.len() as u64,
                config.bytes_per_second,
            );
            let length = chunk.len();
            let outcome = write_chunk(&mut stdout, chunk)?;
            aggregate_attempted += length as u64;
            match outcome {
                WriteOutcome::Written => stdout_state.advance(length),
                WriteOutcome::Closed => stdout_state.complete(),
            }
        }

        if let Some(chunk) = stderr_state.next_chunk() {
            pace(
                started,
                aggregate_attempted + chunk.len() as u64,
                config.bytes_per_second,
            );
            let length = chunk.len();
            let outcome = write_chunk(&mut stderr, chunk)?;
            aggregate_attempted += length as u64;
            match outcome {
                WriteOutcome::Written => stderr_state.advance(length),
                WriteOutcome::Closed => stderr_state.complete(),
            }
        }
    }

    Ok(())
}

fn write_chunk(output: &mut impl Write, chunk: &[u8]) -> Result<WriteOutcome, FixtureError> {
    match output.write_all(chunk).and_then(|()| output.flush()) {
        Ok(()) => Ok(WriteOutcome::Written),
        Err(error) if error.kind() == ErrorKind::BrokenPipe => Ok(WriteOutcome::Closed),
        Err(_) => Err(FixtureError::Runtime),
    }
}

enum WriteOutcome {
    Written,
    Closed,
}

fn build_line(length: usize, prefix: &[u8], fill: u8) -> Vec<u8> {
    let mut line = vec![fill; length];
    if length == 1 {
        line[0] = b'\n';
        return line;
    }

    let prefix_length = prefix.len().min(length - 1);
    line[..prefix_length].copy_from_slice(&prefix[..prefix_length]);
    line[length - 1] = b'\n';
    line
}

fn pace(started: Instant, planned_bytes: u64, bytes_per_second: u64) {
    let target_nanos = u128::from(planned_bytes) * NANOS_PER_SECOND / u128::from(bytes_per_second);
    let target_elapsed = Duration::from_nanos(target_nanos as u64);
    let elapsed = started.elapsed();
    if target_elapsed > elapsed {
        thread::sleep(target_elapsed - elapsed);
    }
}

struct StreamState {
    remaining: u64,
    line: Vec<u8>,
    position: usize,
}

impl StreamState {
    fn new(remaining: u64, mut line: Vec<u8>) -> Self {
        if line.len() < MAX_WRITE_BYTES {
            let repetitions = MAX_WRITE_BYTES / line.len();
            line = line.repeat(repetitions);
        }
        Self {
            remaining,
            line,
            position: 0,
        }
    }

    fn is_complete(&self) -> bool {
        self.remaining == 0
    }

    fn next_chunk(&self) -> Option<&[u8]> {
        if self.is_complete() {
            return None;
        }

        let until_line_end = self.line.len() - self.position;
        let remaining = self.remaining.min(usize::MAX as u64) as usize;
        let length = until_line_end.min(remaining).min(MAX_WRITE_BYTES);
        Some(&self.line[self.position..self.position + length])
    }

    fn advance(&mut self, length: usize) {
        self.remaining -= length as u64;
        self.position += length;
        if self.position == self.line.len() {
            self.position = 0;
        }
    }

    fn complete(&mut self) {
        self.remaining = 0;
    }
}
