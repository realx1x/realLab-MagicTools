mod authorization;
mod config;
mod deadline;
mod encoding;
mod log_output;
mod network;
mod process_tree;

use std::process::ExitCode;

pub(crate) const HARD_DEADLINE_MS: u64 = 60_000;
pub(crate) const MAX_HOLD_MS: u64 = 50_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FixtureError {
    Authorization,
    InvalidArguments,
    Runtime,
    TimedOut,
}

impl FixtureError {
    fn exit_code(self) -> u8 {
        match self {
            Self::Authorization | Self::InvalidArguments => 64,
            Self::Runtime => 70,
            Self::TimedOut => 124,
        }
    }
}

pub(crate) fn main_entry() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => ExitCode::from(error.exit_code()),
    }
}

fn run() -> Result<(), FixtureError> {
    let authorized = authorization::authorize()?;
    let invocation = config::parse(authorized)?;
    let _deadline = deadline::DeadlineGuard::start()?;

    match invocation {
        config::Invocation::ProcessTree(value) => process_tree::run_root(value),
        config::Invocation::Network(value) => network::run(value),
        config::Invocation::LogFlood(value) => log_output::run_flood(value),
        config::Invocation::Encoding(value) => encoding::run(value),
        config::Invocation::InternalProcess(value) => process_tree::run_internal(value),
    }
}
