use std::sync::mpsc::{self, Sender};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use super::{FixtureError, HARD_DEADLINE_MS};

pub(crate) struct DeadlineGuard {
    cancel: Option<Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

impl DeadlineGuard {
    pub(crate) fn start() -> Result<Self, FixtureError> {
        let (cancel, receiver) = mpsc::channel();
        let thread = thread::Builder::new()
            .name("fixture-hard-deadline".to_owned())
            .spawn(move || {
                if receiver
                    .recv_timeout(Duration::from_millis(HARD_DEADLINE_MS))
                    .is_err()
                {
                    std::process::exit(FixtureError::TimedOut.exit_code().into());
                }
            })
            .map_err(|_| FixtureError::Runtime)?;
        Ok(Self {
            cancel: Some(cancel),
            thread: Some(thread),
        })
    }
}

impl Drop for DeadlineGuard {
    fn drop(&mut self) {
        if let Some(cancel) = self.cancel.take() {
            let _ = cancel.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
