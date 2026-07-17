use std::collections::HashMap;
use std::ffi::OsString;
use std::io;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use thiserror::Error;
use tokio::fs::{self, File, OpenOptions};
use tokio::io::{AsyncRead, AsyncWriteExt};
use tokio::process::{Child, Command};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};

const COMMAND_CAPACITY: usize = 64;
const EVENT_CAPACITY: usize = 128;
const REAP_INTERVAL: Duration = Duration::from_millis(250);

static NEXT_SUPERVISOR_ID: AtomicU64 = AtomicU64::new(1);

pub type RunId = u64;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessInstanceKey {
    pub boot_id: String,
    pub pid: u32,
    pub native_start_time: u64,
}

#[derive(Clone, Debug)]
pub struct LaunchRequest {
    pub executable: PathBuf,
    pub arguments: Vec<OsString>,
    pub working_directory: PathBuf,
    pub log_directory: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunSnapshot {
    pub run_id: RunId,
    pub pid: u32,
}

/// Persisted identities are reconciliation hints only. They cannot construct a
/// ManagedRun because only a live Child handle proves ownership in this spike.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistedRunHint {
    pub run_id: RunId,
    pub instance_key: ProcessInstanceKey,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExplicitExitPolicy {
    KeepRunning,
    StopAll,
    Cancel,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExplicitExitDecision {
    UiMayExitKeepingRuns { active_runs: usize },
    StopRequested { requested: usize, failed: usize },
    Cancelled,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SupervisorEvent {
    RunStarted(RunSnapshot),
    StopRequested {
        run_id: RunId,
    },
    RunExited {
        run_id: RunId,
        exit_code: Option<i32>,
    },
    RunFailed {
        run_id: RunId,
        message: String,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SupervisorShutdownDecision {
    Accepted,
    RefusedActiveRuns { active_runs: usize },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpgradeHandoffDecision {
    Accepted { transferred_runs: usize },
    AcknowledgementLost { transferred_runs: usize },
    RejectedSameSupervisor,
    RejectedTargetBusy { target_runs: usize },
    RejectedTargetUnavailable,
}

#[derive(Debug, Error)]
pub enum SupervisorError {
    #[error("the Supervisor command channel is closed")]
    CommandChannelClosed,
    #[error("the Supervisor reply channel is closed")]
    ReplyChannelClosed,
    #[error("run {0} was not found")]
    RunNotFound(RunId),
    #[error("failed to launch or manage a process: {0}")]
    Io(#[from] io::Error),
}

/// The per-user Supervisor process owns this runtime. Dropping the JoinHandle
/// detaches rather than aborts the actor, so UI lifetime cannot cancel it.
pub struct SupervisorRuntime {
    supervisor_id: u64,
    commands: mpsc::Sender<SupervisorCommand>,
    _actor: JoinHandle<()>,
}

impl SupervisorRuntime {
    pub fn spawn() -> Self {
        let supervisor_id = NEXT_SUPERVISOR_ID.fetch_add(1, Ordering::Relaxed);
        let (commands, receiver) = mpsc::channel(COMMAND_CAPACITY);
        let actor = SupervisorActor::new(receiver);
        let actor = tokio::spawn(actor.run());

        Self {
            supervisor_id,
            commands,
            _actor: actor,
        }
    }

    pub async fn connect_ui(&self) -> Result<UiSession, SupervisorError> {
        let (events, event_receiver) = mpsc::channel(EVENT_CAPACITY);
        let (reply, acknowledged) = oneshot::channel();
        self.commands
            .send(SupervisorCommand::ConnectUi { events, reply })
            .await
            .map_err(|_| SupervisorError::CommandChannelClosed)?;
        acknowledged
            .await
            .map_err(|_| SupervisorError::ReplyChannelClosed)?;

        Ok(UiSession {
            commands: self.commands.clone(),
            events: event_receiver,
        })
    }

    pub async fn request_shutdown(&self) -> Result<SupervisorShutdownDecision, SupervisorError> {
        let (reply, decision) = oneshot::channel();
        self.commands
            .send(SupervisorCommand::RequestShutdown { reply })
            .await
            .map_err(|_| SupervisorError::CommandChannelClosed)?;
        decision
            .await
            .map_err(|_| SupervisorError::ReplyChannelClosed)
    }

    /// Moves the actual Child handles, run table, and log task handles to the
    /// replacement actor. No persisted PID is accepted by this API.
    pub async fn handoff_to(
        &self,
        replacement: &SupervisorRuntime,
    ) -> Result<UpgradeHandoffDecision, SupervisorError> {
        if self.supervisor_id == replacement.supervisor_id {
            return Ok(UpgradeHandoffDecision::RejectedSameSupervisor);
        }

        let (reply, decision) = oneshot::channel();
        self.commands
            .send(SupervisorCommand::RequestHandoff {
                target: replacement.commands.clone(),
                reply,
            })
            .await
            .map_err(|_| SupervisorError::CommandChannelClosed)?;
        decision
            .await
            .map_err(|_| SupervisorError::ReplyChannelClosed)
    }
}

/// UI state is intentionally limited to a command sender and a bounded event
/// receiver. Dropping either end cannot reach or drop the actor's RunTable.
pub struct UiSession {
    commands: mpsc::Sender<SupervisorCommand>,
    events: mpsc::Receiver<SupervisorEvent>,
}

impl UiSession {
    pub async fn start_run(&self, request: LaunchRequest) -> Result<RunSnapshot, SupervisorError> {
        let (reply, result) = oneshot::channel();
        self.commands
            .send(SupervisorCommand::StartRun { request, reply })
            .await
            .map_err(|_| SupervisorError::CommandChannelClosed)?;
        result
            .await
            .map_err(|_| SupervisorError::ReplyChannelClosed)?
    }

    pub async fn stop_run(&self, run_id: RunId) -> Result<(), SupervisorError> {
        let (reply, result) = oneshot::channel();
        self.commands
            .send(SupervisorCommand::StopRun { run_id, reply })
            .await
            .map_err(|_| SupervisorError::CommandChannelClosed)?;
        result
            .await
            .map_err(|_| SupervisorError::ReplyChannelClosed)?
    }

    pub async fn request_explicit_exit(
        &self,
        policy: ExplicitExitPolicy,
    ) -> Result<ExplicitExitDecision, SupervisorError> {
        let (reply, decision) = oneshot::channel();
        self.commands
            .send(SupervisorCommand::ExplicitUiExit { policy, reply })
            .await
            .map_err(|_| SupervisorError::CommandChannelClosed)?;
        decision
            .await
            .map_err(|_| SupervisorError::ReplyChannelClosed)
    }

    pub async fn next_event(&mut self) -> Option<SupervisorEvent> {
        self.events.recv().await
    }
}

enum SupervisorCommand {
    ConnectUi {
        events: mpsc::Sender<SupervisorEvent>,
        reply: oneshot::Sender<()>,
    },
    StartRun {
        request: LaunchRequest,
        reply: oneshot::Sender<Result<RunSnapshot, SupervisorError>>,
    },
    StopRun {
        run_id: RunId,
        reply: oneshot::Sender<Result<(), SupervisorError>>,
    },
    ExplicitUiExit {
        policy: ExplicitExitPolicy,
        reply: oneshot::Sender<ExplicitExitDecision>,
    },
    RequestShutdown {
        reply: oneshot::Sender<SupervisorShutdownDecision>,
    },
    RequestHandoff {
        target: mpsc::Sender<SupervisorCommand>,
        reply: oneshot::Sender<UpgradeHandoffDecision>,
    },
    AcceptHandoff {
        runs: RunTable,
        reply: oneshot::Sender<HandoffAcceptance>,
    },
}

enum HandoffAcceptance {
    Accepted {
        transferred_runs: usize,
    },
    RejectedBusy {
        existing_runs: usize,
        runs: RunTable,
    },
}

type RunTable = HashMap<RunId, ManagedRun>;

struct ManagedRun {
    snapshot: RunSnapshot,
    child: Child,
    stdout_log: JoinHandle<io::Result<u64>>,
    stderr_log: JoinHandle<io::Result<u64>>,
    stop_requested: bool,
}

struct SupervisorActor {
    commands: mpsc::Receiver<SupervisorCommand>,
    runs: RunTable,
    subscribers: Vec<mpsc::Sender<SupervisorEvent>>,
    next_run_id: RunId,
}

impl SupervisorActor {
    fn new(commands: mpsc::Receiver<SupervisorCommand>) -> Self {
        Self {
            commands,
            runs: HashMap::new(),
            subscribers: Vec::new(),
            next_run_id: 1,
        }
    }

    async fn run(mut self) {
        let mut commands_closed = false;

        loop {
            if commands_closed {
                sleep(REAP_INTERVAL).await;
            } else if let Ok(command) = timeout(REAP_INTERVAL, self.commands.recv()).await {
                match command {
                    Some(command) => {
                        if !self.handle_command(command).await {
                            break;
                        }
                    }
                    None => commands_closed = true,
                }
            }
            self.reap_exited().await;

            if commands_closed && self.runs.is_empty() {
                break;
            }
        }
    }

    async fn handle_command(&mut self, command: SupervisorCommand) -> bool {
        match command {
            SupervisorCommand::ConnectUi { events, reply } => {
                self.subscribers.push(events);
                let _ = reply.send(());
            }
            SupervisorCommand::StartRun { request, reply } => {
                let result = self.start_run(request).await;
                let _ = reply.send(result);
            }
            SupervisorCommand::StopRun { run_id, reply } => {
                let result = self.stop_run(run_id);
                let _ = reply.send(result);
            }
            SupervisorCommand::ExplicitUiExit { policy, reply } => {
                let decision = self.explicit_ui_exit(policy);
                let _ = reply.send(decision);
            }
            SupervisorCommand::RequestShutdown { reply } => {
                if self.runs.is_empty() {
                    let _ = reply.send(SupervisorShutdownDecision::Accepted);
                    return false;
                }
                let _ = reply.send(SupervisorShutdownDecision::RefusedActiveRuns {
                    active_runs: self.runs.len(),
                });
            }
            SupervisorCommand::RequestHandoff { target, reply } => {
                let decision = self.transfer_to(target).await;
                let ownership_moved = matches!(
                    decision,
                    UpgradeHandoffDecision::Accepted { .. }
                        | UpgradeHandoffDecision::AcknowledgementLost { .. }
                );
                let _ = reply.send(decision);
                if ownership_moved {
                    return false;
                }
            }
            SupervisorCommand::AcceptHandoff { runs, reply } => {
                if self.runs.is_empty() {
                    let transferred_runs = runs.len();
                    self.runs = runs;
                    let _ = reply.send(HandoffAcceptance::Accepted { transferred_runs });
                } else {
                    let existing_runs = self.runs.len();
                    let _ = reply.send(HandoffAcceptance::RejectedBusy {
                        existing_runs,
                        runs,
                    });
                }
            }
        }
        true
    }

    async fn start_run(&mut self, request: LaunchRequest) -> Result<RunSnapshot, SupervisorError> {
        fs::create_dir_all(&request.log_directory).await?;
        let stdout_file = create_log_file(request.log_directory.join("stdout.log")).await?;
        let stderr_file = create_log_file(request.log_directory.join("stderr.log")).await?;

        let mut command = Command::new(&request.executable);
        command
            .args(&request.arguments)
            .current_dir(&request.working_directory)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(false);
        let mut child = command.spawn()?;
        let pid = child.id().ok_or_else(|| {
            io::Error::other("spawned process did not expose a process identifier")
        })?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("spawned process did not expose its piped stdout"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| io::Error::other("spawned process did not expose its piped stderr"))?;

        let run_id = self.next_run_id;
        self.next_run_id = self.next_run_id.saturating_add(1);
        let snapshot = RunSnapshot { run_id, pid };
        let managed = ManagedRun {
            snapshot: snapshot.clone(),
            child,
            stdout_log: tokio::spawn(copy_log(stdout, stdout_file)),
            stderr_log: tokio::spawn(copy_log(stderr, stderr_file)),
            stop_requested: false,
        };
        self.runs.insert(run_id, managed);
        self.emit(SupervisorEvent::RunStarted(snapshot.clone()));
        Ok(snapshot)
    }

    fn stop_run(&mut self, run_id: RunId) -> Result<(), SupervisorError> {
        let run = self
            .runs
            .get_mut(&run_id)
            .ok_or(SupervisorError::RunNotFound(run_id))?;
        let newly_requested = !run.stop_requested;
        run.stop_requested = true;
        if newly_requested {
            self.emit(SupervisorEvent::StopRequested { run_id });
        }
        Ok(())
    }

    fn explicit_ui_exit(&mut self, policy: ExplicitExitPolicy) -> ExplicitExitDecision {
        match policy {
            ExplicitExitPolicy::KeepRunning => ExplicitExitDecision::UiMayExitKeepingRuns {
                active_runs: self.runs.len(),
            },
            ExplicitExitPolicy::Cancel => ExplicitExitDecision::Cancelled,
            ExplicitExitPolicy::StopAll => {
                let run_ids = self.runs.keys().copied().collect::<Vec<_>>();
                for run_id in &run_ids {
                    let run = self
                        .runs
                        .get_mut(run_id)
                        .expect("run id came from the same table");
                    if !run.stop_requested {
                        run.stop_requested = true;
                        self.emit(SupervisorEvent::StopRequested { run_id: *run_id });
                    }
                }
                ExplicitExitDecision::StopRequested {
                    requested: run_ids.len(),
                    failed: 0,
                }
            }
        }
    }

    async fn transfer_to(
        &mut self,
        target: mpsc::Sender<SupervisorCommand>,
    ) -> UpgradeHandoffDecision {
        let runs = std::mem::take(&mut self.runs);
        let transferred_runs = runs.len();
        let (reply, acceptance) = oneshot::channel();
        let command = SupervisorCommand::AcceptHandoff { runs, reply };

        if let Err(error) = target.send(command).await {
            if let SupervisorCommand::AcceptHandoff { runs, .. } = error.0 {
                self.runs = runs;
            }
            return UpgradeHandoffDecision::RejectedTargetUnavailable;
        }

        match acceptance.await {
            Ok(HandoffAcceptance::Accepted { transferred_runs }) => {
                UpgradeHandoffDecision::Accepted { transferred_runs }
            }
            Ok(HandoffAcceptance::RejectedBusy {
                existing_runs,
                runs,
            }) => {
                self.runs = runs;
                UpgradeHandoffDecision::RejectedTargetBusy {
                    target_runs: existing_runs,
                }
            }
            Err(_) => {
                // The resources crossed the channel, so the old actor cannot safely
                // recreate them from persisted PIDs. A real cross-process handoff
                // must keep the old process alive until a durable acknowledgement.
                UpgradeHandoffDecision::AcknowledgementLost { transferred_runs }
            }
        }
    }

    async fn reap_exited(&mut self) {
        let mut exited = Vec::new();
        for (&run_id, run) in &mut self.runs {
            match run.child.try_wait() {
                Ok(Some(status)) => exited.push((run_id, status.code(), None)),
                Ok(None) => {}
                Err(error) => exited.push((run_id, None, Some(error.to_string()))),
            }
        }

        for (run_id, exit_code, error) in exited {
            if let Some(run) = self.runs.remove(&run_id) {
                let _ = run.stdout_log.await;
                let _ = run.stderr_log.await;
                debug_assert_eq!(run.snapshot.run_id, run_id);
            }
            if let Some(message) = error {
                self.emit(SupervisorEvent::RunFailed { run_id, message });
            } else {
                self.emit(SupervisorEvent::RunExited { run_id, exit_code });
            }
        }
    }

    fn emit(&mut self, event: SupervisorEvent) {
        self.subscribers
            .retain(|subscriber| match subscriber.try_send(event.clone()) {
                Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => true,
                Err(mpsc::error::TrySendError::Closed(_)) => false,
            });
    }
}

async fn create_log_file(path: PathBuf) -> io::Result<File> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await
}

async fn copy_log<R>(mut reader: R, mut file: File) -> io::Result<u64>
where
    R: AsyncRead + Unpin,
{
    let copied = tokio::io::copy(&mut reader, &mut file).await?;
    file.flush().await?;
    Ok(copied)
}
