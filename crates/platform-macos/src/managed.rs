use std::ffi::{c_char, c_int, c_short, c_void};
use std::fmt::{self, Display, Formatter};
use std::io::{self, PipeWriter, Read};
use std::mem::{MaybeUninit, size_of};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::ptr;
use std::sync::atomic::{Ordering, compiler_fence};
use std::thread;
use std::time::{Duration, Instant};

use domain::{AppError, ErrorCode, ExecutionPlatform, ProcessInstanceKey};
use lifecycle::{
    MAX_LAUNCH_ARGUMENT_BYTES, MAX_LAUNCH_ARGUMENT_TOTAL_BYTES, MAX_LAUNCH_ARGUMENTS,
    MAX_LAUNCH_ENVIRONMENT_ENTRIES, MAX_LAUNCH_ENVIRONMENT_NAME_BYTES,
    MAX_LAUNCH_ENVIRONMENT_VALUE_BYTES, MAX_LAUNCH_EXECUTABLE_BYTES,
    MAX_LAUNCH_WORKING_DIRECTORY_BYTES, ResolvedEnvironment,
};

const CLEANUP_WAIT: Duration = Duration::from_secs(5);
const CLEANUP_POLL_INTERVAL: Duration = Duration::from_millis(10);
const MAX_MACOS_EXEC_ARGUMENT_ENV_BYTES: usize = 256 * 1_024;
const DEV_NULL: &[u8] = b"/dev/null\0";

unsafe extern "C" {
    fn posix_spawn_file_actions_addchdir_np(
        actions: *mut libc::posix_spawn_file_actions_t,
        path: *const c_char,
    ) -> c_int;
}

/// Fully resolved macOS launch data. `argv` excludes argv[0]; the adapter
/// inserts the exact absolute executable path and never performs PATH lookup.
pub struct MacosManagedLaunchRequest<'a> {
    pub executable: &'a str,
    pub argv: &'a [String],
    pub working_directory: &'a str,
    pub environment: &'a ResolvedEnvironment,
    pub stdio: MacosManagedStdio<'a>,
}

/// Standard-I/O topology for one managed macOS child. Ordinary runs retain
/// independent stdout/stderr pipes. A terminal is allocated only when the
/// launch profile is explicitly interactive.
pub enum MacosManagedStdio<'a> {
    Pipes {
        stdout: &'a PipeWriter,
        stderr: &'a PipeWriter,
    },
    Terminal {
        rows: u16,
        columns: u16,
    },
}

/// The single readable view of an interactive terminal master. Darwin reports
/// `EIO` rather than a zero-length read after the final slave closes; callers
/// observe both forms as EOF.
pub struct MacosManagedTerminalOutput {
    master: OwnedFd,
}

impl Read for MacosManagedTerminalOutput {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        let length = buffer.len().min(isize::MAX as usize);
        loop {
            clear_errno();
            // Safety: master is a live descriptor and buffer exposes length
            // writable bytes for the duration of this call.
            let read =
                unsafe { libc::read(self.master.as_raw_fd(), buffer.as_mut_ptr().cast(), length) };
            if read >= 0 {
                return Ok(read as usize);
            }
            let error = current_errno();
            if error == libc::EINTR {
                continue;
            }
            if error == libc::EIO {
                return Ok(0);
            }
            return Err(io::Error::from_raw_os_error(error));
        }
    }
}

/// Closed result of one managed stop signal attempt. Platform failures are
/// values so the Supervisor can persist the operation outcome while retaining
/// this process owner for a later retry.
#[derive(Clone, Debug, PartialEq)]
pub enum MacosManagedStopSignalResult {
    Delivered,
    SignalUnavailable(AppError),
}

/// Non-blocking observation of the root child and its dedicated process group.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacosManagedExitPoll {
    Running,
    Exited,
}

/// Closed result of reconciling one persisted macOS managed process group.
/// Only `Recovered` carries control capability; every other result is
/// deliberately evidence-only.
#[derive(Debug)]
pub enum MacosManagedRecoveryProbe {
    Recovered(RecoveredMacosProcessGroup),
    ExitedWhileOffline,
    IdentityMismatch,
    Orphaned,
}

/// Control evidence recovered after the original Supervisor process exited.
///
/// This value owns no child, wait right, or output pipe. Dropping it therefore
/// has no process-side effect. Every nonzero signal revalidates the complete
/// process identity and dedicated PGID immediately before delivery.
pub struct RecoveredMacosProcessGroup {
    instance_key: ProcessInstanceKey,
    process_group_id: libc::pid_t,
    exit_confirmed: bool,
}

impl RecoveredMacosProcessGroup {
    pub fn instance_key(&self) -> &ProcessInstanceKey {
        &self.instance_key
    }

    pub fn process_group_id(&self) -> u32 {
        self.process_group_id as u32
    }

    pub fn validate_identity_and_group(&self) -> Result<(), AppError> {
        revalidate_recovered_identity_and_group(&self.instance_key, self.process_group_id)
    }

    /// Revalidates boot identity, PID, start time, and PGID immediately before
    /// sending SIGTERM to the recovered dedicated process group.
    pub fn send_graceful(&mut self) -> Result<MacosManagedStopSignalResult, AppError> {
        self.send_stop_signal(libc::SIGTERM, "killpg(SIGTERM)")
    }

    /// Revalidates boot identity, PID, start time, and PGID immediately before
    /// sending SIGKILL to the recovered dedicated process group.
    pub fn send_force(&mut self) -> Result<MacosManagedStopSignalResult, AppError> {
        self.send_stop_signal(libc::SIGKILL, "killpg(SIGKILL)")
    }

    /// Observes only the persisted process group. A recovered owner has no
    /// parent wait right, so only ESRCH from killpg(0) confirms final exit.
    pub fn poll_exit(&mut self) -> Result<MacosManagedExitPoll, AppError> {
        if self.exit_confirmed {
            return Ok(MacosManagedExitPoll::Exited);
        }
        match send_signal(-self.process_group_id, 0) {
            Ok(SignalOutcome::Delivered) => Ok(MacosManagedExitPoll::Running),
            Ok(SignalOutcome::Missing) => {
                self.exit_confirmed = true;
                Ok(MacosManagedExitPoll::Exited)
            }
            Err(errno) => Err(errno_app_error("killpg(0)", errno)),
        }
    }

    fn send_stop_signal(
        &mut self,
        signal: c_int,
        stage: &'static str,
    ) -> Result<MacosManagedStopSignalResult, AppError> {
        if self.exit_confirmed {
            return Ok(MacosManagedStopSignalResult::SignalUnavailable(
                managed_error(
                    ErrorCode::AlreadyExited,
                    stage,
                    "recovered macOS process group exit was already confirmed",
                ),
            ));
        }
        self.validate_identity_and_group()?;
        match send_signal(-self.process_group_id, signal) {
            Ok(SignalOutcome::Delivered) => Ok(MacosManagedStopSignalResult::Delivered),
            Ok(SignalOutcome::Missing) => Ok(MacosManagedStopSignalResult::SignalUnavailable(
                errno_app_error(stage, libc::ESRCH),
            )),
            Err(errno) => Ok(MacosManagedStopSignalResult::SignalUnavailable(
                errno_app_error(stage, errno),
            )),
        }
    }
}

impl fmt::Debug for RecoveredMacosProcessGroup {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoveredMacosProcessGroup")
            .field("instance_key", &self.instance_key)
            .field("process_group_id", &self.process_group_id)
            .field("exit_confirmed", &self.exit_confirmed)
            .finish_non_exhaustive()
    }
}

/// Reconciles persisted identity and PGID evidence without adopting a child or
/// fabricating wait/log capabilities. Invalid or incomplete evidence is always
/// orphaned; only an explicit ESRCH proves that the process exited offline.
pub fn probe_recovered_process_group(
    instance_key: &ProcessInstanceKey,
    persisted_process_group_id: u32,
) -> MacosManagedRecoveryProbe {
    let Some(pid) = i32::try_from(instance_key.pid).ok().filter(|pid| *pid > 0) else {
        return MacosManagedRecoveryProbe::Orphaned;
    };
    let Some(process_group_id) = i32::try_from(persisted_process_group_id)
        .ok()
        .filter(|process_group_id| *process_group_id > 0)
    else {
        return MacosManagedRecoveryProbe::Orphaned;
    };
    if process_group_id != pid || persisted_process_group_id != instance_key.pid {
        return MacosManagedRecoveryProbe::Orphaned;
    }
    let Some(expected_boot) = parse_canonical_nonzero_u64(&instance_key.boot_id) else {
        return MacosManagedRecoveryProbe::Orphaned;
    };
    let Some(expected_start) = parse_canonical_nonzero_u64(&instance_key.native_start_time) else {
        return MacosManagedRecoveryProbe::Orphaned;
    };

    let boot_id = match crate::native::query_boot_identifier() {
        Ok(boot_id) => boot_id,
        Err(_) => return MacosManagedRecoveryProbe::Orphaned,
    };
    if parse_canonical_nonzero_u64(&boot_id) != Some(expected_boot)
        || boot_id != instance_key.boot_id
    {
        return MacosManagedRecoveryProbe::ExitedWhileOffline;
    }

    let observation = match query_process_observation(pid) {
        Ok(Some(observation)) => observation,
        Ok(None) => return classify_missing_recovered_root(process_group_id),
        Err(_) => return MacosManagedRecoveryProbe::Orphaned,
    };
    if observation.pid != instance_key.pid || observation.start_micros != expected_start {
        return MacosManagedRecoveryProbe::IdentityMismatch;
    }
    if observation.process_group_id != persisted_process_group_id
        || observation.process_group_id != observation.pid
    {
        return MacosManagedRecoveryProbe::Orphaned;
    }

    match query_process_group(pid) {
        Ok(Some(observed_process_group)) if observed_process_group == process_group_id => {
            MacosManagedRecoveryProbe::Recovered(RecoveredMacosProcessGroup {
                instance_key: instance_key.clone(),
                process_group_id,
                exit_confirmed: false,
            })
        }
        Ok(Some(_)) | Err(_) => MacosManagedRecoveryProbe::Orphaned,
        Ok(None) => classify_missing_recovered_root(process_group_id),
    }
}

fn classify_missing_recovered_root(process_group_id: libc::pid_t) -> MacosManagedRecoveryProbe {
    match send_signal(-process_group_id, 0) {
        Ok(SignalOutcome::Missing) => MacosManagedRecoveryProbe::ExitedWhileOffline,
        Ok(SignalOutcome::Delivered) | Err(_) => MacosManagedRecoveryProbe::Orphaned,
    }
}

struct MacosManagedTerminal {
    master: OwnedFd,
    output: Option<MacosManagedTerminalOutput>,
}

impl MacosManagedTerminal {
    fn take_output(&mut self) -> Option<MacosManagedTerminalOutput> {
        self.output.take()
    }

    fn write_all(&mut self, mut input: &[u8]) -> Result<(), AppError> {
        while !input.is_empty() {
            let length = input.len().min(isize::MAX as usize);
            clear_errno();
            // Safety: master is a live descriptor and input exposes length
            // readable bytes for the duration of this call.
            let written =
                unsafe { libc::write(self.master.as_raw_fd(), input.as_ptr().cast(), length) };
            if written > 0 {
                input = &input[written as usize..];
                continue;
            }
            if written == 0 {
                return Err(managed_error(
                    ErrorCode::PlatformError,
                    "write(pty-master)",
                    "macOS terminal input write made no progress",
                ));
            }
            let error = current_errno();
            if error != libc::EINTR {
                return Err(errno_app_error("write(pty-master)", error));
            }
        }
        Ok(())
    }

    fn resize(&self, rows: u16, columns: u16) -> Result<(), AppError> {
        validate_terminal_size(rows, columns)?;
        let size = terminal_window_size(rows, columns);
        clear_errno();
        // Safety: master is a live terminal descriptor and size points to a
        // complete winsize value for the duration of the ioctl.
        if unsafe {
            libc::ioctl(
                self.master.as_raw_fd(),
                libc::TIOCSWINSZ as _,
                &size as *const _,
            )
        } != 0
        {
            return Err(errno_app_error("ioctl(TIOCSWINSZ)", current_errno()));
        }
        Ok(())
    }
}

fn required_terminal(
    terminal: &Option<MacosManagedTerminal>,
) -> Result<&MacosManagedTerminal, AppError> {
    terminal.as_ref().ok_or_else(terminal_unavailable_error)
}

fn required_terminal_mut(
    terminal: &mut Option<MacosManagedTerminal>,
) -> Result<&mut MacosManagedTerminal, AppError> {
    terminal.as_mut().ok_or_else(terminal_unavailable_error)
}

fn terminal_unavailable_error() -> AppError {
    managed_error(
        ErrorCode::NotSupported,
        "ManagedTerminal",
        "managed run does not own an interactive macOS terminal",
    )
}

/// A child created in its own process group and held before user code runs.
pub struct SuspendedMacosManagedProcess {
    child: Option<OwnedMacosChild>,
    instance_key: ProcessInstanceKey,
    process_group_id: u32,
    terminal: Option<MacosManagedTerminal>,
}

impl SuspendedMacosManagedProcess {
    pub fn instance_key(&self) -> &ProcessInstanceKey {
        &self.instance_key
    }

    pub fn process_group_id(&self) -> u32 {
        self.process_group_id
    }

    pub fn is_terminal(&self) -> bool {
        self.terminal.is_some()
    }

    /// Transfers the only readable terminal-master descriptor to the capture
    /// owner. Input and resize remain available through this process owner.
    pub fn take_terminal_output(&mut self) -> Option<MacosManagedTerminalOutput> {
        self.terminal
            .as_mut()
            .and_then(MacosManagedTerminal::take_output)
    }

    pub fn write_terminal_input(&mut self, input: &[u8]) -> Result<(), AppError> {
        required_terminal_mut(&mut self.terminal)?.write_all(input)
    }

    pub fn resize_terminal(&self, rows: u16, columns: u16) -> Result<(), AppError> {
        required_terminal(&self.terminal)?.resize(rows, columns)
    }

    pub fn abort(mut self) -> Result<(), MacosManagedLaunchError> {
        let child = self.child.take().expect("suspended macOS child owner");
        terminate_owned_child(child)
    }

    /// Revalidates the complete instance and PGID immediately before SIGCONT.
    pub fn resume(mut self) -> Result<MacosManagedProcess, MacosManagedLaunchError> {
        let mut child = self.child.take().expect("suspended macOS child owner");
        if let Err(error) = child.revalidate_identity_and_group() {
            return Err(cleanup_after_failure(error, child));
        }
        match send_signal(child.pid, libc::SIGCONT) {
            Ok(SignalOutcome::Delivered) => {}
            Ok(SignalOutcome::Missing) => {
                return Err(cleanup_after_failure(
                    managed_error(
                        ErrorCode::NotFound,
                        "SIGCONT",
                        "managed child no longer exists",
                    ),
                    child,
                ));
            }
            Err(errno) => {
                return Err(cleanup_after_failure(
                    errno_app_error("SIGCONT", errno),
                    child,
                ));
            }
        }
        child.execution = ChildExecution::Running;
        Ok(MacosManagedProcess {
            child: Some(child),
            instance_key: self.instance_key.clone(),
            process_group_id: self.process_group_id,
            terminal: self.terminal.take(),
        })
    }
}

impl fmt::Debug for SuspendedMacosManagedProcess {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SuspendedMacosManagedProcess")
            .field("instance_key", &self.instance_key)
            .field("process_group_id", &self.process_group_id)
            .field("terminal", &self.is_terminal())
            .finish_non_exhaustive()
    }
}

impl Drop for SuspendedMacosManagedProcess {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take()
            && child.terminate_and_confirm().is_err()
        {
            quarantine_failed_cleanup(child);
        }
    }
}

/// Owns the parent wait right and the verified process-group control evidence.
pub struct MacosManagedProcess {
    child: Option<OwnedMacosChild>,
    instance_key: ProcessInstanceKey,
    process_group_id: u32,
    terminal: Option<MacosManagedTerminal>,
}

impl MacosManagedProcess {
    pub fn instance_key(&self) -> &ProcessInstanceKey {
        &self.instance_key
    }

    pub fn process_group_id(&self) -> u32 {
        self.process_group_id
    }

    pub fn is_terminal(&self) -> bool {
        self.terminal.is_some()
    }

    pub fn write_terminal_input(&mut self, input: &[u8]) -> Result<(), AppError> {
        required_terminal_mut(&mut self.terminal)?.write_all(input)
    }

    pub fn resize_terminal(&self, rows: u16, columns: u16) -> Result<(), AppError> {
        required_terminal(&self.terminal)?.resize(rows, columns)
    }

    pub fn validate_identity_and_group(&self) -> Result<(), AppError> {
        self.child
            .as_ref()
            .expect("running macOS child owner")
            .revalidate_identity_and_group()
    }

    /// Revalidates boot identity, PID, start time, and PGID immediately before
    /// sending SIGTERM to the dedicated process group.
    pub fn send_graceful(&mut self) -> Result<MacosManagedStopSignalResult, AppError> {
        self.child
            .as_mut()
            .expect("running macOS child owner")
            .send_managed_stop_signal(libc::SIGTERM, "killpg(SIGTERM)", false)
    }

    /// Revalidates boot identity, PID, start time, and PGID immediately before
    /// sending SIGKILL to the dedicated process group.
    pub fn send_force(&mut self) -> Result<MacosManagedStopSignalResult, AppError> {
        self.child
            .as_mut()
            .expect("running macOS child owner")
            .send_managed_stop_signal(libc::SIGKILL, "killpg(SIGKILL)", true)
    }

    /// Performs one non-blocking exit observation without sending another
    /// terminating signal. The root is not reaped while its original PGID
    /// still exists, preserving the identity evidence required by escalation.
    pub fn poll_exit(&mut self) -> Result<MacosManagedExitPoll, AppError> {
        self.child
            .as_mut()
            .expect("running macOS child owner")
            .poll_managed_exit()
    }

    /// Observes a natural exit without requiring or delivering a stop signal.
    /// The process group must disappear before the owned root is reaped, so a
    /// surviving descendant cannot be mistaken for complete run exit.
    pub fn poll_natural_exit(&mut self) -> Result<MacosManagedExitPoll, AppError> {
        self.child
            .as_mut()
            .expect("running macOS child owner")
            .poll_natural_exit()
    }

    /// Sends SIGKILL only after identity and PGID revalidation, then confirms
    /// both the root child was reaped and the controlled process group is gone.
    pub fn terminate_and_wait(mut self) -> Result<(), MacosManagedLaunchError> {
        let child = self.child.take().expect("running macOS child owner");
        terminate_owned_child(child)
    }
}

impl fmt::Debug for MacosManagedProcess {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MacosManagedProcess")
            .field("instance_key", &self.instance_key)
            .field("process_group_id", &self.process_group_id)
            .field("terminal", &self.is_terminal())
            .finish_non_exhaustive()
    }
}

impl Drop for MacosManagedProcess {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take()
            && child.terminate_and_confirm().is_err()
        {
            quarantine_failed_cleanup(child);
        }
    }
}

#[must_use = "cleanup-pending launch errors retain child control evidence and must be retried"]
pub struct MacosManagedLaunchError {
    public: AppError,
    pending_cleanup: Option<OwnedMacosChild>,
}

impl MacosManagedLaunchError {
    pub fn public_error(&self) -> &AppError {
        &self.public
    }

    pub fn cleanup_pending(&self) -> bool {
        self.pending_cleanup.is_some()
    }

    pub fn process_instance_key(&self) -> Option<&ProcessInstanceKey> {
        self.pending_cleanup
            .as_ref()
            .and_then(|child| child.identity.as_ref())
    }

    pub fn retry_cleanup(&mut self) -> Result<(), AppError> {
        let Some(mut child) = self.pending_cleanup.take() else {
            return Ok(());
        };
        match child.terminate_and_confirm() {
            Ok(()) => Ok(()),
            Err(cleanup) => {
                let error = cleanup_app_error(&cleanup);
                self.pending_cleanup = Some(child);
                Err(error)
            }
        }
    }
}

impl Display for MacosManagedLaunchError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        self.public.fmt(formatter)
    }
}

impl fmt::Debug for MacosManagedLaunchError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MacosManagedLaunchError")
            .field("public", &self.public)
            .field("cleanup_pending", &self.cleanup_pending())
            .finish()
    }
}

impl std::error::Error for MacosManagedLaunchError {}

impl Drop for MacosManagedLaunchError {
    fn drop(&mut self) {
        if let Some(mut child) = self.pending_cleanup.take()
            && child.terminate_and_confirm().is_err()
        {
            quarantine_failed_cleanup(child);
        }
    }
}

/// Atomically creates a suspended child whose PGID equals its PID. The caller
/// can durably persist the returned identity and PGID before calling resume.
pub fn prepare_suspended_process_group(
    request: &MacosManagedLaunchRequest<'_>,
) -> Result<SuspendedMacosManagedProcess, MacosManagedLaunchError> {
    validate_request(request).map_err(launch_error)?;
    let boot_id = crate::native::query_boot_identifier().map_err(|source| {
        launch_error(managed_error(
            source.code,
            "QueryBootIdentifier",
            "macOS boot identity could not be read",
        ))
    })?;
    let spawn_data = SpawnData::new(request).map_err(launch_error)?;
    let attributes = SpawnAttributes::new().map_err(launch_error)?;
    let (file_actions, terminal) =
        SpawnFileActions::new(request.working_directory, &request.stdio).map_err(launch_error)?;

    let mut pid: libc::pid_t = 0;
    // Safety: every C string and pointer array is NUL-terminated and remains
    // live through the call. posix_spawn (not posix_spawnp) receives an exact
    // absolute executable path, explicit argv/envp, attributes, and actions.
    let result = unsafe {
        libc::posix_spawn(
            &mut pid,
            spawn_data.executable_ptr(),
            file_actions.as_ptr(),
            attributes.as_ptr(),
            spawn_data.argv_ptr(),
            spawn_data.environment_ptr(),
        )
    };
    drop(file_actions);
    drop(spawn_data);
    if result != 0 {
        return Err(launch_error(errno_app_error("posix_spawn", result)));
    }
    if pid <= 0 {
        return Err(launch_error(managed_error(
            ErrorCode::PlatformError,
            "posix_spawn",
            "posix_spawn returned an invalid child identifier",
        )));
    }

    let mut child = OwnedMacosChild::new(pid);
    let observation = match query_process_observation(pid) {
        Ok(Some(observation)) => observation,
        Ok(None) => {
            return Err(cleanup_after_failure(
                managed_error(
                    ErrorCode::NotFound,
                    "proc_pidinfo(PROC_PIDTBSDINFO)",
                    "spawned macOS child disappeared before identity capture",
                ),
                child,
            ));
        }
        Err(error) => return Err(cleanup_after_failure(error, child)),
    };
    if observation.pid != pid as u32 || observation.process_group_id != pid as u32 {
        return Err(cleanup_after_failure(
            managed_error(
                ErrorCode::IdentityMismatch,
                "proc_pidinfo(PROC_PIDTBSDINFO)",
                "spawned macOS child did not enter its dedicated process group",
            ),
            child,
        ));
    }
    match query_process_group(pid) {
        Ok(Some(process_group)) if process_group == pid => {}
        Ok(Some(_)) => {
            return Err(cleanup_after_failure(
                managed_error(
                    ErrorCode::IdentityMismatch,
                    "getpgid",
                    "spawned macOS child process group did not equal its PID",
                ),
                child,
            ));
        }
        Ok(None) => {
            return Err(cleanup_after_failure(
                managed_error(
                    ErrorCode::NotFound,
                    "getpgid",
                    "spawned macOS child disappeared before PGID verification",
                ),
                child,
            ));
        }
        Err(error) => return Err(cleanup_after_failure(error, child)),
    }

    let pid_u32 = pid as u32;
    let instance_key = ProcessInstanceKey {
        boot_id,
        pid: pid_u32,
        native_start_time: observation.start_micros.to_string(),
    };
    child.identity = Some(instance_key.clone());
    child.group_verified = true;
    Ok(SuspendedMacosManagedProcess {
        child: Some(child),
        instance_key,
        process_group_id: pid_u32,
        terminal,
    })
}

fn validate_request(request: &MacosManagedLaunchRequest<'_>) -> Result<(), AppError> {
    validate_absolute_path(
        "executable",
        request.executable,
        MAX_LAUNCH_EXECUTABLE_BYTES,
    )?;
    validate_absolute_path(
        "workingDirectory",
        request.working_directory,
        MAX_LAUNCH_WORKING_DIRECTORY_BYTES,
    )?;
    if request.argv.len() > MAX_LAUNCH_ARGUMENTS {
        return Err(invalid_launch_input("argv", "contains too many arguments"));
    }
    let mut argument_bytes = request.executable.len().saturating_add(1);
    for argument in request.argv {
        if argument.contains('\0') || argument.len() > MAX_LAUNCH_ARGUMENT_BYTES {
            return Err(invalid_launch_input(
                "argv",
                "contains an invalid or overlong argument",
            ));
        }
        argument_bytes = argument_bytes
            .checked_add(argument.len().saturating_add(1))
            .ok_or_else(|| invalid_launch_input("argv", "exceeds the macOS argument budget"))?;
    }
    if argument_bytes > MAX_LAUNCH_ARGUMENT_TOTAL_BYTES.saturating_add(request.executable.len() + 1)
    {
        return Err(invalid_launch_input(
            "argv",
            "exceeds the macOS argument budget",
        ));
    }
    if request.environment.platform() != ExecutionPlatform::MacOs {
        return Err(invalid_launch_input(
            "environment",
            "must be resolved for macOS",
        ));
    }
    if request.environment.entries().len() > MAX_LAUNCH_ENVIRONMENT_ENTRIES {
        return Err(invalid_launch_input(
            "environment",
            "contains too many entries",
        ));
    }
    if let MacosManagedStdio::Terminal { rows, columns } = &request.stdio {
        validate_terminal_size(*rows, *columns)?;
    }
    Ok(())
}

fn validate_terminal_size(rows: u16, columns: u16) -> Result<(), AppError> {
    if rows == 0 || columns == 0 {
        return Err(invalid_launch_input(
            "terminalSize",
            "rows and columns must both be nonzero",
        ));
    }
    Ok(())
}

fn terminal_window_size(rows: u16, columns: u16) -> libc::winsize {
    libc::winsize {
        ws_row: rows,
        ws_col: columns,
        ws_xpixel: 0,
        ws_ypixel: 0,
    }
}

fn validate_absolute_path(
    field: &'static str,
    value: &str,
    maximum: usize,
) -> Result<(), AppError> {
    if value.is_empty() || value.contains('\0') || value.len() > maximum {
        return Err(invalid_launch_input(
            field,
            "must be a bounded absolute macOS path",
        ));
    }
    if value != "/"
        && !value.strip_prefix('/').is_some_and(|tail| {
            tail.split('/')
                .all(|component| !component.is_empty() && !matches!(component, "." | ".."))
        })
    {
        return Err(invalid_launch_input(
            field,
            "must be an absolute path without dot components",
        ));
    }
    Ok(())
}

fn portable_environment_name(value: &str) -> bool {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

struct SpawnData {
    executable: ZeroingCString,
    arguments: Vec<ZeroingCString>,
    argument_pointers: Vec<*mut c_char>,
    environment: Vec<ZeroingCString>,
    environment_pointers: Vec<*mut c_char>,
}

impl SpawnData {
    fn new(request: &MacosManagedLaunchRequest<'_>) -> Result<Self, AppError> {
        let executable = ZeroingCString::from_str(request.executable, "executable")?;
        let mut arguments = Vec::with_capacity(request.argv.len().saturating_add(1));
        arguments.push(ZeroingCString::from_str(request.executable, "argv")?);
        for argument in request.argv {
            arguments.push(ZeroingCString::from_str(argument, "argv")?);
        }

        let mut entries = request.environment.entries().iter().collect::<Vec<_>>();
        entries.sort_by(|left, right| left.name().cmp(right.name()));
        let mut previous_name: Option<&str> = None;
        let mut environment_bytes = 0_usize;
        for entry in &entries {
            if previous_name.is_some_and(|name| name == entry.name()) {
                return Err(invalid_launch_input(
                    "environment",
                    "contains duplicate names",
                ));
            }
            if !portable_environment_name(entry.name())
                || entry.name().len() > MAX_LAUNCH_ENVIRONMENT_NAME_BYTES
            {
                return Err(invalid_launch_input(
                    "environment.name",
                    "must match [A-Za-z_][A-Za-z0-9_]*",
                ));
            }
            let value = entry.value().expose();
            if value.contains('\0') || value.len() > MAX_LAUNCH_ENVIRONMENT_VALUE_BYTES {
                return Err(invalid_launch_input(
                    "environment.value",
                    "contains an invalid or overlong value",
                ));
            }
            environment_bytes = environment_bytes
                .checked_add(entry.name().len())
                .and_then(|bytes| bytes.checked_add(value.len()))
                .and_then(|bytes| bytes.checked_add(2))
                .ok_or_else(|| {
                    invalid_launch_input("environment", "exceeds the macOS environment budget")
                })?;
            previous_name = Some(entry.name());
        }

        let argument_bytes = arguments.iter().try_fold(0_usize, |total, argument| {
            total
                .checked_add(argument.len())
                .ok_or_else(|| invalid_launch_input("argv", "exceeds the macOS argument budget"))
        })?;
        if argument_bytes.saturating_add(environment_bytes) > MAX_MACOS_EXEC_ARGUMENT_ENV_BYTES {
            return Err(invalid_launch_input(
                "invocation",
                "exceeds the macOS argument and environment budget",
            ));
        }

        // All environment buffers allocate their exact size before the second
        // pass exposes and copies secret values, preventing growth copies.
        let mut environment = Vec::with_capacity(entries.len());
        for entry in entries {
            environment.push(ZeroingCString::from_environment(
                entry.name(),
                entry.value().expose(),
            )?);
        }

        let mut result = Self {
            executable,
            arguments,
            argument_pointers: Vec::new(),
            environment,
            environment_pointers: Vec::new(),
        };
        result.argument_pointers = pointer_array(&mut result.arguments);
        result.environment_pointers = pointer_array(&mut result.environment);
        Ok(result)
    }

    fn executable_ptr(&self) -> *const c_char {
        self.executable.as_ptr()
    }

    fn argv_ptr(&self) -> *const *mut c_char {
        self.argument_pointers.as_ptr()
    }

    fn environment_ptr(&self) -> *const *mut c_char {
        self.environment_pointers.as_ptr()
    }
}

fn pointer_array(values: &mut [ZeroingCString]) -> Vec<*mut c_char> {
    let mut pointers = Vec::with_capacity(values.len().saturating_add(1));
    pointers.extend(values.iter_mut().map(ZeroingCString::as_mut_ptr));
    pointers.push(ptr::null_mut());
    pointers
}

struct ZeroingCString(Vec<u8>);

impl ZeroingCString {
    fn from_str(value: &str, field: &'static str) -> Result<Self, AppError> {
        if value.contains('\0') {
            return Err(invalid_launch_input(field, "must not contain NUL"));
        }
        let mut bytes = Vec::with_capacity(value.len().saturating_add(1));
        bytes.extend_from_slice(value.as_bytes());
        bytes.push(0);
        Ok(Self(bytes))
    }

    fn from_environment(name: &str, value: &str) -> Result<Self, AppError> {
        if name.contains(['\0', '=']) || value.contains('\0') {
            return Err(invalid_launch_input(
                "environment",
                "contains an invalid name or value",
            ));
        }
        let capacity = name
            .len()
            .checked_add(value.len())
            .and_then(|bytes| bytes.checked_add(2))
            .ok_or_else(|| {
                invalid_launch_input("environment", "exceeds the macOS environment budget")
            })?;
        let mut bytes = Vec::with_capacity(capacity);
        bytes.extend_from_slice(name.as_bytes());
        bytes.push(b'=');
        bytes.extend_from_slice(value.as_bytes());
        bytes.push(0);
        debug_assert_eq!(bytes.len(), capacity);
        Ok(Self(bytes))
    }

    fn len(&self) -> usize {
        self.0.len()
    }

    fn as_ptr(&self) -> *const c_char {
        self.0.as_ptr().cast()
    }

    fn as_mut_ptr(&mut self) -> *mut c_char {
        self.0.as_mut_ptr().cast()
    }
}

impl Drop for ZeroingCString {
    fn drop(&mut self) {
        for byte in &mut self.0 {
            // Safety: every byte is uniquely borrowed from this owned buffer.
            unsafe { ptr::write_volatile(byte, 0) };
        }
        compiler_fence(Ordering::SeqCst);
    }
}

struct SpawnAttributes {
    raw: libc::posix_spawnattr_t,
    initialized: bool,
}

impl SpawnAttributes {
    fn new() -> Result<Self, AppError> {
        let mut result = Self {
            raw: ptr::null_mut(),
            initialized: false,
        };
        check_spawn_result(
            "posix_spawnattr_init",
            // Safety: raw points to one writable opaque attribute handle.
            unsafe { libc::posix_spawnattr_init(&mut result.raw) },
        )?;
        result.initialized = true;
        check_spawn_result(
            "posix_spawnattr_setpgroup",
            // Safety: the initialized attribute handle remains exclusively owned.
            unsafe { libc::posix_spawnattr_setpgroup(&mut result.raw, 0) },
        )?;

        let signal_mask = empty_signal_set("sigemptyset(mask)")?;
        check_spawn_result(
            "posix_spawnattr_setsigmask",
            // Safety: both initialized objects remain live through the call.
            unsafe { libc::posix_spawnattr_setsigmask(&mut result.raw, &signal_mask) },
        )?;
        let mut signal_defaults = empty_signal_set("sigemptyset(defaults)")?;
        for signal in [
            libc::SIGHUP,
            libc::SIGINT,
            libc::SIGQUIT,
            libc::SIGPIPE,
            libc::SIGTERM,
            libc::SIGCONT,
        ] {
            clear_errno();
            // Safety: signal_defaults is initialized and signal is valid.
            if unsafe { libc::sigaddset(&mut signal_defaults, signal) } != 0 {
                return Err(errno_app_error("sigaddset(defaults)", current_errno()));
            }
        }
        check_spawn_result(
            "posix_spawnattr_setsigdefault",
            // Safety: both initialized objects remain live through the call.
            unsafe { libc::posix_spawnattr_setsigdefault(&mut result.raw, &signal_defaults) },
        )?;

        let flags = libc::POSIX_SPAWN_SETPGROUP
            | libc::POSIX_SPAWN_START_SUSPENDED
            | libc::POSIX_SPAWN_CLOEXEC_DEFAULT
            | libc::POSIX_SPAWN_SETSIGMASK
            | libc::POSIX_SPAWN_SETSIGDEF;
        let flags = c_short::try_from(flags).map_err(|_| {
            managed_error(
                ErrorCode::PlatformError,
                "posix_spawnattr_setflags",
                "macOS spawn flags exceeded c_short",
            )
        })?;
        check_spawn_result(
            "posix_spawnattr_setflags",
            // Safety: the initialized attribute handle remains exclusively owned.
            unsafe { libc::posix_spawnattr_setflags(&mut result.raw, flags) },
        )?;
        Ok(result)
    }

    fn as_ptr(&self) -> *const libc::posix_spawnattr_t {
        &self.raw
    }
}

impl Drop for SpawnAttributes {
    fn drop(&mut self) {
        if self.initialized {
            // Safety: raw is an initialized attribute handle owned by self.
            let _ = unsafe { libc::posix_spawnattr_destroy(&mut self.raw) };
        }
    }
}

struct SpawnFileActions {
    raw: libc::posix_spawn_file_actions_t,
    initialized: bool,
    working_directory: ZeroingCString,
    stdio_sources: SpawnStdioSources,
}

enum SpawnStdioSources {
    Pipes {
        stdout_source: OwnedFd,
        stderr_source: OwnedFd,
    },
    Terminal {
        slave_source: OwnedFd,
    },
}

impl SpawnFileActions {
    fn new(
        working_directory: &str,
        stdio: &MacosManagedStdio<'_>,
    ) -> Result<(Self, Option<MacosManagedTerminal>), AppError> {
        let working_directory = ZeroingCString::from_str(working_directory, "workingDirectory")?;
        let (stdio_sources, terminal) = match stdio {
            MacosManagedStdio::Pipes { stdout, stderr } => (
                SpawnStdioSources::Pipes {
                    stdout_source: duplicate_pipe_writer(stdout, "fcntl(F_DUPFD_CLOEXEC, stdout)")?,
                    stderr_source: duplicate_pipe_writer(stderr, "fcntl(F_DUPFD_CLOEXEC, stderr)")?,
                },
                None,
            ),
            MacosManagedStdio::Terminal { rows, columns } => {
                let (terminal, slave_source) = open_managed_terminal(*rows, *columns)?;
                (SpawnStdioSources::Terminal { slave_source }, Some(terminal))
            }
        };
        let mut result = Self {
            raw: ptr::null_mut(),
            initialized: false,
            working_directory,
            stdio_sources,
        };
        check_spawn_result(
            "posix_spawn_file_actions_init",
            // Safety: raw points to one writable opaque action handle.
            unsafe { libc::posix_spawn_file_actions_init(&mut result.raw) },
        )?;
        result.initialized = true;
        check_spawn_result(
            "posix_spawn_file_actions_addchdir_np",
            // Safety: the initialized actions and NUL-terminated path are live.
            unsafe {
                posix_spawn_file_actions_addchdir_np(
                    &mut result.raw,
                    result.working_directory.as_ptr(),
                )
            },
        )?;
        enum StdioAction {
            Pipes(c_int, c_int),
            Terminal(c_int),
        }
        let stdio_action = match &result.stdio_sources {
            SpawnStdioSources::Pipes {
                stdout_source,
                stderr_source,
            } => StdioAction::Pipes(stdout_source.as_raw_fd(), stderr_source.as_raw_fd()),
            SpawnStdioSources::Terminal { slave_source } => {
                StdioAction::Terminal(slave_source.as_raw_fd())
            }
        };
        match stdio_action {
            StdioAction::Pipes(stdout_source_fd, stderr_source_fd) => {
                result.add_dev_null(
                    libc::STDIN_FILENO,
                    libc::O_RDONLY,
                    "posix_spawn_file_actions_addopen(stdin)",
                )?;
                result.add_pipe_writer(
                    stdout_source_fd,
                    libc::STDOUT_FILENO,
                    "posix_spawn_file_actions_adddup2(stdout)",
                    "posix_spawn_file_actions_addclose(stdout-source)",
                )?;
                result.add_pipe_writer(
                    stderr_source_fd,
                    libc::STDERR_FILENO,
                    "posix_spawn_file_actions_adddup2(stderr)",
                    "posix_spawn_file_actions_addclose(stderr-source)",
                )?;
            }
            StdioAction::Terminal(slave_source_fd) => {
                debug_assert!(slave_source_fd >= 3);
                // The slave provides terminal descriptors and line discipline,
                // but this adapter deliberately preserves the existing spawn
                // session and PGID contract. It does not claim a controlling
                // terminal with setsid/TIOCSCTTY.
                result.add_duplicate(
                    slave_source_fd,
                    libc::STDIN_FILENO,
                    "posix_spawn_file_actions_adddup2(pty-stdin)",
                )?;
                result.add_duplicate(
                    slave_source_fd,
                    libc::STDOUT_FILENO,
                    "posix_spawn_file_actions_adddup2(pty-stdout)",
                )?;
                result.add_duplicate(
                    slave_source_fd,
                    libc::STDERR_FILENO,
                    "posix_spawn_file_actions_adddup2(pty-stderr)",
                )?;
                result.add_close(
                    slave_source_fd,
                    "posix_spawn_file_actions_addclose(pty-slave)",
                )?;
            }
        }
        Ok((result, terminal))
    }

    fn add_dev_null(
        &mut self,
        fd: c_int,
        flags: c_int,
        stage: &'static str,
    ) -> Result<(), AppError> {
        check_spawn_result(
            stage,
            // Safety: the action handle is initialized and DEV_NULL is static
            // NUL-terminated storage.
            unsafe {
                libc::posix_spawn_file_actions_addopen(
                    &mut self.raw,
                    fd,
                    DEV_NULL.as_ptr().cast(),
                    flags,
                    0,
                )
            },
        )
    }

    fn add_pipe_writer(
        &mut self,
        source_fd: c_int,
        destination_fd: c_int,
        duplicate_stage: &'static str,
        close_stage: &'static str,
    ) -> Result<(), AppError> {
        self.add_duplicate(source_fd, destination_fd, duplicate_stage)?;
        self.add_close(source_fd, close_stage)
    }

    fn add_duplicate(
        &mut self,
        source_fd: c_int,
        destination_fd: c_int,
        stage: &'static str,
    ) -> Result<(), AppError> {
        check_spawn_result(
            stage,
            // Safety: the action handle is initialized and both descriptors
            // are valid for the duration of the eventual posix_spawn call.
            unsafe {
                libc::posix_spawn_file_actions_adddup2(&mut self.raw, source_fd, destination_fd)
            },
        )
    }

    fn add_close(&mut self, source_fd: c_int, stage: &'static str) -> Result<(), AppError> {
        check_spawn_result(
            stage,
            // Safety: source_fd is the temporary descriptor just referenced
            // by dup2 actions and is not a standard descriptor.
            unsafe { libc::posix_spawn_file_actions_addclose(&mut self.raw, source_fd) },
        )
    }

    fn as_ptr(&self) -> *const libc::posix_spawn_file_actions_t {
        &self.raw
    }
}

impl Drop for SpawnFileActions {
    fn drop(&mut self) {
        if self.initialized {
            // Safety: raw is an initialized action handle owned by self.
            let _ = unsafe { libc::posix_spawn_file_actions_destroy(&mut self.raw) };
        }
    }
}

fn duplicate_pipe_writer(writer: &PipeWriter, stage: &'static str) -> Result<OwnedFd, AppError> {
    duplicate_descriptor(writer.as_raw_fd(), stage)
}

fn duplicate_descriptor(source: c_int, stage: &'static str) -> Result<OwnedFd, AppError> {
    clear_errno();
    // Safety: source is a live descriptor for this call. F_DUPFD_CLOEXEC
    // returns a new descriptor owned by the caller and never mutates source.
    let duplicated = unsafe { libc::fcntl(source, libc::F_DUPFD_CLOEXEC, 3) };
    if duplicated < 0 {
        return Err(errno_app_error(stage, current_errno()));
    }
    debug_assert!(duplicated >= 3);
    // Safety: fcntl returned a fresh descriptor whose ownership is transferred
    // exactly once into OwnedFd.
    Ok(unsafe { OwnedFd::from_raw_fd(duplicated) })
}

fn open_managed_terminal(
    rows: u16,
    columns: u16,
) -> Result<(MacosManagedTerminal, OwnedFd), AppError> {
    validate_terminal_size(rows, columns)?;
    let mut master = -1;
    let mut slave = -1;
    let mut size = terminal_window_size(rows, columns);
    clear_errno();
    // Safety: master/slave point to writable descriptors, size is initialized,
    // and the optional name and termios outputs are intentionally omitted.
    let open_result = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut size,
        )
    };
    if open_result != 0 {
        let error = current_errno();
        close_openpty_descriptors(master, slave);
        return Err(errno_app_error("openpty", error));
    }
    if master < 0 || slave < 0 || master == slave {
        close_openpty_descriptors(master, slave);
        return Err(managed_error(
            ErrorCode::PlatformError,
            "openpty",
            "openpty returned invalid macOS terminal descriptors",
        ));
    }
    // Safety: successful openpty returned two fresh descriptors, each of which
    // is transferred exactly once into an OwnedFd.
    let master = unsafe { OwnedFd::from_raw_fd(master) };
    // Safety: see the successful openpty ownership argument above.
    let slave = unsafe { OwnedFd::from_raw_fd(slave) };

    // Normalize both descriptors above the standard range and make every
    // parent-side copy close-on-exec before building spawn actions.
    let normalized_master =
        duplicate_descriptor(master.as_raw_fd(), "fcntl(F_DUPFD_CLOEXEC, pty-master)")?;
    let normalized_slave =
        duplicate_descriptor(slave.as_raw_fd(), "fcntl(F_DUPFD_CLOEXEC, pty-slave)")?;
    drop(master);
    drop(slave);
    let output_master = duplicate_descriptor(
        normalized_master.as_raw_fd(),
        "fcntl(F_DUPFD_CLOEXEC, pty-output)",
    )?;

    Ok((
        MacosManagedTerminal {
            master: normalized_master,
            output: Some(MacosManagedTerminalOutput {
                master: output_master,
            }),
        },
        normalized_slave,
    ))
}

fn close_openpty_descriptors(master: c_int, slave: c_int) {
    if master >= 0 {
        // Safety: a nonnegative descriptor returned by openpty has not been
        // transferred into an owner on this failure path.
        let _ = unsafe { libc::close(master) };
    }
    if slave >= 0 && slave != master {
        // Safety: see the openpty failure-path ownership argument above.
        let _ = unsafe { libc::close(slave) };
    }
}

fn empty_signal_set(stage: &'static str) -> Result<libc::sigset_t, AppError> {
    let mut value = MaybeUninit::<libc::sigset_t>::zeroed();
    clear_errno();
    // Safety: value points to one writable sigset_t.
    if unsafe { libc::sigemptyset(value.as_mut_ptr()) } != 0 {
        return Err(errno_app_error(stage, current_errno()));
    }
    // Safety: sigemptyset initialized the complete value on success.
    Ok(unsafe { value.assume_init() })
}

fn check_spawn_result(stage: &'static str, result: c_int) -> Result<(), AppError> {
    if result == 0 {
        Ok(())
    } else {
        Err(errno_app_error(stage, result))
    }
}

#[derive(Clone, Copy)]
struct ProcessObservation {
    pid: u32,
    process_group_id: u32,
    start_micros: u64,
}

fn query_process_observation(pid: libc::pid_t) -> Result<Option<ProcessObservation>, AppError> {
    if pid <= 0 {
        return Err(managed_error(
            ErrorCode::PlatformError,
            "proc_pidinfo(PROC_PIDTBSDINFO)",
            "macOS process PID was outside the supported range",
        ));
    }
    let mut information = MaybeUninit::<libc::proc_bsdinfo>::zeroed();
    let expected = size_of::<libc::proc_bsdinfo>();
    let expected_i32 = c_int::try_from(expected).map_err(|_| {
        managed_error(
            ErrorCode::PlatformError,
            "proc_pidinfo(PROC_PIDTBSDINFO)",
            "macOS process identity structure exceeded c_int",
        )
    })?;
    clear_errno();
    // Safety: the fixed-size output is writable and remains live through the call.
    let actual = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            information.as_mut_ptr().cast::<c_void>(),
            expected_i32,
        )
    };
    if actual <= 0 {
        let errno = current_errno();
        return match errno {
            libc::ESRCH => Ok(None),
            0 => Err(managed_error(
                ErrorCode::PlatformError,
                "proc_pidinfo(PROC_PIDTBSDINFO)",
                "macOS process identity query failed without errno evidence",
            )),
            libc::EPERM | libc::EACCES => {
                Err(errno_app_error("proc_pidinfo(PROC_PIDTBSDINFO)", errno))
            }
            _ => Err(errno_app_error("proc_pidinfo(PROC_PIDTBSDINFO)", errno)),
        };
    }
    if actual as usize != expected {
        return Err(managed_error(
            ErrorCode::PlatformError,
            "proc_pidinfo(PROC_PIDTBSDINFO)",
            "macOS process identity query returned a short structure",
        ));
    }
    // Safety: an exact successful read initialized the fixed structure.
    let information = unsafe { information.assume_init() };
    if information.pbi_pid == 0
        || information.pbi_pgid == 0
        || information.pbi_start_tvusec >= 1_000_000
    {
        return Err(managed_error(
            ErrorCode::PlatformError,
            "proc_pidinfo(PROC_PIDTBSDINFO)",
            "macOS process identity query returned invalid fields",
        ));
    }
    let start_micros = information
        .pbi_start_tvsec
        .checked_mul(1_000_000)
        .and_then(|value| value.checked_add(information.pbi_start_tvusec))
        .filter(|value| *value != 0)
        .ok_or_else(|| {
            managed_error(
                ErrorCode::PlatformError,
                "proc_pidinfo(PROC_PIDTBSDINFO)",
                "macOS process start time was invalid",
            )
        })?;
    Ok(Some(ProcessObservation {
        pid: information.pbi_pid,
        process_group_id: information.pbi_pgid,
        start_micros,
    }))
}

fn parse_canonical_nonzero_u64(value: &str) -> Option<u64> {
    value
        .parse::<u64>()
        .ok()
        .filter(|parsed| *parsed != 0 && parsed.to_string() == value)
}

fn revalidate_recovered_identity_and_group(
    instance_key: &ProcessInstanceKey,
    process_group_id: libc::pid_t,
) -> Result<(), AppError> {
    let current_boot = crate::native::query_boot_identifier().map_err(|source| {
        managed_error(
            source.code,
            "QueryBootIdentifier",
            "macOS boot identity could not be revalidated",
        )
    })?;
    if current_boot != instance_key.boot_id {
        return Err(managed_error(
            ErrorCode::IdentityMismatch,
            "QueryBootIdentifier",
            "recovered macOS boot identity changed",
        ));
    }
    let observation = query_process_observation(process_group_id)?.ok_or_else(|| {
        managed_error(
            ErrorCode::NotFound,
            "proc_pidinfo(PROC_PIDTBSDINFO)",
            "recovered macOS process no longer exists",
        )
    })?;
    let expected_start =
        parse_canonical_nonzero_u64(&instance_key.native_start_time).ok_or_else(|| {
            managed_error(
                ErrorCode::PlatformError,
                "RevalidateRecoveredProcessIdentity",
                "persisted macOS process start time was invalid",
            )
        })?;
    if observation.pid != instance_key.pid || observation.start_micros != expected_start {
        return Err(managed_error(
            ErrorCode::IdentityMismatch,
            "RevalidateRecoveredProcessIdentity",
            "recovered macOS process identity changed",
        ));
    }
    if observation.process_group_id != process_group_id as u32
        || observation.process_group_id != observation.pid
    {
        return Err(managed_error(
            ErrorCode::PlatformError,
            "RevalidateRecoveredProcessGroup",
            "recovered macOS process left its dedicated process group",
        ));
    }
    match query_process_group(process_group_id)? {
        Some(observed_process_group) if observed_process_group == process_group_id => Ok(()),
        Some(_) => Err(managed_error(
            ErrorCode::PlatformError,
            "getpgid",
            "recovered macOS process group changed",
        )),
        None => Err(managed_error(
            ErrorCode::NotFound,
            "getpgid",
            "recovered macOS process no longer exists",
        )),
    }
}

fn query_process_group(pid: libc::pid_t) -> Result<Option<libc::pid_t>, AppError> {
    clear_errno();
    // Safety: pid is a validated positive process identifier.
    let process_group = unsafe { libc::getpgid(pid) };
    if process_group >= 0 {
        return Ok(Some(process_group));
    }
    let errno = current_errno();
    if errno == libc::ESRCH {
        Ok(None)
    } else {
        Err(errno_app_error("getpgid", errno))
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ChildExecution {
    Suspended,
    Running,
}

struct OwnedMacosChild {
    pid: libc::pid_t,
    process_group_id: libc::pid_t,
    identity: Option<ProcessInstanceKey>,
    execution: ChildExecution,
    group_verified: bool,
    group_kill_sent: bool,
    group_boundary_lost: bool,
    root_reaped: bool,
    stop_attempt_observed: bool,
    controlled_exit_confirmed: bool,
}

impl OwnedMacosChild {
    fn new(pid: libc::pid_t) -> Self {
        Self {
            pid,
            process_group_id: pid,
            identity: None,
            execution: ChildExecution::Suspended,
            group_verified: false,
            group_kill_sent: false,
            group_boundary_lost: false,
            root_reaped: false,
            stop_attempt_observed: false,
            controlled_exit_confirmed: false,
        }
    }

    fn revalidate_identity_and_group(&self) -> Result<(), AppError> {
        let identity = self.identity.as_ref().ok_or_else(|| {
            managed_error(
                ErrorCode::IdentityMismatch,
                "RevalidateProcessIdentity",
                "macOS child identity was not captured",
            )
        })?;
        if crate::native::query_boot_identifier().map_err(|source| {
            managed_error(
                source.code,
                "QueryBootIdentifier",
                "macOS boot identity could not be revalidated",
            )
        })? != identity.boot_id
        {
            return Err(managed_error(
                ErrorCode::IdentityMismatch,
                "QueryBootIdentifier",
                "macOS boot identity changed",
            ));
        }
        let observation = query_process_observation(self.pid)?.ok_or_else(|| {
            managed_error(
                ErrorCode::NotFound,
                "proc_pidinfo(PROC_PIDTBSDINFO)",
                "managed macOS child no longer exists",
            )
        })?;
        let expected_start = identity.native_start_time.parse::<u64>().map_err(|_| {
            managed_error(
                ErrorCode::IdentityMismatch,
                "RevalidateProcessIdentity",
                "stored macOS process start time was invalid",
            )
        })?;
        if observation.pid != identity.pid || observation.start_micros != expected_start {
            return Err(managed_error(
                ErrorCode::IdentityMismatch,
                "RevalidateProcessIdentity",
                "managed macOS process identity changed",
            ));
        }
        if !self.group_verified
            || observation.process_group_id != self.process_group_id as u32
            || observation.process_group_id != observation.pid
        {
            return Err(managed_error(
                ErrorCode::IdentityMismatch,
                "RevalidateProcessGroup",
                "managed macOS process left its dedicated process group",
            ));
        }
        match query_process_group(self.pid)? {
            Some(process_group) if process_group == self.process_group_id => Ok(()),
            Some(_) => Err(managed_error(
                ErrorCode::IdentityMismatch,
                "getpgid",
                "managed macOS process group changed",
            )),
            None => Err(managed_error(
                ErrorCode::NotFound,
                "getpgid",
                "managed macOS child no longer exists",
            )),
        }
    }

    fn terminate_and_confirm(&mut self) -> Result<(), CleanupFailure> {
        if self.controlled_exit_confirmed {
            return Ok(());
        }
        let deadline = Instant::now() + CLEANUP_WAIT;
        match self.execution {
            ChildExecution::Suspended => {
                let signal_error = match send_signal(self.pid, libc::SIGKILL) {
                    Ok(SignalOutcome::Delivered | SignalOutcome::Missing) => None,
                    Err(errno) => Some(CleanupFailure::Api {
                        stage: "kill(SIGKILL)",
                        errno,
                    }),
                };
                match self.wait_for_root_exit(deadline) {
                    Ok(()) => Ok(()),
                    Err(wait) => Err(signal_error.unwrap_or(wait)),
                }
            }
            ChildExecution::Running => self.terminate_running_group(deadline),
        }
    }

    fn terminate_running_group(&mut self, deadline: Instant) -> Result<(), CleanupFailure> {
        if self.group_boundary_lost {
            return match self.kill_and_wait_root(deadline) {
                Ok(()) => Err(CleanupFailure::BoundaryLost),
                Err(cleanup) => Err(cleanup),
            };
        }
        if !self.group_kill_sent {
            if let Err(error) = self.revalidate_identity_and_group() {
                if error.code == ErrorCode::NotFound {
                    // This owner has not reaped the root child, so its PID and
                    // original PGID cannot be reused yet. The root may have
                    // exited between resume and cleanup; kill the original
                    // group before reap, then confirm both boundaries below.
                } else if confirms_group_boundary_lost(&error) {
                    let root_cleanup = self.kill_and_wait_root(deadline);
                    self.group_boundary_lost = true;
                    return match root_cleanup {
                        Ok(()) => Err(CleanupFailure::BoundaryLost),
                        Err(cleanup) => Err(cleanup),
                    };
                } else {
                    return Err(CleanupFailure::RevalidationUnavailable);
                }
            }
            match send_signal(-self.process_group_id, libc::SIGKILL) {
                Ok(SignalOutcome::Delivered | SignalOutcome::Missing) => {
                    self.group_kill_sent = true;
                }
                Err(errno) => {
                    return Err(CleanupFailure::Api {
                        stage: "killpg(SIGKILL)",
                        errno,
                    });
                }
            }
        }
        self.wait_for_root_exit(deadline)?;
        wait_for_group_absent(self.process_group_id, deadline)?;
        self.controlled_exit_confirmed = true;
        Ok(())
    }

    fn send_managed_stop_signal(
        &mut self,
        signal: c_int,
        stage: &'static str,
        force: bool,
    ) -> Result<MacosManagedStopSignalResult, AppError> {
        if let Err(error) = self.revalidate_identity_and_group() {
            if confirms_managed_root_missing(&error) {
                self.stop_attempt_observed = true;
                return Ok(MacosManagedStopSignalResult::SignalUnavailable(error));
            }
            return Err(error);
        }
        let result = send_signal(-self.process_group_id, signal);
        self.stop_attempt_observed = true;
        match result {
            Ok(SignalOutcome::Delivered) => {
                if force {
                    self.group_kill_sent = true;
                }
                Ok(MacosManagedStopSignalResult::Delivered)
            }
            Ok(SignalOutcome::Missing) => {
                // ESRCH is observed by the same syscall that immediately
                // follows full identity and group validation. Polling may now
                // distinguish an exited root from a boundary-changing race.
                if force {
                    self.group_kill_sent = true;
                }
                Ok(MacosManagedStopSignalResult::SignalUnavailable(
                    errno_app_error(stage, libc::ESRCH),
                ))
            }
            Err(errno) => Ok(MacosManagedStopSignalResult::SignalUnavailable(
                errno_app_error(stage, errno),
            )),
        }
    }

    fn poll_managed_exit(&mut self) -> Result<MacosManagedExitPoll, AppError> {
        if self.controlled_exit_confirmed {
            return Ok(MacosManagedExitPoll::Exited);
        }
        if !self.stop_attempt_observed {
            return Err(managed_error(
                ErrorCode::Conflict,
                "PollManagedExit",
                "managed macOS exit polling requires a recorded stop attempt",
            ));
        }

        self.poll_complete_group_exit()
    }

    fn poll_natural_exit(&mut self) -> Result<MacosManagedExitPoll, AppError> {
        if self.controlled_exit_confirmed {
            return Ok(MacosManagedExitPoll::Exited);
        }
        self.poll_complete_group_exit()
    }

    fn poll_complete_group_exit(&mut self) -> Result<MacosManagedExitPoll, AppError> {
        match send_signal(-self.process_group_id, 0) {
            Ok(SignalOutcome::Delivered) | Err(libc::EPERM) => {
                return Ok(MacosManagedExitPoll::Running);
            }
            Ok(SignalOutcome::Missing) => {}
            Err(errno) => return Err(errno_app_error("killpg(0)", errno)),
        }

        if self.root_reaped {
            self.controlled_exit_confirmed = true;
            return Ok(MacosManagedExitPoll::Exited);
        }

        let mut status: c_int = 0;
        clear_errno();
        // Safety: pid is the positive, unreaped child returned by posix_spawn;
        // WNOHANG makes this a single non-blocking observation.
        let result = unsafe { libc::waitpid(self.pid, &mut status, libc::WNOHANG) };
        if result == self.pid {
            self.root_reaped = true;
            self.controlled_exit_confirmed = true;
            return Ok(MacosManagedExitPoll::Exited);
        }
        if result == 0 {
            return Err(managed_error(
                ErrorCode::IdentityMismatch,
                "PollManagedProcessGroup",
                "managed macOS root remained alive after its process group disappeared",
            ));
        }
        if result < 0 {
            return Err(errno_app_error("waitpid(WNOHANG)", current_errno()));
        }
        Err(managed_error(
            ErrorCode::PlatformError,
            "waitpid(WNOHANG)",
            "macOS managed child wait returned an unexpected PID",
        ))
    }

    fn kill_and_wait_root(&mut self, deadline: Instant) -> Result<(), CleanupFailure> {
        if self.root_reaped {
            return Ok(());
        }
        let signal_error = match send_signal(self.pid, libc::SIGKILL) {
            Ok(SignalOutcome::Delivered | SignalOutcome::Missing) => None,
            Err(errno) => Some(CleanupFailure::Api {
                stage: "kill(SIGKILL)",
                errno,
            }),
        };
        match self.wait_for_root_exit(deadline) {
            Ok(()) => Ok(()),
            Err(wait) => Err(signal_error.unwrap_or(wait)),
        }
    }

    fn wait_for_root_exit(&mut self, deadline: Instant) -> Result<(), CleanupFailure> {
        if self.root_reaped {
            return Ok(());
        }
        loop {
            let mut status: c_int = 0;
            clear_errno();
            // Safety: pid is the positive, unreaped child returned by posix_spawn.
            let result = unsafe { libc::waitpid(self.pid, &mut status, libc::WNOHANG) };
            if result == self.pid {
                self.root_reaped = true;
                return Ok(());
            }
            if result < 0 {
                let errno = current_errno();
                if errno == libc::EINTR {
                    continue;
                }
                return Err(CleanupFailure::Api {
                    stage: "waitpid",
                    errno,
                });
            }
            if result != 0 {
                return Err(CleanupFailure::UnexpectedWait(result));
            }
            sleep_until_retry(deadline, "waitpid")?;
        }
    }
}

fn confirms_group_boundary_lost(error: &AppError) -> bool {
    error.code == ErrorCode::IdentityMismatch
        && matches!(
            error.details.get("stage").map(String::as_str),
            Some("RevalidateProcessGroup" | "getpgid")
        )
}

fn confirms_managed_root_missing(error: &AppError) -> bool {
    error.code == ErrorCode::NotFound
        && matches!(
            error.details.get("stage").map(String::as_str),
            Some("proc_pidinfo(PROC_PIDTBSDINFO)" | "getpgid")
        )
}

fn wait_for_group_absent(
    process_group_id: libc::pid_t,
    deadline: Instant,
) -> Result<(), CleanupFailure> {
    loop {
        match send_signal(-process_group_id, 0) {
            Ok(SignalOutcome::Missing) => return Ok(()),
            Ok(SignalOutcome::Delivered) => sleep_until_retry(deadline, "killpg(0)")?,
            Err(errno) if errno == libc::EPERM => sleep_until_retry(deadline, "killpg(0)")?,
            Err(errno) => {
                return Err(CleanupFailure::Api {
                    stage: "killpg(0)",
                    errno,
                });
            }
        }
    }
}

fn sleep_until_retry(deadline: Instant, stage: &'static str) -> Result<(), CleanupFailure> {
    let now = Instant::now();
    if now >= deadline {
        return Err(CleanupFailure::Timeout { stage });
    }
    thread::sleep(CLEANUP_POLL_INTERVAL.min(deadline - now));
    Ok(())
}

enum SignalOutcome {
    Delivered,
    Missing,
}

fn send_signal(target: libc::pid_t, signal: c_int) -> Result<SignalOutcome, c_int> {
    clear_errno();
    // Safety: target is either the owned positive child or its negative PGID.
    if unsafe { libc::kill(target, signal) } == 0 {
        return Ok(SignalOutcome::Delivered);
    }
    let errno = current_errno();
    if errno == libc::ESRCH {
        Ok(SignalOutcome::Missing)
    } else {
        Err(errno)
    }
}

enum CleanupFailure {
    Api { stage: &'static str, errno: c_int },
    Timeout { stage: &'static str },
    BoundaryLost,
    RevalidationUnavailable,
    UnexpectedWait(libc::pid_t),
}

impl CleanupFailure {
    fn stage(&self) -> &'static str {
        match self {
            Self::Api { stage, .. } | Self::Timeout { stage } => stage,
            Self::BoundaryLost => "RevalidateProcessGroup",
            Self::RevalidationUnavailable => "RevalidateProcessIdentity",
            Self::UnexpectedWait(_) => "waitpid",
        }
    }

    fn result_code(&self) -> String {
        match self {
            Self::Api { errno, .. } => format!("ERRNO:{errno}"),
            Self::Timeout { .. } => "TIMEOUT".into(),
            Self::BoundaryLost => "CONTROL_BOUNDARY_LOST".into(),
            Self::RevalidationUnavailable => "CONTROL_REVALIDATION_UNAVAILABLE".into(),
            Self::UnexpectedWait(result) => format!("WAITPID:{result}"),
        }
    }
}

fn cleanup_after_failure(error: AppError, mut child: OwnedMacosChild) -> MacosManagedLaunchError {
    match child.terminate_and_confirm() {
        Ok(()) => MacosManagedLaunchError {
            public: error,
            pending_cleanup: None,
        },
        Err(cleanup) => {
            let mut public = error;
            add_cleanup_details(&mut public, &cleanup);
            MacosManagedLaunchError {
                public,
                pending_cleanup: Some(child),
            }
        }
    }
}

fn terminate_owned_child(mut child: OwnedMacosChild) -> Result<(), MacosManagedLaunchError> {
    match child.terminate_and_confirm() {
        Ok(()) => Ok(()),
        Err(cleanup) => Err(MacosManagedLaunchError {
            public: cleanup_app_error(&cleanup),
            pending_cleanup: Some(child),
        }),
    }
}

fn quarantine_failed_cleanup(child: OwnedMacosChild) {
    // Normal retry ownership remains in MacosManagedLaunchError. If that owner
    // is dropped after another failure, retain only the in-process evidence so
    // Drop cannot send an unvalidated signal or claim cleanup. macOS provides no
    // kernel control handle here, and forgetting this value creates no new retry
    // path and does not prevent PID or PGID reuse.
    std::mem::forget(child);
}

fn launch_error(public: AppError) -> MacosManagedLaunchError {
    MacosManagedLaunchError {
        public,
        pending_cleanup: None,
    }
}

fn cleanup_app_error(cleanup: &CleanupFailure) -> AppError {
    let mut error = AppError::new(
        ErrorCode::PlatformError,
        "macOS controlled process cleanup was not confirmed",
    );
    add_cleanup_details(&mut error, cleanup);
    error
}

fn add_cleanup_details(error: &mut AppError, cleanup: &CleanupFailure) {
    error
        .details
        .insert("cleanupStage".into(), cleanup.stage().into());
    error
        .details
        .insert("cleanupResult".into(), cleanup.result_code());
}

fn invalid_launch_input(field: &'static str, reason: &'static str) -> AppError {
    let mut error = managed_error(
        ErrorCode::InvalidArgument,
        "ValidateLaunchRequest",
        "invalid macOS launch request",
    );
    error.details.insert("field".into(), field.into());
    error.details.insert("reason".into(), reason.into());
    error
}

fn managed_error(code: ErrorCode, stage: &'static str, message: &'static str) -> AppError {
    let mut error = AppError::new(code, message);
    error.details.insert("stage".into(), stage.into());
    error
}

fn errno_app_error(stage: &'static str, errno: c_int) -> AppError {
    let code = match errno {
        libc::ENOENT | libc::ENOTDIR | libc::ESRCH => ErrorCode::NotFound,
        libc::EACCES | libc::EPERM => ErrorCode::AccessDenied,
        libc::EINVAL | libc::E2BIG => ErrorCode::InvalidArgument,
        _ => ErrorCode::PlatformError,
    };
    let mut error = managed_error(code, stage, "macOS managed process operation failed");
    error
        .details
        .insert("platformCode".into(), format!("ERRNO:{errno}"));
    error
}

fn clear_errno() {
    // Safety: __error returns this thread's errno slot on macOS.
    unsafe { *libc::__error() = 0 };
}

fn current_errno() -> c_int {
    // Safety: __error returns this thread's errno slot on macOS.
    unsafe { *libc::__error() }
}
