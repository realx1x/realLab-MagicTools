use std::ffi::c_void;
use std::fmt::{self, Display, Formatter};
use std::io::{self, PipeReader, PipeWriter, Read, Write, pipe};
use std::mem::{size_of, size_of_val};
use std::os::windows::io::AsRawHandle;
use std::sync::atomic::{Ordering, compiler_fence};
use std::thread;
use std::time::{Duration, Instant};

use domain::{AppError, ErrorCode, ExecutionPlatform, ProcessInstanceKey};
use lifecycle::{
    MAX_PROCESS_BOOT_ID_BYTES, MAX_PROCESS_NATIVE_START_TIME_BYTES, ResolvedEnvironment,
};
use windows::Win32::Foundation::{
    CloseHandle, DUPLICATE_SAME_ACCESS, DuplicateHandle, ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND,
    ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_PARAMETER, ERROR_NOT_FOUND, ERROR_PATH_NOT_FOUND,
    ERROR_PROCESS_ABORTED, FILETIME, HANDLE, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT, WIN32_ERROR,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_ID_INFO, FILE_READ_ATTRIBUTES,
    FILE_SHARE_READ, FILE_SHARE_WRITE, FileIdInfo, GetFileInformationByHandleEx, OPEN_EXISTING,
};
use windows::Win32::System::Console::{
    COORD, CTRL_BREAK_EVENT, ClosePseudoConsole, CreatePseudoConsole, GenerateConsoleCtrlEvent,
    HPCON, ResizePseudoConsole,
};
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOBOBJECT_BASIC_ACCOUNTING_INFORMATION,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectBasicAccountingInformation,
    JobObjectExtendedLimitInformation, QueryInformationJobObject, SetInformationJobObject,
    TerminateJobObject,
};
use windows::Win32::System::Threading::{
    CREATE_NEW_PROCESS_GROUP, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessW,
    DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess, GetProcessId,
    GetProcessTimes, InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST, OpenProcess,
    PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, PROCESS_CREATION_FLAGS,
    PROCESS_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
    QueryFullProcessImageNameW, ResumeThread, STARTF_USESTDHANDLES, STARTUPINFOEXW, STARTUPINFOW,
    TerminateProcess, UpdateProcThreadAttribute, WaitForSingleObject,
};
use windows::core::{Error as WindowsError, PCWSTR, PWSTR};

const CLEANUP_EXIT_CODE: u32 = 0xFFFF_FF01;
const FORCE_STOP_EXIT_CODE: u32 = 0xFFFF_FF02;
const CLEANUP_WAIT_MS: u32 = 5_000;
const CLEANUP_POLL_INTERVAL: Duration = Duration::from_millis(10);
const MAX_WINDOWS_COMMAND_LINE_UTF16_UNITS: usize = 32_767;
const MAX_WINDOWS_ENVIRONMENT_UTF16_UNITS: usize = 32_767;
const MAX_WINDOWS_IMAGE_PATH_UTF16_UNITS: usize = 32_768;
const MAX_PSEUDO_CONSOLE_DIMENSION: u16 = i16::MAX as u16;
const NULL_DEVICE_NAME: [u16; 4] = [b'N' as u16, b'U' as u16, b'L' as u16, 0];

/// Standard I/O mode for one managed launch. Ordinary launches retain their
/// independent stdout/stderr pipes; only explicitly interactive launches use
/// the merged UTF-8 ConPTY stream.
pub enum WindowsManagedStdio<'a> {
    Pipes {
        stdout: &'a PipeWriter,
        stderr: &'a PipeWriter,
        create_new_process_group: bool,
    },
    PseudoConsole {
        columns: u16,
        rows: u16,
    },
}

impl WindowsManagedStdio<'_> {
    fn create_new_process_group(&self) -> bool {
        matches!(
            self,
            Self::Pipes {
                create_new_process_group: true,
                ..
            }
        )
    }
}

/// Unique readable master endpoint for a managed ConPTY session. ConPTY
/// output is always UTF-8 with virtual-terminal sequences interleaved.
pub struct WindowsManagedTerminalOutput {
    reader: PipeReader,
}

impl WindowsManagedTerminalOutput {
    pub const ENCODING: &'static str = "UTF-8";
}

impl Read for WindowsManagedTerminalOutput {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.reader.read(buffer)
    }
}

impl fmt::Debug for WindowsManagedTerminalOutput {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WindowsManagedTerminalOutput")
            .finish_non_exhaustive()
    }
}

/// Fully resolved launch data. `argv` excludes argv[0]; the adapter always
/// inserts the exact absolute application path as argv[0].
pub struct WindowsManagedLaunchRequest<'a> {
    pub executable: &'a str,
    pub argv: &'a [String],
    pub working_directory: &'a str,
    pub environment: &'a ResolvedEnvironment,
    pub stdio: WindowsManagedStdio<'a>,
}

/// A process that is already inside its kill-on-close Job but whose primary
/// thread has not executed. This value is intentionally non-cloneable.
pub struct SuspendedWindowsManagedProcess {
    child: Option<SuspendedChild>,
    instance_key: ProcessInstanceKey,
    process_group_id: Option<u32>,
}

impl SuspendedWindowsManagedProcess {
    pub fn instance_key(&self) -> &ProcessInstanceKey {
        &self.instance_key
    }

    pub fn process_group_id(&self) -> Option<u32> {
        self.process_group_id
    }

    pub fn is_terminal(&self) -> bool {
        self.child.as_ref().is_some_and(SuspendedChild::is_terminal)
    }

    /// Transfers the only readable ConPTY master endpoint. The caller must
    /// continuously drain it on a dedicated worker, including while the
    /// pseudoconsole is being closed.
    pub fn take_terminal_output(&mut self) -> Option<WindowsManagedTerminalOutput> {
        self.child
            .as_mut()
            .and_then(SuspendedChild::take_terminal_output)
    }

    pub fn write_terminal(&mut self, input: &[u8]) -> Result<(), AppError> {
        self.child
            .as_mut()
            .ok_or_else(|| platform_invariant_error("WritePseudoConsole", "child owner was empty"))?
            .write_terminal(input)
    }

    pub fn resize_terminal(&mut self, columns: u16, rows: u16) -> Result<(), AppError> {
        self.child
            .as_mut()
            .ok_or_else(|| {
                platform_invariant_error("ResizePseudoConsole", "child owner was empty")
            })?
            .resize_terminal(columns, rows)
    }

    /// Explicitly abandons a prepared launch without ever resuming its thread.
    /// A cleanup failure returns the controlling handles in the error.
    pub fn abort(mut self) -> Result<(), WindowsManagedLaunchError> {
        let child = self.child.take().expect("suspended child owner");
        terminate_owned_child(child)
    }

    /// Consumes the suspended owner. Only the exact initial suspend count is
    /// accepted; every other result enters fail-closed cleanup.
    pub fn resume(mut self) -> Result<WindowsManagedProcess, WindowsManagedLaunchError> {
        let child = self.child.take().expect("suspended child owner");
        // Safety: this is the exclusively owned primary thread returned by
        // CreateProcessW and it has not previously been resumed by this API.
        let previous_suspend_count = unsafe { ResumeThread(child.thread_raw()) };
        if previous_suspend_count != 1 {
            let error = if previous_suspend_count == u32::MAX {
                platform_api_error("ResumeThread", &WindowsError::from_win32())
            } else {
                platform_invariant_error(
                    "ResumeThread",
                    "primary thread suspend count was not exactly one",
                )
            };
            return Err(cleanup_after_failure(error, child));
        }

        let (job, process, terminal) = child.commit();
        Ok(WindowsManagedProcess {
            job,
            process,
            terminal,
            instance_key: self.instance_key.clone(),
            process_group_id: self.process_group_id,
        })
    }
}

impl fmt::Debug for SuspendedWindowsManagedProcess {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SuspendedWindowsManagedProcess")
            .field("instance_key", &self.instance_key)
            .field("process_group_id", &self.process_group_id)
            .finish_non_exhaustive()
    }
}

impl Drop for SuspendedWindowsManagedProcess {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take()
            && child.terminate_and_confirm().is_err()
        {
            quarantine_failed_cleanup(child);
        }
    }
}

/// Owns both control handles for the running managed process. Dropping the Job
/// handle activates KILL_ON_JOB_CLOSE. This value is intentionally non-cloneable.
pub struct WindowsManagedProcess {
    // Job is declared first so it closes before the observation handle.
    job: OwnedHandle,
    process: OwnedHandle,
    // The Job closes before ConPTY, so an implicit owner drop cannot use the
    // terminal channel as a substitute for Job-based process-tree control.
    terminal: Option<WindowsPseudoConsole>,
    instance_key: ProcessInstanceKey,
    process_group_id: Option<u32>,
}

/// Result of one explicit signal-delivery attempt. Signal unavailability is a
/// closed platform outcome so the Supervisor can persist it without dropping
/// the process owner or silently escalating to a force stop.
#[derive(Clone, Debug, PartialEq)]
pub enum WindowsManagedStopSignalResult {
    Delivered,
    SignalUnavailable(AppError),
}

/// Non-blocking observation of the complete Job control boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsManagedExitPoll {
    Running,
    Exited,
}

/// Closed reconciliation result for a persisted Windows managed-process
/// identity. A live identity remains orphaned because an anonymous Job handle
/// cannot be reacquired after the Supervisor process that owned it exits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsManagedRecoveryProbe {
    ExitedWhileOffline,
    IdentityMismatch,
    Orphaned,
}

/// Reconciles a persisted identity without reacquiring control or sending a
/// signal. Every observation after OpenProcess uses the same pinned process
/// object and requests only query and synchronization rights.
pub fn probe_managed_process_recovery(
    instance_key: &ProcessInstanceKey,
) -> WindowsManagedRecoveryProbe {
    let Some(expected_creation_time) = validate_recovery_instance_key(instance_key) else {
        return WindowsManagedRecoveryProbe::Orphaned;
    };

    let current_boot_id = match crate::native::query_boot_identifier() {
        Ok(boot_id) => boot_id,
        Err(_) => return WindowsManagedRecoveryProbe::Orphaned,
    };
    if current_boot_id != instance_key.boot_id {
        return WindowsManagedRecoveryProbe::ExitedWhileOffline;
    }

    let rights = PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE;
    // Safety: the persisted PID is only a lookup hint. This probe never sends
    // a signal or constructs a WindowsManagedProcess from the returned handle.
    let process = match unsafe { OpenProcess(rights, false, instance_key.pid) } {
        Ok(handle) => OwnedHandle::new(handle),
        Err(source) => {
            return match WIN32_ERROR::from_error(&source) {
                Some(ERROR_INVALID_PARAMETER | ERROR_NOT_FOUND | ERROR_PROCESS_ABORTED) => {
                    WindowsManagedRecoveryProbe::ExitedWhileOffline
                }
                _ => WindowsManagedRecoveryProbe::Orphaned,
            };
        }
    };

    // Safety: `process` pins the exact object used for all identity and
    // liveness observations in this probe. Identity is checked before exit so
    // a reused PID cannot be misclassified when the replacement has exited.
    let actual_pid = unsafe { GetProcessId(process.raw()) };
    if actual_pid == 0 {
        return WindowsManagedRecoveryProbe::Orphaned;
    }
    if actual_pid != instance_key.pid {
        return WindowsManagedRecoveryProbe::IdentityMismatch;
    }

    let actual_creation_time = match query_creation_time(process.raw()) {
        Ok(creation_time) if creation_time != 0 => creation_time,
        Ok(_) | Err(_) => return WindowsManagedRecoveryProbe::Orphaned,
    };
    if actual_creation_time != expected_creation_time {
        return WindowsManagedRecoveryProbe::IdentityMismatch;
    }

    match recovery_process_exit_state(process.raw()) {
        Some(true) => WindowsManagedRecoveryProbe::ExitedWhileOffline,
        Some(false) | None => WindowsManagedRecoveryProbe::Orphaned,
    }
}

fn validate_recovery_instance_key(instance_key: &ProcessInstanceKey) -> Option<u64> {
    if instance_key.boot_id.trim().is_empty()
        || instance_key.boot_id.len() > MAX_PROCESS_BOOT_ID_BYTES
        || instance_key.boot_id.contains('\0')
        || instance_key.pid == 0
        || instance_key.native_start_time.len() > MAX_PROCESS_NATIVE_START_TIME_BYTES
    {
        return None;
    }

    instance_key
        .native_start_time
        .parse::<u64>()
        .ok()
        .filter(|creation_time| {
            *creation_time != 0 && creation_time.to_string() == instance_key.native_start_time
        })
}

fn recovery_process_exit_state(process: HANDLE) -> Option<bool> {
    // Safety: the caller owns this process handle for the complete wait.
    match unsafe { WaitForSingleObject(process, 0) } {
        WAIT_OBJECT_0 => Some(true),
        WAIT_TIMEOUT => Some(false),
        WAIT_FAILED => None,
        _ => None,
    }
}

impl WindowsManagedProcess {
    pub fn instance_key(&self) -> &ProcessInstanceKey {
        &self.instance_key
    }

    pub fn process_group_id(&self) -> Option<u32> {
        self.process_group_id
    }

    pub fn is_terminal(&self) -> bool {
        self.terminal.is_some()
    }

    /// This normally returns `None` because interactive output is taken and
    /// drained before ResumeThread. It remains available for fail-closed
    /// callers that commit the process before starting their drain worker.
    pub fn take_terminal_output(&mut self) -> Option<WindowsManagedTerminalOutput> {
        self.terminal
            .as_mut()
            .and_then(WindowsPseudoConsole::take_output)
    }

    pub fn write_terminal(&mut self, input: &[u8]) -> Result<(), AppError> {
        self.terminal
            .as_mut()
            .ok_or_else(|| terminal_not_configured_error("WritePseudoConsole"))?
            .write(input)
    }

    pub fn resize_terminal(&mut self, columns: u16, rows: u16) -> Result<(), AppError> {
        self.terminal
            .as_mut()
            .ok_or_else(|| terminal_not_configured_error("ResizePseudoConsole"))?
            .resize(columns, rows)
    }

    /// Attempts one graceful CTRL_BREAK delivery. Every call revalidates the
    /// root identity first; callers must persist their phase to prevent a
    /// repeated request from delivering the signal again.
    pub fn send_graceful(&mut self) -> Result<WindowsManagedStopSignalResult, AppError> {
        self.revalidate_identity()?;

        let Some(group_id) = self.process_group_id else {
            return Ok(WindowsManagedStopSignalResult::SignalUnavailable(
                signal_unavailable_error(
                    ErrorCode::NotSupported,
                    "GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT)",
                    "processGroupNotConfigured",
                ),
            ));
        };
        if group_id != self.instance_key.pid {
            return Err(identity_mismatch_error(
                "RevalidateProcessGroup",
                "processGroupId",
            ));
        }

        // A terminated root no longer reserves its numeric PID. Do not target
        // that number as a console group after it could have been reused.
        match unsafe { WaitForSingleObject(self.process.raw(), 0) } {
            WAIT_TIMEOUT => {}
            WAIT_OBJECT_0 => {
                return Ok(WindowsManagedStopSignalResult::SignalUnavailable(
                    signal_unavailable_error(
                        ErrorCode::NotSupported,
                        "WaitForSingleObject(rootProcess)",
                        "rootProcessExited",
                    ),
                ));
            }
            WAIT_FAILED => {
                return Ok(WindowsManagedStopSignalResult::SignalUnavailable(
                    signal_api_unavailable_error(
                        "WaitForSingleObject(rootProcess)",
                        &WindowsError::from_win32(),
                    ),
                ));
            }
            status => {
                let mut error = signal_unavailable_error(
                    ErrorCode::PlatformError,
                    "WaitForSingleObject(rootProcess)",
                    "unexpectedWaitResult",
                );
                error
                    .details
                    .insert("platformCode".into(), format!("WAIT:0x{:08X}", status.0));
                return Ok(WindowsManagedStopSignalResult::SignalUnavailable(error));
            }
        }

        // Safety: this exact root was created with CREATE_NEW_PROCESS_GROUP,
        // and its group id was retained with the process owner. Windows still
        // validates the shared-console precondition for CTRL_BREAK delivery.
        match unsafe { GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, group_id) } {
            Ok(()) => Ok(WindowsManagedStopSignalResult::Delivered),
            Err(source) => Ok(WindowsManagedStopSignalResult::SignalUnavailable(
                signal_api_unavailable_error("GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT)", &source),
            )),
        }
    }

    /// Attempts one force-stop delivery to the established Job boundary. This
    /// never falls back to PID enumeration and does not wait for Job exit.
    pub fn send_force(&mut self) -> Result<WindowsManagedStopSignalResult, AppError> {
        self.revalidate_identity()?;

        // Safety: this is the same exclusively owned Job handle into which the
        // verified root process was assigned before it was resumed.
        match unsafe { TerminateJobObject(self.job.raw(), FORCE_STOP_EXIT_CODE) } {
            Ok(()) => Ok(WindowsManagedStopSignalResult::Delivered),
            Err(source) => Ok(WindowsManagedStopSignalResult::SignalUnavailable(
                signal_api_unavailable_error("TerminateJobObject", &source),
            )),
        }
    }

    /// Observes complete Job exit without sending another signal or blocking.
    pub fn poll_exit(&mut self) -> Result<WindowsManagedExitPoll, AppError> {
        match query_job_active_processes(self.job.raw())? {
            0 => Ok(WindowsManagedExitPoll::Exited),
            _ => Ok(WindowsManagedExitPoll::Running),
        }
    }

    fn revalidate_identity(&self) -> Result<(), AppError> {
        // Safety: the exact process handle returned by CreateProcessW remains
        // owned by self for this complete identity check and signal attempt.
        let process_id = unsafe { GetProcessId(self.process.raw()) };
        if process_id == 0 {
            return Err(platform_api_error(
                "RevalidateProcessIdentity(GetProcessId)",
                &WindowsError::from_win32(),
            ));
        }
        if process_id != self.instance_key.pid {
            return Err(identity_mismatch_error("RevalidateProcessIdentity", "pid"));
        }

        let creation_time = query_creation_time(self.process.raw()).map_err(|source| {
            platform_api_error("RevalidateProcessIdentity(GetProcessTimes)", &source)
        })?;
        if creation_time == 0 {
            return Err(platform_invariant_error(
                "RevalidateProcessIdentity(GetProcessTimes)",
                "creation time was zero",
            ));
        }
        if creation_time.to_string() != self.instance_key.native_start_time {
            return Err(identity_mismatch_error(
                "RevalidateProcessIdentity",
                "nativeStartTime",
            ));
        }

        let boot_id = crate::native::query_boot_identifier().map_err(|mut error| {
            error
                .details
                .insert("stopStage".into(), "RevalidateProcessIdentity".into());
            error
        })?;
        if boot_id != self.instance_key.boot_id {
            return Err(identity_mismatch_error(
                "RevalidateProcessIdentity",
                "bootId",
            ));
        }
        Ok(())
    }

    /// Terminates the complete Job and consumes the process owner. If bounded
    /// exit confirmation fails, the returned error retains both handles.
    pub fn terminate_and_wait(self) -> Result<(), WindowsManagedLaunchError> {
        terminate_owned_child(SuspendedChild {
            job: Some(self.job),
            process: Some(self.process),
            thread: None,
            terminal: self.terminal,
            assigned_to_job: true,
            instance_key: Some(self.instance_key),
        })
    }
}

impl fmt::Debug for WindowsManagedProcess {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WindowsManagedProcess")
            .field("instance_key", &self.instance_key)
            .field("process_group_id", &self.process_group_id)
            .finish_non_exhaustive()
    }
}

/// Redacted launch failure. When cleanup could not be confirmed, this value
/// retains the still-suspended process and exposes an explicit retry method.
#[must_use = "cleanup-pending launch errors retain process control handles and must be retried"]
pub struct WindowsManagedLaunchError {
    public: AppError,
    pending_cleanup: Option<SuspendedChild>,
}

impl WindowsManagedLaunchError {
    pub fn public_error(&self) -> &AppError {
        &self.public
    }

    pub fn cleanup_pending(&self) -> bool {
        self.pending_cleanup.is_some()
    }

    pub fn process_instance_key(&self) -> Option<&ProcessInstanceKey> {
        self.pending_cleanup
            .as_ref()
            .and_then(|child| child.instance_key.as_ref())
    }

    pub fn retry_cleanup(&mut self) -> Result<(), AppError> {
        let Some(mut child) = self.pending_cleanup.take() else {
            return Ok(());
        };
        match child.terminate_and_confirm() {
            Ok(()) => Ok(()),
            Err(cleanup) => {
                let result = cleanup_app_error(&cleanup);
                self.pending_cleanup = Some(child);
                Err(result)
            }
        }
    }
}

impl Display for WindowsManagedLaunchError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        self.public.fmt(formatter)
    }
}

impl fmt::Debug for WindowsManagedLaunchError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WindowsManagedLaunchError")
            .field("public", &self.public)
            .field("cleanup_pending", &self.cleanup_pending())
            .finish()
    }
}

impl std::error::Error for WindowsManagedLaunchError {}

impl Drop for WindowsManagedLaunchError {
    fn drop(&mut self) {
        if let Some(mut child) = self.pending_cleanup.take()
            && child.terminate_and_confirm().is_err()
        {
            quarantine_failed_cleanup(child);
        }
    }
}

/// Creates a suspended process, binds it to a kill-on-close Job, and returns
/// without allowing user code to execute. `resume` is a separate consuming step
/// so the Supervisor can durably record the returned identity first.
pub fn prepare_suspended_into_job(
    request: &WindowsManagedLaunchRequest<'_>,
) -> Result<SuspendedWindowsManagedProcess, WindowsManagedLaunchError> {
    validate_request(request).map_err(launch_error)?;
    let boot_id = crate::native::query_boot_identifier().map_err(launch_error)?;
    let application = WideBuffer::from_str_nul(
        request.executable,
        "executable",
        MAX_WINDOWS_COMMAND_LINE_UTF16_UNITS,
    )
    .map_err(launch_error)?;
    let requested_image =
        open_image_file(request.executable, "OpenRequestedExecutable").map_err(launch_error)?;
    let requested_image_identity =
        query_file_identity(requested_image.raw(), "GetRequestedExecutableFileId")
            .map_err(launch_error)?;
    let current_directory = WideBuffer::from_str_nul(
        request.working_directory,
        "workingDirectory",
        MAX_WINDOWS_COMMAND_LINE_UTF16_UNITS,
    )
    .map_err(launch_error)?;
    let mut command_line =
        build_command_line(request.executable, request.argv).map_err(launch_error)?;
    let environment = build_environment_block(request.environment).map_err(launch_error)?;

    // Safety: null security attributes and name create an unnamed current-user Job.
    let job = OwnedHandle::new(
        unsafe { CreateJobObjectW(None, PCWSTR::null()) }
            .map_err(|source| launch_error(platform_api_error("CreateJobObjectW", &source)))?,
    );
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    limits.BasicLimitInformation.LimitFlags =
        JOB_OBJECT_LIMIT(JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE.0);
    // Safety: the pointer describes the fixed-size initialized structure and
    // remains valid for the complete call.
    unsafe {
        SetInformationJobObject(
            job.raw(),
            JobObjectExtendedLimitInformation,
            (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    }
    .map_err(|source| launch_error(platform_api_error("SetInformationJobObject", &source)))?;

    let mut process_info = PROCESS_INFORMATION::default();
    let mut creation_flags = PROCESS_CREATION_FLAGS(
        CREATE_SUSPENDED.0 | CREATE_UNICODE_ENVIRONMENT.0 | EXTENDED_STARTUPINFO_PRESENT.0,
    );
    let create_new_process_group = request.stdio.create_new_process_group();
    if create_new_process_group {
        creation_flags |= CREATE_NEW_PROCESS_GROUP;
    }

    let mut terminal = None;
    let create_result = match &request.stdio {
        WindowsManagedStdio::Pipes { stdout, stderr, .. } => {
            let inherited_handles =
                InheritedStandardHandles::new(stdout, stderr).map_err(launch_error)?;
            let startup = inherited_handles.startup_info();

            // Safety: all pointed-to UTF-16 buffers are NUL-terminated,
            // bounded, and live through the call. The extended startup
            // structure and its three-handle whitelist remain live for the
            // complete call.
            unsafe {
                CreateProcessW(
                    PCWSTR(application.as_ptr()),
                    Some(PWSTR(command_line.as_mut_ptr())),
                    None,
                    None,
                    true,
                    creation_flags,
                    Some(environment.as_ptr().cast::<c_void>()),
                    PCWSTR(current_directory.as_ptr()),
                    &startup.StartupInfo,
                    &mut process_info,
                )
            }
        }
        WindowsManagedStdio::PseudoConsole { columns, rows } => {
            let prepared = PreparedPseudoConsole::new(*columns, *rows).map_err(launch_error)?;
            let attributes = ProcThreadAttributeList::with_pseudo_console(prepared.handle())
                .map_err(launch_error)?;
            let startup = STARTUPINFOEXW {
                StartupInfo: STARTUPINFOW {
                    cb: size_of::<STARTUPINFOEXW>() as u32,
                    ..Default::default()
                },
                lpAttributeList: attributes.raw(),
            };

            // ConPTY transports standard input/output through its own device;
            // no ordinary pipe handle is inherited by the client process.
            let result = unsafe {
                CreateProcessW(
                    PCWSTR(application.as_ptr()),
                    Some(PWSTR(command_line.as_mut_ptr())),
                    None,
                    None,
                    false,
                    creation_flags,
                    Some(environment.as_ptr().cast::<c_void>()),
                    PCWSTR(current_directory.as_ptr()),
                    &startup.StartupInfo,
                    &mut process_info,
                )
            };
            drop(attributes);
            if result.is_ok() {
                terminal = Some(prepared.into_terminal());
            }
            result
        }
    };
    // Ordinary inheritable duplicates and ConPTY's device-side pipe handles
    // are closed immediately after CreateProcessW returns. Caller-owned
    // ordinary PipeWriters and ConPTY master handles were never inherited.
    create_result.map_err(|source| launch_error(platform_api_error("CreateProcessW", &source)))?;

    let mut child = SuspendedChild::new(job, process_info, terminal, false);
    if process_info.dwProcessId == 0 {
        return Err(cleanup_after_failure(
            platform_invariant_error("CreateProcessW", "process identifier was zero"),
            child,
        ));
    }

    // Safety: the process and Job handles are exclusively owned, and the
    // primary thread is still at its initial suspended count.
    if let Err(source) = unsafe { AssignProcessToJobObject(child.job_raw(), child.process_raw()) } {
        return Err(cleanup_after_failure(
            platform_api_error("AssignProcessToJobObject", &source),
            child,
        ));
    }
    child.assigned_to_job = true;

    let creation_time = match query_creation_time(child.process_raw()) {
        Ok(value) if value != 0 => value,
        Ok(_) => {
            return Err(cleanup_after_failure(
                platform_invariant_error("GetProcessTimes", "creation time was zero"),
                child,
            ));
        }
        Err(source) => {
            return Err(cleanup_after_failure(
                platform_api_error("GetProcessTimes", &source),
                child,
            ));
        }
    };

    if let Err(error) = verify_process_image(child.process_raw(), &requested_image_identity) {
        return Err(cleanup_after_failure(error, child));
    }

    let instance_key = ProcessInstanceKey {
        boot_id,
        pid: process_info.dwProcessId,
        native_start_time: creation_time.to_string(),
    };
    child.instance_key = Some(instance_key.clone());
    Ok(SuspendedWindowsManagedProcess {
        child: Some(child),
        instance_key,
        process_group_id: create_new_process_group.then_some(process_info.dwProcessId),
    })
}

fn validate_request(request: &WindowsManagedLaunchRequest<'_>) -> Result<(), AppError> {
    if let WindowsManagedStdio::PseudoConsole { columns, rows } = &request.stdio {
        validate_pseudo_console_size(*columns, *rows)?;
    }
    if request
        .executable
        .encode_utf16()
        .take(MAX_WINDOWS_COMMAND_LINE_UTF16_UNITS)
        .count()
        >= MAX_WINDOWS_COMMAND_LINE_UTF16_UNITS
    {
        return Err(invalid_launch_input(
            "executable",
            "exceeds the Windows UTF-16 limit",
        ));
    }
    if request
        .working_directory
        .encode_utf16()
        .take(MAX_WINDOWS_COMMAND_LINE_UTF16_UNITS)
        .count()
        >= MAX_WINDOWS_COMMAND_LINE_UTF16_UNITS
    {
        return Err(invalid_launch_input(
            "workingDirectory",
            "exceeds the Windows UTF-16 limit",
        ));
    }
    if !valid_absolute_windows_path(request.executable) {
        return Err(invalid_launch_input(
            "executable",
            "must be an absolute drive or UNC path without a device namespace",
        ));
    }
    if !valid_absolute_windows_path(request.working_directory) {
        return Err(invalid_launch_input(
            "workingDirectory",
            "must be an absolute drive or UNC path without a device namespace",
        ));
    }
    if request.environment.platform() != ExecutionPlatform::Windows {
        return Err(invalid_launch_input(
            "environment",
            "must be resolved for Windows",
        ));
    }
    Ok(())
}

fn valid_absolute_windows_path(value: &str) -> bool {
    if value.is_empty() || value.contains('\0') {
        return false;
    }
    let value = value.replace('/', "\\");
    if ["\\\\?\\", "\\\\.\\", "\\??\\", "\\Device\\"]
        .iter()
        .any(|prefix| starts_with_ascii_case(&value, prefix))
    {
        return false;
    }
    let bytes = value.as_bytes();
    if bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'\\' {
        return bytes.len() == 3 || value[3..].split('\\').all(valid_windows_component);
    }
    if !value.starts_with("\\\\") {
        return false;
    }
    let mut components = value[2..].split('\\');
    let server = components.next().unwrap_or_default();
    let share = components.next().unwrap_or_default();
    valid_windows_component(server)
        && valid_windows_component(share)
        && !matches!(
            server.to_ascii_uppercase().as_str(),
            "." | "?" | "GLOBALROOT"
        )
        && components.all(valid_windows_component)
}

fn starts_with_ascii_case(value: &str, prefix: &str) -> bool {
    value
        .get(..prefix.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
}

fn valid_windows_component(component: &str) -> bool {
    !component.is_empty()
        && !matches!(component, "." | "..")
        && !component.ends_with(' ')
        && !component.ends_with('.')
        && !component
            .chars()
            .any(|character| character.is_control() || "<>:\"/\\|?*".contains(character))
}

fn build_command_line(executable: &str, argv: &[String]) -> Result<WideBuffer, AppError> {
    let mut result = WideBuffer::new();
    append_windows_argument(&mut result, executable)?;
    for argument in argv {
        result.push_bounded(
            ' ' as u16,
            "commandLine",
            MAX_WINDOWS_COMMAND_LINE_UTF16_UNITS,
        )?;
        append_windows_argument(&mut result, argument)?;
    }
    result.push_bounded(0, "commandLine", MAX_WINDOWS_COMMAND_LINE_UTF16_UNITS)?;
    Ok(result)
}

fn append_windows_argument(result: &mut WideBuffer, argument: &str) -> Result<(), AppError> {
    if argument.contains('\0') {
        return Err(invalid_launch_input("argv", "must not contain NUL"));
    }
    let quoted = argument.is_empty()
        || argument
            .encode_utf16()
            .any(|unit| unit == b' ' as u16 || unit == b'\t' as u16 || unit == b'"' as u16);
    if !quoted {
        return result.extend_bounded(
            argument.encode_utf16(),
            "commandLine",
            MAX_WINDOWS_COMMAND_LINE_UTF16_UNITS,
        );
    }

    result.push_bounded(
        b'"' as u16,
        "commandLine",
        MAX_WINDOWS_COMMAND_LINE_UTF16_UNITS,
    )?;
    let mut backslashes = 0_usize;
    for unit in argument.encode_utf16() {
        if unit == b'\\' as u16 {
            backslashes = backslashes.saturating_add(1);
            continue;
        }
        if unit == b'"' as u16 {
            push_backslashes(result, backslashes.saturating_mul(2).saturating_add(1))?;
            result.push_bounded(unit, "commandLine", MAX_WINDOWS_COMMAND_LINE_UTF16_UNITS)?;
        } else {
            push_backslashes(result, backslashes)?;
            result.push_bounded(unit, "commandLine", MAX_WINDOWS_COMMAND_LINE_UTF16_UNITS)?;
        }
        backslashes = 0;
    }
    push_backslashes(result, backslashes.saturating_mul(2))?;
    result.push_bounded(
        b'"' as u16,
        "commandLine",
        MAX_WINDOWS_COMMAND_LINE_UTF16_UNITS,
    )
}

fn push_backslashes(result: &mut WideBuffer, count: usize) -> Result<(), AppError> {
    for _ in 0..count {
        result.push_bounded(
            b'\\' as u16,
            "commandLine",
            MAX_WINDOWS_COMMAND_LINE_UTF16_UNITS,
        )?;
    }
    Ok(())
}

fn build_environment_block(environment: &ResolvedEnvironment) -> Result<WideBuffer, AppError> {
    let mut entries = environment.entries().iter().collect::<Vec<_>>();
    entries.sort_by(|left, right| {
        left.name()
            .to_ascii_uppercase()
            .cmp(&right.name().to_ascii_uppercase())
            .then_with(|| left.name().cmp(right.name()))
    });

    let mut previous_name: Option<&str> = None;
    let mut required_units = 1_usize;
    for entry in &entries {
        if previous_name.is_some_and(|name| name.eq_ignore_ascii_case(entry.name())) {
            return Err(invalid_launch_input(
                "environment",
                "contains duplicate names",
            ));
        }
        if !portable_environment_name(entry.name()) {
            return Err(invalid_launch_input(
                "environment.name",
                "must match [A-Za-z_][A-Za-z0-9_]*",
            ));
        }
        let value = entry.value().expose();
        if value.contains('\0') {
            return Err(invalid_launch_input(
                "environment.value",
                "must not contain NUL",
            ));
        }
        required_units = required_units
            .checked_add(entry.name().encode_utf16().count())
            .and_then(|units| units.checked_add(1))
            .and_then(|units| units.checked_add(value.encode_utf16().count()))
            .and_then(|units| units.checked_add(1))
            .ok_or_else(|| {
                invalid_launch_input("environment", "exceeds the Windows UTF-16 limit")
            })?;
        if required_units > MAX_WINDOWS_ENVIRONMENT_UTF16_UNITS {
            return Err(invalid_launch_input(
                "environment",
                "exceeds the Windows UTF-16 limit",
            ));
        }
        previous_name = Some(entry.name());
    }
    if entries.is_empty() {
        required_units = 2;
    }

    // The exact allocation happens before values are encoded into this
    // buffer, so secret UTF-16 units are never copied by Vec growth.
    let mut result = WideBuffer::with_capacity(required_units);
    for entry in entries {
        let value = entry.value().expose();
        result.extend_bounded(
            entry.name().encode_utf16(),
            "environment",
            MAX_WINDOWS_ENVIRONMENT_UTF16_UNITS,
        )?;
        result.push_bounded(
            b'=' as u16,
            "environment",
            MAX_WINDOWS_ENVIRONMENT_UTF16_UNITS,
        )?;
        result.extend_bounded(
            value.encode_utf16(),
            "environment",
            MAX_WINDOWS_ENVIRONMENT_UTF16_UNITS,
        )?;
        result.push_bounded(0, "environment", MAX_WINDOWS_ENVIRONMENT_UTF16_UNITS)?;
    }
    if result.is_empty() {
        result.push_bounded(0, "environment", MAX_WINDOWS_ENVIRONMENT_UTF16_UNITS)?;
    }
    result.push_bounded(0, "environment", MAX_WINDOWS_ENVIRONMENT_UTF16_UNITS)?;
    debug_assert_eq!(result.len(), required_units);
    Ok(result)
}

fn portable_environment_name(value: &str) -> bool {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn query_creation_time(process: HANDLE) -> windows::core::Result<u64> {
    let mut create = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    // Safety: the process handle is live and every output pointer is writable.
    unsafe { GetProcessTimes(process, &mut create, &mut exit, &mut kernel, &mut user) }?;
    Ok(((create.dwHighDateTime as u64) << 32) | create.dwLowDateTime as u64)
}

fn verify_process_image(process: HANDLE, requested: &FileIdentity) -> Result<(), AppError> {
    let mut buffer = vec![0_u16; MAX_WINDOWS_IMAGE_PATH_UTF16_UNITS];
    let mut length = buffer.len() as u32;
    // Safety: the bounded buffer and length are writable, and `process` is the
    // exact still-suspended handle returned by CreateProcessW.
    unsafe {
        QueryFullProcessImageNameW(
            process,
            Default::default(),
            PWSTR(buffer.as_mut_ptr()),
            &mut length,
        )
    }
    .map_err(|source| platform_api_error("QueryFullProcessImageNameW", &source))?;

    let length = length as usize;
    if length == 0 || length >= buffer.len() {
        return Err(platform_invariant_error(
            "QueryFullProcessImageNameW",
            "returned image path length was invalid",
        ));
    }
    let actual = String::from_utf16(&buffer[..length]).map_err(|_| {
        platform_invariant_error(
            "QueryFullProcessImageNameW",
            "returned image path was not strict UTF-16",
        )
    })?;
    let actual = open_image_file(&actual, "OpenCreatedProcessImage")?;
    let actual = query_file_identity(actual.raw(), "GetCreatedProcessImageFileId")?;
    if &actual != requested {
        return Err(platform_invariant_error(
            "GetCreatedProcessImageFileId",
            "created process image did not match the requested executable file identity",
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct FileIdentity {
    volume_serial_number: u64,
    file_id: [u8; 16],
}

fn open_image_file(path: &str, stage: &'static str) -> Result<OwnedHandle, AppError> {
    let path = extended_image_path(path).ok_or_else(|| {
        platform_invariant_error(stage, "image path was not an absolute Win32 file path")
    })?;
    let path = WideBuffer::from_str_nul(&path, "imagePath", MAX_WINDOWS_IMAGE_PATH_UTF16_UNITS)
        .map_err(|_| platform_invariant_error(stage, "image path exceeded the Windows limit"))?;
    // Safety: the path is a live NUL-terminated UTF-16 buffer. Denying write
    // and delete sharing keeps this exact file object stable across process
    // creation and the post-create identity comparison.
    let handle = unsafe {
        CreateFileW(
            PCWSTR(path.as_ptr()),
            FILE_READ_ATTRIBUTES.0,
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
    }
    .map_err(|source| platform_api_error(stage, &source))?;
    Ok(OwnedHandle::new(handle))
}

fn extended_image_path(path: &str) -> Option<String> {
    if path.is_empty() || path.contains('\0') {
        return None;
    }
    let path = path.replace('/', "\\");
    if starts_with_ascii_case(&path, "\\\\?\\") {
        return Some(path);
    }
    if path.starts_with("\\\\") {
        let tail = path.get(2..)?;
        return (!tail.is_empty()).then(|| format!("\\\\?\\UNC\\{tail}"));
    }
    let bytes = path.as_bytes();
    (bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'\\')
        .then(|| format!("\\\\?\\{path}"))
}

fn query_file_identity(handle: HANDLE, stage: &'static str) -> Result<FileIdentity, AppError> {
    let mut information = FILE_ID_INFO::default();
    // Safety: the handle remains live and the output points to a writable
    // fixed-size FILE_ID_INFO for the complete call.
    unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileIdInfo,
            (&mut information as *mut FILE_ID_INFO).cast(),
            size_of::<FILE_ID_INFO>() as u32,
        )
    }
    .map_err(|source| platform_api_error(stage, &source))?;
    Ok(FileIdentity {
        volume_serial_number: information.VolumeSerialNumber,
        file_id: information.FileId.Identifier,
    })
}

fn cleanup_after_failure(error: AppError, mut child: SuspendedChild) -> WindowsManagedLaunchError {
    match child.terminate_and_confirm() {
        Ok(()) => WindowsManagedLaunchError {
            public: error,
            pending_cleanup: None,
        },
        Err(cleanup) => {
            let mut public = error;
            add_cleanup_details(&mut public, &cleanup);
            WindowsManagedLaunchError {
                public,
                pending_cleanup: Some(child),
            }
        }
    }
}

fn terminate_owned_child(mut child: SuspendedChild) -> Result<(), WindowsManagedLaunchError> {
    match child.terminate_and_confirm() {
        Ok(()) => Ok(()),
        Err(cleanup) => Err(WindowsManagedLaunchError {
            public: cleanup_app_error(&cleanup),
            pending_cleanup: Some(child),
        }),
    }
}

fn quarantine_failed_cleanup(child: SuspendedChild) {
    // The owning error exposes retry_cleanup and is the normal quarantine.
    // If that owner is nevertheless dropped, never close the last handles to
    // an unconfirmed child. An assigned child still has KILL_ON_JOB_CLOSE; an
    // unassigned child has no such guarantee but its primary thread remains
    // suspended and this adapter never resumes it. This is intentionally not
    // described as eventual OS cleanup.
    std::mem::forget(child);
}

fn launch_error(public: AppError) -> WindowsManagedLaunchError {
    WindowsManagedLaunchError {
        public,
        pending_cleanup: None,
    }
}

fn invalid_launch_input(field: &'static str, reason: &'static str) -> AppError {
    let mut error = AppError::new(ErrorCode::InvalidArgument, "invalid Windows launch request");
    error.details.insert("field".into(), field.into());
    error.details.insert("reason".into(), reason.into());
    error
}

fn terminal_not_configured_error(stage: &'static str) -> AppError {
    let mut error = AppError::new(
        ErrorCode::NotSupported,
        "managed process does not own a pseudoconsole",
    );
    error.details.insert("stage".into(), stage.into());
    error
        .details
        .insert("reason".into(), "terminalNotConfigured".into());
    error
}

fn terminal_io_error(stage: &'static str, source: &io::Error) -> AppError {
    let mut error = AppError::new(
        ErrorCode::PlatformError,
        "Windows pseudoconsole I/O operation failed",
    );
    error.details.insert("stage".into(), stage.into());
    let platform_code = source.raw_os_error().map_or_else(
        || format!("IO:{:?}", source.kind()),
        |code| format!("WIN32:{code}"),
    );
    error.details.insert("platformCode".into(), platform_code);
    error
}

fn platform_api_error(stage: &'static str, source: &WindowsError) -> AppError {
    let win32_code = WIN32_ERROR::from_error(source);
    let code = match win32_code {
        Some(ERROR_ACCESS_DENIED) => ErrorCode::AccessDenied,
        Some(code) if matches!(code, ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND) => {
            ErrorCode::NotFound
        }
        _ => ErrorCode::PlatformError,
    };
    let mut error = AppError::new(code, "Windows managed process operation failed");
    error.details.insert("stage".into(), stage.into());
    error
        .details
        .insert("platformCode".into(), redacted_platform_code(source));
    error
}

fn platform_invariant_error(stage: &'static str, reason: &'static str) -> AppError {
    let mut error = AppError::new(
        ErrorCode::PlatformError,
        "Windows managed process invariant failed",
    );
    error.details.insert("stage".into(), stage.into());
    error.details.insert("reason".into(), reason.into());
    error
}

fn identity_mismatch_error(stage: &'static str, field: &'static str) -> AppError {
    let mut error = AppError::new(
        ErrorCode::IdentityMismatch,
        "Windows managed process identity no longer matches",
    );
    error.details.insert("stage".into(), stage.into());
    error.details.insert("field".into(), field.into());
    error
}

fn signal_unavailable_error(
    code: ErrorCode,
    stage: &'static str,
    reason: &'static str,
) -> AppError {
    let mut error = AppError::new(code, "Windows managed stop signal is unavailable");
    error.details.insert("stage".into(), stage.into());
    error.details.insert("reason".into(), reason.into());
    error
}

fn signal_api_unavailable_error(stage: &'static str, source: &WindowsError) -> AppError {
    let mut error =
        signal_unavailable_error(ErrorCode::PlatformError, stage, "platformRejectedSignal");
    error
        .details
        .insert("platformCode".into(), redacted_platform_code(source));
    error
}

fn redacted_platform_code(source: &WindowsError) -> String {
    WIN32_ERROR::from_error(source).map_or_else(
        || format!("HRESULT:0x{:08X}", source.code().0 as u32),
        |code| format!("WIN32:{}", code.0),
    )
}

fn cleanup_app_error(cleanup: &CleanupFailure) -> AppError {
    let mut error = AppError::new(
        ErrorCode::PlatformError,
        "Windows controlled process cleanup was not confirmed",
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

struct SuspendedChild {
    job: Option<OwnedHandle>,
    process: Option<OwnedHandle>,
    thread: Option<OwnedHandle>,
    terminal: Option<WindowsPseudoConsole>,
    assigned_to_job: bool,
    instance_key: Option<ProcessInstanceKey>,
}

impl SuspendedChild {
    fn new(
        job: OwnedHandle,
        info: PROCESS_INFORMATION,
        terminal: Option<WindowsPseudoConsole>,
        assigned_to_job: bool,
    ) -> Self {
        Self {
            job: Some(job),
            process: Some(OwnedHandle::new(info.hProcess)),
            thread: Some(OwnedHandle::new(info.hThread)),
            terminal,
            assigned_to_job,
            instance_key: None,
        }
    }

    fn is_terminal(&self) -> bool {
        self.terminal.is_some()
    }

    fn take_terminal_output(&mut self) -> Option<WindowsManagedTerminalOutput> {
        self.terminal
            .as_mut()
            .and_then(WindowsPseudoConsole::take_output)
    }

    fn write_terminal(&mut self, input: &[u8]) -> Result<(), AppError> {
        self.terminal
            .as_mut()
            .ok_or_else(|| terminal_not_configured_error("WritePseudoConsole"))?
            .write(input)
    }

    fn resize_terminal(&mut self, columns: u16, rows: u16) -> Result<(), AppError> {
        self.terminal
            .as_mut()
            .ok_or_else(|| terminal_not_configured_error("ResizePseudoConsole"))?
            .resize(columns, rows)
    }

    fn job_raw(&self) -> HANDLE {
        self.job.as_ref().expect("job handle").raw()
    }

    fn process_raw(&self) -> HANDLE {
        self.process.as_ref().expect("process handle").raw()
    }

    fn thread_raw(&self) -> HANDLE {
        self.thread.as_ref().expect("thread handle").raw()
    }

    fn terminate_and_confirm(&mut self) -> Result<(), CleanupFailure> {
        let termination_stage = if self.assigned_to_job {
            "TerminateJobObject"
        } else {
            "TerminateProcess"
        };
        let termination_error = if self.assigned_to_job {
            // Safety: the Job remains exclusively owned and contains this process.
            unsafe { TerminateJobObject(self.job_raw(), CLEANUP_EXIT_CODE) }
        } else {
            // Safety: CreateProcessW grants terminate rights on this owned handle.
            unsafe { TerminateProcess(self.process_raw(), CLEANUP_EXIT_CODE) }
        }
        .err()
        .map(|source| CleanupFailure::Api {
            stage: termination_stage,
            code: redacted_platform_code(&source),
        });

        if self.assigned_to_job {
            wait_for_job_empty(self.job_raw(), termination_error)
        } else {
            wait_for_process_exit(self.process_raw(), termination_error)
        }
    }

    fn commit(mut self) -> (OwnedHandle, OwnedHandle, Option<WindowsPseudoConsole>) {
        self.thread.take();
        (
            self.job.take().expect("job handle"),
            self.process.take().expect("process handle"),
            self.terminal.take(),
        )
    }
}

fn wait_for_job_empty(
    job: HANDLE,
    termination_error: Option<CleanupFailure>,
) -> Result<(), CleanupFailure> {
    let started = Instant::now();
    loop {
        let active_processes = match query_job_active_processes_native(job) {
            Ok(active_processes) => active_processes,
            Err(source) => {
                return Err(termination_error.unwrap_or_else(|| CleanupFailure::Api {
                    stage: "QueryInformationJobObject",
                    code: redacted_platform_code(&source),
                }));
            }
        };
        if active_processes == 0 {
            return Ok(());
        }

        let elapsed = started.elapsed();
        if elapsed >= Duration::from_millis(u64::from(CLEANUP_WAIT_MS)) {
            return Err(termination_error.unwrap_or(CleanupFailure::Timeout {
                stage: "QueryInformationJobObject",
            }));
        }
        let remaining = Duration::from_millis(u64::from(CLEANUP_WAIT_MS)) - elapsed;
        thread::sleep(CLEANUP_POLL_INTERVAL.min(remaining));
    }
}

fn query_job_active_processes(job: HANDLE) -> Result<u32, AppError> {
    query_job_active_processes_native(job)
        .map_err(|source| platform_api_error("QueryInformationJobObject", &source))
}

fn query_job_active_processes_native(job: HANDLE) -> windows::core::Result<u32> {
    let mut information = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
    // Safety: the Job handle remains owned and the fixed-size output is
    // writable for the complete query.
    unsafe {
        QueryInformationJobObject(
            Some(job),
            JobObjectBasicAccountingInformation,
            (&mut information as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
            size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
            None,
        )
    }?;
    Ok(information.ActiveProcesses)
}

fn wait_for_process_exit(
    process: HANDLE,
    termination_error: Option<CleanupFailure>,
) -> Result<(), CleanupFailure> {
    // Safety: the process handle remains owned throughout the bounded wait.
    match unsafe { WaitForSingleObject(process, CLEANUP_WAIT_MS) } {
        WAIT_OBJECT_0 => Ok(()),
        WAIT_TIMEOUT => Err(termination_error.unwrap_or(CleanupFailure::Timeout {
            stage: "WaitForSingleObject",
        })),
        WAIT_FAILED => Err(termination_error.unwrap_or_else(|| CleanupFailure::Api {
            stage: "WaitForSingleObject",
            code: redacted_platform_code(&WindowsError::from_win32()),
        })),
        status => Err(termination_error.unwrap_or(CleanupFailure::UnexpectedWait(status.0))),
    }
}

enum CleanupFailure {
    Api { stage: &'static str, code: String },
    Timeout { stage: &'static str },
    UnexpectedWait(u32),
}

impl CleanupFailure {
    fn stage(&self) -> &'static str {
        match self {
            Self::Api { stage, .. } => stage,
            Self::Timeout { stage } => stage,
            Self::UnexpectedWait(_) => "WaitForSingleObject",
        }
    }

    fn result_code(&self) -> String {
        match self {
            Self::Api { code, .. } => code.clone(),
            Self::Timeout { .. } => "WAIT_TIMEOUT".into(),
            Self::UnexpectedWait(status) => format!("WAIT:0x{status:08X}"),
        }
    }
}

struct PreparedPseudoConsole {
    // These ConPTY-side handles remain open through CreateProcessW and are
    // closed by into_terminal immediately after that call returns.
    input_reader: PipeReader,
    output_writer: PipeWriter,
    terminal: WindowsPseudoConsole,
}

impl PreparedPseudoConsole {
    fn new(columns: u16, rows: u16) -> Result<Self, AppError> {
        validate_pseudo_console_size(columns, rows)?;
        let (input_reader, input_writer) =
            pipe().map_err(|source| terminal_io_error("CreatePseudoConsoleInputPipe", &source))?;
        let (output_reader, output_writer) =
            pipe().map_err(|source| terminal_io_error("CreatePseudoConsoleOutputPipe", &source))?;
        let size = pseudo_console_coord(columns, rows);
        // Safety: both borrowed synchronous pipe handles remain open through
        // CreateProcessW, and the validated dimensions fit COORD.
        let handle = unsafe {
            CreatePseudoConsole(
                size,
                HANDLE(input_reader.as_raw_handle()),
                HANDLE(output_writer.as_raw_handle()),
                0,
            )
        }
        .map_err(|source| platform_api_error("CreatePseudoConsole", &source))?;
        if handle.is_invalid() {
            return Err(platform_invariant_error(
                "CreatePseudoConsole",
                "pseudoconsole handle was invalid",
            ));
        }

        Ok(Self {
            input_reader,
            output_writer,
            terminal: WindowsPseudoConsole {
                handle: Some(handle),
                input_writer: Some(input_writer),
                output_reader: Some(output_reader),
            },
        })
    }

    fn handle(&self) -> HPCON {
        self.terminal.handle()
    }

    fn into_terminal(self) -> WindowsPseudoConsole {
        let Self {
            input_reader,
            output_writer,
            terminal,
        } = self;
        drop(input_reader);
        drop(output_writer);
        terminal
    }
}

struct WindowsPseudoConsole {
    handle: Option<HPCON>,
    // Input remains owned by the Supervisor's process control even when no UI
    // is connected. Output may be transferred exactly once to its drain worker.
    input_writer: Option<PipeWriter>,
    output_reader: Option<PipeReader>,
}

impl WindowsPseudoConsole {
    fn handle(&self) -> HPCON {
        self.handle.expect("pseudoconsole handle")
    }

    fn take_output(&mut self) -> Option<WindowsManagedTerminalOutput> {
        self.output_reader
            .take()
            .map(|reader| WindowsManagedTerminalOutput { reader })
    }

    fn write(&mut self, input: &[u8]) -> Result<(), AppError> {
        self.input_writer
            .as_mut()
            .ok_or_else(|| {
                platform_invariant_error("WritePseudoConsole", "terminal input owner was empty")
            })?
            .write_all(input)
            .map_err(|source| terminal_io_error("WritePseudoConsole", &source))
    }

    fn resize(&mut self, columns: u16, rows: u16) -> Result<(), AppError> {
        validate_pseudo_console_size(columns, rows)?;
        let handle = self.handle();
        // Safety: this owner keeps the pseudoconsole open for the complete
        // call, and both validated dimensions fit COORD.
        unsafe { ResizePseudoConsole(handle, pseudo_console_coord(columns, rows)) }
            .map_err(|source| platform_api_error("ResizePseudoConsole", &source))
    }
}

impl Drop for WindowsPseudoConsole {
    fn drop(&mut self) {
        self.input_writer.take();
        // If output was not transferred to a dedicated drain worker, close it
        // before ClosePseudoConsole so older Windows versions cannot block on
        // a final frame whose pipe has no reader.
        self.output_reader.take();
        if let Some(handle) = self.handle.take() {
            // Safety: this value exclusively owns the HPCON and closes it once.
            unsafe { ClosePseudoConsole(handle) };
        }
    }
}

fn validate_pseudo_console_size(columns: u16, rows: u16) -> Result<(), AppError> {
    if columns == 0 || columns > MAX_PSEUDO_CONSOLE_DIMENSION {
        return Err(invalid_launch_input(
            "terminalColumns",
            "must be between 1 and 32767",
        ));
    }
    if rows == 0 || rows > MAX_PSEUDO_CONSOLE_DIMENSION {
        return Err(invalid_launch_input(
            "terminalRows",
            "must be between 1 and 32767",
        ));
    }
    Ok(())
}

fn pseudo_console_coord(columns: u16, rows: u16) -> COORD {
    COORD {
        X: columns as i16,
        Y: rows as i16,
    }
}

struct InheritedStandardHandles {
    // Attribute values must outlive the attribute list. Field declaration
    // order ensures the list is deleted before its backing handle array and
    // the inheritable duplicates are closed.
    attribute_list: ProcThreadAttributeList,
    _handle_list: Box<[HANDLE; 3]>,
    stdin: OwnedHandle,
    stdout: OwnedHandle,
    stderr: OwnedHandle,
}

impl InheritedStandardHandles {
    fn new(stdout: &PipeWriter, stderr: &PipeWriter) -> Result<Self, AppError> {
        let null_input = open_null_standard_input()?;
        let stdin = duplicate_inheritable_handle(null_input.raw(), "DuplicateStandardInput")?;
        let stdout = duplicate_inheritable_handle(
            HANDLE(stdout.as_raw_handle()),
            "DuplicateStandardOutput",
        )?;
        let stderr =
            duplicate_inheritable_handle(HANDLE(stderr.as_raw_handle()), "DuplicateStandardError")?;
        let handle_list = Box::new([stdin.raw(), stdout.raw(), stderr.raw()]);
        let attribute_list = ProcThreadAttributeList::with_handle_list(&handle_list)?;

        Ok(Self {
            attribute_list,
            _handle_list: handle_list,
            stdin,
            stdout,
            stderr,
        })
    }

    fn startup_info(&self) -> STARTUPINFOEXW {
        STARTUPINFOEXW {
            StartupInfo: STARTUPINFOW {
                cb: size_of::<STARTUPINFOEXW>() as u32,
                dwFlags: STARTF_USESTDHANDLES,
                hStdInput: self.stdin.raw(),
                hStdOutput: self.stdout.raw(),
                hStdError: self.stderr.raw(),
                ..Default::default()
            },
            lpAttributeList: self.attribute_list.raw(),
        }
    }
}

fn open_null_standard_input() -> Result<OwnedHandle, AppError> {
    // Safety: the static buffer is NUL-terminated. Null security attributes
    // make the source handle non-inheritable; only its duplicate is inherited.
    let handle = unsafe {
        CreateFileW(
            PCWSTR(NULL_DEVICE_NAME.as_ptr()),
            FILE_GENERIC_READ.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
    }
    .map_err(|source| platform_api_error("OpenStandardInputNull", &source))?;
    Ok(OwnedHandle::new(handle))
}

fn duplicate_inheritable_handle(
    source: HANDLE,
    stage: &'static str,
) -> Result<OwnedHandle, AppError> {
    let mut duplicate = HANDLE::default();
    // Safety: both process arguments identify this process, the source remains
    // borrowed for the call, and the writable output receives unique ownership.
    unsafe {
        let current_process = GetCurrentProcess();
        DuplicateHandle(
            current_process,
            source,
            current_process,
            &mut duplicate,
            0,
            true,
            DUPLICATE_SAME_ACCESS,
        )
    }
    .map_err(|source| platform_api_error(stage, &source))?;
    if duplicate.is_invalid() {
        return Err(platform_invariant_error(
            stage,
            "duplicate handle was invalid",
        ));
    }
    Ok(OwnedHandle::new(duplicate))
}

struct ProcThreadAttributeList {
    list: LPPROC_THREAD_ATTRIBUTE_LIST,
    _storage: Vec<usize>,
}

impl ProcThreadAttributeList {
    fn with_handle_list(handles: &[HANDLE; 3]) -> Result<Self, AppError> {
        let result = Self::with_capacity(1)?;
        // Safety: the initialized list and fixed-size boxed handle array remain
        // live until after CreateProcessW. All listed handles are inheritable.
        unsafe {
            UpdateProcThreadAttribute(
                result.list,
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                Some(handles.as_ptr().cast()),
                size_of_val(handles),
                None,
                None,
            )
        }
        .map_err(|source| platform_api_error("UpdateProcThreadAttribute(handleList)", &source))?;
        Ok(result)
    }

    fn with_pseudo_console(handle: HPCON) -> Result<Self, AppError> {
        let result = Self::with_capacity(1)?;
        // PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE takes the pointer-shaped HPCON
        // value itself, not a pointer to a Rust HPCON wrapper.
        unsafe {
            UpdateProcThreadAttribute(
                result.list,
                0,
                PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE as usize,
                Some(handle.0 as *const c_void),
                size_of::<HPCON>(),
                None,
                None,
            )
        }
        .map_err(|source| {
            platform_api_error("UpdateProcThreadAttribute(pseudoConsole)", &source)
        })?;
        Ok(result)
    }

    fn with_capacity(attribute_count: u32) -> Result<Self, AppError> {
        let mut required_bytes = 0_usize;
        // Safety: a null list is the documented sizing call and required_bytes
        // is writable for the complete call.
        let sizing = unsafe {
            InitializeProcThreadAttributeList(None, attribute_count, None, &mut required_bytes)
        };
        match sizing {
            Err(source)
                if WIN32_ERROR::from_error(&source) == Some(ERROR_INSUFFICIENT_BUFFER)
                    && required_bytes > 0 => {}
            Err(source) => {
                return Err(platform_api_error(
                    "InitializeProcThreadAttributeList(size)",
                    &source,
                ));
            }
            Ok(()) => {
                return Err(platform_invariant_error(
                    "InitializeProcThreadAttributeList(size)",
                    "sizing call unexpectedly succeeded",
                ));
            }
        }

        let words = required_bytes.div_ceil(size_of::<usize>());
        let mut storage = vec![0_usize; words];
        let list = LPPROC_THREAD_ATTRIBUTE_LIST(storage.as_mut_ptr().cast());
        // Safety: storage is pointer-aligned and has at least required_bytes;
        // it does not move or resize while the native list exists.
        unsafe {
            InitializeProcThreadAttributeList(
                Some(list),
                attribute_count,
                None,
                &mut required_bytes,
            )
        }
        .map_err(|source| platform_api_error("InitializeProcThreadAttributeList", &source))?;

        Ok(Self {
            list,
            _storage: storage,
        })
    }

    fn raw(&self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.list
    }
}

impl Drop for ProcThreadAttributeList {
    fn drop(&mut self) {
        // Safety: this list was successfully initialized exactly once and its
        // backing storage remains owned by self during this drop.
        unsafe { DeleteProcThreadAttributeList(self.list) };
    }
}

struct OwnedHandle(HANDLE);

// Windows kernel handles are process-wide and may be transferred between
// threads. This wrapper preserves unique ownership, so only Send is required.
unsafe impl Send for OwnedHandle {}

impl OwnedHandle {
    fn new(handle: HANDLE) -> Self {
        Self(handle)
    }

    fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // Safety: this wrapper exclusively owns the handle.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

struct WideBuffer(Vec<u16>);

impl WideBuffer {
    fn new() -> Self {
        Self(Vec::new())
    }

    fn with_capacity(capacity: usize) -> Self {
        Self(Vec::with_capacity(capacity))
    }

    fn from_str_nul(value: &str, field: &'static str, limit: usize) -> Result<Self, AppError> {
        if value.contains('\0') {
            return Err(invalid_launch_input(field, "must not contain NUL"));
        }
        let mut result = Self::new();
        result.extend_bounded(value.encode_utf16(), field, limit)?;
        result.push_bounded(0, field, limit)?;
        Ok(result)
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn len(&self) -> usize {
        self.0.len()
    }

    fn as_ptr(&self) -> *const u16 {
        self.0.as_ptr()
    }

    fn as_mut_ptr(&mut self) -> *mut u16 {
        self.0.as_mut_ptr()
    }

    fn push_bounded(
        &mut self,
        unit: u16,
        field: &'static str,
        limit: usize,
    ) -> Result<(), AppError> {
        if self.0.len() >= limit {
            return Err(invalid_launch_input(
                field,
                "exceeds the Windows UTF-16 limit",
            ));
        }
        self.0.push(unit);
        Ok(())
    }

    fn extend_bounded(
        &mut self,
        units: impl IntoIterator<Item = u16>,
        field: &'static str,
        limit: usize,
    ) -> Result<(), AppError> {
        for unit in units {
            self.push_bounded(unit, field, limit)?;
        }
        Ok(())
    }
}

impl Drop for WideBuffer {
    fn drop(&mut self) {
        for unit in &mut self.0 {
            // Safety: each unit is uniquely borrowed from this owned buffer.
            unsafe { std::ptr::write_volatile(unit, 0) };
        }
        compiler_fence(Ordering::SeqCst);
    }
}
