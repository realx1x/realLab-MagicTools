#![forbid(unsafe_op_in_unsafe_fn)]

#[cfg(not(windows))]
compile_error!("windows-job-object-spike must be compiled for a Windows target");

#[cfg(windows)]
mod windows_spike {
    use std::error::Error;
    use std::ffi::OsStr;
    use std::fmt::{self, Display, Formatter};
    use std::mem::size_of;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;

    use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0};
    use windows::Win32::System::Console::{CTRL_BREAK_EVENT, GenerateConsoleCtrlEvent};
    use windows::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT,
        JOB_OBJECT_LIMIT_BREAKAWAY_OK, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
        SetInformationJobObject, TerminateJobObject,
    };
    use windows::Win32::System::Threading::{
        CREATE_NEW_PROCESS_GROUP, CREATE_SUSPENDED, CreateProcessW, INFINITE,
        PROCESS_CREATION_FLAGS, PROCESS_INFORMATION, ResumeThread, STARTUPINFOW, TerminateProcess,
        WaitForSingleObject,
    };
    use windows::core::{Error as WindowsError, PCWSTR, PWSTR};

    const CLEANUP_EXIT_CODE: u32 = 0xFFFF_FF01;

    /// Inputs for the lifecycle spike. `command_line` is the exact mutable command line
    /// handed to CreateProcessW; production argv quoting belongs to P4.
    pub struct LaunchSpec<'a> {
        pub application: &'a OsStr,
        pub command_line: &'a OsStr,
        pub current_directory: Option<&'a Path>,
        pub enable_ctrl_break: bool,
        pub allow_breakaway: bool,
    }

    #[derive(Debug)]
    pub enum SpikeError {
        InteriorNul(&'static str),
        CtrlBreakNotConfigured,
        Windows {
            stage: &'static str,
            source: WindowsError,
            cleanup: Option<WindowsError>,
        },
    }

    impl Display for SpikeError {
        fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
            match self {
                Self::InteriorNul(field) => write!(formatter, "{field} contains an interior NUL"),
                Self::CtrlBreakNotConfigured => {
                    formatter.write_str("the process was not created as a CTRL_BREAK process group")
                }
                Self::Windows {
                    stage,
                    source,
                    cleanup,
                } => {
                    write!(formatter, "{stage} failed: {source}")?;
                    if let Some(cleanup) = cleanup {
                        write!(formatter, "; cleanup also failed: {cleanup}")?;
                    }
                    Ok(())
                }
            }
        }
    }

    impl Error for SpikeError {
        fn source(&self) -> Option<&(dyn Error + 'static)> {
            match self {
                Self::Windows { source, .. } => Some(source),
                _ => None,
            }
        }
    }

    /// Owns the process and job handles. Closing the job is a final safety boundary
    /// because JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE is always enabled.
    pub struct ManagedProcess {
        job: OwnedHandle,
        process: OwnedHandle,
        process_id: u32,
        ctrl_break_group_id: Option<u32>,
    }

    impl ManagedProcess {
        pub fn process_id(&self) -> u32 {
            self.process_id
        }

        pub fn request_ctrl_break(&self) -> Result<(), SpikeError> {
            let group_id = self
                .ctrl_break_group_id
                .ok_or(SpikeError::CtrlBreakNotConfigured)?;

            // Safety: the group id is the id returned by CreateProcessW for a process
            // created with CREATE_NEW_PROCESS_GROUP. Windows still validates console
            // attachment and returns an error when CTRL_BREAK is not applicable.
            unsafe { GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, group_id) }.map_err(|source| {
                SpikeError::Windows {
                    stage: "GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT)",
                    source,
                    cleanup: None,
                }
            })
        }

        pub fn force_terminate(&self, exit_code: u32) -> Result<(), SpikeError> {
            // Safety: `job` remains owned by self for the duration of the call.
            unsafe { TerminateJobObject(self.job.raw(), exit_code) }.map_err(|source| {
                SpikeError::Windows {
                    stage: "TerminateJobObject",
                    source,
                    cleanup: None,
                }
            })
        }

        pub fn has_exited(&self) -> bool {
            // Safety: `process` remains owned by self for the duration of the call.
            unsafe { WaitForSingleObject(self.process.raw(), 0) == WAIT_OBJECT_0 }
        }
    }

    pub fn launch_suspended_into_job(spec: &LaunchSpec<'_>) -> Result<ManagedProcess, SpikeError> {
        let application = wide_nul(spec.application, "application")?;
        let mut command_line = wide_nul(spec.command_line, "command_line")?;
        let current_directory = spec
            .current_directory
            .map(|path| wide_nul(path.as_os_str(), "current_directory"))
            .transpose()?;

        // Safety: null security attributes and name request an unnamed, current-user job.
        let job = OwnedHandle::new(
            unsafe { CreateJobObjectW(None, PCWSTR::null()) }
                .map_err(|source| windows_error("CreateJobObjectW", source))?,
        );

        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT(
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE.0
                | if spec.allow_breakaway {
                    JOB_OBJECT_LIMIT_BREAKAWAY_OK.0
                } else {
                    0
                },
        );

        // Safety: the pointer and size describe `limits`, which lives through the call.
        unsafe {
            SetInformationJobObject(
                job.raw(),
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        }
        .map_err(|source| windows_error("SetInformationJobObject", source))?;

        let startup = STARTUPINFOW {
            cb: size_of::<STARTUPINFOW>() as u32,
            ..Default::default()
        };
        let mut process_info = PROCESS_INFORMATION::default();
        let creation_flags = PROCESS_CREATION_FLAGS(
            CREATE_SUSPENDED.0
                | if spec.enable_ctrl_break {
                    CREATE_NEW_PROCESS_GROUP.0
                } else {
                    0
                },
        );
        let current_directory = current_directory
            .as_ref()
            .map_or(PCWSTR::null(), |value| PCWSTR(value.as_ptr()));

        // Safety: all UTF-16 buffers are NUL-terminated and remain valid for the call;
        // CreateProcessW is allowed to modify `command_line`.
        unsafe {
            CreateProcessW(
                PCWSTR(application.as_ptr()),
                Some(PWSTR(command_line.as_mut_ptr())),
                None,
                None,
                false,
                creation_flags,
                None,
                current_directory,
                &startup,
                &mut process_info,
            )
        }
        .map_err(|source| windows_error("CreateProcessW(CREATE_SUSPENDED)", source))?;

        let mut suspended = SuspendedProcess::new(process_info, job.raw());

        // Safety: both handles are owned and the primary thread has not run yet.
        if let Err(source) = unsafe { AssignProcessToJobObject(job.raw(), suspended.process_raw()) }
        {
            let cleanup = suspended.terminate_and_wait().err();
            return Err(SpikeError::Windows {
                stage: "AssignProcessToJobObject",
                source,
                cleanup,
            });
        }
        suspended.assigned_to_job = true;

        // Safety: this is the primary thread returned by the suspended CreateProcessW call.
        if unsafe { ResumeThread(suspended.thread_raw()) } == u32::MAX {
            let source = WindowsError::from_win32();
            let cleanup = suspended.terminate_and_wait().err();
            return Err(SpikeError::Windows {
                stage: "ResumeThread",
                source,
                cleanup,
            });
        }

        let process_id = process_info.dwProcessId;
        let process = suspended.commit();
        Ok(ManagedProcess {
            job,
            process,
            process_id,
            ctrl_break_group_id: spec.enable_ctrl_break.then_some(process_id),
        })
    }

    fn wide_nul(value: &OsStr, field: &'static str) -> Result<Vec<u16>, SpikeError> {
        let mut encoded = value.encode_wide().collect::<Vec<_>>();
        if encoded.contains(&0) {
            return Err(SpikeError::InteriorNul(field));
        }
        encoded.push(0);
        Ok(encoded)
    }

    fn windows_error(stage: &'static str, source: WindowsError) -> SpikeError {
        SpikeError::Windows {
            stage,
            source,
            cleanup: None,
        }
    }

    struct OwnedHandle(HANDLE);

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

    struct SuspendedProcess {
        process: Option<OwnedHandle>,
        thread: Option<OwnedHandle>,
        job: HANDLE,
        assigned_to_job: bool,
        armed: bool,
    }

    impl SuspendedProcess {
        fn new(info: PROCESS_INFORMATION, job: HANDLE) -> Self {
            Self {
                process: Some(OwnedHandle::new(info.hProcess)),
                thread: Some(OwnedHandle::new(info.hThread)),
                job,
                assigned_to_job: false,
                armed: true,
            }
        }

        fn process_raw(&self) -> HANDLE {
            self.process.as_ref().expect("process handle").raw()
        }

        fn thread_raw(&self) -> HANDLE {
            self.thread.as_ref().expect("thread handle").raw()
        }

        fn terminate_and_wait(&mut self) -> windows::core::Result<()> {
            if self.assigned_to_job {
                // Safety: the job is still owned by the launch function.
                unsafe { TerminateJobObject(self.job, CLEANUP_EXIT_CODE) }?;
            } else {
                // Safety: CreateProcessW grants PROCESS_TERMINATE on this owned handle.
                unsafe { TerminateProcess(self.process_raw(), CLEANUP_EXIT_CODE) }?;
            }

            // Safety: termination was requested while the primary thread was suspended.
            let wait = unsafe { WaitForSingleObject(self.process_raw(), INFINITE) };
            if wait != WAIT_OBJECT_0 {
                return Err(WindowsError::from_win32());
            }

            self.armed = false;
            Ok(())
        }

        fn commit(mut self) -> OwnedHandle {
            self.armed = false;
            self.thread.take();
            self.process.take().expect("process handle")
        }
    }

    impl Drop for SuspendedProcess {
        fn drop(&mut self) {
            if self.armed {
                let _ = self.terminate_and_wait();
            }
        }
    }
}

#[cfg(windows)]
pub use windows_spike::*;
