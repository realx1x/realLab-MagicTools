#![forbid(unsafe_op_in_unsafe_fn)]

#[cfg(not(target_os = "macos"))]
compile_error!("macos-process-group-spike must be compiled on a macOS target runner");

#[cfg(target_os = "macos")]
mod macos_spike {
    use std::ffi::{OsStr, c_void};
    use std::fmt::{self, Display, Formatter};
    use std::io;
    use std::mem::{size_of, zeroed};
    use std::os::unix::process::CommandExt;
    use std::process::{Child, Command};

    use nix::sys::signal::{Signal, killpg};
    use nix::unistd::{Pid, getpgid};

    const PROC_PIDLISTFDS: i32 = 1;
    const PROC_PIDTBSDINFO: i32 = 3;
    const PROC_PIDFDSOCKETINFO: i32 = 3;
    const PROX_FDTYPE_SOCKET: u32 = 2;
    const MAXCOMLEN: usize = 16;
    const MAX_FD_ENTRIES: usize = 16_384;
    const MAX_SOCKET_INFO_BYTES: usize = 4_096;

    unsafe extern "C" {
        fn proc_pidinfo(
            pid: libc::c_int,
            flavor: libc::c_int,
            arg: u64,
            buffer: *mut c_void,
            buffer_size: libc::c_int,
        ) -> libc::c_int;

        fn proc_pidfdinfo(
            pid: libc::c_int,
            fd: libc::c_int,
            flavor: libc::c_int,
            buffer: *mut c_void,
            buffer_size: libc::c_int,
        ) -> libc::c_int;
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct ProcBsdInfo {
        flags: u32,
        status: u32,
        xstatus: u32,
        pid: u32,
        ppid: u32,
        uid: libc::uid_t,
        gid: libc::gid_t,
        ruid: libc::uid_t,
        rgid: libc::gid_t,
        svuid: libc::uid_t,
        svgid: libc::gid_t,
        reserved: u32,
        command: [libc::c_char; MAXCOMLEN],
        name: [libc::c_char; MAXCOMLEN * 2],
        open_file_count: u32,
        process_group_id: u32,
        job_control_count: u32,
        controlling_device: u32,
        foreground_process_group_id: u32,
        nice: i32,
        start_seconds: u64,
        start_microseconds: u64,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct ProcFdInfo {
        fd: i32,
        fd_type: u32,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct MacProcessIdentity {
        pub pid: i32,
        pub native_start_seconds: u64,
        pub native_start_microseconds: u64,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct ProcessProbe {
        pub identity: MacProcessIdentity,
        pub parent_pid: u32,
        pub process_group_id: u32,
        pub owner_uid: u32,
        pub open_file_count: u32,
        pub name: String,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct SocketFdProbe {
        pub fd: i32,
        /// Raw `socket_fdinfo` bytes are retained only by the isolated spike. The
        /// production adapter converts the native structure into domain bindings.
        pub native_info: Vec<u8>,
    }

    #[derive(Debug)]
    pub enum SpikeError {
        AccessLimited {
            operation: &'static str,
        },
        NotFound {
            pid: i32,
        },
        IdentityMismatch {
            expected: MacProcessIdentity,
        },
        ProcessGroupChanged {
            expected: i32,
            actual: i32,
        },
        Native {
            operation: &'static str,
            source: io::Error,
        },
        ShortRead {
            operation: &'static str,
            expected: usize,
            actual: usize,
        },
    }

    impl Display for SpikeError {
        fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
            match self {
                Self::AccessLimited { operation } => {
                    write!(formatter, "{operation} is access limited")
                }
                Self::NotFound { pid } => write!(formatter, "process {pid} no longer exists"),
                Self::IdentityMismatch { expected } => {
                    write!(formatter, "process {} identity changed", expected.pid)
                }
                Self::ProcessGroupChanged { expected, actual } => write!(
                    formatter,
                    "process group changed from {expected} to {actual}"
                ),
                Self::Native { operation, source } => write!(formatter, "{operation}: {source}"),
                Self::ShortRead {
                    operation,
                    expected,
                    actual,
                } => write!(
                    formatter,
                    "{operation} returned {actual} bytes; expected at least {expected}"
                ),
            }
        }
    }

    impl std::error::Error for SpikeError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            match self {
                Self::Native { source, .. } => Some(source),
                _ => None,
            }
        }
    }

    pub struct ManagedProcessGroup {
        child: Child,
        identity: MacProcessIdentity,
        process_group_id: Pid,
    }

    impl ManagedProcessGroup {
        pub fn spawn(
            executable: &OsStr,
            args: &[&OsStr],
        ) -> Result<ManagedProcessGroup, SpikeError> {
            let mut command = Command::new(executable);
            command.args(args);

            // Safety: pre_exec runs after fork and before exec. setpgid is
            // async-signal-safe and creates a group whose id equals the child PID.
            unsafe {
                command.pre_exec(|| {
                    if libc::setpgid(0, 0) == -1 {
                        Err(io::Error::last_os_error())
                    } else {
                        Ok(())
                    }
                });
            }

            let mut child = command.spawn().map_err(|source| SpikeError::Native {
                operation: "spawn with setpgid",
                source,
            })?;
            let pid = Pid::from_raw(child.id() as i32);

            let actual_group = match getpgid(Some(pid)) {
                Ok(group) => group,
                Err(errno) => {
                    let error = native_errno("getpgid", errno, pid.as_raw());
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(error);
                }
            };
            if actual_group != pid {
                let _ = child.kill();
                let _ = child.wait();
                return Err(SpikeError::ProcessGroupChanged {
                    expected: pid.as_raw(),
                    actual: actual_group.as_raw(),
                });
            }

            let identity = match probe_process(pid.as_raw()) {
                Ok(probe) => probe.identity,
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(error);
                }
            };

            Ok(Self {
                child,
                identity,
                process_group_id: pid,
            })
        }

        pub fn identity(&self) -> MacProcessIdentity {
            self.identity
        }

        pub fn request_graceful_stop(&self) -> Result<(), SpikeError> {
            self.signal_validated_group(Signal::SIGTERM)
        }

        pub fn force_stop(&self) -> Result<(), SpikeError> {
            self.signal_validated_group(Signal::SIGKILL)
        }

        pub fn try_wait(&mut self) -> io::Result<Option<std::process::ExitStatus>> {
            self.child.try_wait()
        }

        fn signal_validated_group(&self, signal: Signal) -> Result<(), SpikeError> {
            validate_identity(self.identity)?;
            let actual_group = getpgid(Some(Pid::from_raw(self.identity.pid)))
                .map_err(|errno| native_errno("getpgid before signal", errno, self.identity.pid))?;
            if actual_group != self.process_group_id {
                return Err(SpikeError::ProcessGroupChanged {
                    expected: self.process_group_id.as_raw(),
                    actual: actual_group.as_raw(),
                });
            }

            killpg(self.process_group_id, signal)
                .map_err(|errno| native_errno("killpg", errno, self.identity.pid))
        }
    }

    pub fn probe_process(pid: i32) -> Result<ProcessProbe, SpikeError> {
        // Safety: ProcBsdInfo is a plain C structure and the buffer remains valid.
        let mut info: ProcBsdInfo = unsafe { zeroed() };
        let actual = call_pidinfo(
            pid,
            PROC_PIDTBSDINFO,
            0,
            (&mut info as *mut ProcBsdInfo).cast(),
            size_of::<ProcBsdInfo>(),
            "proc_pidinfo(PROC_PIDTBSDINFO)",
            false,
        )?;
        if actual < size_of::<ProcBsdInfo>() {
            return Err(SpikeError::ShortRead {
                operation: "proc_pidinfo(PROC_PIDTBSDINFO)",
                expected: size_of::<ProcBsdInfo>(),
                actual,
            });
        }

        Ok(ProcessProbe {
            identity: MacProcessIdentity {
                pid,
                native_start_seconds: info.start_seconds,
                native_start_microseconds: info.start_microseconds,
            },
            parent_pid: info.ppid,
            process_group_id: info.process_group_id,
            owner_uid: info.uid,
            open_file_count: info.open_file_count,
            name: c_char_array_to_string(&info.name),
        })
    }

    pub fn probe_socket_fds(pid: i32) -> Result<Vec<SocketFdProbe>, SpikeError> {
        let mut entries = vec![ProcFdInfo { fd: -1, fd_type: 0 }; MAX_FD_ENTRIES];
        let byte_capacity = entries.len() * size_of::<ProcFdInfo>();
        let actual = call_pidinfo(
            pid,
            PROC_PIDLISTFDS,
            0,
            entries.as_mut_ptr().cast(),
            byte_capacity,
            "proc_pidinfo(PROC_PIDLISTFDS)",
            true,
        )?;
        entries.truncate(actual / size_of::<ProcFdInfo>());

        let mut sockets = Vec::new();
        for entry in entries
            .into_iter()
            .filter(|entry| entry.fd_type == PROX_FDTYPE_SOCKET)
        {
            let mut native_info = vec![0_u8; MAX_SOCKET_INFO_BYTES];
            clear_errno();
            // Safety: the bounded byte buffer is writable and lives through the FFI call.
            let actual = unsafe {
                proc_pidfdinfo(
                    pid,
                    entry.fd,
                    PROC_PIDFDSOCKETINFO,
                    native_info.as_mut_ptr().cast(),
                    native_info.len() as i32,
                )
            };
            if actual <= 0 {
                let source = io::Error::last_os_error();
                match source.raw_os_error() {
                    Some(code) if code == libc::EBADF || code == libc::ENOENT => continue,
                    _ => {
                        return Err(map_errno("proc_pidfdinfo(PROC_PIDFDSOCKETINFO)", pid));
                    }
                }
            }
            native_info.truncate(actual as usize);
            sockets.push(SocketFdProbe {
                fd: entry.fd,
                native_info,
            });
        }
        Ok(sockets)
    }

    pub fn validate_identity(expected: MacProcessIdentity) -> Result<(), SpikeError> {
        let actual = probe_process(expected.pid)?.identity;
        if actual == expected {
            Ok(())
        } else {
            Err(SpikeError::IdentityMismatch { expected })
        }
    }

    fn call_pidinfo(
        pid: i32,
        flavor: i32,
        arg: u64,
        buffer: *mut c_void,
        buffer_size: usize,
        operation: &'static str,
        allow_empty: bool,
    ) -> Result<usize, SpikeError> {
        clear_errno();
        // Safety: callers provide a writable buffer of buffer_size bytes.
        let actual = unsafe {
            proc_pidinfo(
                pid,
                flavor,
                arg,
                buffer,
                buffer_size.min(i32::MAX as usize) as i32,
            )
        };
        if actual == 0 && allow_empty && io::Error::last_os_error().raw_os_error() == Some(0) {
            Ok(0)
        } else if actual <= 0 {
            Err(map_errno(operation, pid))
        } else {
            Ok(actual as usize)
        }
    }

    fn clear_errno() {
        // Safety: __error returns the calling thread's errno slot on macOS.
        unsafe { *libc::__error() = 0 };
    }

    fn map_errno(operation: &'static str, pid: i32) -> SpikeError {
        let source = io::Error::last_os_error();
        match source.raw_os_error() {
            Some(code) if code == libc::EPERM || code == libc::EACCES => {
                SpikeError::AccessLimited { operation }
            }
            Some(libc::ESRCH) => SpikeError::NotFound { pid },
            _ => SpikeError::Native { operation, source },
        }
    }

    fn native_errno(operation: &'static str, errno: nix::errno::Errno, pid: i32) -> SpikeError {
        let source = io::Error::from_raw_os_error(errno as i32);
        match errno {
            nix::errno::Errno::EPERM | nix::errno::Errno::EACCES => {
                SpikeError::AccessLimited { operation }
            }
            nix::errno::Errno::ESRCH => SpikeError::NotFound { pid },
            _ => SpikeError::Native { operation, source },
        }
    }

    fn c_char_array_to_string(value: &[libc::c_char]) -> String {
        let end = value
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(value.len());
        let bytes = value[..end]
            .iter()
            .map(|byte| *byte as u8)
            .collect::<Vec<_>>();
        String::from_utf8_lossy(&bytes).into_owned()
    }
}

#[cfg(target_os = "macos")]
pub use macos_spike::*;
