use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::io;
use std::mem::{MaybeUninit, align_of, offset_of, size_of};
use std::net::{Ipv4Addr, Ipv6Addr};

use discovery::CancellationToken;
use domain::{
    AddressFamily, AppError, ErrorCode, FieldValue, PortProtocol, PortState, ProcessInstanceKey,
    ProcessStatus,
};

const PROC_ALL_PIDS: u32 = 1;
const INITIAL_PID_BUFFER_BYTES: usize = 64 * 1024;
const MAX_PID_BUFFER_BYTES: usize = 4 * 1024 * 1024;
const MAX_PID_QUERY_ATTEMPTS: usize = 8;
const MAX_LOGICAL_CPUS: u32 = 4_096;
const MAX_PATH_BYTES: usize = libc::PROC_PIDPATHINFO_MAXSIZE as usize;
const MAX_PROCARGS_BYTES: usize = 256 * 1024;
const MAX_ARGUMENT_COUNT: usize = 65_536;
const CANCELLATION_CHECK_INTERVAL: usize = 64;
const PROC_PIDFDSOCKETINFO: i32 = 3;
const SOCKINFO_IN: i32 = 1;
const SOCKINFO_TCP: i32 = 2;
const INI_IPV4: u8 = 0x1;
const INI_IPV6: u8 = 0x2;
const TSI_S_LISTEN: i32 = 1;
const TSI_S_ESTABLISHED: i32 = 4;
const MAX_FD_ENTRIES: usize = 16_384;
const MAX_FD_QUERY_ATTEMPTS: usize = 8;
const MAX_FD_BUFFER_BYTES: usize = MAX_FD_ENTRIES * size_of::<libc::proc_fdinfo>();
const MAX_SOCKET_INFO_BYTES: usize = 4 * 1024;

// These definitions mirror the public XNU Ventura proc_info.h ABI. The
// protocol union must retain its largest (Unix socket) member even though only
// IN and TCP members are read.
#[repr(C)]
#[derive(Clone, Copy)]
struct NativeProcFileInfo {
    fi_openflags: u32,
    fi_status: u32,
    fi_offset: i64,
    fi_type: i32,
    fi_guardflags: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct NativeIn4In6Addr {
    i46a_pad32: [u32; 3],
    i46a_addr4: [u8; 4],
}

#[repr(C)]
#[derive(Clone, Copy)]
union NativeInAddress {
    ina_46: NativeIn4In6Addr,
    ina_6: [u32; 4],
    bytes: [u8; 16],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct NativeIpv4SockInfo {
    in4_tos: u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct NativeIpv6SockInfo {
    in6_hlim: u8,
    in6_cksum: i32,
    in6_ifindex: u16,
    in6_hops: i16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct NativeInSockInfo {
    insi_fport: i32,
    insi_lport: i32,
    insi_gencnt: u64,
    insi_flags: u32,
    insi_flow: u32,
    insi_vflag: u8,
    insi_ip_ttl: u8,
    rfu_1: u32,
    insi_faddr: NativeInAddress,
    insi_laddr: NativeInAddress,
    insi_v4: NativeIpv4SockInfo,
    insi_v6: NativeIpv6SockInfo,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct NativeTcpSockInfo {
    tcpsi_ini: NativeInSockInfo,
    tcpsi_state: i32,
    tcpsi_timer: [i32; 4],
    tcpsi_mss: i32,
    tcpsi_flags: u32,
    rfu_1: u32,
    tcpsi_tp: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct NativeUnixSockInfo {
    unsi_conn_so: u64,
    unsi_conn_pcb: u64,
    unsi_addr: [u8; 255],
    unsi_caddr: [u8; 255],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct NativeSockbufInfo {
    sbi_cc: u32,
    sbi_hiwat: u32,
    sbi_mbcnt: u32,
    sbi_mbmax: u32,
    sbi_lowat: u32,
    sbi_flags: i16,
    sbi_timeo: i16,
}

#[repr(C)]
#[derive(Clone, Copy)]
union NativeSocketProtocolInfo {
    pri_in: NativeInSockInfo,
    pri_tcp: NativeTcpSockInfo,
    pri_un: NativeUnixSockInfo,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct NativeSocketInfo {
    soi_stat: libc::vinfo_stat,
    soi_so: u64,
    soi_pcb: u64,
    soi_type: i32,
    soi_protocol: i32,
    soi_family: i32,
    soi_options: i16,
    soi_linger: i16,
    soi_state: i16,
    soi_qlen: i16,
    soi_incqlen: i16,
    soi_qlimit: i16,
    soi_timeo: i16,
    soi_error: u16,
    soi_oobmark: u32,
    soi_rcv: NativeSockbufInfo,
    soi_snd: NativeSockbufInfo,
    soi_kind: i32,
    rfu_1: u32,
    soi_proto: NativeSocketProtocolInfo,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct NativeSocketFdInfo {
    pfi: NativeProcFileInfo,
    psi: NativeSocketInfo,
}

const _: () = {
    assert!(size_of::<libc::timeval>() == 16);
    assert!(align_of::<libc::timeval>() == 8);

    assert!(size_of::<libc::proc_bsdinfo>() == 136);
    assert!(align_of::<libc::proc_bsdinfo>() == 8);
    assert!(offset_of!(libc::proc_bsdinfo, pbi_pid) == 12);
    assert!(offset_of!(libc::proc_bsdinfo, pbi_ppid) == 16);
    assert!(offset_of!(libc::proc_bsdinfo, pbi_uid) == 20);
    assert!(offset_of!(libc::proc_bsdinfo, pbi_start_tvsec) == 120);
    assert!(offset_of!(libc::proc_bsdinfo, pbi_start_tvusec) == 128);

    assert!(size_of::<libc::proc_taskinfo>() == 96);
    assert!(align_of::<libc::proc_taskinfo>() == 8);
    assert!(offset_of!(libc::proc_taskinfo, pti_resident_size) == 8);
    assert!(offset_of!(libc::proc_taskinfo, pti_total_user) == 16);
    assert!(offset_of!(libc::proc_taskinfo, pti_total_system) == 24);

    assert!(size_of::<libc::proc_vnodepathinfo>() == 2352);
    assert!(align_of::<libc::proc_vnodepathinfo>() == 8);
    assert!(offset_of!(libc::proc_vnodepathinfo, pvi_cdir) == 0);
    assert!(offset_of!(libc::proc_vnodepathinfo, pvi_rdir) == 1176);
    assert!(size_of::<libc::vnode_info_path>() == 1176);
    assert!(offset_of!(libc::vnode_info_path, vip_path) == 152);
    assert!(size_of::<[[libc::c_char; 32]; 32]>() == 1024);

    assert!(size_of::<libc::proc_fdinfo>() == 8);
    assert!(align_of::<libc::proc_fdinfo>() == 4);
    assert!(offset_of!(libc::proc_fdinfo, proc_fd) == 0);
    assert!(offset_of!(libc::proc_fdinfo, proc_fdtype) == 4);

    assert!(size_of::<NativeProcFileInfo>() == 24);
    assert!(align_of::<NativeProcFileInfo>() == 8);
    assert!(offset_of!(NativeProcFileInfo, fi_offset) == 8);
    assert!(offset_of!(NativeProcFileInfo, fi_type) == 16);
    assert!(offset_of!(NativeProcFileInfo, fi_guardflags) == 20);

    assert!(size_of::<libc::vinfo_stat>() == 136);
    assert!(align_of::<libc::vinfo_stat>() == 8);
    assert!(size_of::<NativeInAddress>() == 16);
    assert!(align_of::<NativeInAddress>() == 4);

    assert!(size_of::<NativeIpv6SockInfo>() == 12);
    assert!(align_of::<NativeIpv6SockInfo>() == 4);
    assert!(offset_of!(NativeIpv6SockInfo, in6_cksum) == 4);
    assert!(offset_of!(NativeIpv6SockInfo, in6_ifindex) == 8);

    assert!(size_of::<NativeInSockInfo>() == 80);
    assert!(align_of::<NativeInSockInfo>() == 8);
    assert!(offset_of!(NativeInSockInfo, insi_lport) == 4);
    assert!(offset_of!(NativeInSockInfo, insi_gencnt) == 8);
    assert!(offset_of!(NativeInSockInfo, insi_vflag) == 24);
    assert!(offset_of!(NativeInSockInfo, rfu_1) == 28);
    assert!(offset_of!(NativeInSockInfo, insi_faddr) == 32);
    assert!(offset_of!(NativeInSockInfo, insi_laddr) == 48);
    assert!(offset_of!(NativeInSockInfo, insi_v4) == 64);
    assert!(offset_of!(NativeInSockInfo, insi_v6) == 68);
    assert!(
        offset_of!(NativeInSockInfo, insi_v6) + offset_of!(NativeIpv6SockInfo, in6_ifindex) == 76
    );

    assert!(size_of::<NativeTcpSockInfo>() == 120);
    assert!(align_of::<NativeTcpSockInfo>() == 8);
    assert!(offset_of!(NativeTcpSockInfo, tcpsi_state) == 80);
    assert!(offset_of!(NativeTcpSockInfo, tcpsi_timer) == 84);
    assert!(offset_of!(NativeTcpSockInfo, tcpsi_mss) == 100);
    assert!(offset_of!(NativeTcpSockInfo, tcpsi_flags) == 104);
    assert!(offset_of!(NativeTcpSockInfo, tcpsi_tp) == 112);

    assert!(size_of::<NativeUnixSockInfo>() == 528);
    assert!(align_of::<NativeUnixSockInfo>() == 8);
    assert!(size_of::<NativeSockbufInfo>() == 24);
    assert!(align_of::<NativeSockbufInfo>() == 4);
    assert!(size_of::<NativeSocketProtocolInfo>() == 528);
    assert!(align_of::<NativeSocketProtocolInfo>() == 8);

    assert!(size_of::<NativeSocketInfo>() == 768);
    assert!(align_of::<NativeSocketInfo>() == 8);
    assert!(offset_of!(NativeSocketInfo, soi_so) == 136);
    assert!(offset_of!(NativeSocketInfo, soi_pcb) == 144);
    assert!(offset_of!(NativeSocketInfo, soi_type) == 152);
    assert!(offset_of!(NativeSocketInfo, soi_protocol) == 156);
    assert!(offset_of!(NativeSocketInfo, soi_family) == 160);
    assert!(offset_of!(NativeSocketInfo, soi_options) == 164);
    assert!(offset_of!(NativeSocketInfo, soi_state) == 168);
    assert!(offset_of!(NativeSocketInfo, soi_error) == 178);
    assert!(offset_of!(NativeSocketInfo, soi_oobmark) == 180);
    assert!(offset_of!(NativeSocketInfo, soi_rcv) == 184);
    assert!(offset_of!(NativeSocketInfo, soi_snd) == 208);
    assert!(offset_of!(NativeSocketInfo, soi_kind) == 232);
    assert!(offset_of!(NativeSocketInfo, soi_proto) == 240);

    assert!(size_of::<NativeSocketFdInfo>() == 792);
    assert!(align_of::<NativeSocketFdInfo>() == 8);
    assert!(offset_of!(NativeSocketFdInfo, pfi) == 0);
    assert!(offset_of!(NativeSocketFdInfo, psi) == 24);
    assert!(size_of::<NativeSocketFdInfo>() <= MAX_SOCKET_INFO_BYTES);
};

#[derive(Clone, Debug)]
pub(crate) struct NativeSnapshot {
    pub(crate) monotonic_ns: Option<u64>,
    pub(crate) logical_cpus: Option<u32>,
    pub(crate) processes: Vec<NativeProcessSample>,
}

#[derive(Clone, Debug)]
pub(crate) struct NativeProcessSample {
    pub(crate) pid: u32,
    pub(crate) parent_pid: Option<u32>,
    pub(crate) uid: u32,
    pub(crate) start_micros: u64,
    pub(crate) name: FieldValue<String>,
    pub(crate) status: ProcessStatus,
    pub(crate) resident_bytes: FieldValue<u64>,
    pub(crate) cpu_total_ns: Option<u64>,
    pub(crate) access_limited: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct NativeEnrichment {
    pub(crate) executable_path: FieldValue<String>,
    pub(crate) command_line: FieldValue<String>,
    pub(crate) working_directory: FieldValue<String>,
    pub(crate) access_limited: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum NativePathObservation {
    Known(String),
    Missing,
    AccessLimited(String),
    NotSupported,
}

#[derive(Clone, Debug)]
pub(crate) struct NativePortSample {
    pub(crate) protocol: PortProtocol,
    pub(crate) address_family: AddressFamily,
    pub(crate) local_address: String,
    pub(crate) local_port: u16,
    pub(crate) state: Option<PortState>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct NativePortKey {
    protocol: PortProtocol,
    address_family: AddressFamily,
    local_address: String,
    local_port: u16,
}

pub(crate) fn query_boot_identifier() -> Result<String, AppError> {
    let mut value = MaybeUninit::<libc::timeval>::zeroed();
    let mut length = size_of::<libc::timeval>();
    let mut mib = [libc::CTL_KERN, libc::KERN_BOOTTIME];
    clear_errno();
    // Safety: the fixed MIB and exact timeval output remain writable and live.
    let result = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as libc::c_uint,
            value.as_mut_ptr().cast(),
            &mut length,
            std::ptr::null_mut(),
            0,
        )
    };
    if result != 0 {
        return Err(errno_error("sysctl(KERN_BOOTTIME)"));
    }
    if length != size_of::<libc::timeval>() {
        return Err(short_read_error(
            "sysctl(KERN_BOOTTIME)",
            size_of::<libc::timeval>(),
            length,
        ));
    }
    // Safety: the successful exact-size sysctl initialized the value.
    let value = unsafe { value.assume_init() };
    let seconds = u64::try_from(value.tv_sec)
        .map_err(|_| invalid_native_error("sysctl(KERN_BOOTTIME)", "negative seconds"))?;
    let micros = u64::try_from(value.tv_usec)
        .ok()
        .filter(|value| *value < 1_000_000)
        .ok_or_else(|| invalid_native_error("sysctl(KERN_BOOTTIME)", "invalid microseconds"))?;
    let total = seconds
        .checked_mul(1_000_000)
        .and_then(|value| value.checked_add(micros))
        .filter(|value| *value != 0)
        .ok_or_else(|| invalid_native_error("sysctl(KERN_BOOTTIME)", "invalid boot time"))?;
    Ok(total.to_string())
}

pub(crate) fn query_process_snapshot(
    cancellation: &CancellationToken,
) -> Result<NativeSnapshot, AppError> {
    check_cancelled(cancellation, "query process snapshot")?;
    let monotonic_ns = monotonic_raw_ns().ok();
    let logical_cpus = logical_cpu_count().ok();
    let pids = list_pids(cancellation)?;
    let mut processes = Vec::with_capacity(pids.len());

    for (index, pid) in pids.into_iter().enumerate() {
        if index % CANCELLATION_CHECK_INTERVAL == 0 {
            check_cancelled(cancellation, "query process snapshot")?;
        }
        let first = match query_bsd_info(pid) {
            Ok(info) => info,
            Err(ProcessQueryError::Gone) => continue,
            // Without BSD start time there is no safe ProcessInstanceKey. A
            // protected PID is skipped rather than assigned a fabricated key.
            Err(ProcessQueryError::AccessLimited(_)) => continue,
            Err(ProcessQueryError::Platform(error)) => return Err(error),
        };
        let start_micros = bsd_start_micros(&first)?;
        let metrics = match query_task_info(pid) {
            Ok(info) => TaskMetrics::Known(info),
            Err(ProcessQueryError::AccessLimited(reason)) => TaskMetrics::AccessLimited(reason),
            Err(ProcessQueryError::Gone) => continue,
            Err(ProcessQueryError::Platform(error)) => return Err(error),
        };
        check_cancelled(cancellation, "query process snapshot")?;
        let verified = match query_bsd_info(pid) {
            Ok(info) => info,
            Err(ProcessQueryError::Gone | ProcessQueryError::AccessLimited(_)) => continue,
            Err(ProcessQueryError::Platform(error)) => return Err(error),
        };
        if verified.pbi_pid != first.pbi_pid || bsd_start_micros(&verified)? != start_micros {
            continue;
        }
        processes.push(materialize_native_sample(first, start_micros, metrics)?);
    }

    Ok(NativeSnapshot {
        monotonic_ns,
        logical_cpus,
        processes,
    })
}

pub(crate) fn query_enrichment(
    instance_key: &ProcessInstanceKey,
    cancellation: &CancellationToken,
) -> Result<Option<NativeEnrichment>, AppError> {
    check_cancelled(cancellation, "enrich process")?;
    if query_boot_identifier()? != instance_key.boot_id {
        return Err(identity_mismatch_error(
            instance_key,
            "boot identifier changed",
        ));
    }
    let pid = i32::try_from(instance_key.pid)
        .ok()
        .filter(|pid| *pid > 0)
        .ok_or_else(|| invalid_instance_key_error(instance_key, "PID is outside pid_t range"))?;
    let expected_start = instance_key
        .native_start_time
        .parse::<u64>()
        .map_err(|_| invalid_instance_key_error(instance_key, "native start time is not u64"))?;
    let first = match query_bsd_info(pid) {
        Ok(info) => info,
        Err(ProcessQueryError::Gone) => return Ok(None),
        Err(ProcessQueryError::AccessLimited(reason)) => {
            return Err(access_denied_error(instance_key, reason));
        }
        Err(ProcessQueryError::Platform(error)) => return Err(error),
    };
    if first.pbi_pid != instance_key.pid || bsd_start_micros(&first)? != expected_start {
        return Ok(None);
    }

    check_cancelled(cancellation, "proc_pidpath")?;
    let executable_path = match query_process_path(pid, cancellation) {
        Ok(value) => value,
        Err(ProcessQueryError::Gone) => return Ok(None),
        Err(ProcessQueryError::AccessLimited(reason)) => FieldValue::AccessLimited {
            reason: Some(reason),
        },
        Err(ProcessQueryError::Platform(error)) => return Err(error),
    };
    check_cancelled(cancellation, "proc_pidinfo(PROC_PIDVNODEPATHINFO)")?;
    let working_directory = match query_working_directory(pid, cancellation) {
        Ok(value) => value,
        Err(ProcessQueryError::Gone) => return Ok(None),
        Err(ProcessQueryError::AccessLimited(reason)) => FieldValue::AccessLimited {
            reason: Some(reason),
        },
        Err(ProcessQueryError::Platform(error)) => return Err(error),
    };
    check_cancelled(cancellation, "sysctl(KERN_PROCARGS2)")?;
    let command_line = match query_command_line(pid, cancellation) {
        Ok(value) => value,
        Err(ProcessQueryError::Gone) => return Ok(None),
        Err(ProcessQueryError::AccessLimited(reason)) => FieldValue::AccessLimited {
            reason: Some(reason),
        },
        Err(ProcessQueryError::Platform(error)) => return Err(error),
    };

    check_cancelled(cancellation, "revalidate process identity")?;
    let verified = match query_bsd_info(pid) {
        Ok(info) => info,
        Err(ProcessQueryError::Gone) => return Ok(None),
        Err(ProcessQueryError::AccessLimited(reason)) => {
            return Err(access_denied_error(instance_key, reason));
        }
        Err(ProcessQueryError::Platform(error)) => return Err(error),
    };
    if verified.pbi_pid != instance_key.pid || bsd_start_micros(&verified)? != expected_start {
        return Ok(None);
    }
    let access_limited = matches!(executable_path, FieldValue::AccessLimited { .. })
        || matches!(working_directory, FieldValue::AccessLimited { .. })
        || matches!(command_line, FieldValue::AccessLimited { .. });
    Ok(Some(NativeEnrichment {
        executable_path,
        command_line,
        working_directory,
        access_limited,
    }))
}

pub(crate) fn query_verified_working_directory(
    instance_key: &ProcessInstanceKey,
    cancellation: &CancellationToken,
) -> Result<NativePathObservation, AppError> {
    check_cancelled(cancellation, "query verified process working directory")?;
    if query_boot_identifier()? != instance_key.boot_id {
        return Err(stale_project_observation_error(
            instance_key,
            "boot identifier changed before the working-directory query",
        ));
    }
    let pid = i32::try_from(instance_key.pid)
        .ok()
        .filter(|pid| *pid > 0)
        .ok_or_else(|| invalid_instance_key_error(instance_key, "PID is outside pid_t range"))?;
    let expected_start = instance_key
        .native_start_time
        .parse::<u64>()
        .map_err(|_| invalid_instance_key_error(instance_key, "native start time is not u64"))?;
    verify_project_process_identity(
        instance_key,
        pid,
        expected_start,
        "before cwd query",
        cancellation,
    )?;

    let working_directory = match query_working_directory_observation(pid, cancellation) {
        Ok(value) => value,
        Err(ProcessQueryError::Gone) => {
            return Err(stale_project_observation_error(
                instance_key,
                "process disappeared during the working-directory query",
            ));
        }
        Err(ProcessQueryError::AccessLimited(reason)) => {
            NativePathObservation::AccessLimited(reason)
        }
        Err(ProcessQueryError::Platform(error)) => return Err(error),
    };

    check_cancelled(cancellation, "revalidate process working directory")?;
    if query_boot_identifier()? != instance_key.boot_id {
        return Err(stale_project_observation_error(
            instance_key,
            "boot identifier changed after the working-directory query",
        ));
    }
    verify_project_process_identity(
        instance_key,
        pid,
        expected_start,
        "after cwd query",
        cancellation,
    )?;
    Ok(working_directory)
}

pub(crate) fn query_process_ports(
    instance_key: &ProcessInstanceKey,
    cancellation: &CancellationToken,
) -> Result<Option<FieldValue<Vec<NativePortSample>>>, AppError> {
    check_cancelled(cancellation, "query process ports")?;
    if query_boot_identifier()? != instance_key.boot_id {
        return Ok(None);
    }
    let pid = i32::try_from(instance_key.pid)
        .ok()
        .filter(|pid| *pid > 0)
        .ok_or_else(|| invalid_instance_key_error(instance_key, "PID is outside pid_t range"))?;
    let expected_start = instance_key
        .native_start_time
        .parse::<u64>()
        .map_err(|_| invalid_instance_key_error(instance_key, "native start time is not u64"))?;
    let first = match query_bsd_info(pid) {
        Ok(info) => info,
        Err(ProcessQueryError::Gone) => return Ok(None),
        Err(ProcessQueryError::AccessLimited(reason)) => {
            return Err(access_denied_error(instance_key, reason));
        }
        Err(ProcessQueryError::Platform(error)) => return Err(error),
    };
    if first.pbi_pid != instance_key.pid || bsd_start_micros(&first)? != expected_start {
        return Ok(None);
    }

    let bindings = match query_socket_samples(pid, cancellation) {
        Ok(value) => value,
        Err(ProcessQueryError::Gone) => return Ok(None),
        Err(ProcessQueryError::AccessLimited(reason)) => FieldValue::AccessLimited {
            reason: Some(reason),
        },
        Err(ProcessQueryError::Platform(error)) => return Err(error),
    };

    check_cancelled(cancellation, "revalidate process port identity")?;
    if query_boot_identifier()? != instance_key.boot_id {
        return Ok(None);
    }
    let verified = match query_bsd_info(pid) {
        Ok(info) => info,
        Err(ProcessQueryError::Gone) => return Ok(None),
        Err(ProcessQueryError::AccessLimited(reason)) => {
            return Err(access_denied_error(instance_key, reason));
        }
        Err(ProcessQueryError::Platform(error)) => return Err(error),
    };
    if verified.pbi_pid != instance_key.pid || bsd_start_micros(&verified)? != expected_start {
        return Ok(None);
    }
    Ok(Some(bindings))
}

fn query_socket_samples(
    pid: i32,
    cancellation: &CancellationToken,
) -> Result<FieldValue<Vec<NativePortSample>>, ProcessQueryError> {
    let descriptors = list_process_fds(pid, cancellation)?;
    let mut ports = HashMap::<NativePortKey, Option<PortState>>::new();
    for (index, descriptor) in descriptors.into_iter().enumerate() {
        if index % CANCELLATION_CHECK_INTERVAL == 0 {
            check_cancelled(cancellation, "scan process socket descriptors")
                .map_err(ProcessQueryError::Platform)?;
        }
        if descriptor.proc_fdtype != libc::PROX_FDTYPE_SOCKET as u32 {
            continue;
        }
        if descriptor.proc_fd < 0 {
            return Err(ProcessQueryError::Platform(invalid_native_error(
                "proc_pidinfo(PROC_PIDLISTFDS)",
                "returned a negative file descriptor",
            )));
        }
        let Some(sample) = query_socket_fd(pid, descriptor.proc_fd, cancellation)? else {
            continue;
        };
        let key = NativePortKey {
            protocol: sample.protocol,
            address_family: sample.address_family,
            local_address: sample.local_address,
            local_port: sample.local_port,
        };
        ports
            .entry(key)
            .and_modify(|state| *state = preferred_port_state(*state, sample.state))
            .or_insert(sample.state);
    }

    let mut samples = ports
        .into_iter()
        .map(|(key, state)| NativePortSample {
            protocol: key.protocol,
            address_family: key.address_family,
            local_address: key.local_address,
            local_port: key.local_port,
            state,
        })
        .collect::<Vec<_>>();
    samples.sort_by(compare_native_port_samples);
    Ok(FieldValue::Known(samples))
}

fn list_process_fds(
    pid: i32,
    cancellation: &CancellationToken,
) -> Result<Vec<libc::proc_fdinfo>, ProcessQueryError> {
    let operation = "proc_pidinfo(PROC_PIDLISTFDS)";
    check_cancelled(cancellation, operation).map_err(ProcessQueryError::Platform)?;
    clear_errno();
    // Safety: a null buffer with zero length is the documented sizing probe.
    let required =
        unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0) };
    if required == 0 && current_errno() == 0 {
        return Ok(Vec::new());
    }
    if required <= 0 {
        return Err(classify_process_errno(operation));
    }
    let mut requested = required as usize;
    if requested % size_of::<libc::proc_fdinfo>() != 0 {
        return Err(ProcessQueryError::Platform(invalid_native_error(
            operation,
            "sizing probe returned a partial descriptor entry",
        )));
    }
    ensure_fd_buffer_limit(operation, requested).map_err(ProcessQueryError::Platform)?;

    for _ in 0..MAX_FD_QUERY_ATTEMPTS {
        check_cancelled(cancellation, operation).map_err(ProcessQueryError::Platform)?;
        let capacity = requested / size_of::<libc::proc_fdinfo>();
        let mut entries = Vec::<MaybeUninit<libc::proc_fdinfo>>::with_capacity(capacity);
        entries.resize_with(capacity, MaybeUninit::uninit);
        let requested_i32 = i32::try_from(requested).map_err(|_| {
            ProcessQueryError::Platform(fd_buffer_limit_error(operation, requested))
        })?;
        clear_errno();
        // Safety: the aligned allocation contains exactly `requested` writable bytes.
        let actual = unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDLISTFDS,
                0,
                entries.as_mut_ptr().cast(),
                requested_i32,
            )
        };
        if actual == 0 {
            if current_errno() == 0 {
                return Ok(Vec::new());
            }
            return Err(classify_process_errno(operation));
        }
        if actual < 0 {
            return Err(classify_process_errno(operation));
        }
        let actual = actual as usize;
        if actual > requested || actual % size_of::<libc::proc_fdinfo>() != 0 {
            return Err(ProcessQueryError::Platform(invalid_native_error(
                operation,
                "returned an invalid descriptor byte count",
            )));
        }
        let has_growth_margin = actual
            .checked_add(size_of::<libc::proc_fdinfo>())
            .is_some_and(|next_entry_end| next_entry_end < requested);
        if has_growth_margin {
            let count = actual / size_of::<libc::proc_fdinfo>();
            let mut descriptors = Vec::with_capacity(count);
            let mut seen = HashSet::with_capacity(count);
            for (index, entry) in entries.into_iter().take(count).enumerate() {
                if index % CANCELLATION_CHECK_INTERVAL == 0 {
                    check_cancelled(cancellation, operation)
                        .map_err(ProcessQueryError::Platform)?;
                }
                // Safety: the successful call initialized every complete entry
                // covered by its returned byte count.
                let entry = unsafe { entry.assume_init() };
                if seen.insert(entry.proc_fd) {
                    descriptors.push(entry);
                }
            }
            return Ok(descriptors);
        }

        requested = requested.checked_mul(2).ok_or_else(|| {
            ProcessQueryError::Platform(fd_buffer_limit_error(operation, requested))
        })?;
        ensure_fd_buffer_limit(operation, requested).map_err(ProcessQueryError::Platform)?;
    }
    Err(ProcessQueryError::Platform(fd_buffer_limit_error(
        operation, requested,
    )))
}

fn query_socket_fd(
    pid: i32,
    fd: i32,
    cancellation: &CancellationToken,
) -> Result<Option<NativePortSample>, ProcessQueryError> {
    let operation = "proc_pidfdinfo(PROC_PIDFDSOCKETINFO)";
    check_cancelled(cancellation, operation).map_err(ProcessQueryError::Platform)?;
    let mut value = MaybeUninit::<NativeSocketFdInfo>::zeroed();
    let expected = size_of::<NativeSocketFdInfo>();
    let expected_i32 = i32::try_from(expected).map_err(|_| {
        ProcessQueryError::Platform(invalid_native_error(operation, "structure is too large"))
    })?;
    clear_errno();
    // Safety: the exact ABI-sized, aligned socket structure remains writable.
    let actual = unsafe {
        libc::proc_pidfdinfo(
            pid,
            fd,
            PROC_PIDFDSOCKETINFO,
            value.as_mut_ptr().cast(),
            expected_i32,
        )
    };
    if actual <= 0 {
        return match current_errno() {
            libc::EBADF | libc::ENOENT | libc::ENOTSOCK | libc::EOPNOTSUPP => Ok(None),
            _ => Err(classify_process_errno(operation)),
        };
    }
    if actual as usize != expected {
        return Err(ProcessQueryError::Platform(short_read_error(
            operation,
            expected,
            actual as usize,
        )));
    }
    // Safety: an exact successful read initialized the complete structure.
    convert_socket_info(unsafe { value.assume_init() }).map_err(ProcessQueryError::Platform)
}

fn convert_socket_info(value: NativeSocketFdInfo) -> Result<Option<NativePortSample>, AppError> {
    let socket = value.psi;
    let family = match socket.soi_family {
        libc::AF_INET => AddressFamily::Ipv4,
        libc::AF_INET6 => AddressFamily::Ipv6,
        _ => return Ok(None),
    };
    let (protocol, internet, state) = match (socket.soi_type, socket.soi_protocol) {
        (libc::SOCK_STREAM, libc::IPPROTO_TCP) => {
            if socket.soi_kind != SOCKINFO_TCP {
                return Ok(None);
            }
            // Safety: SOCKINFO_TCP selects the TCP member of the native union.
            let tcp = unsafe { socket.soi_proto.pri_tcp };
            let state = match tcp.tcpsi_state {
                TSI_S_LISTEN => Some(PortState::TcpListen),
                TSI_S_ESTABLISHED => Some(PortState::TcpEstablished),
                0 | 2..=3 | 5..=11 => Some(PortState::TcpOther),
                _ => None,
            };
            (PortProtocol::Tcp, tcp.tcpsi_ini, state)
        }
        (libc::SOCK_DGRAM, libc::IPPROTO_UDP) => {
            if socket.soi_kind != SOCKINFO_IN {
                return Ok(None);
            }
            // Safety: SOCKINFO_IN selects the Internet member of the union.
            (
                PortProtocol::Udp,
                unsafe { socket.soi_proto.pri_in },
                Some(PortState::UdpBound),
            )
        }
        _ => return Ok(None),
    };

    let required_vflag = match family {
        AddressFamily::Ipv4 => INI_IPV4,
        AddressFamily::Ipv6 => INI_IPV6,
    };
    if internet.insi_vflag & required_vflag == 0 {
        return Err(invalid_native_error(
            "parse socket_fdinfo",
            "address family and Internet flags disagree",
        ));
    }
    let network_port = u16::try_from(internet.insi_lport).map_err(|_| {
        invalid_native_error("parse socket_fdinfo", "local port is outside u16 range")
    })?;
    let local_port = u16::from_be(network_port);
    if local_port == 0 {
        return Ok(None);
    }
    // Safety: byte access is valid for every initialized member representation.
    let address = unsafe { internet.insi_laddr.bytes };
    let local_address = match family {
        AddressFamily::Ipv4 => {
            Ipv4Addr::new(address[12], address[13], address[14], address[15]).to_string()
        }
        AddressFamily::Ipv6 => {
            let address = Ipv6Addr::from(address);
            let scope_id = internet.insi_v6.in6_ifindex;
            if scope_id == 0 {
                address.to_string()
            } else {
                format!("{address}%{scope_id}")
            }
        }
    };
    Ok(Some(NativePortSample {
        protocol,
        address_family: family,
        local_address,
        local_port,
        state,
    }))
}

fn preferred_port_state(left: Option<PortState>, right: Option<PortState>) -> Option<PortState> {
    if port_state_rank(right) > port_state_rank(left) {
        right
    } else {
        left
    }
}

fn port_state_rank(state: Option<PortState>) -> u8 {
    match state {
        Some(PortState::TcpListen) => 5,
        Some(PortState::TcpEstablished) => 4,
        Some(PortState::UdpBound) => 3,
        Some(PortState::TcpOther) => 2,
        Some(PortState::Unknown) => 1,
        None => 0,
    }
}

fn compare_native_port_samples(left: &NativePortSample, right: &NativePortSample) -> Ordering {
    native_protocol_rank(left.protocol)
        .cmp(&native_protocol_rank(right.protocol))
        .then_with(|| {
            native_family_rank(left.address_family).cmp(&native_family_rank(right.address_family))
        })
        .then_with(|| left.local_address.cmp(&right.local_address))
        .then_with(|| left.local_port.cmp(&right.local_port))
}

fn native_protocol_rank(protocol: PortProtocol) -> u8 {
    match protocol {
        PortProtocol::Tcp => 0,
        PortProtocol::Udp => 1,
    }
}

fn native_family_rank(family: AddressFamily) -> u8 {
    match family {
        AddressFamily::Ipv4 => 0,
        AddressFamily::Ipv6 => 1,
    }
}

fn ensure_fd_buffer_limit(operation: &'static str, requested: usize) -> Result<(), AppError> {
    if requested <= MAX_FD_BUFFER_BYTES {
        Ok(())
    } else {
        Err(fd_buffer_limit_error(operation, requested))
    }
}

fn fd_buffer_limit_error(operation: &'static str, requested: usize) -> AppError {
    let mut error = AppError::new(
        ErrorCode::PlatformError,
        "macOS file descriptor query exceeded its limit",
    );
    error.retryable = true;
    error.details.insert("operation".into(), operation.into());
    error
        .details
        .insert("requestedBytes".into(), requested.to_string());
    error
        .details
        .insert("maximumBytes".into(), MAX_FD_BUFFER_BYTES.to_string());
    error
        .details
        .insert("maximumEntries".into(), MAX_FD_ENTRIES.to_string());
    error
}

fn query_process_path(
    pid: i32,
    cancellation: &CancellationToken,
) -> Result<FieldValue<String>, ProcessQueryError> {
    let mut buffer = vec![0_u8; MAX_PATH_BYTES];
    let buffer_size = u32::try_from(buffer.len()).map_err(|_| {
        ProcessQueryError::Platform(invalid_native_error(
            "proc_pidpath",
            "path buffer exceeds u32",
        ))
    })?;
    clear_errno();
    // Safety: the byte buffer is writable for the exact bounded capacity.
    let actual = unsafe { libc::proc_pidpath(pid, buffer.as_mut_ptr().cast(), buffer_size) };
    if actual <= 0 {
        return Err(classify_process_errno("proc_pidpath"));
    }
    let actual = actual as usize;
    if actual > buffer.len() {
        return Err(ProcessQueryError::Platform(invalid_native_error(
            "proc_pidpath",
            "returned length exceeds buffer",
        )));
    }
    let checked_length = actual
        .checked_add(1)
        .filter(|length| *length <= buffer.len())
        .unwrap_or(actual);
    decode_bounded_c_string(&buffer[..checked_length], "proc_pidpath", cancellation)
        .map(FieldValue::Known)
}

fn query_working_directory(
    pid: i32,
    cancellation: &CancellationToken,
) -> Result<FieldValue<String>, ProcessQueryError> {
    Ok(
        match query_working_directory_observation(pid, cancellation)? {
            NativePathObservation::Known(path) => FieldValue::Known(path),
            NativePathObservation::Missing => FieldValue::Unknown,
            NativePathObservation::AccessLimited(reason) => FieldValue::AccessLimited {
                reason: Some(reason),
            },
            NativePathObservation::NotSupported => FieldValue::NotSupported,
        },
    )
}

fn query_working_directory_observation(
    pid: i32,
    cancellation: &CancellationToken,
) -> Result<NativePathObservation, ProcessQueryError> {
    const OPERATION: &str = "proc_pidinfo(PROC_PIDVNODEPATHINFO)";
    check_cancelled(cancellation, OPERATION).map_err(ProcessQueryError::Platform)?;
    let mut value = MaybeUninit::<libc::proc_vnodepathinfo>::zeroed();
    let expected = size_of::<libc::proc_vnodepathinfo>();
    let expected_i32 = i32::try_from(expected).map_err(|_| {
        ProcessQueryError::Platform(invalid_native_error(OPERATION, "structure is too large"))
    })?;
    clear_errno();
    // Safety: the output points to an aligned vnode-path buffer of the exact
    // public ABI size.
    let actual = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDVNODEPATHINFO,
            0,
            value.as_mut_ptr().cast(),
            expected_i32,
        )
    };
    if actual <= 0 {
        return match current_errno() {
            libc::ENOENT => Ok(NativePathObservation::Missing),
            libc::EPERM | libc::EACCES => Ok(NativePathObservation::AccessLimited(format!(
                "{OPERATION}:accessLimited"
            ))),
            libc::ESRCH => Err(ProcessQueryError::Gone),
            _ => Err(ProcessQueryError::Platform(errno_error(OPERATION))),
        };
    }
    if actual as usize != expected {
        return Err(ProcessQueryError::Platform(short_read_error(
            OPERATION,
            expected,
            actual as usize,
        )));
    }
    // Safety: an exact successful read initialized the complete structure.
    let value = unsafe { value.assume_init() };
    let mut bytes = Vec::with_capacity(1024);
    'outer: for (chunk_index, chunk) in value.pvi_cdir.vip_path.iter().enumerate() {
        for (byte_index, byte) in chunk.iter().enumerate() {
            let index = chunk_index * chunk.len() + byte_index;
            if index % CANCELLATION_CHECK_INTERVAL == 0 {
                check_cancelled(cancellation, "parse process working directory")
                    .map_err(ProcessQueryError::Platform)?;
            }
            if *byte == 0 {
                break 'outer;
            }
            bytes.push(*byte as u8);
        }
    }
    if bytes.is_empty() {
        Ok(NativePathObservation::Missing)
    } else {
        Ok(match String::from_utf8(bytes) {
            Ok(path) => NativePathObservation::Known(path),
            Err(_) => NativePathObservation::NotSupported,
        })
    }
}

fn query_command_line(
    pid: i32,
    cancellation: &CancellationToken,
) -> Result<FieldValue<String>, ProcessQueryError> {
    let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid];
    let mut buffer = vec![0_u8; MAX_PROCARGS_BYTES];
    let mut actual = buffer.len();
    clear_errno();
    // Safety: the fixed MIB is valid and the output buffer is writable for the
    // exact 256 KiB policy limit.
    let result = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as libc::c_uint,
            buffer.as_mut_ptr().cast(),
            &mut actual,
            std::ptr::null_mut(),
            0,
        )
    };
    if result != 0 {
        if current_errno() == libc::ENOMEM {
            return Ok(FieldValue::AccessLimited {
                reason: Some("process arguments exceed the 256 KiB read limit".into()),
            });
        }
        return Err(classify_process_errno("sysctl(KERN_PROCARGS2)"));
    }
    if actual > buffer.len() || actual < size_of::<libc::c_int>() {
        return Err(ProcessQueryError::Platform(invalid_native_error(
            "sysctl(KERN_PROCARGS2)",
            "invalid returned length",
        )));
    }
    buffer.truncate(actual);
    parse_procargs2(&buffer, cancellation).map(FieldValue::Known)
}

fn parse_procargs2(
    buffer: &[u8],
    cancellation: &CancellationToken,
) -> Result<String, ProcessQueryError> {
    let argc_bytes: [u8; size_of::<libc::c_int>()] = buffer
        .get(..size_of::<libc::c_int>())
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| {
            ProcessQueryError::Platform(invalid_native_error(
                "parse KERN_PROCARGS2",
                "missing argc",
            ))
        })?;
    let argc = libc::c_int::from_ne_bytes(argc_bytes);
    let argc = usize::try_from(argc)
        .ok()
        .filter(|argc| *argc <= MAX_ARGUMENT_COUNT)
        .ok_or_else(|| {
            ProcessQueryError::Platform(invalid_native_error(
                "parse KERN_PROCARGS2",
                "invalid argc",
            ))
        })?;
    let mut offset = size_of::<libc::c_int>();
    let executable_end = find_nul(buffer, offset, cancellation)?.ok_or_else(|| {
        ProcessQueryError::Platform(invalid_native_error(
            "parse KERN_PROCARGS2",
            "unterminated executable path",
        ))
    })?;
    let executable = String::from_utf8_lossy(&buffer[offset..executable_end]).into_owned();
    if executable.is_empty() {
        return Err(ProcessQueryError::Platform(invalid_native_error(
            "parse KERN_PROCARGS2",
            "empty executable path",
        )));
    }
    offset = executable_end.checked_add(1).ok_or_else(|| {
        ProcessQueryError::Platform(invalid_native_error(
            "parse KERN_PROCARGS2",
            "offset overflow",
        ))
    })?;
    let mut padding_count = 0_usize;
    while offset < buffer.len() && buffer[offset] == 0 {
        if padding_count % CANCELLATION_CHECK_INTERVAL == 0 {
            check_cancelled(cancellation, "parse KERN_PROCARGS2 padding")
                .map_err(ProcessQueryError::Platform)?;
        }
        offset += 1;
        padding_count += 1;
    }

    let mut arguments = Vec::with_capacity(argc.min(256));
    for index in 0..argc {
        if index % CANCELLATION_CHECK_INTERVAL == 0 {
            check_cancelled(cancellation, "parse KERN_PROCARGS2 arguments")
                .map_err(ProcessQueryError::Platform)?;
        }
        let end = find_nul(buffer, offset, cancellation)?.ok_or_else(|| {
            ProcessQueryError::Platform(invalid_native_error(
                "parse KERN_PROCARGS2",
                "argument list is truncated",
            ))
        })?;
        arguments.push(String::from_utf8_lossy(&buffer[offset..end]).into_owned());
        offset = end.checked_add(1).ok_or_else(|| {
            ProcessQueryError::Platform(invalid_native_error(
                "parse KERN_PROCARGS2",
                "offset overflow",
            ))
        })?;
    }
    // Deliberately stop at argc. Bytes after this point contain environment
    // entries and are never parsed, logged, or returned.
    if arguments.is_empty() {
        quote_argument(&executable, cancellation)
    } else {
        let mut command_line = String::new();
        for (index, argument) in arguments.iter().enumerate() {
            if index % CANCELLATION_CHECK_INTERVAL == 0 {
                check_cancelled(cancellation, "format KERN_PROCARGS2 arguments")
                    .map_err(ProcessQueryError::Platform)?;
            }
            if index != 0 {
                command_line.push(' ');
            }
            command_line.push_str(&quote_argument(argument, cancellation)?);
        }
        Ok(command_line)
    }
}

fn find_nul(
    buffer: &[u8],
    offset: usize,
    cancellation: &CancellationToken,
) -> Result<Option<usize>, ProcessQueryError> {
    let Some(remaining) = buffer.get(offset..) else {
        return Ok(None);
    };
    for (relative, byte) in remaining.iter().enumerate() {
        if relative % CANCELLATION_CHECK_INTERVAL == 0 {
            check_cancelled(cancellation, "scan KERN_PROCARGS2 string")
                .map_err(ProcessQueryError::Platform)?;
        }
        if *byte == 0 {
            return Ok(offset.checked_add(relative));
        }
    }
    Ok(None)
}

fn quote_argument(
    argument: &str,
    cancellation: &CancellationToken,
) -> Result<String, ProcessQueryError> {
    let mut shell_safe = !argument.is_empty();
    for (index, character) in argument.chars().enumerate() {
        if index % CANCELLATION_CHECK_INTERVAL == 0 {
            check_cancelled(cancellation, "format process argument")
                .map_err(ProcessQueryError::Platform)?;
        }
        shell_safe &= character.is_ascii_alphanumeric()
            || matches!(
                character,
                '_' | '-' | '.' | '/' | ':' | '@' | '+' | '=' | ','
            );
    }
    if shell_safe {
        Ok(argument.to_owned())
    } else {
        let mut quoted = String::with_capacity(argument.len().saturating_add(2));
        quoted.push('\'');
        for (index, character) in argument.chars().enumerate() {
            if index % CANCELLATION_CHECK_INTERVAL == 0 {
                check_cancelled(cancellation, "escape process argument")
                    .map_err(ProcessQueryError::Platform)?;
            }
            if character == '\'' {
                quoted.push_str("'\\''");
            } else {
                quoted.push(character);
            }
        }
        quoted.push('\'');
        Ok(quoted)
    }
}

fn decode_bounded_c_string(
    bytes: &[u8],
    operation: &'static str,
    cancellation: &CancellationToken,
) -> Result<String, ProcessQueryError> {
    let nul = find_nul(bytes, 0, cancellation)?.ok_or_else(|| {
        ProcessQueryError::Platform(invalid_native_error(operation, "unterminated string"))
    })?;
    if nul == 0 {
        return Err(ProcessQueryError::Platform(invalid_native_error(
            operation,
            "empty string",
        )));
    }
    Ok(String::from_utf8_lossy(&bytes[..nul]).into_owned())
}

fn list_pids(cancellation: &CancellationToken) -> Result<Vec<i32>, AppError> {
    let mut requested = INITIAL_PID_BUFFER_BYTES;
    for _ in 0..MAX_PID_QUERY_ATTEMPTS {
        check_cancelled(cancellation, "proc_listpids")?;
        requested = requested.min(MAX_PID_BUFFER_BYTES);
        let count = requested / size_of::<libc::pid_t>();
        let mut pids = vec![0 as libc::pid_t; count];
        clear_errno();
        // Safety: the PID array is writable for the exact bounded byte count.
        let actual = unsafe {
            libc::proc_listpids(
                PROC_ALL_PIDS,
                0,
                pids.as_mut_ptr().cast(),
                requested as libc::c_int,
            )
        };
        if actual <= 0 {
            return Err(if current_errno() == 0 {
                invalid_native_error("proc_listpids(PROC_ALL_PIDS)", "zero-length process list")
            } else {
                errno_error("proc_listpids(PROC_ALL_PIDS)")
            });
        }
        let actual = actual as usize;
        if actual > requested || actual % size_of::<libc::pid_t>() != 0 {
            return Err(invalid_native_error(
                "proc_listpids(PROC_ALL_PIDS)",
                "invalid returned byte count",
            ));
        }
        if actual < requested {
            pids.truncate(actual / size_of::<libc::pid_t>());
            let mut seen = HashSet::with_capacity(pids.len());
            let mut deduplicated = Vec::with_capacity(pids.len());
            for (index, pid) in pids.into_iter().enumerate() {
                if index % CANCELLATION_CHECK_INTERVAL == 0 {
                    check_cancelled(cancellation, "deduplicate process identifiers")?;
                }
                if pid > 0 && seen.insert(pid) {
                    deduplicated.push(pid);
                }
            }
            return Ok(deduplicated);
        }
        requested = requested.checked_mul(2).ok_or_else(|| {
            invalid_native_error("proc_listpids(PROC_ALL_PIDS)", "buffer size overflow")
        })?;
        if requested > MAX_PID_BUFFER_BYTES {
            return Err(buffer_limit_error("proc_listpids(PROC_ALL_PIDS)"));
        }
    }
    Err(buffer_limit_error("proc_listpids(PROC_ALL_PIDS)"))
}

enum TaskMetrics {
    Known(libc::proc_taskinfo),
    AccessLimited(String),
}

fn query_bsd_info(pid: i32) -> Result<libc::proc_bsdinfo, ProcessQueryError> {
    let info: libc::proc_bsdinfo = query_pid_info(
        pid,
        libc::PROC_PIDTBSDINFO,
        "proc_pidinfo(PROC_PIDTBSDINFO)",
    )?;
    if info.pbi_pid != pid as u32 {
        return Err(ProcessQueryError::Platform(invalid_native_error(
            "proc_pidinfo(PROC_PIDTBSDINFO)",
            "returned PID does not match request",
        )));
    }
    Ok(info)
}

fn verify_project_process_identity(
    instance_key: &ProcessInstanceKey,
    pid: i32,
    expected_start: u64,
    stage: &'static str,
    cancellation: &CancellationToken,
) -> Result<(), AppError> {
    check_cancelled(cancellation, "validate project process identity")?;
    let info = match query_bsd_info(pid) {
        Ok(info) => info,
        Err(ProcessQueryError::Gone) => {
            return Err(stale_project_observation_error(
                instance_key,
                "process disappeared while validating project evidence",
            ));
        }
        Err(ProcessQueryError::AccessLimited(reason)) => {
            return Err(access_denied_error(instance_key, reason));
        }
        Err(ProcessQueryError::Platform(error)) => return Err(error),
    };
    if info.pbi_pid != instance_key.pid || bsd_start_micros(&info)? != expected_start {
        return Err(stale_project_observation_error(instance_key, stage));
    }
    Ok(())
}

fn query_task_info(pid: i32) -> Result<libc::proc_taskinfo, ProcessQueryError> {
    query_pid_info(
        pid,
        libc::PROC_PIDTASKINFO,
        "proc_pidinfo(PROC_PIDTASKINFO)",
    )
}

fn query_pid_info<T>(
    pid: i32,
    flavor: i32,
    operation: &'static str,
) -> Result<T, ProcessQueryError> {
    let mut value = MaybeUninit::<T>::zeroed();
    let expected = size_of::<T>();
    let expected_i32 = i32::try_from(expected).map_err(|_| {
        ProcessQueryError::Platform(invalid_native_error(operation, "structure is too large"))
    })?;
    clear_errno();
    // Safety: the output points to an aligned buffer of the exact fixed size.
    let actual =
        unsafe { libc::proc_pidinfo(pid, flavor, 0, value.as_mut_ptr().cast(), expected_i32) };
    if actual <= 0 {
        return Err(classify_process_errno(operation));
    }
    if actual as usize != expected {
        return Err(ProcessQueryError::Platform(short_read_error(
            operation,
            expected,
            actual as usize,
        )));
    }
    // Safety: an exact successful read initialized the fixed structure.
    Ok(unsafe { value.assume_init() })
}

fn bsd_start_micros(info: &libc::proc_bsdinfo) -> Result<u64, AppError> {
    if info.pbi_start_tvusec >= 1_000_000 {
        return Err(invalid_native_error(
            "proc_pidinfo(PROC_PIDTBSDINFO)",
            "invalid start microseconds",
        ));
    }
    info.pbi_start_tvsec
        .checked_mul(1_000_000)
        .and_then(|value| value.checked_add(info.pbi_start_tvusec))
        .filter(|value| *value != 0)
        .ok_or_else(|| {
            invalid_native_error(
                "proc_pidinfo(PROC_PIDTBSDINFO)",
                "invalid process start time",
            )
        })
}

fn materialize_native_sample(
    info: libc::proc_bsdinfo,
    start_micros: u64,
    metrics: TaskMetrics,
) -> Result<NativeProcessSample, AppError> {
    let pid = info.pbi_pid;
    if pid == 0 || pid > i32::MAX as u32 {
        return Err(invalid_native_error(
            "proc_pidinfo(PROC_PIDTBSDINFO)",
            "invalid process identifier",
        ));
    }
    let name = c_char_name(&info.pbi_name)
        .or_else(|| c_char_name(&info.pbi_comm))
        .map(FieldValue::Known)
        .unwrap_or(FieldValue::Unknown);
    let (resident_bytes, cpu_total_ns, access_limited) = match metrics {
        TaskMetrics::Known(task) => (
            FieldValue::Known(task.pti_resident_size),
            task.pti_total_user.checked_add(task.pti_total_system),
            false,
        ),
        TaskMetrics::AccessLimited(reason) => (
            FieldValue::AccessLimited {
                reason: Some(reason),
            },
            None,
            true,
        ),
    };
    Ok(NativeProcessSample {
        pid,
        parent_pid: (info.pbi_ppid != 0).then_some(info.pbi_ppid),
        uid: info.pbi_uid,
        start_micros,
        name,
        status: map_status(info.pbi_status),
        resident_bytes,
        cpu_total_ns,
        access_limited,
    })
}

fn c_char_name<const N: usize>(value: &[libc::c_char; N]) -> Option<String> {
    let end = value.iter().position(|byte| *byte == 0).unwrap_or(N);
    let bytes = value[..end]
        .iter()
        .map(|byte| *byte as u8)
        .collect::<Vec<_>>();
    let decoded = String::from_utf8_lossy(&bytes).into_owned();
    (!decoded.is_empty()).then_some(decoded)
}

fn map_status(status: u32) -> ProcessStatus {
    match status {
        libc::SIDL | libc::SRUN => ProcessStatus::Running,
        libc::SSLEEP => ProcessStatus::Sleeping,
        libc::SSTOP => ProcessStatus::Stopped,
        libc::SZOMB => ProcessStatus::Zombie,
        _ => ProcessStatus::Unknown,
    }
}

fn monotonic_raw_ns() -> Result<u64, AppError> {
    let mut value = MaybeUninit::<libc::timespec>::zeroed();
    clear_errno();
    // Safety: value points to one writable timespec.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC_RAW, value.as_mut_ptr()) } != 0 {
        return Err(errno_error("clock_gettime(CLOCK_MONOTONIC_RAW)"));
    }
    // Safety: a successful call initialized the timespec.
    let value = unsafe { value.assume_init() };
    let seconds = u64::try_from(value.tv_sec)
        .map_err(|_| invalid_native_error("clock_gettime", "negative seconds"))?;
    let nanos = u64::try_from(value.tv_nsec)
        .ok()
        .filter(|value| *value < 1_000_000_000)
        .ok_or_else(|| invalid_native_error("clock_gettime", "invalid nanoseconds"))?;
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanos))
        .ok_or_else(|| invalid_native_error("clock_gettime", "timestamp overflow"))
}

fn logical_cpu_count() -> Result<u32, AppError> {
    let name = c"hw.logicalcpu";
    let mut value: libc::c_int = 0;
    let mut length = size_of::<libc::c_int>();
    clear_errno();
    // Safety: the name is NUL-terminated and output is one writable c_int.
    if unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            (&mut value as *mut libc::c_int).cast(),
            &mut length,
            std::ptr::null_mut(),
            0,
        )
    } != 0
    {
        return Err(errno_error("sysctlbyname(hw.logicalcpu)"));
    }
    if length != size_of::<libc::c_int>() || value <= 0 || value as u32 > MAX_LOGICAL_CPUS {
        return Err(invalid_native_error(
            "sysctlbyname(hw.logicalcpu)",
            "invalid logical CPU count",
        ));
    }
    Ok(value as u32)
}

enum ProcessQueryError {
    Gone,
    AccessLimited(String),
    Platform(AppError),
}

fn classify_process_errno(operation: &'static str) -> ProcessQueryError {
    match io::Error::last_os_error().raw_os_error() {
        Some(libc::ESRCH) => ProcessQueryError::Gone,
        Some(libc::EPERM | libc::EACCES) => {
            ProcessQueryError::AccessLimited(format!("{operation}:accessLimited"))
        }
        _ => ProcessQueryError::Platform(errno_error(operation)),
    }
}

fn clear_errno() {
    // Safety: __error returns this thread's errno slot on macOS.
    unsafe { *libc::__error() = 0 };
}

fn current_errno() -> i32 {
    // Safety: __error returns this thread's errno slot on macOS.
    unsafe { *libc::__error() }
}

fn check_cancelled(
    cancellation: &CancellationToken,
    operation: &'static str,
) -> Result<(), AppError> {
    if cancellation.is_cancelled() {
        let mut error = AppError::new(ErrorCode::Timeout, "macOS discovery was cancelled");
        error.retryable = true;
        error.details.insert("operation".into(), operation.into());
        Err(error)
    } else {
        Ok(())
    }
}

fn errno_error(operation: &'static str) -> AppError {
    let source = io::Error::last_os_error();
    let mut error = AppError::new(ErrorCode::PlatformError, "macOS native query failed");
    error.retryable = true;
    error.details.insert("operation".into(), operation.into());
    if let Some(errno) = source.raw_os_error() {
        error.details.insert("errno".into(), errno.to_string());
    }
    error
}

fn short_read_error(operation: &'static str, expected: usize, actual: usize) -> AppError {
    let mut error = AppError::new(
        ErrorCode::PlatformError,
        "macOS native query returned a short buffer",
    );
    error.details.insert("operation".into(), operation.into());
    error
        .details
        .insert("expectedBytes".into(), expected.to_string());
    error
        .details
        .insert("actualBytes".into(), actual.to_string());
    error
}

fn invalid_native_error(operation: &'static str, reason: &'static str) -> AppError {
    let mut error = AppError::new(ErrorCode::PlatformError, "macOS native data is invalid");
    error.details.insert("operation".into(), operation.into());
    error.details.insert("reason".into(), reason.into());
    error
}

fn buffer_limit_error(operation: &'static str) -> AppError {
    let mut error = AppError::new(
        ErrorCode::PlatformError,
        "macOS native query exceeded its buffer limit",
    );
    error.retryable = true;
    error.details.insert("operation".into(), operation.into());
    error
        .details
        .insert("maximumBytes".into(), MAX_PID_BUFFER_BYTES.to_string());
    error
}

fn identity_mismatch_error(instance_key: &ProcessInstanceKey, reason: &'static str) -> AppError {
    let mut error = AppError::new(
        ErrorCode::IdentityMismatch,
        "macOS process instance identity no longer matches",
    );
    error
        .details
        .insert("pid".into(), instance_key.pid.to_string());
    error.details.insert("reason".into(), reason.into());
    error
}

fn stale_project_observation_error(
    instance_key: &ProcessInstanceKey,
    reason: &'static str,
) -> AppError {
    let mut error = AppError::new(
        ErrorCode::IdentityMismatch,
        "macOS project observation is stale",
    );
    error.retryable = true;
    error
        .details
        .insert("pid".into(), instance_key.pid.to_string());
    error.details.insert("reason".into(), reason.into());
    error
}

fn invalid_instance_key_error(instance_key: &ProcessInstanceKey, reason: &'static str) -> AppError {
    let mut error = AppError::new(
        ErrorCode::InvalidArgument,
        "process instance key is invalid",
    );
    error
        .details
        .insert("pid".into(), instance_key.pid.to_string());
    error.details.insert("reason".into(), reason.into());
    error
}

fn access_denied_error(instance_key: &ProcessInstanceKey, reason: String) -> AppError {
    let mut error = AppError::new(
        ErrorCode::AccessDenied,
        "macOS process identity cannot be revalidated",
    );
    error
        .details
        .insert("pid".into(), instance_key.pid.to_string());
    error.details.insert("reason".into(), reason);
    error
}
