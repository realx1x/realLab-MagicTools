use std::mem::{MaybeUninit, size_of};

use domain::{AppError, ErrorCode, ProcessInstanceKey};

const MAX_PROTECTED_PROCESS_IDS: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacosExternalStopResult {
    SignalDelivered,
    AlreadyExited,
}

/// Sends one SIGTERM to one external PID. The caller supplies application PIDs
/// that are protected in addition to this Supervisor process.
pub fn stop_external_process(
    target: &ProcessInstanceKey,
    protected_process_ids: &[u32],
) -> Result<MacosExternalStopResult, AppError> {
    validate_target(target, protected_process_ids)?;
    let pid = libc::pid_t::try_from(target.pid)
        .map_err(|_| invalid_target_error("processInstanceKey.pid"))?;
    if pid <= 1 {
        return Err(protected_process_error(target.pid, "systemCriticalProcess"));
    }

    let boot_id = crate::native::query_boot_identifier().map_err(|mut error| {
        error
            .details
            .insert("stopStage".into(), "QueryBootIdentifier".into());
        error
    })?;
    if boot_id != target.boot_id {
        return Err(identity_mismatch_error("bootId"));
    }

    let Some(observation) = query_process_observation(pid)? else {
        return Ok(MacosExternalStopResult::AlreadyExited);
    };
    let expected_start = target
        .native_start_time
        .parse::<u64>()
        .ok()
        .filter(|value| *value != 0 && value.to_string() == target.native_start_time)
        .ok_or_else(|| invalid_target_error("nativeStartTime"))?;
    if observation.pid != target.pid || observation.start_micros != expected_start {
        return Err(identity_mismatch_error("nativeStartTime"));
    }

    // V1 never uses elevated or set-user-ID authority for process control.
    let real_uid = unsafe { libc::getuid() };
    let effective_uid = unsafe { libc::geteuid() };
    let real_gid = unsafe { libc::getgid() };
    let effective_gid = unsafe { libc::getegid() };
    if effective_uid == 0
        || effective_uid != real_uid
        || effective_gid != real_gid
        || unsafe { libc::issetugid() } != 0
    {
        return Err(access_denied_error("supervisorPrivilegeBoundary"));
    }
    if observation.effective_uid != effective_uid
        || observation.real_uid != real_uid
        || observation.saved_uid != effective_uid
        || observation.effective_gid != effective_gid
        || observation.real_gid != real_gid
        || observation.saved_gid != effective_gid
    {
        return Err(access_denied_error("targetUserMismatch"));
    }

    clear_errno();
    // Safety: pid is the positive, identity-revalidated single target. No
    // negative PGID or recursive process-tree operation is used here.
    if unsafe { libc::kill(pid, libc::SIGTERM) } == 0 {
        return Ok(MacosExternalStopResult::SignalDelivered);
    }
    match current_errno() {
        libc::ESRCH => Ok(MacosExternalStopResult::AlreadyExited),
        libc::EPERM | libc::EACCES => Err(access_denied_error("kill(SIGTERM)")),
        errno => Err(platform_error("kill(SIGTERM)", errno)),
    }
}

fn validate_target(
    target: &ProcessInstanceKey,
    protected_process_ids: &[u32],
) -> Result<(), AppError> {
    if protected_process_ids.len() > MAX_PROTECTED_PROCESS_IDS {
        return Err(invalid_target_error("protectedProcessIds"));
    }
    if target.boot_id.trim().is_empty()
        || target.boot_id.contains('\0')
        || target.native_start_time.trim().is_empty()
        || target.native_start_time.contains('\0')
    {
        return Err(invalid_target_error("target"));
    }
    if target.pid <= 1 {
        return Err(protected_process_error(target.pid, "systemCriticalProcess"));
    }
    if target.pid == std::process::id() {
        return Err(protected_process_error(target.pid, "supervisorProcess"));
    }
    if protected_process_ids.contains(&target.pid) {
        return Err(protected_process_error(target.pid, "applicationProcess"));
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct ProcessObservation {
    pid: u32,
    effective_uid: libc::uid_t,
    real_uid: libc::uid_t,
    saved_uid: libc::uid_t,
    effective_gid: libc::gid_t,
    real_gid: libc::gid_t,
    saved_gid: libc::gid_t,
    start_micros: u64,
}

fn query_process_observation(pid: libc::pid_t) -> Result<Option<ProcessObservation>, AppError> {
    let mut information = MaybeUninit::<libc::proc_bsdinfo>::zeroed();
    let expected = size_of::<libc::proc_bsdinfo>();
    let expected_i32 = libc::c_int::try_from(expected)
        .map_err(|_| platform_invariant_error("proc_pidinfo size"))?;
    clear_errno();
    // Safety: the fixed-size output is writable for the complete native query.
    let actual = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            information.as_mut_ptr().cast(),
            expected_i32,
        )
    };
    if actual <= 0 {
        return match current_errno() {
            libc::ESRCH => Ok(None),
            libc::EPERM | libc::EACCES => {
                Err(access_denied_error("proc_pidinfo(PROC_PIDTBSDINFO)"))
            }
            0 => Err(platform_invariant_error(
                "proc_pidinfo returned no process data without errno",
            )),
            errno => Err(platform_error("proc_pidinfo(PROC_PIDTBSDINFO)", errno)),
        };
    }
    if actual as usize != expected {
        return Err(platform_invariant_error(
            "proc_pidinfo returned a short structure",
        ));
    }
    // Safety: an exact successful read initialized the complete structure.
    let information = unsafe { information.assume_init() };
    let pid_u32 = u32::try_from(pid).map_err(|_| platform_invariant_error("pid range"))?;
    if information.pbi_pid != pid_u32 || information.pbi_start_tvusec >= 1_000_000 {
        return Err(platform_invariant_error(
            "proc_pidinfo returned invalid identity fields",
        ));
    }
    let start_micros = information
        .pbi_start_tvsec
        .checked_mul(1_000_000)
        .and_then(|value| value.checked_add(information.pbi_start_tvusec))
        .filter(|value| *value != 0)
        .ok_or_else(|| platform_invariant_error("process start time"))?;
    Ok(Some(ProcessObservation {
        pid: pid_u32,
        effective_uid: information.pbi_uid,
        real_uid: information.pbi_ruid,
        saved_uid: information.pbi_svuid,
        effective_gid: information.pbi_gid,
        real_gid: information.pbi_rgid,
        saved_gid: information.pbi_svgid,
        start_micros,
    }))
}

fn invalid_target_error(field: &'static str) -> AppError {
    let mut error = AppError::new(
        ErrorCode::InvalidArgument,
        "invalid external process stop target",
    );
    error.details.insert("field".into(), field.into());
    error
}

fn protected_process_error(pid: u32, reason: &'static str) -> AppError {
    let mut error = AppError::new(
        ErrorCode::AccessDenied,
        "external process stop target is protected",
    );
    error.details.insert("pid".into(), pid.to_string());
    error.details.insert("reason".into(), reason.into());
    error
}

fn identity_mismatch_error(field: &'static str) -> AppError {
    let mut error = AppError::new(
        ErrorCode::IdentityMismatch,
        "external process identity no longer matches",
    );
    error.details.insert("field".into(), field.into());
    error
}

fn access_denied_error(stage: &'static str) -> AppError {
    let mut error = AppError::new(
        ErrorCode::AccessDenied,
        "external process stop is not permitted",
    );
    error.details.insert("stage".into(), stage.into());
    error
}

fn platform_error(stage: &'static str, errno: libc::c_int) -> AppError {
    let mut error = AppError::new(ErrorCode::PlatformError, "external process stop failed");
    error.details.insert("stage".into(), stage.into());
    error
        .details
        .insert("platformCode".into(), format!("ERRNO:{errno}"));
    error
}

fn platform_invariant_error(reason: &'static str) -> AppError {
    let mut error = AppError::new(
        ErrorCode::PlatformError,
        "external process identity inspection failed",
    );
    error.details.insert("reason".into(), reason.into());
    error
}

fn clear_errno() {
    unsafe { *libc::__error() = 0 };
}

fn current_errno() -> libc::c_int {
    unsafe { *libc::__error() }
}
