use std::mem::size_of;

use domain::{AppError, ErrorCode, ProcessInstanceKey};
use windows::Win32::Foundation::{
    CloseHandle, ERROR_ACCESS_DENIED, ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_PARAMETER,
    ERROR_NOT_FOUND, ERROR_PROCESS_ABORTED, FILETIME, HANDLE, WAIT_FAILED, WAIT_OBJECT_0,
    WAIT_TIMEOUT, WIN32_ERROR,
};
use windows::Win32::Security::{
    GetLengthSid, GetTokenInformation, IsValidSid, TOKEN_ELEVATION, TOKEN_QUERY, TOKEN_USER,
    TokenElevation, TokenSessionId, TokenUser,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetProcessId, GetProcessTimes, IsProcessCritical, OpenProcess,
    OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, PROCESS_TERMINATE,
    TerminateProcess, WaitForSingleObject,
};
use windows::core::{BOOL, Error as WindowsError};

const SYSTEM_IDLE_PROCESS_ID: u32 = 0;
const SYSTEM_PROCESS_ID: u32 = 4;
const EXTERNAL_STOP_EXIT_CODE: u32 = 0xFFFF_FF03;
const MAX_TOKEN_INFORMATION_BYTES: usize = 64 * 1024;
const MAX_PROTECTED_PROCESS_IDS: usize = 16;

/// Closed result set for one external-process stop attempt. The adapter never
/// enumerates descendants and never retries or substitutes another signal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsExternalStopResult {
    SignalDelivered,
    AlreadyExited,
}

/// Stops only the exact external process represented by `target`.
///
/// The caller supplies additional protected process IDs, normally including
/// the desktop application. The current process is always protected as the
/// Supervisor boundary. A successful call performs exactly one destructive
/// action against the same handle used for PID, creation-time, owner, session,
/// and critical-process validation.
pub fn stop_external_process(
    target: &ProcessInstanceKey,
    protected_process_ids: &[u32],
) -> Result<WindowsExternalStopResult, AppError> {
    let expected_creation_time = validate_request(target, protected_process_ids)?;

    let process = match open_target_process(target.pid)? {
        Some(process) => process,
        None => return Ok(WindowsExternalStopResult::AlreadyExited),
    };
    if process_exit_state(process.raw())? {
        return Ok(WindowsExternalStopResult::AlreadyExited);
    }

    // Identity mismatch takes precedence over later permission-boundary
    // checks, so a reused PID is never reported as merely inaccessible.
    revalidate_instance(&process, target, expected_creation_time)?;
    if let Err(error) = validate_current_user_and_session(&process) {
        return if process_exit_state(process.raw())? {
            Ok(WindowsExternalStopResult::AlreadyExited)
        } else {
            Err(error)
        };
    }

    // Keep the exit and critical-process checks adjacent to the sole
    // destructive call. The exact object remains pinned by `process`.
    if process_exit_state(process.raw())? {
        return Ok(WindowsExternalStopResult::AlreadyExited);
    }
    if let Err(error) = validate_not_critical(&process) {
        return if process_exit_state(process.raw())? {
            Ok(WindowsExternalStopResult::AlreadyExited)
        } else {
            Err(error)
        };
    }
    // Safety: this is the same uniquely owned process handle used for every
    // validation above and it carries only the rights required by this API.
    match unsafe { TerminateProcess(process.raw(), EXTERNAL_STOP_EXIT_CODE) } {
        Ok(()) => Ok(WindowsExternalStopResult::SignalDelivered),
        Err(source) => classify_termination_failure(process.raw(), &source),
    }
}

fn validate_request(
    target: &ProcessInstanceKey,
    protected_process_ids: &[u32],
) -> Result<u64, AppError> {
    if protected_process_ids.len() > MAX_PROTECTED_PROCESS_IDS {
        let mut error = invalid_request_error(
            "protectedProcessIds",
            "contains more entries than the platform limit",
        );
        error
            .details
            .insert("maxCount".into(), MAX_PROTECTED_PROCESS_IDS.to_string());
        return Err(error);
    }
    if target.boot_id.is_empty() {
        return Err(invalid_request_error("bootId", "must not be empty"));
    }
    let creation_time = target
        .native_start_time
        .parse::<u64>()
        .ok()
        .filter(|value| *value != 0 && value.to_string() == target.native_start_time)
        .ok_or_else(|| {
            invalid_request_error(
                "nativeStartTime",
                "must be a non-zero canonical decimal value",
            )
        })?;

    let supervisor_pid = std::process::id();
    let reason = match target.pid {
        SYSTEM_IDLE_PROCESS_ID => Some("systemIdleProcess"),
        SYSTEM_PROCESS_ID => Some("systemProcess"),
        pid if pid == supervisor_pid => Some("supervisorProcess"),
        pid if protected_process_ids.contains(&pid) => Some("callerProtectedProcess"),
        _ => None,
    };
    if let Some(reason) = reason {
        return Err(protected_process_error(target.pid, reason));
    }
    Ok(creation_time)
}

fn open_target_process(pid: u32) -> Result<Option<OwnedHandle>, AppError> {
    let rights = PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE;
    // Safety: PID is only a lookup hint. The returned object is not acted on
    // until its complete identity and protection boundaries are revalidated.
    match unsafe { OpenProcess(rights, false, pid) } {
        Ok(handle) => Ok(Some(OwnedHandle::new(handle))),
        Err(source) => match WIN32_ERROR::from_error(&source) {
            Some(ERROR_INVALID_PARAMETER | ERROR_NOT_FOUND | ERROR_PROCESS_ABORTED) => Ok(None),
            Some(ERROR_ACCESS_DENIED) => Err(access_denied_error(
                "OpenProcess",
                "targetProcessAccessDenied",
                Some(&source),
            )),
            _ => Err(platform_api_error("OpenProcess", &source)),
        },
    }
}

fn revalidate_instance(
    process: &OwnedHandle,
    target: &ProcessInstanceKey,
    expected_creation_time: u64,
) -> Result<(), AppError> {
    // Safety: `process` owns the exact handle for this complete validation.
    let actual_pid = unsafe { GetProcessId(process.raw()) };
    if actual_pid == 0 {
        return Err(platform_api_error(
            "RevalidateProcessIdentity(GetProcessId)",
            &WindowsError::from_win32(),
        ));
    }
    if actual_pid != target.pid {
        return Err(identity_mismatch_error("pid"));
    }

    let actual_creation_time = query_creation_time(process.raw()).map_err(|source| {
        platform_api_error("RevalidateProcessIdentity(GetProcessTimes)", &source)
    })?;
    if actual_creation_time == 0 {
        return Err(platform_invariant_error(
            "RevalidateProcessIdentity(GetProcessTimes)",
            "creationTimeWasZero",
        ));
    }
    if actual_creation_time != expected_creation_time {
        return Err(identity_mismatch_error("nativeStartTime"));
    }

    let actual_boot_id = crate::native::query_boot_identifier().map_err(|mut error| {
        error.details.insert(
            "stage".into(),
            "RevalidateProcessIdentity(QueryBootIdentifier)".into(),
        );
        error
    })?;
    if actual_boot_id != target.boot_id {
        return Err(identity_mismatch_error("bootId"));
    }
    Ok(())
}

fn validate_current_user_and_session(process: &OwnedHandle) -> Result<(), AppError> {
    // Safety: GetCurrentProcess returns a process-local pseudo handle.
    let current_process = unsafe { GetCurrentProcess() };
    let current = query_process_security_boundary(current_process, "QueryCurrentUser")?;
    let target = query_process_security_boundary(process.raw(), "QueryTargetUser")?;
    if current.elevated {
        return Err(access_denied_error(
            "ValidateSupervisorElevation",
            "elevatedSupervisor",
            None,
        ));
    }
    if target.elevated {
        return Err(access_denied_error(
            "ValidateProcessElevation",
            "elevatedTarget",
            None,
        ));
    }
    if current.sid != target.sid {
        return Err(access_denied_error(
            "ValidateProcessOwner",
            "differentUser",
            None,
        ));
    }

    if current.session_id != target.session_id {
        return Err(access_denied_error(
            "ValidateProcessSession",
            "differentSession",
            None,
        ));
    }
    Ok(())
}

fn validate_not_critical(process: &OwnedHandle) -> Result<(), AppError> {
    let mut critical = BOOL(0);
    // Safety: output is writable and `process` remains the exact target handle.
    unsafe { IsProcessCritical(process.raw(), &mut critical) }.map_err(|source| {
        if WIN32_ERROR::from_error(&source) == Some(ERROR_ACCESS_DENIED) {
            access_denied_error(
                "IsProcessCritical",
                "criticalStatusAccessDenied",
                Some(&source),
            )
        } else {
            platform_api_error("IsProcessCritical", &source)
        }
    })?;
    if critical.as_bool() {
        return Err(protected_process_error(
            // The target PID was already revalidated on this handle.
            unsafe { GetProcessId(process.raw()) },
            "criticalProcess",
        ));
    }
    Ok(())
}

fn process_exit_state(process: HANDLE) -> Result<bool, AppError> {
    // Safety: the handle remains live and was opened with PROCESS_SYNCHRONIZE.
    match unsafe { WaitForSingleObject(process, 0) } {
        WAIT_OBJECT_0 => Ok(true),
        WAIT_TIMEOUT => Ok(false),
        WAIT_FAILED => Err(platform_api_error(
            "WaitForSingleObject",
            &WindowsError::from_win32(),
        )),
        status => {
            let mut error = platform_invariant_error("WaitForSingleObject", "unexpectedWaitResult");
            error
                .details
                .insert("platformCode".into(), format!("WAIT:0x{:08X}", status.0));
            Err(error)
        }
    }
}

fn query_creation_time(process: HANDLE) -> windows::core::Result<u64> {
    let mut create = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    // Safety: every output is writable and the exact process handle is live.
    unsafe { GetProcessTimes(process, &mut create, &mut exit, &mut kernel, &mut user) }?;
    Ok(((create.dwHighDateTime as u64) << 32) | create.dwLowDateTime as u64)
}

fn query_process_security_boundary(
    process: HANDLE,
    stage: &'static str,
) -> Result<ProcessSecurityBoundary, AppError> {
    let mut raw_token = HANDLE::default();
    // Safety: output is writable and only TOKEN_QUERY is requested.
    unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut raw_token) }
        .map_err(|source| access_denied_error(stage, "processTokenUnavailable", Some(&source)))?;
    let token = OwnedHandle::new(raw_token);

    let mut required = 0_u32;
    // Safety: this is the documented size probe with no output buffer.
    let probe = unsafe { GetTokenInformation(token.raw(), TokenUser, None, 0, &mut required) };
    if !matches!(
        probe,
        Err(ref source)
            if WIN32_ERROR::from_error(source) == Some(ERROR_INSUFFICIENT_BUFFER)
                && required > 0
    ) {
        return Err(access_denied_error(
            stage,
            "tokenUserUnknown",
            probe.as_ref().err(),
        ));
    }
    let required = required as usize;
    if !(size_of::<TOKEN_USER>()..=MAX_TOKEN_INFORMATION_BYTES).contains(&required) {
        return Err(access_denied_error(stage, "tokenUserSizeInvalid", None));
    }

    let words = required.div_ceil(size_of::<usize>());
    let mut storage = vec![0_usize; words];
    let capacity = storage.len() * size_of::<usize>();
    let mut returned = 0_u32;
    // Safety: storage is aligned for TOKEN_USER and writable for its capacity.
    unsafe {
        GetTokenInformation(
            token.raw(),
            TokenUser,
            Some(storage.as_mut_ptr().cast()),
            capacity as u32,
            &mut returned,
        )
    }
    .map_err(|source| access_denied_error(stage, "tokenUserUnknown", Some(&source)))?;

    let returned = returned as usize;
    if returned < size_of::<TOKEN_USER>() || returned > capacity {
        return Err(access_denied_error(stage, "tokenUserResultInvalid", None));
    }
    // Safety: the successful API call initialized a TOKEN_USER header.
    let token_user = unsafe { &*(storage.as_ptr().cast::<TOKEN_USER>()) };
    let sid_address = token_user.User.Sid.0 as usize;
    let base = storage.as_ptr() as usize;
    let end = base
        .checked_add(returned)
        .ok_or_else(|| access_denied_error(stage, "tokenUserResultInvalid", None))?;
    if sid_address < base || sid_address.checked_add(8).is_none_or(|value| value > end) {
        return Err(access_denied_error(stage, "tokenUserSidInvalid", None));
    }
    // The fixed SID header is in bounds before SubAuthorityCount is read.
    let subauthority_count = unsafe { *((sid_address + 1) as *const u8) } as usize;
    let sid_length = subauthority_count
        .checked_mul(size_of::<u32>())
        .and_then(|value| value.checked_add(8))
        .ok_or_else(|| access_denied_error(stage, "tokenUserSidInvalid", None))?;
    if sid_address
        .checked_add(sid_length)
        .is_none_or(|value| value > end)
    {
        return Err(access_denied_error(stage, "tokenUserSidInvalid", None));
    }
    // Safety: the complete candidate SID lies inside initialized token data.
    if unsafe { !IsValidSid(token_user.User.Sid).as_bool() }
        || unsafe { GetLengthSid(token_user.User.Sid) } as usize != sid_length
    {
        return Err(access_denied_error(stage, "tokenUserSidInvalid", None));
    }
    // Safety: the validated SID range lies inside initialized live storage.
    let mut session_id = 0_u32;
    let mut session_bytes = 0_u32;
    // Safety: the token remains owned and the u32 output is writable.
    unsafe {
        GetTokenInformation(
            token.raw(),
            TokenSessionId,
            Some((&mut session_id as *mut u32).cast()),
            size_of::<u32>() as u32,
            &mut session_bytes,
        )
    }
    .map_err(|source| access_denied_error(stage, "tokenSessionUnknown", Some(&source)))?;
    if session_bytes != size_of::<u32>() as u32 {
        return Err(access_denied_error(
            stage,
            "tokenSessionResultInvalid",
            None,
        ));
    }

    let mut elevation = TOKEN_ELEVATION::default();
    let mut elevation_bytes = 0_u32;
    // Safety: the token remains owned and TOKEN_ELEVATION is writable.
    unsafe {
        GetTokenInformation(
            token.raw(),
            TokenElevation,
            Some((&mut elevation as *mut TOKEN_ELEVATION).cast()),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut elevation_bytes,
        )
    }
    .map_err(|source| access_denied_error(stage, "tokenElevationUnknown", Some(&source)))?;
    if elevation_bytes != size_of::<TOKEN_ELEVATION>() as u32 {
        return Err(access_denied_error(
            stage,
            "tokenElevationResultInvalid",
            None,
        ));
    }

    // Safety: this range was bounded above and remains live until the copy.
    let sid = unsafe { std::slice::from_raw_parts(sid_address as *const u8, sid_length) }.to_vec();
    Ok(ProcessSecurityBoundary {
        sid,
        session_id,
        elevated: elevation.TokenIsElevated != 0,
    })
}

fn classify_termination_failure(
    process: HANDLE,
    source: &WindowsError,
) -> Result<WindowsExternalStopResult, AppError> {
    if process_exit_state(process)? {
        return Ok(WindowsExternalStopResult::AlreadyExited);
    }
    if WIN32_ERROR::from_error(source) == Some(ERROR_ACCESS_DENIED) {
        return Err(access_denied_error(
            "TerminateProcess",
            "targetProcessAccessDenied",
            Some(source),
        ));
    }
    Err(platform_api_error("TerminateProcess", source))
}

fn invalid_request_error(field: &'static str, reason: &'static str) -> AppError {
    let mut error = AppError::new(
        ErrorCode::InvalidArgument,
        "invalid Windows external stop request",
    );
    error.details.insert("field".into(), field.into());
    error.details.insert("reason".into(), reason.into());
    error
}

fn protected_process_error(pid: u32, reason: &'static str) -> AppError {
    let mut error = AppError::new(
        ErrorCode::AccessDenied,
        "Windows external process is protected from stop",
    );
    error
        .details
        .insert("stage".into(), "ValidateProtectedProcess".into());
    error.details.insert("reason".into(), reason.into());
    error.details.insert("pid".into(), pid.to_string());
    error
}

fn identity_mismatch_error(field: &'static str) -> AppError {
    let mut error = AppError::new(
        ErrorCode::IdentityMismatch,
        "Windows external process identity no longer matches",
    );
    error
        .details
        .insert("stage".into(), "RevalidateProcessIdentity".into());
    error.details.insert("field".into(), field.into());
    error
}

fn access_denied_error(
    stage: &'static str,
    reason: &'static str,
    source: Option<&WindowsError>,
) -> AppError {
    let mut error = AppError::new(
        ErrorCode::AccessDenied,
        "Windows external process stop was denied",
    );
    error.details.insert("stage".into(), stage.into());
    error.details.insert("reason".into(), reason.into());
    if let Some(source) = source {
        error
            .details
            .insert("platformCode".into(), redacted_platform_code(source));
    }
    error
}

fn platform_api_error(stage: &'static str, source: &WindowsError) -> AppError {
    let mut error = AppError::new(
        if WIN32_ERROR::from_error(source) == Some(ERROR_ACCESS_DENIED) {
            ErrorCode::AccessDenied
        } else {
            ErrorCode::PlatformError
        },
        "Windows external process stop operation failed",
    );
    error.details.insert("stage".into(), stage.into());
    error
        .details
        .insert("platformCode".into(), redacted_platform_code(source));
    error
}

fn platform_invariant_error(stage: &'static str, reason: &'static str) -> AppError {
    let mut error = AppError::new(
        ErrorCode::PlatformError,
        "Windows external process stop invariant failed",
    );
    error.details.insert("stage".into(), stage.into());
    error.details.insert("reason".into(), reason.into());
    error
}

fn redacted_platform_code(source: &WindowsError) -> String {
    WIN32_ERROR::from_error(source).map_or_else(
        || format!("HRESULT:0x{:08X}", source.code().0 as u32),
        |code| format!("WIN32:{}", code.0),
    )
}

struct OwnedHandle(HANDLE);

struct ProcessSecurityBoundary {
    sid: Vec<u8>,
    session_id: u32,
    elevated: bool,
}

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
        // Safety: this wrapper owns one successful process or token handle.
        let _ = unsafe { CloseHandle(self.0) };
    }
}
