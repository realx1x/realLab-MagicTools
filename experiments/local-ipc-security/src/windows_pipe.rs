use std::ffi::c_void;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;

use thiserror::Error;
use windows::Win32::Foundation::{CloseHandle, HANDLE, HLOCAL, INVALID_HANDLE_VALUE, LocalFree};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{
    GetTokenInformation, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
    TokenUser,
};
use windows::Win32::Storage::FileSystem::{
    FILE_FLAG_OVERLAPPED, FILE_FLAGS_AND_ATTRIBUTES, PIPE_ACCESS_DUPLEX,
};
use windows::Win32::System::Pipes::{
    CreateNamedPipeW, NAMED_PIPE_MODE, PIPE_READMODE_MESSAGE, PIPE_REJECT_REMOTE_CLIENTS,
    PIPE_TYPE_MESSAGE, PIPE_WAIT,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::core::{BOOL, Error as WindowsError, PCWSTR, PWSTR};

const PIPE_PREFIX: &str = r"\\.\pipe\com.local.devprocessmanager-";
const PIPE_BUFFER_BYTES: u32 = 64 * 1024;

#[derive(Debug, Error)]
pub enum PipeSecurityError {
    #[error("invalid pipe name")]
    InvalidPipeName,
    #[error("the current user SID could not be converted to UTF-16")]
    InvalidSidString,
    #[error("{stage}: {source}")]
    Windows {
        stage: &'static str,
        source: WindowsError,
    },
}

/// Owns an overlapped pipe server handle. P2 wraps this handle in its async
/// adapter; the spike is limited to endpoint creation and access control.
pub struct CurrentUserPipe(HANDLE);

impl CurrentUserPipe {
    pub fn raw_handle(&self) -> HANDLE {
        self.0
    }
}

impl Drop for CurrentUserPipe {
    fn drop(&mut self) {
        // Safety: this type exclusively owns the valid pipe handle.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

pub fn create_current_user_pipe(name_suffix: &str) -> Result<CurrentUserPipe, PipeSecurityError> {
    if name_suffix.is_empty()
        || name_suffix.len() > 96
        || !name_suffix
            .bytes()
            .all(|value| value.is_ascii_alphanumeric() || matches!(value, b'-' | b'_'))
    {
        return Err(PipeSecurityError::InvalidPipeName);
    }

    let sid = current_user_sid_string()?;
    let sddl = format!("D:P(A;;GA;;;{sid})");
    let descriptor = LocalSecurityDescriptor::from_sddl(&sddl)?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0.0,
        bInheritHandle: BOOL(0),
    };

    let path = wide_nul(&format!("{PIPE_PREFIX}{name_suffix}"));
    let open_mode = FILE_FLAGS_AND_ATTRIBUTES(PIPE_ACCESS_DUPLEX.0 | FILE_FLAG_OVERLAPPED.0);
    let pipe_mode = NAMED_PIPE_MODE(
        PIPE_TYPE_MESSAGE.0 | PIPE_READMODE_MESSAGE.0 | PIPE_WAIT.0 | PIPE_REJECT_REMOTE_CLIENTS.0,
    );
    // Safety: path and security descriptor live through the call; the descriptor
    // grants generic-all only to the current user SID and is non-inheritable.
    let handle = unsafe {
        CreateNamedPipeW(
            PCWSTR(path.as_ptr()),
            open_mode,
            pipe_mode,
            1,
            PIPE_BUFFER_BYTES,
            PIPE_BUFFER_BYTES,
            0,
            Some(&attributes),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(windows_error("CreateNamedPipeW"));
    }
    Ok(CurrentUserPipe(handle))
}

fn current_user_sid_string() -> Result<String, PipeSecurityError> {
    let mut token = HANDLE::default();
    // Safety: GetCurrentProcess returns a pseudo-handle and token receives the
    // owned process-token handle.
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }.map_err(
        |source| PipeSecurityError::Windows {
            stage: "OpenProcessToken",
            source,
        },
    )?;
    let token = OwnedHandle(token);

    let mut required = 0_u32;
    // The first call intentionally discovers the required buffer size.
    let _ = unsafe { GetTokenInformation(token.0, TokenUser, None, 0, &mut required) };
    if required < size_of::<TOKEN_USER>() as u32 {
        return Err(windows_error("GetTokenInformation(size)"));
    }
    let words = (required as usize).div_ceil(size_of::<usize>());
    let mut buffer = vec![0_usize; words];
    // Safety: usize storage provides TOKEN_USER alignment and `required` writable bytes.
    unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            Some(buffer.as_mut_ptr().cast()),
            required,
            &mut required,
        )
    }
    .map_err(|source| PipeSecurityError::Windows {
        stage: "GetTokenInformation(TokenUser)",
        source,
    })?;
    // Safety: GetTokenInformation initialized a TOKEN_USER at this aligned address.
    let token_user = unsafe { &*(buffer.as_ptr().cast::<TOKEN_USER>()) };

    let mut sid_text = PWSTR::null();
    // Safety: the SID belongs to the token buffer and sid_text receives LocalAlloc memory.
    unsafe { ConvertSidToStringSidW(token_user.User.Sid, &mut sid_text) }.map_err(|source| {
        PipeSecurityError::Windows {
            stage: "ConvertSidToStringSidW",
            source,
        }
    })?;
    let sid_text = LocalWideString(sid_text);
    // Safety: ConvertSidToStringSidW returned a NUL-terminated string.
    unsafe { sid_text.0.to_string() }.map_err(|_| PipeSecurityError::InvalidSidString)
}

fn wide_nul(value: &str) -> Vec<u16> {
    std::ffi::OsStr::new(value)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn windows_error(stage: &'static str) -> PipeSecurityError {
    PipeSecurityError::Windows {
        stage,
        source: WindowsError::from_win32(),
    }
}

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // Safety: this type exclusively owns the token handle.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

struct LocalWideString(PWSTR);

impl Drop for LocalWideString {
    fn drop(&mut self) {
        // Safety: ConvertSidToStringSidW allocated this pointer with LocalAlloc.
        unsafe { LocalFree(Some(HLOCAL(self.0.0.cast::<c_void>()))) };
    }
}

struct LocalSecurityDescriptor(PSECURITY_DESCRIPTOR);

impl LocalSecurityDescriptor {
    fn from_sddl(sddl: &str) -> Result<Self, PipeSecurityError> {
        let sddl = wide_nul(sddl);
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        // Safety: sddl is NUL-terminated and descriptor receives LocalAlloc memory.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(sddl.as_ptr()),
                SDDL_REVISION_1,
                &mut descriptor,
                None,
            )
        }
        .map_err(|source| PipeSecurityError::Windows {
            stage: "ConvertStringSecurityDescriptorToSecurityDescriptorW",
            source,
        })?;
        Ok(Self(descriptor))
    }
}

impl Drop for LocalSecurityDescriptor {
    fn drop(&mut self) {
        // Safety: the conversion function allocated this descriptor with LocalAlloc.
        unsafe { LocalFree(Some(HLOCAL(self.0.0))) };
    }
}
