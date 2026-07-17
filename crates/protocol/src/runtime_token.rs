use std::io;
use std::path::PathBuf;

use thiserror::Error;

use crate::SessionToken;

const SESSION_TOKEN_BYTES: usize = 32;

#[derive(Debug, Error)]
pub enum SessionTokenReadError {
    #[error("failed to resolve the current-user Supervisor runtime directory")]
    ResolveRuntime(#[source] io::Error),
    #[error("failed to open the current-user Supervisor runtime data")]
    Open(#[source] io::Error),
    #[error("failed to inspect the current-user Supervisor runtime data")]
    Inspect(#[source] io::Error),
    #[error("the Supervisor runtime object has an unsafe type")]
    UnsafeType,
    #[error("the Supervisor runtime object is not owned by the current user")]
    OwnerMismatch,
    #[error("the Supervisor runtime object has unsafe permissions")]
    UnsafePermissions,
    #[error("the Supervisor session token contains {actual} bytes instead of 32")]
    InvalidLength { actual: usize },
}

impl SessionTokenReadError {
    pub fn is_access_denied(&self) -> bool {
        matches!(self, Self::OwnerMismatch | Self::UnsafePermissions)
            || match self {
                Self::ResolveRuntime(source) | Self::Open(source) | Self::Inspect(source) => {
                    source.kind() == io::ErrorKind::PermissionDenied
                }
                Self::UnsafeType
                | Self::OwnerMismatch
                | Self::UnsafePermissions
                | Self::InvalidLength { .. } => false,
            }
    }
}

pub fn current_user_runtime_root() -> Result<PathBuf, SessionTokenReadError> {
    platform::current_user_runtime_root().map_err(SessionTokenReadError::ResolveRuntime)
}

pub fn read_current_session_token() -> Result<SessionToken, SessionTokenReadError> {
    let root = current_user_runtime_root()?;
    let bytes = platform::read_token(&root)?;
    if bytes.len() != SESSION_TOKEN_BYTES {
        return Err(SessionTokenReadError::InvalidLength {
            actual: bytes.len(),
        });
    }
    SessionToken::from_slice(&bytes).map_err(|_| SessionTokenReadError::InvalidLength {
        actual: bytes.len(),
    })
}

#[cfg(windows)]
mod platform {
    use std::ffi::{OsStr, OsString};
    use std::fs::File;
    use std::io::{self, Read};
    use std::mem::size_of;
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use std::path::{Path, PathBuf};

    use windows::Win32::Foundation::{CloseHandle, ERROR_SUCCESS, HANDLE, HLOCAL, LocalFree};
    use windows::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
    use windows::Win32::Security::{
        EqualSid, GetTokenInformation, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
        TOKEN_QUERY, TOKEN_USER, TokenUser,
    };
    use windows::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, CreateFileW, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL,
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_GENERIC_READ, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE, FILE_TYPE_DISK, GetFileInformationByHandle, GetFileType, OPEN_EXISTING,
        READ_CONTROL,
    };
    use windows::Win32::System::Com::CoTaskMemFree;
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use windows::Win32::UI::Shell::{FOLDERID_LocalAppData, KF_FLAG_DEFAULT, SHGetKnownFolderPath};
    use windows::core::{Error as WindowsError, PCWSTR, PWSTR};

    use super::SessionTokenReadError;

    pub(super) fn current_user_runtime_root() -> io::Result<PathBuf> {
        let local_app_data =
            unsafe { SHGetKnownFolderPath(&FOLDERID_LocalAppData, KF_FLAG_DEFAULT, None) }
                .map_err(windows_error)?;
        let local_app_data = KnownFolderPath(local_app_data);
        let local_app_data =
            PathBuf::from(OsString::from_wide(unsafe { local_app_data.0.as_wide() }));
        if !local_app_data.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the Local AppData known folder is not absolute",
            ));
        }
        let identity = crate::windows_pipe::CurrentWindowsIdentity::for_current_process()
            .map_err(io::Error::other)?;
        Ok(local_app_data
            .join("DevProcessManager")
            .join(format!("session-{}", identity.session_id()))
            .join("runtime"))
    }

    pub(super) fn read_token(root: &Path) -> Result<Vec<u8>, SessionTokenReadError> {
        let session_root = root.parent().ok_or(SessionTokenReadError::UnsafeType)?;
        let application_root = session_root
            .parent()
            .ok_or(SessionTokenReadError::UnsafeType)?;
        for directory in [application_root, session_root, root] {
            let handle = open_path(directory, true).map_err(SessionTokenReadError::Open)?;
            validate_handle(&handle, true)?;
            validate_current_user_owner(&handle)?;
        }

        let mut file =
            open_path(&root.join("session.token"), false).map_err(SessionTokenReadError::Open)?;
        validate_handle(&file, false)?;
        validate_current_user_owner(&file)?;
        read_bounded(&mut file)
    }

    fn open_path(path: &Path, directory: bool) -> io::Result<File> {
        let wide = wide_nul(path.as_os_str())?;
        let access = if directory {
            (FILE_READ_ATTRIBUTES | READ_CONTROL).0
        } else {
            FILE_GENERIC_READ.0
        };
        let flags = FILE_FLAG_OPEN_REPARSE_POINT
            | if directory {
                FILE_FLAG_BACKUP_SEMANTICS
            } else {
                FILE_ATTRIBUTE_NORMAL
            };
        let handle = unsafe {
            CreateFileW(
                PCWSTR(wide.as_ptr()),
                access,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                None,
                OPEN_EXISTING,
                flags,
                None,
            )
        }
        .map_err(windows_error)?;
        Ok(unsafe { File::from_raw_handle(handle.0) })
    }

    fn validate_handle(file: &File, expected_directory: bool) -> Result<(), SessionTokenReadError> {
        let handle = HANDLE(file.as_raw_handle());
        let mut information = BY_HANDLE_FILE_INFORMATION::default();
        unsafe { GetFileInformationByHandle(handle, &mut information) }
            .map_err(windows_error)
            .map_err(SessionTokenReadError::Inspect)?;
        let attributes = information.dwFileAttributes;
        let is_directory = attributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0;
        if attributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
            || is_directory != expected_directory
            || unsafe { GetFileType(handle) } != FILE_TYPE_DISK
        {
            return Err(SessionTokenReadError::UnsafeType);
        }
        Ok(())
    }

    fn validate_current_user_owner(file: &File) -> Result<(), SessionTokenReadError> {
        let token = current_process_token().map_err(SessionTokenReadError::Inspect)?;
        let sid_buffer = current_user_sid(token.0).map_err(SessionTokenReadError::Inspect)?;
        let token_user = unsafe { &*(sid_buffer.as_ptr().cast::<TOKEN_USER>()) };
        let mut owner = PSID::default();
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        let status = unsafe {
            GetSecurityInfo(
                HANDLE(file.as_raw_handle()),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION,
                Some(&mut owner),
                None,
                None,
                None,
                Some(&mut descriptor),
            )
        };
        if status != ERROR_SUCCESS {
            return Err(SessionTokenReadError::Inspect(
                io::Error::from_raw_os_error(status.0 as i32),
            ));
        }
        let _descriptor = LocalSecurityDescriptor(descriptor);
        if unsafe { EqualSid(owner, token_user.User.Sid) }.is_err() {
            return Err(SessionTokenReadError::OwnerMismatch);
        }
        Ok(())
    }

    fn read_bounded(file: &mut File) -> Result<Vec<u8>, SessionTokenReadError> {
        let mut bytes = Vec::with_capacity(super::SESSION_TOKEN_BYTES + 1);
        file.take((super::SESSION_TOKEN_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(SessionTokenReadError::Open)?;
        Ok(bytes)
    }

    fn current_process_token() -> io::Result<OwnedHandle> {
        let mut token = HANDLE::default();
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }
            .map_err(windows_error)?;
        Ok(OwnedHandle(token))
    }

    fn current_user_sid(token: HANDLE) -> io::Result<Vec<usize>> {
        let mut required = 0_u32;
        let _ = unsafe { GetTokenInformation(token, TokenUser, None, 0, &mut required) };
        if required == 0 {
            return Err(windows_error(WindowsError::from_win32()));
        }
        let mut buffer = vec![0_usize; (required as usize).div_ceil(size_of::<usize>())];
        unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                Some(buffer.as_mut_ptr().cast()),
                required,
                &mut required,
            )
        }
        .map_err(windows_error)?;
        Ok(buffer)
    }

    fn wide_nul(value: &OsStr) -> io::Result<Vec<u16>> {
        let mut wide = value.encode_wide().collect::<Vec<_>>();
        if wide.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "runtime path contains an interior NUL",
            ));
        }
        wide.push(0);
        Ok(wide)
    }

    fn windows_error(error: WindowsError) -> io::Error {
        let value = error.code().0 as u32;
        if value & 0xFFFF_0000 == 0x8007_0000 {
            io::Error::from_raw_os_error((value & 0xFFFF) as i32)
        } else {
            io::Error::other(error.to_string())
        }
    }

    struct OwnedHandle(HANDLE);

    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            let _ = unsafe { CloseHandle(self.0) };
        }
    }

    struct KnownFolderPath(PWSTR);

    impl Drop for KnownFolderPath {
        fn drop(&mut self) {
            unsafe { CoTaskMemFree(Some(self.0.0.cast())) };
        }
    }

    struct LocalSecurityDescriptor(PSECURITY_DESCRIPTOR);

    impl Drop for LocalSecurityDescriptor {
        fn drop(&mut self) {
            let _ = unsafe { LocalFree(Some(HLOCAL(self.0.0))) };
        }
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use std::ffi::CString;
    use std::fs::File;
    use std::io::{self, Read};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::MetadataExt;
    use std::path::{Path, PathBuf};

    use super::SessionTokenReadError;

    pub(super) fn current_user_runtime_root() -> io::Result<PathBuf> {
        let identity = crate::macos_socket::CurrentMacOsIdentity::for_current_process()
            .map_err(io::Error::other)?;
        identity
            .endpoint()
            .as_path()
            .parent()
            .map(Path::to_path_buf)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "socket has no parent"))
    }

    pub(super) fn read_token(root: &Path) -> Result<Vec<u8>, SessionTokenReadError> {
        let expected_uid = unsafe { libc::geteuid() };
        let directory = open_directory(root).map_err(SessionTokenReadError::Open)?;
        let metadata = directory
            .metadata()
            .map_err(SessionTokenReadError::Inspect)?;
        validate_metadata(&metadata, true, expected_uid, 0o700)?;

        let name = CString::new("session.token").expect("static token name contains no NUL");
        let file = loop {
            let fd = unsafe {
                libc::openat(
                    directory.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd >= 0 {
                break unsafe { File::from_raw_fd(fd) };
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(SessionTokenReadError::Open(error));
            }
        };
        let metadata = file.metadata().map_err(SessionTokenReadError::Inspect)?;
        validate_metadata(&metadata, false, expected_uid, 0o600)?;
        if metadata.nlink() != 1 {
            return Err(SessionTokenReadError::UnsafeType);
        }
        read_bounded(file)
    }

    fn open_directory(path: &Path) -> io::Result<File> {
        loop {
            let path = CString::new(path.as_os_str().as_encoded_bytes()).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "runtime path contains a NUL")
            })?;
            let fd = unsafe {
                libc::open(
                    path.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd >= 0 {
                return Ok(unsafe { File::from_raw_fd(fd) });
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }

    fn validate_metadata(
        metadata: &std::fs::Metadata,
        directory: bool,
        expected_uid: libc::uid_t,
        expected_mode: u32,
    ) -> Result<(), SessionTokenReadError> {
        if metadata.is_dir() != directory || metadata.is_file() == directory {
            return Err(SessionTokenReadError::UnsafeType);
        }
        if metadata.uid() != expected_uid {
            return Err(SessionTokenReadError::OwnerMismatch);
        }
        if metadata.mode() & 0o777 != expected_mode {
            return Err(SessionTokenReadError::UnsafePermissions);
        }
        Ok(())
    }

    fn read_bounded(file: File) -> Result<Vec<u8>, SessionTokenReadError> {
        let mut bytes = Vec::with_capacity(super::SESSION_TOKEN_BYTES + 1);
        file.take((super::SESSION_TOKEN_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(SessionTokenReadError::Open)?;
        Ok(bytes)
    }
}
