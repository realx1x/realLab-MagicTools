use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io;
use std::mem::size_of;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::{Path, PathBuf};
use std::ptr::null_mut;

use windows::Win32::Foundation::{
    CloseHandle, ERROR_ALREADY_EXISTS, ERROR_SUCCESS, HANDLE, HLOCAL, LocalFree, WIN32_ERROR,
};
use windows::Win32::Security::Authorization::{
    EXPLICIT_ACCESS_W, GetSecurityInfo, NO_MULTIPLE_TRUSTEE, SE_FILE_OBJECT, SET_ACCESS,
    SetEntriesInAclW, SetSecurityInfo, TRUSTEE_IS_SID, TRUSTEE_IS_USER, TRUSTEE_W,
};
use windows::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, EqualSid, GetTokenInformation, InitializeSecurityDescriptor,
    NO_INHERITANCE, OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED, SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR,
    SUB_CONTAINERS_AND_OBJECTS_INHERIT, SetSecurityDescriptorControl, SetSecurityDescriptorDacl,
    TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CreateDirectoryW, CreateFileW, FILE_ALL_ACCESS,
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ,
    FILE_GENERIC_WRITE, FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TYPE_DISK,
    GetFileInformationByHandle, GetFileType, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    MoveFileExW, OPEN_ALWAYS, OPEN_EXISTING, READ_CONTROL, WRITE_DAC,
};
use windows::Win32::System::Com::CoTaskMemFree;
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::Win32::UI::Shell::{FOLDERID_LocalAppData, KF_FLAG_DEFAULT, SHGetKnownFolderPath};
use windows::core::{BOOL, Error as WindowsError, PCWSTR, PWSTR};

const SECURITY_DESCRIPTOR_REVISION: u32 = 1;

pub(super) fn current_user_runtime_root() -> io::Result<PathBuf> {
    let local_app_data =
        unsafe { SHGetKnownFolderPath(&FOLDERID_LocalAppData, KF_FLAG_DEFAULT, None) }
            .map_err(windows_error)?;
    let local_app_data = KnownFolderPath(local_app_data);
    let local_app_data = PathBuf::from(OsString::from_wide(unsafe { local_app_data.0.as_wide() }));
    if !local_app_data.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the Local AppData known folder is not absolute",
        ));
    }
    let identity = protocol::windows_pipe::CurrentWindowsIdentity::for_current_process()
        .map_err(io::Error::other)?;
    Ok(local_app_data
        .join("DevProcessManager")
        .join(format!("session-{}", identity.session_id()))
        .join("runtime"))
}

pub(super) fn prepare_runtime_directory(path: &Path) -> io::Result<()> {
    let session_root = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "runtime directory has no session parent",
        )
    })?;
    let application_root = session_root.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "session directory has no application parent",
        )
    })?;

    create_private_directory(application_root)?;
    secure_directory_handle(application_root)?;
    create_private_directory(session_root)?;
    secure_directory_handle(session_root)?;
    create_private_directory(path)?;
    secure_directory_handle(path)
}

pub(super) fn open_private_file(path: &Path, truncate: bool) -> io::Result<File> {
    let acl = current_user_acl(false)?;
    let mut descriptor = security_descriptor(&acl)?;
    let attributes = security_attributes(&mut descriptor);
    let wide_path = wide_nul(path.as_os_str())?;
    let access = (FILE_GENERIC_READ | FILE_GENERIC_WRITE | READ_CONTROL | WRITE_DAC).0;
    let share = FILE_SHARE_READ | FILE_SHARE_WRITE;
    let flags = FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT;
    let handle = unsafe {
        CreateFileW(
            PCWSTR(wide_path.as_ptr()),
            access,
            share,
            Some(&attributes),
            OPEN_ALWAYS,
            flags,
            None,
        )
    }
    .map_err(windows_error)?;
    let file = unsafe { File::from_raw_handle(handle.0) };
    validate_handle(&file, false)?;
    validate_current_user_owner(&file)?;
    apply_current_user_dacl(&file, false)?;
    if truncate {
        file.set_len(0)?;
    }
    Ok(file)
}

pub(super) fn atomic_replace(source: &Path, destination: &Path) -> io::Result<()> {
    let source = wide_nul(source.as_os_str())?;
    let destination = wide_nul(destination.as_os_str())?;
    unsafe {
        MoveFileExW(
            PCWSTR(source.as_ptr()),
            PCWSTR(destination.as_ptr()),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    }
    .map_err(windows_error)
}

fn create_private_directory(path: &Path) -> io::Result<()> {
    let acl = current_user_acl(true)?;
    let mut descriptor = security_descriptor(&acl)?;
    let attributes = security_attributes(&mut descriptor);
    let wide_path = wide_nul(path.as_os_str())?;
    match unsafe { CreateDirectoryW(PCWSTR(wide_path.as_ptr()), Some(&attributes)) } {
        Ok(()) => Ok(()),
        Err(error) => {
            let error = windows_error(error);
            if error.raw_os_error() == Some(ERROR_ALREADY_EXISTS.0 as i32) {
                Ok(())
            } else {
                Err(error)
            }
        }
    }
}

fn secure_directory_handle(path: &Path) -> io::Result<()> {
    let wide_path = wide_nul(path.as_os_str())?;
    let access = (FILE_READ_ATTRIBUTES | READ_CONTROL | WRITE_DAC).0;
    let share = FILE_SHARE_READ | FILE_SHARE_WRITE;
    let flags = FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT;
    let handle = unsafe {
        CreateFileW(
            PCWSTR(wide_path.as_ptr()),
            access,
            share,
            None,
            OPEN_EXISTING,
            flags,
            None,
        )
    }
    .map_err(windows_error)?;
    let directory = unsafe { File::from_raw_handle(handle.0) };
    validate_handle(&directory, true)?;
    validate_current_user_owner(&directory)?;
    apply_current_user_dacl(&directory, true)
}

fn validate_handle(file: &File, expected_directory: bool) -> io::Result<()> {
    let handle = HANDLE(file.as_raw_handle());
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    unsafe { GetFileInformationByHandle(handle, &mut information) }.map_err(windows_error)?;

    let attributes = information.dwFileAttributes;
    if attributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "sensitive path is a reparse point",
        ));
    }
    let is_directory = attributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0;
    if is_directory != expected_directory || unsafe { GetFileType(handle) } != FILE_TYPE_DISK {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            if expected_directory {
                "sensitive path is not a regular directory"
            } else {
                "sensitive path is not a regular file"
            },
        ));
    }
    Ok(())
}

fn apply_current_user_dacl(file: &File, directory: bool) -> io::Result<()> {
    let acl = current_user_acl(directory)?;
    let security_information = DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION;
    let status = unsafe {
        SetSecurityInfo(
            HANDLE(file.as_raw_handle()),
            SE_FILE_OBJECT,
            security_information,
            None,
            None,
            Some(acl.0),
            None,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(win32_status_error(status));
    }
    Ok(())
}

fn validate_current_user_owner(file: &File) -> io::Result<()> {
    let token = current_process_token()?;
    let sid_buffer = current_user_sid(token.raw())?;
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
        return Err(win32_status_error(status));
    }
    let _descriptor = LocalSecurityDescriptor(descriptor);
    if unsafe { EqualSid(owner, token_user.User.Sid) }.is_err() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "sensitive path is not owned by the current user",
        ));
    }
    Ok(())
}

fn current_user_acl(directory: bool) -> io::Result<LocalAcl> {
    let token = current_process_token()?;
    let sid_buffer = current_user_sid(token.raw())?;
    let token_user = unsafe { &*(sid_buffer.as_ptr().cast::<TOKEN_USER>()) };
    let inheritance = if directory {
        SUB_CONTAINERS_AND_OBJECTS_INHERIT
    } else {
        NO_INHERITANCE
    };
    let access = EXPLICIT_ACCESS_W {
        grfAccessPermissions: FILE_ALL_ACCESS.0,
        grfAccessMode: SET_ACCESS,
        grfInheritance: inheritance,
        Trustee: TRUSTEE_W {
            pMultipleTrustee: null_mut(),
            MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_USER,
            ptstrName: PWSTR(token_user.User.Sid.0.cast()),
        },
    };

    let mut acl = null_mut::<ACL>();
    let status = unsafe { SetEntriesInAclW(Some(&[access]), None, &mut acl) };
    if status != ERROR_SUCCESS {
        return Err(win32_status_error(status));
    }
    Ok(LocalAcl(acl))
}

fn security_descriptor(acl: &LocalAcl) -> io::Result<SECURITY_DESCRIPTOR> {
    let mut descriptor = SECURITY_DESCRIPTOR::default();
    let pointer = PSECURITY_DESCRIPTOR((&mut descriptor as *mut SECURITY_DESCRIPTOR).cast());
    unsafe { InitializeSecurityDescriptor(pointer, SECURITY_DESCRIPTOR_REVISION) }
        .map_err(windows_error)?;
    unsafe { SetSecurityDescriptorDacl(pointer, true, Some(acl.0), false) }
        .map_err(windows_error)?;
    unsafe { SetSecurityDescriptorControl(pointer, SE_DACL_PROTECTED, SE_DACL_PROTECTED) }
        .map_err(windows_error)?;
    Ok(descriptor)
}

fn security_attributes(descriptor: &mut SECURITY_DESCRIPTOR) -> SECURITY_ATTRIBUTES {
    SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: (descriptor as *mut SECURITY_DESCRIPTOR).cast(),
        bInheritHandle: BOOL(0),
    }
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

    let word_count = (required as usize).div_ceil(size_of::<usize>());
    let mut buffer = vec![0_usize; word_count];
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
            "path contains an interior NUL",
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

fn win32_status_error(status: WIN32_ERROR) -> io::Error {
    io::Error::from_raw_os_error(status.0 as i32)
}

struct OwnedHandle(HANDLE);

impl OwnedHandle {
    fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        let _ = unsafe { CloseHandle(self.0) };
    }
}

struct LocalAcl(*mut ACL);

impl Drop for LocalAcl {
    fn drop(&mut self) {
        let _ = unsafe { LocalFree(Some(HLOCAL(self.0.cast()))) };
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
