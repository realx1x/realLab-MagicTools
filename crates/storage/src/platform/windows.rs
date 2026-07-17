use std::ffi::{OsStr, OsString, c_void};
use std::fs::File;
use std::io;
use std::mem::size_of;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::{Component, Path, PathBuf, Prefix};
use std::ptr::null_mut;

use windows::Win32::Foundation::{
    CloseHandle, ERROR_ALREADY_EXISTS, ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, ERROR_SUCCESS,
    HANDLE, HLOCAL, LocalFree, WIN32_ERROR,
};
use windows::Win32::Security::Authorization::{
    EXPLICIT_ACCESS_W, GetSecurityInfo, NO_MULTIPLE_TRUSTEE, SE_FILE_OBJECT, SET_ACCESS,
    SetEntriesInAclW, SetSecurityInfo, TRUSTEE_IS_SID, TRUSTEE_IS_USER, TRUSTEE_W,
};
use windows::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION, AclSizeInformation,
    DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetAclInformation, GetLengthSid,
    GetSecurityDescriptorControl, GetTokenInformation, InitializeSecurityDescriptor, IsValidAcl,
    IsValidSid, NO_INHERITANCE, OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED, SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR,
    SUB_CONTAINERS_AND_OBJECTS_INHERIT, SetSecurityDescriptorControl, SetSecurityDescriptorDacl,
    TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CREATE_NEW, CreateDirectoryW, CreateFileW, DELETE, FILE_ALL_ACCESS,
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_DISPOSITION_INFO, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TYPE_DISK, FileDispositionInfo, GetDriveTypeW,
    GetFileInformationByHandle, GetFileType, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    MoveFileExW, OPEN_ALWAYS, OPEN_EXISTING, READ_CONTROL, SetFileInformationByHandle, WRITE_DAC,
};
use windows::Win32::System::Com::CoTaskMemFree;
use windows::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::Win32::System::WindowsProgramming::DRIVE_FIXED;
use windows::Win32::UI::Shell::{FOLDERID_LocalAppData, KF_FLAG_DEFAULT, SHGetKnownFolderPath};
use windows::core::{BOOL, Error as WindowsError, PCWSTR, PWSTR};

use crate::database_path::DatabaseArtifact;

const APPLICATION_DIRECTORY: &str = "DevProcessManager";
const DATA_DIRECTORY: &str = "data";
const DATABASE_FILE_NAME: &str = "supervisor.sqlite3";
const SECURITY_DESCRIPTOR_REVISION: u32 = 1;

pub(super) fn prepare_private_database_root() -> io::Result<PathBuf> {
    let root = expected_database_root()?;
    if !is_local_disk_path(&root) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the private database directory is not on a local disk",
        ));
    }
    let application_root = root.parent().ok_or_else(invalid_database_root)?;
    create_private_directory(application_root)?;
    secure_private_directory(application_root)?;
    create_private_directory(&root)?;
    secure_private_directory(&root)?;
    Ok(root)
}

pub(super) fn validate_private_database_root(root: &Path) -> io::Result<()> {
    if root != expected_database_root()? || !is_local_disk_path(root) {
        return Err(invalid_database_root());
    }
    let application_root = root.parent().ok_or_else(invalid_database_root)?;
    validate_private_directory(application_root)?;
    validate_private_directory(root)
}

pub(super) fn harden_existing_database_files(root: &Path, database: &Path) -> io::Result<()> {
    validate_database_file_path(root, database)?;
    validate_private_database_root(root)?;
    for artifact in DatabaseArtifact::RECOVERY_FILES {
        let path = artifact_path(root, artifact);
        if let Some(file) = open_optional_file(&path)? {
            validate_current_user_owner(&file)?;
            apply_current_user_dacl(&file, false)?;
            validate_private_current_user_acl(&file)?;
        }
    }
    validate_private_database_root(root)
}

pub(super) fn inspect_database_artifact(
    root: &Path,
    artifact: DatabaseArtifact,
) -> io::Result<Option<u64>> {
    validate_private_database_root(root)?;
    open_database_artifact_file(root, artifact)?
        .map(|file| file.metadata().map(|metadata| metadata.len()))
        .transpose()
}

pub(super) fn open_database_artifact(
    root: &Path,
    artifact: DatabaseArtifact,
) -> io::Result<Option<File>> {
    validate_private_database_root(root)?;
    open_database_artifact_file(root, artifact)
}

pub(super) fn create_database_artifact(
    root: &Path,
    artifact: DatabaseArtifact,
) -> io::Result<File> {
    validate_private_database_root(root)?;
    let path = artifact_path(root, artifact);
    let acl = current_user_acl(false)?;
    let mut descriptor = security_descriptor(&acl)?;
    let attributes = security_attributes(&mut descriptor);
    let path = wide_nul(path.as_os_str())?;
    let access = (FILE_GENERIC_READ | FILE_GENERIC_WRITE | READ_CONTROL | WRITE_DAC).0;
    let handle = unsafe {
        CreateFileW(
            PCWSTR(path.as_ptr()),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            Some(&attributes),
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    }
    .map_err(windows_error)?;
    let file = unsafe { File::from_raw_handle(handle.0) };
    validate_handle(&file, false)?;
    validate_current_user_owner(&file)?;
    apply_current_user_dacl(&file, false)?;
    validate_private_current_user_acl(&file)?;
    Ok(file)
}

pub(super) fn validate_database_artifact_identity(
    root: &Path,
    artifact: DatabaseArtifact,
    expected: &File,
) -> io::Result<()> {
    validate_private_database_root(root)?;
    validate_handle(expected, false)?;
    validate_current_user_owner(expected)?;
    validate_private_current_user_acl(expected)?;
    let current = open_database_artifact_file(root, artifact)?
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "a database artifact is missing"))?;
    validate_same_file(expected, &current)
}

pub(super) fn remove_database_artifact(root: &Path, artifact: DatabaseArtifact) -> io::Result<()> {
    validate_private_database_root(root)?;
    let path = artifact_path(root, artifact);
    let path_wide = wide_nul(path.as_os_str())?;
    let access = (FILE_READ_ATTRIBUTES | READ_CONTROL | DELETE).0;
    let handle = match unsafe {
        CreateFileW(
            PCWSTR(path_wide.as_ptr()),
            access,
            windows::Win32::Storage::FileSystem::FILE_SHARE_MODE(0),
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    } {
        Ok(handle) => handle,
        Err(error) => {
            let error = windows_error(error);
            if is_not_found(&error) {
                return Ok(());
            }
            return Err(error);
        }
    };
    let file = unsafe { File::from_raw_handle(handle.0) };
    validate_handle(&file, false)?;
    validate_current_user_owner(&file)?;
    validate_private_current_user_acl(&file)?;
    let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
    unsafe {
        SetFileInformationByHandle(
            HANDLE(file.as_raw_handle()),
            FileDispositionInfo,
            (&raw const disposition).cast::<c_void>(),
            size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    }
    .map_err(windows_error)
}

pub(super) fn discard_sqlite_database_artifact(
    root: &Path,
    artifact: DatabaseArtifact,
) -> io::Result<()> {
    validate_private_database_root(root)?;
    let path = artifact_path(root, artifact);
    let path_wide = wide_nul(path.as_os_str())?;
    let access =
        (FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_READ_ATTRIBUTES | READ_CONTROL | DELETE).0;
    let handle = match unsafe {
        CreateFileW(
            PCWSTR(path_wide.as_ptr()),
            access,
            windows::Win32::Storage::FileSystem::FILE_SHARE_MODE(0),
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    } {
        Ok(handle) => handle,
        Err(error) => {
            let error = windows_error(error);
            if is_not_found(&error) {
                return Ok(());
            }
            return Err(error);
        }
    };
    let file = unsafe { File::from_raw_handle(handle.0) };
    validate_handle(&file, false)?;
    validate_current_user_owner(&file)?;
    validate_private_current_user_acl(&file)?;
    file.set_len(0)?;
    file.sync_all()?;
    let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
    unsafe {
        SetFileInformationByHandle(
            HANDLE(file.as_raw_handle()),
            FileDispositionInfo,
            (&raw const disposition).cast::<c_void>(),
            size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    }
    .map_err(windows_error)
}

pub(super) fn replace_database_artifact_if_exists(
    root: &Path,
    source: DatabaseArtifact,
    destination: DatabaseArtifact,
) -> io::Result<()> {
    validate_private_database_root(root)?;
    let Some(expected) = open_database_artifact_file(root, source)? else {
        return Ok(());
    };
    replace_database_artifact(root, source, destination, &expected)
}

pub(super) fn replace_database_artifact_required(
    root: &Path,
    source: DatabaseArtifact,
    destination: DatabaseArtifact,
    expected: &File,
) -> io::Result<()> {
    validate_private_database_root(root)?;
    replace_database_artifact(root, source, destination, expected)
}

pub(super) fn sync_database_root(root: &Path) -> io::Result<()> {
    validate_private_database_root(root)
}

pub(super) fn acquire_database_repository_lock(root: &Path) -> io::Result<File> {
    validate_private_database_root(root)?;
    let path = artifact_path(root, DatabaseArtifact::MigrationLock);
    let acl = current_user_acl(false)?;
    let mut descriptor = security_descriptor(&acl)?;
    let attributes = security_attributes(&mut descriptor);
    let path = wide_nul(path.as_os_str())?;
    let access = (FILE_GENERIC_READ | FILE_GENERIC_WRITE | READ_CONTROL | WRITE_DAC).0;
    let handle = unsafe {
        CreateFileW(
            PCWSTR(path.as_ptr()),
            access,
            windows::Win32::Storage::FileSystem::FILE_SHARE_MODE(0),
            Some(&attributes),
            OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    }
    .map_err(windows_error)?;
    let file = unsafe { File::from_raw_handle(handle.0) };
    validate_handle(&file, false)?;
    validate_current_user_owner(&file)?;
    apply_current_user_dacl(&file, false)?;
    validate_private_current_user_acl(&file)?;
    file.set_len(0)?;
    file.sync_all()?;
    Ok(file)
}

fn expected_database_root() -> io::Result<PathBuf> {
    let local_app_data =
        unsafe { SHGetKnownFolderPath(&FOLDERID_LocalAppData, KF_FLAG_DEFAULT, None) }
            .map_err(windows_error)?;
    let local_app_data = KnownFolderPath(local_app_data);
    let local_app_data = PathBuf::from(OsString::from_wide(unsafe { local_app_data.0.as_wide() }));
    if !local_app_data.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the current-user Local AppData directory is not absolute",
        ));
    }
    Ok(local_app_data
        .join(APPLICATION_DIRECTORY)
        .join(DATA_DIRECTORY))
}

fn validate_database_file_path(root: &Path, database: &Path) -> io::Result<()> {
    if database.parent() != Some(root)
        || database.file_name() != Some(OsStr::new(DATABASE_FILE_NAME))
    {
        return Err(invalid_database_root());
    }
    Ok(())
}

fn artifact_path(root: &Path, artifact: DatabaseArtifact) -> PathBuf {
    root.join(artifact.file_name())
}

fn open_database_artifact_file(
    root: &Path,
    artifact: DatabaseArtifact,
) -> io::Result<Option<File>> {
    let path = artifact_path(root, artifact);
    let Some(file) = open_optional_file_read_only(&path)? else {
        return Ok(None);
    };
    validate_current_user_owner(&file)?;
    validate_private_current_user_acl(&file)?;
    Ok(Some(file))
}

fn open_optional_file_read_only(path: &Path) -> io::Result<Option<File>> {
    let path = wide_nul(path.as_os_str())?;
    let access = (FILE_GENERIC_READ | READ_CONTROL).0;
    let handle = match unsafe {
        CreateFileW(
            PCWSTR(path.as_ptr()),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    } {
        Ok(handle) => handle,
        Err(error) => {
            let error = windows_error(error);
            if is_not_found(&error) {
                return Ok(None);
            }
            return Err(error);
        }
    };
    let file = unsafe { File::from_raw_handle(handle.0) };
    validate_handle(&file, false)?;
    Ok(Some(file))
}

fn replace_database_artifact(
    root: &Path,
    source: DatabaseArtifact,
    destination: DatabaseArtifact,
    expected: &File,
) -> io::Result<()> {
    validate_database_artifact_identity(root, source, expected)?;
    let _ = open_database_artifact_file(root, destination)?;
    let source_path = artifact_path(root, source);
    let destination_path = artifact_path(root, destination);
    let source_wide = wide_nul(source_path.as_os_str())?;
    let destination_wide = wide_nul(destination_path.as_os_str())?;
    unsafe {
        MoveFileExW(
            PCWSTR(source_wide.as_ptr()),
            PCWSTR(destination_wide.as_ptr()),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    }
    .map_err(windows_error)?;
    let published = open_database_artifact_file(root, destination)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "a published database artifact is missing",
        )
    })?;
    validate_same_file(expected, &published)
}

fn validate_same_file(expected: &File, current: &File) -> io::Result<()> {
    if file_identity(expected)? == file_identity(current)? {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "a database artifact identity changed",
        ))
    }
}

fn file_identity(file: &File) -> io::Result<(u32, u32, u32)> {
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    unsafe { GetFileInformationByHandle(HANDLE(file.as_raw_handle()), &mut information) }
        .map_err(windows_error)?;
    Ok((
        information.dwVolumeSerialNumber,
        information.nFileIndexHigh,
        information.nFileIndexLow,
    ))
}

fn is_not_found(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(code)
            if code == ERROR_FILE_NOT_FOUND.0 as i32 || code == ERROR_PATH_NOT_FOUND.0 as i32
    )
}

fn is_local_disk_path(path: &Path) -> bool {
    local_volume_serial(path).is_ok()
}

fn local_volume_serial(path: &Path) -> io::Result<u32> {
    let Some(Component::Prefix(prefix)) = path.components().next() else {
        return Err(invalid_database_root());
    };
    let Prefix::Disk(letter) = prefix.kind() else {
        return Err(invalid_database_root());
    };
    let root = [u16::from(letter), u16::from(b':'), u16::from(b'\\'), 0];
    if unsafe { GetDriveTypeW(PCWSTR(root.as_ptr())) } != DRIVE_FIXED {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the private database directory is not on a fixed local disk",
        ));
    }
    let handle = unsafe {
        CreateFileW(
            PCWSTR(root.as_ptr()),
            FILE_READ_ATTRIBUTES.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    }
    .map_err(windows_error)?;
    let volume = unsafe { File::from_raw_handle(handle.0) };
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    unsafe { GetFileInformationByHandle(HANDLE(volume.as_raw_handle()), &mut information) }
        .map_err(windows_error)?;
    if information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
        || information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 == 0
        || unsafe { GetFileType(HANDLE(volume.as_raw_handle())) } != FILE_TYPE_DISK
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the private database volume root is invalid",
        ));
    }
    Ok(information.dwVolumeSerialNumber)
}

fn create_private_directory(path: &Path) -> io::Result<()> {
    let acl = current_user_acl(true)?;
    let mut descriptor = security_descriptor(&acl)?;
    let attributes = security_attributes(&mut descriptor);
    let path = wide_nul(path.as_os_str())?;
    match unsafe { CreateDirectoryW(PCWSTR(path.as_ptr()), Some(&attributes)) } {
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

fn secure_private_directory(path: &Path) -> io::Result<()> {
    let directory = open_directory(path, true)?;
    validate_current_user_owner(&directory)?;
    apply_current_user_dacl(&directory, true)?;
    validate_private_current_user_acl(&directory)
}

fn validate_private_directory(path: &Path) -> io::Result<()> {
    let directory = open_directory(path, true)?;
    validate_current_user_owner(&directory)?;
    validate_private_current_user_acl(&directory)
}

fn open_directory(path: &Path, writable_acl: bool) -> io::Result<File> {
    let path = wide_nul(path.as_os_str())?;
    let mut access = (FILE_READ_ATTRIBUTES | READ_CONTROL).0;
    if writable_acl {
        access |= WRITE_DAC.0;
    }
    let handle = unsafe {
        CreateFileW(
            PCWSTR(path.as_ptr()),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    }
    .map_err(windows_error)?;
    let directory = unsafe { File::from_raw_handle(handle.0) };
    validate_handle(&directory, true)?;
    Ok(directory)
}

fn open_optional_file(path: &Path) -> io::Result<Option<File>> {
    let path = wide_nul(path.as_os_str())?;
    let access = (FILE_READ_ATTRIBUTES | READ_CONTROL | WRITE_DAC).0;
    let handle = match unsafe {
        CreateFileW(
            PCWSTR(path.as_ptr()),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    } {
        Ok(handle) => handle,
        Err(error) => {
            let error = windows_error(error);
            if matches!(
                error.raw_os_error(),
                Some(code)
                    if code == ERROR_FILE_NOT_FOUND.0 as i32
                        || code == ERROR_PATH_NOT_FOUND.0 as i32
            ) {
                return Ok(None);
            }
            return Err(error);
        }
    };
    let file = unsafe { File::from_raw_handle(handle.0) };
    validate_handle(&file, false)?;
    Ok(Some(file))
}

fn validate_handle(file: &File, expected_directory: bool) -> io::Result<()> {
    let handle = HANDLE(file.as_raw_handle());
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    unsafe { GetFileInformationByHandle(handle, &mut information) }.map_err(windows_error)?;
    if information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "a private database path is a reparse point",
        ));
    }
    let is_directory = information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0;
    if is_directory != expected_directory || unsafe { GetFileType(handle) } != FILE_TYPE_DISK {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "a private database path has an invalid file type",
        ));
    }
    if !expected_directory && information.nNumberOfLinks != 1 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "a private database file has multiple hard links",
        ));
    }
    let expected_volume = local_volume_serial(&expected_database_root()?)?;
    if information.dwVolumeSerialNumber != expected_volume {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "a private database path crossed onto another file system",
        ));
    }
    Ok(())
}

fn validate_private_current_user_acl(file: &File) -> io::Result<()> {
    let token = current_process_token()?;
    let sid_buffer = current_user_sid(token.raw())?;
    let token_user = unsafe { &*(sid_buffer.as_ptr().cast::<TOKEN_USER>()) };
    let mut owner = PSID::default();
    let mut dacl = null_mut::<ACL>();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    let status = unsafe {
        GetSecurityInfo(
            HANDLE(file.as_raw_handle()),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            Some(&mut owner),
            None,
            Some(&mut dacl),
            None,
            Some(&mut descriptor),
        )
    };
    if status != ERROR_SUCCESS {
        return Err(win32_status_error(status));
    }
    let _descriptor = LocalSecurityDescriptor(descriptor);
    if unsafe { EqualSid(owner, token_user.User.Sid) }.is_err()
        || dacl.is_null()
        || !unsafe { IsValidAcl(dacl) }.as_bool()
    {
        return Err(private_acl_error());
    }

    let mut control = 0_u16;
    let mut revision = 0_u32;
    unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) }
        .map_err(windows_error)?;
    if control & SE_DACL_PROTECTED.0 == 0 {
        return Err(private_acl_error());
    }

    let mut information = ACL_SIZE_INFORMATION::default();
    unsafe {
        GetAclInformation(
            dacl,
            (&mut information as *mut ACL_SIZE_INFORMATION).cast(),
            size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    }
    .map_err(windows_error)?;
    if information.AceCount == 0 {
        return Err(private_acl_error());
    }

    for index in 0..information.AceCount {
        let mut raw_ace = null_mut::<c_void>();
        unsafe { GetAce(dacl, index, &mut raw_ace) }.map_err(windows_error)?;
        if raw_ace.is_null() {
            return Err(private_acl_error());
        }
        let header = unsafe { &*raw_ace.cast::<ACE_HEADER>() };
        if u32::from(header.AceType) != ACCESS_ALLOWED_ACE_TYPE {
            return Err(private_acl_error());
        }
        let sid_offset = std::mem::offset_of!(ACCESS_ALLOWED_ACE, SidStart);
        let ace_size = usize::from(header.AceSize);
        if ace_size < sid_offset + 8 {
            return Err(private_acl_error());
        }
        let sid_pointer = unsafe { raw_ace.cast::<u8>().add(sid_offset) };
        let sub_authority_count = usize::from(unsafe { *sid_pointer.add(1) });
        let sid_length = 8_usize
            .checked_add(
                sub_authority_count
                    .checked_mul(4)
                    .ok_or_else(private_acl_error)?,
            )
            .ok_or_else(private_acl_error)?;
        if sid_offset
            .checked_add(sid_length)
            .is_none_or(|required| required > ace_size)
        {
            return Err(private_acl_error());
        }
        let sid = PSID(sid_pointer.cast());
        if !unsafe { IsValidSid(sid) }.as_bool()
            || unsafe { GetLengthSid(sid) } as usize != sid_length
            || unsafe { EqualSid(sid, token_user.User.Sid) }.is_err()
        {
            return Err(private_acl_error());
        }
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
            "a private database path is not owned by the current user",
        ));
    }
    Ok(())
}

fn apply_current_user_dacl(file: &File, directory: bool) -> io::Result<()> {
    let acl = current_user_acl(directory)?;
    let status = unsafe {
        SetSecurityInfo(
            HANDLE(file.as_raw_handle()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(acl.0),
            None,
        )
    };
    if status == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(win32_status_error(status))
    }
}

fn current_user_acl(directory: bool) -> io::Result<LocalAcl> {
    let token = current_process_token()?;
    let sid_buffer = current_user_sid(token.raw())?;
    let token_user = unsafe { &*(sid_buffer.as_ptr().cast::<TOKEN_USER>()) };
    let access = EXPLICIT_ACCESS_W {
        grfAccessPermissions: FILE_ALL_ACCESS.0,
        grfAccessMode: SET_ACCESS,
        grfInheritance: if directory {
            SUB_CONTAINERS_AND_OBJECTS_INHERIT
        } else {
            NO_INHERITANCE
        },
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
            "a private database path contains an interior NUL",
        ));
    }
    wide.push(0);
    Ok(wide)
}

fn invalid_database_root() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "the database path is outside the fixed current-user data root",
    )
}

fn private_acl_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "a private database path is not restricted to the current user",
    )
}

fn windows_error(error: WindowsError) -> io::Error {
    let value = error.code().0 as u32;
    if value & 0xFFFF_0000 == 0x8007_0000 {
        io::Error::from_raw_os_error((value & 0xFFFF) as i32)
    } else {
        io::Error::other("Windows private-database API failure")
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
