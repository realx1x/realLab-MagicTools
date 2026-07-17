use std::ffi::{OsStr, c_void};
use std::fs::File;
use std::io::{self, Seek, SeekFrom};
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
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
    BY_HANDLE_FILE_INFORMATION, CREATE_NEW, CreateDirectoryW, CreateFileW, DELETE, DeleteFileW,
    FILE_ALL_ACCESS, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_CREATION_DISPOSITION, FILE_DISPOSITION_INFO, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_READ_ATTRIBUTES,
    FILE_SHARE_DELETE, FILE_SHARE_MODE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TYPE_DISK,
    FileDispositionInfo, GetFileInformationByHandle, GetFileType, MOVEFILE_REPLACE_EXISTING,
    MOVEFILE_WRITE_THROUGH, MoveFileExW, OPEN_ALWAYS, OPEN_EXISTING, READ_CONTROL,
    SetFileInformationByHandle, WRITE_DAC,
};
use windows::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::core::{BOOL, Error as WindowsError, PCWSTR, PWSTR};

use crate::secure_directory::{
    map_io, validate_file_name, validate_log_root_path, validate_run_directory_path,
};
use crate::{LogError, LogErrorKind, LogOperation, LogStream};

const SECURITY_DESCRIPTOR_REVISION: u32 = 1;

pub(crate) struct SecureLogRoot {
    path: PathBuf,
    directory: File,
    identity: DirectoryIdentity,
}

impl SecureLogRoot {
    pub(crate) fn open(path: &Path) -> Result<Self, LogError> {
        validate_log_root_path(path)?;
        if !is_local_disk_path(path) {
            return Err(LogError::configuration(
                LogOperation::ValidateRetentionLogRoot,
                LogErrorKind::InvalidPath,
            ));
        }
        validate_directory_chain(path)
            .map_err(|error| map_io(None, LogOperation::ValidateRetentionLogRoot, &error))?;
        let directory = open_directory(path, false, (FILE_READ_ATTRIBUTES | READ_CONTROL).0)
            .map_err(|error| map_io(None, LogOperation::ValidateRetentionLogRoot, &error))?;
        validate_current_user_owner(&directory)
            .map_err(|error| map_io(None, LogOperation::ValidateRetentionLogRoot, &error))?;
        validate_private_current_user_directory(&directory)
            .map_err(|error| map_io(None, LogOperation::ValidateRetentionLogRoot, &error))?;
        let identity = directory_identity(&directory)
            .map_err(|error| map_io(None, LogOperation::ValidateRetentionLogRoot, &error))?;
        Ok(Self {
            path: path.to_owned(),
            directory,
            identity,
        })
    }

    pub(crate) fn open_run_existing(&self, run_id: &str) -> Result<SecureRunDirectory, LogError> {
        self.open_run(run_id, false)
    }

    pub(crate) fn open_run_for_retention(
        &self,
        run_id: &str,
    ) -> Result<SecureRunDirectory, LogError> {
        self.open_run(run_id, true)
    }

    fn open_run(&self, run_id: &str, for_retention: bool) -> Result<SecureRunDirectory, LogError> {
        validate_file_name(run_id)?;
        self.validate_path_identity()?;
        let path = self.path.join(run_id);
        let result = if for_retention {
            SecureRunDirectory::open_for_retention(&path)
        } else {
            SecureRunDirectory::open_existing(&path)
        };
        self.validate_path_identity()?;
        result
    }

    fn validate_path_identity(&self) -> Result<(), LogError> {
        validate_expected_directory_identity(&self.directory, self.identity)
            .map_err(|error| map_io(None, LogOperation::ValidateRetentionLogRoot, &error))?;
        let current = open_directory(&self.path, true, (FILE_READ_ATTRIBUTES | READ_CONTROL).0)
            .map_err(|error| map_io(None, LogOperation::ValidateRetentionLogRoot, &error))?;
        validate_current_user_owner(&current)
            .map_err(|error| map_io(None, LogOperation::ValidateRetentionLogRoot, &error))?;
        validate_private_current_user_directory(&current)
            .map_err(|error| map_io(None, LogOperation::ValidateRetentionLogRoot, &error))?;
        validate_expected_directory_identity(&current, self.identity)
            .map_err(|error| map_io(None, LogOperation::ValidateRetentionLogRoot, &error))
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct DirectoryIdentity {
    volume_serial_number: u32,
    file_index: u64,
}

pub(crate) struct SecureRunDirectory {
    path: PathBuf,
    _directory: File,
}

impl SecureRunDirectory {
    pub(crate) fn prepare(path: &Path) -> Result<Self, LogError> {
        validate_run_directory_path(path)?;
        validate_local_disk_path(path)?;
        let parent = path.parent().ok_or_else(|| {
            LogError::configuration(
                LogOperation::ValidateRunDirectory,
                LogErrorKind::InvalidPath,
            )
        })?;
        validate_directory_chain(parent)
            .map_err(|error| map_io(None, LogOperation::InspectRunDirectory, &error))?;
        validate_parent_owner(parent)
            .map_err(|error| map_io(None, LogOperation::InspectRunDirectory, &error))?;
        create_private_directory(path)
            .map_err(|error| map_io(None, LogOperation::CreateRunDirectory, &error))?;
        let directory = open_directory(
            path,
            false,
            (FILE_READ_ATTRIBUTES | READ_CONTROL | WRITE_DAC).0,
        )
        .map_err(|error| map_io(None, LogOperation::InspectRunDirectory, &error))?;
        validate_current_user_owner(&directory)
            .map_err(|error| map_io(None, LogOperation::SecureRunDirectory, &error))?;
        apply_current_user_dacl(&directory, true)
            .map_err(|error| map_io(None, LogOperation::SecureRunDirectory, &error))?;
        Ok(Self {
            path: path.to_owned(),
            _directory: directory,
        })
    }

    pub(crate) fn open_existing(path: &Path) -> Result<Self, LogError> {
        validate_run_directory_path(path)?;
        validate_local_disk_path(path)?;
        let parent = path.parent().ok_or_else(|| {
            LogError::configuration(
                LogOperation::ValidateRunDirectory,
                LogErrorKind::InvalidPath,
            )
        })?;
        validate_directory_chain(parent)
            .map_err(|error| map_io(None, LogOperation::InspectRunDirectory, &error))?;
        validate_parent_owner(parent)
            .map_err(|error| map_io(None, LogOperation::InspectRunDirectory, &error))?;
        let directory = open_directory(path, true, (FILE_READ_ATTRIBUTES | READ_CONTROL).0)
            .map_err(|error| map_io(None, LogOperation::InspectRunDirectory, &error))?;
        validate_current_user_owner(&directory)
            .map_err(|error| map_io(None, LogOperation::InspectRunDirectory, &error))?;
        validate_private_current_user_directory(&directory)
            .map_err(|error| map_io(None, LogOperation::InspectRunDirectory, &error))?;
        Ok(Self {
            path: path.to_owned(),
            _directory: directory,
        })
    }

    pub(crate) fn open_for_retention(path: &Path) -> Result<Self, LogError> {
        validate_run_directory_path(path)?;
        validate_local_disk_path(path)?;
        let parent = path.parent().ok_or_else(|| {
            LogError::configuration(
                LogOperation::ValidateRunDirectory,
                LogErrorKind::InvalidPath,
            )
        })?;
        validate_directory_chain(parent)
            .map_err(|error| map_io(None, LogOperation::InspectRunDirectory, &error))?;
        validate_parent_owner(parent)
            .map_err(|error| map_io(None, LogOperation::InspectRunDirectory, &error))?;
        let access = (FILE_READ_ATTRIBUTES | READ_CONTROL | DELETE).0;
        let directory = open_directory_exclusive(path, access)
            .map_err(|error| map_io(None, LogOperation::InspectRunDirectory, &error))?;
        validate_current_user_owner(&directory)
            .map_err(|error| map_io(None, LogOperation::InspectRunDirectory, &error))?;
        validate_private_current_user_directory(&directory)
            .map_err(|error| map_io(None, LogOperation::InspectRunDirectory, &error))?;
        Ok(Self {
            path: path.to_owned(),
            _directory: directory,
        })
    }

    pub(crate) fn open_file(
        &self,
        file_name: &str,
        truncate: bool,
        stream: Option<LogStream>,
        operation: LogOperation,
    ) -> Result<File, LogError> {
        validate_file_name(file_name)?;
        let path = self.path.join(file_name);
        let mut file = open_private_file(&path, OPEN_ALWAYS, FILE_SHARE_READ | FILE_SHARE_DELETE)
            .map_err(|error| map_io(stream, operation, &error))?;
        if truncate {
            file.set_len(0)
                .map_err(|error| map_io(stream, operation, &error))?;
        }
        file.seek(SeekFrom::End(0))
            .map_err(|error| map_io(stream, operation, &error))?;
        Ok(file)
    }

    pub(crate) fn open_existing_file(
        &self,
        file_name: &str,
        stream: Option<LogStream>,
        operation: LogOperation,
    ) -> Result<Option<File>, LogError> {
        validate_file_name(file_name)?;
        let path = self.path.join(file_name);
        let file = match open_private_file_read_only(&path) {
            Ok(file) => file,
            Err(error)
                if matches!(
                    error.raw_os_error(),
                    Some(code)
                        if code == ERROR_FILE_NOT_FOUND.0 as i32
                            || code == ERROR_PATH_NOT_FOUND.0 as i32
                ) =>
            {
                return Ok(None);
            }
            Err(error) => return Err(map_io(stream, operation, &error)),
        };
        Ok(Some(file))
    }

    pub(crate) fn create_new_file(
        &self,
        file_name: &str,
        stream: Option<LogStream>,
        operation: LogOperation,
    ) -> Result<File, LogError> {
        validate_file_name(file_name)?;
        let path = self.path.join(file_name);
        open_private_file(&path, CREATE_NEW, FILE_SHARE_READ | FILE_SHARE_DELETE)
            .map_err(|error| map_io(stream, operation, &error))
    }

    pub(crate) fn inspect_file(
        &self,
        file_name: &str,
        stream: Option<LogStream>,
        operation: LogOperation,
    ) -> Result<Option<u64>, LogError> {
        validate_file_name(file_name)?;
        let path = self.path.join(file_name);
        let file = match open_private_file(
            &path,
            OPEN_EXISTING,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        ) {
            Ok(file) => file,
            Err(error)
                if matches!(
                    error.raw_os_error(),
                    Some(code)
                        if code == ERROR_FILE_NOT_FOUND.0 as i32
                            || code == ERROR_PATH_NOT_FOUND.0 as i32
                ) =>
            {
                return Ok(None);
            }
            Err(error) => return Err(map_io(stream, operation, &error)),
        };
        file.metadata()
            .map(|metadata| Some(metadata.len()))
            .map_err(|error| map_io(stream, operation, &error))
    }

    pub(crate) fn remove_file_if_exists(
        &self,
        file_name: &str,
        stream: Option<LogStream>,
        operation: LogOperation,
    ) -> Result<(), LogError> {
        validate_file_name(file_name)?;
        if self.inspect_file(file_name, stream, operation)?.is_none() {
            return Ok(());
        }
        let path = wide_nul(self.path.join(file_name).as_os_str())
            .map_err(|error| map_io(stream, operation, &error))?;
        match unsafe { DeleteFileW(PCWSTR(path.as_ptr())) } {
            Ok(()) => Ok(()),
            Err(error) => {
                let error = windows_error(error);
                if matches!(
                    error.raw_os_error(),
                    Some(code)
                        if code == ERROR_FILE_NOT_FOUND.0 as i32
                            || code == ERROR_PATH_NOT_FOUND.0 as i32
                ) {
                    Ok(())
                } else {
                    Err(map_io(stream, operation, &error))
                }
            }
        }
    }

    pub(crate) fn remove_file_for_retention(
        &self,
        file_name: &str,
        stream: Option<LogStream>,
        operation: LogOperation,
    ) -> Result<Option<u64>, LogError> {
        validate_file_name(file_name)?;
        let path = self.path.join(file_name);
        let file = match open_private_file_for_deletion(&path) {
            Ok(file) => file,
            Err(error) if is_not_found(&error) => return Ok(None),
            Err(error) => return Err(map_io(stream, operation, &error)),
        };
        let length = file
            .metadata()
            .map_err(|error| map_io(stream, operation, &error))?
            .len();
        mark_handle_for_deletion(&file).map_err(|error| map_io(stream, operation, &error))?;
        Ok(Some(length))
    }

    pub(crate) fn remove_run_directory(self, operation: LogOperation) -> Result<(), LogError> {
        mark_handle_for_deletion(&self._directory).map_err(|error| map_io(None, operation, &error))
    }

    pub(crate) fn replace_file_if_exists(
        &self,
        source: &str,
        destination: &str,
        stream: Option<LogStream>,
        operation: LogOperation,
    ) -> Result<(), LogError> {
        validate_file_name(source)?;
        validate_file_name(destination)?;
        if self.inspect_file(source, stream, operation)?.is_none() {
            return Ok(());
        }
        let _ = self.inspect_file(destination, stream, operation)?;
        let source = wide_nul(self.path.join(source).as_os_str())
            .map_err(|error| map_io(stream, operation, &error))?;
        let destination = wide_nul(self.path.join(destination).as_os_str())
            .map_err(|error| map_io(stream, operation, &error))?;
        unsafe {
            MoveFileExW(
                PCWSTR(source.as_ptr()),
                PCWSTR(destination.as_ptr()),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        }
        .map_err(windows_error)
        .map_err(|error| map_io(stream, operation, &error))
    }

    pub(crate) fn replace_file_required(
        &self,
        source: &str,
        destination: &str,
        stream: Option<LogStream>,
        operation: LogOperation,
    ) -> Result<(), LogError> {
        validate_file_name(source)?;
        validate_file_name(destination)?;
        let source_path = self.path.join(source);
        let source_file = open_private_file_read_only(&source_path)
            .map_err(|error| map_io(stream, operation, &error))?;
        let source_identity =
            directory_identity(&source_file).map_err(|error| map_io(stream, operation, &error))?;
        let _ = self.inspect_file(destination, stream, operation)?;
        let source =
            wide_nul(source_path.as_os_str()).map_err(|error| map_io(stream, operation, &error))?;
        let destination_path = self.path.join(destination);
        let destination = wide_nul(destination_path.as_os_str())
            .map_err(|error| map_io(stream, operation, &error))?;
        unsafe {
            MoveFileExW(
                PCWSTR(source.as_ptr()),
                PCWSTR(destination.as_ptr()),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        }
        .map_err(windows_error)
        .map_err(|error| map_io(stream, operation, &error))?;
        let published = open_private_file_read_only(&destination_path)
            .map_err(|error| map_io(stream, operation, &error))?;
        validate_expected_file_identity(&published, source_identity)
            .map_err(|error| map_io(stream, operation, &error))
    }

    pub(crate) fn sync(
        &self,
        _stream: Option<LogStream>,
        _operation: LogOperation,
    ) -> Result<(), LogError> {
        // Every Windows rename uses MOVEFILE_WRITE_THROUGH. Directory handles
        // do not provide a portable additional flush operation.
        Ok(())
    }
}

fn validate_local_disk_path(path: &Path) -> Result<(), LogError> {
    if is_local_disk_path(path) {
        Ok(())
    } else {
        Err(LogError::configuration(
            LogOperation::ValidateRunDirectory,
            LogErrorKind::InvalidPath,
        ))
    }
}

fn is_local_disk_path(path: &Path) -> bool {
    matches!(
        path.components().next(),
        Some(Component::Prefix(prefix)) if matches!(prefix.kind(), Prefix::Disk(_))
    )
}

fn validate_directory_chain(path: &Path) -> io::Result<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        if matches!(component, Component::RootDir | Component::Normal(_)) {
            let _directory = open_directory(&current, true, FILE_READ_ATTRIBUTES.0)?;
        }
    }
    Ok(())
}

fn validate_parent_owner(path: &Path) -> io::Result<()> {
    let parent = open_directory(path, true, (FILE_READ_ATTRIBUTES | READ_CONTROL).0)?;
    validate_private_current_user_directory(&parent)
}

fn validate_private_current_user_directory(directory: &File) -> io::Result<()> {
    let token = current_process_token()?;
    let sid_buffer = current_user_sid(token.raw())?;
    let token_user = unsafe { &*(sid_buffer.as_ptr().cast::<TOKEN_USER>()) };
    let mut owner = PSID::default();
    let mut dacl = null_mut::<ACL>();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    let status = unsafe {
        GetSecurityInfo(
            HANDLE(directory.as_raw_handle()),
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
    if unsafe { EqualSid(owner, token_user.User.Sid) }.is_err() {
        return Err(private_parent_error());
    }
    if dacl.is_null() || !unsafe { IsValidAcl(dacl) }.as_bool() {
        return Err(private_parent_error());
    }

    let mut control = 0_u16;
    let mut revision = 0_u32;
    unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) }
        .map_err(windows_error)?;
    if control & SE_DACL_PROTECTED.0 == 0 {
        return Err(private_parent_error());
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

    let mut current_user_allowed = false;
    for index in 0..information.AceCount {
        let mut raw_ace = null_mut::<c_void>();
        unsafe { GetAce(dacl, index, &mut raw_ace) }.map_err(windows_error)?;
        if raw_ace.is_null() {
            return Err(private_parent_error());
        }
        let header = unsafe { &*raw_ace.cast::<ACE_HEADER>() };
        if u32::from(header.AceType) != ACCESS_ALLOWED_ACE_TYPE {
            return Err(private_parent_error());
        }
        let sid_offset = std::mem::offset_of!(ACCESS_ALLOWED_ACE, SidStart);
        let ace_size = usize::from(header.AceSize);
        if ace_size < sid_offset + 8 {
            return Err(private_parent_error());
        }
        let sid_pointer = unsafe { raw_ace.cast::<u8>().add(sid_offset) };
        let sub_authority_count = usize::from(unsafe { *sid_pointer.add(1) });
        let sid_length = 8_usize
            .checked_add(
                sub_authority_count
                    .checked_mul(4)
                    .ok_or_else(private_parent_error)?,
            )
            .ok_or_else(private_parent_error)?;
        if sid_offset
            .checked_add(sid_length)
            .is_none_or(|required| required > ace_size)
        {
            return Err(private_parent_error());
        }
        let sid = PSID(sid_pointer.cast());
        if !unsafe { IsValidSid(sid) }.as_bool() {
            return Err(private_parent_error());
        }
        if unsafe { GetLengthSid(sid) } as usize != sid_length {
            return Err(private_parent_error());
        }
        if unsafe { EqualSid(sid, token_user.User.Sid) }.is_err() {
            return Err(private_parent_error());
        }
        current_user_allowed = true;
    }
    if !current_user_allowed {
        return Err(private_parent_error());
    }
    Ok(())
}

fn private_parent_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "run log parent is not private to the current user",
    )
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

fn open_directory(path: &Path, share_delete: bool, access: u32) -> io::Result<File> {
    let share = if share_delete {
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
    } else {
        FILE_SHARE_READ | FILE_SHARE_WRITE
    };
    open_directory_with_share(path, share, access)
}

fn open_directory_exclusive(path: &Path, access: u32) -> io::Result<File> {
    open_directory_with_share(path, FILE_SHARE_MODE(0), access)
}

fn open_directory_with_share(path: &Path, share: FILE_SHARE_MODE, access: u32) -> io::Result<File> {
    let path = wide_nul(path.as_os_str())?;
    let handle = unsafe {
        CreateFileW(
            PCWSTR(path.as_ptr()),
            access,
            share,
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

fn open_private_file(
    path: &Path,
    disposition: FILE_CREATION_DISPOSITION,
    share: FILE_SHARE_MODE,
) -> io::Result<File> {
    let acl = current_user_acl(false)?;
    let mut descriptor = security_descriptor(&acl)?;
    let attributes = security_attributes(&mut descriptor);
    let path = wide_nul(path.as_os_str())?;
    let access = (FILE_GENERIC_READ | FILE_GENERIC_WRITE | READ_CONTROL | WRITE_DAC).0;
    let handle = unsafe {
        CreateFileW(
            PCWSTR(path.as_ptr()),
            access,
            share,
            Some(&attributes),
            disposition,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    }
    .map_err(windows_error)?;
    let file = unsafe { File::from_raw_handle(handle.0) };
    validate_handle(&file, false)?;
    validate_current_user_owner(&file)?;
    apply_current_user_dacl(&file, false)?;
    Ok(file)
}

fn open_private_file_read_only(path: &Path) -> io::Result<File> {
    let path = wide_nul(path.as_os_str())?;
    let access = (FILE_GENERIC_READ | READ_CONTROL).0;
    let handle = unsafe {
        CreateFileW(
            PCWSTR(path.as_ptr()),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    }
    .map_err(windows_error)?;
    let file = unsafe { File::from_raw_handle(handle.0) };
    validate_handle(&file, false)?;
    validate_current_user_owner(&file)?;
    validate_private_current_user_directory(&file)?;
    Ok(file)
}

fn open_private_file_for_deletion(path: &Path) -> io::Result<File> {
    let path = wide_nul(path.as_os_str())?;
    let access = (FILE_READ_ATTRIBUTES | READ_CONTROL | DELETE).0;
    let handle = unsafe {
        CreateFileW(
            PCWSTR(path.as_ptr()),
            access,
            FILE_SHARE_MODE(0),
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    }
    .map_err(windows_error)?;
    let file = unsafe { File::from_raw_handle(handle.0) };
    validate_handle(&file, false)?;
    validate_current_user_owner(&file)?;
    validate_private_current_user_directory(&file)?;
    Ok(file)
}

fn mark_handle_for_deletion(file: &File) -> io::Result<()> {
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

fn is_not_found(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(code)
            if code == ERROR_FILE_NOT_FOUND.0 as i32 || code == ERROR_PATH_NOT_FOUND.0 as i32
    )
}

fn directory_identity(file: &File) -> io::Result<DirectoryIdentity> {
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    unsafe { GetFileInformationByHandle(HANDLE(file.as_raw_handle()), &mut information) }
        .map_err(windows_error)?;
    Ok(DirectoryIdentity {
        volume_serial_number: information.dwVolumeSerialNumber,
        file_index: (u64::from(information.nFileIndexHigh) << 32)
            | u64::from(information.nFileIndexLow),
    })
}

fn validate_expected_directory_identity(
    directory: &File,
    expected: DirectoryIdentity,
) -> io::Result<()> {
    validate_handle(directory, true)?;
    if directory_identity(directory)? == expected {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "sensitive directory identity changed",
        ))
    }
}

fn validate_expected_file_identity(file: &File, expected: DirectoryIdentity) -> io::Result<()> {
    validate_handle(file, false)?;
    if directory_identity(file)? == expected {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "sensitive file identity changed",
        ))
    }
}

fn validate_handle(file: &File, expected_directory: bool) -> io::Result<()> {
    let handle = HANDLE(file.as_raw_handle());
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    unsafe { GetFileInformationByHandle(handle, &mut information) }.map_err(windows_error)?;
    if information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "sensitive path is a reparse point",
        ));
    }
    let is_directory = information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0;
    if is_directory != expected_directory || unsafe { GetFileType(handle) } != FILE_TYPE_DISK {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "sensitive path has an invalid file type",
        ));
    }
    if !expected_directory && information.nNumberOfLinks != 1 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "sensitive file has multiple hard links",
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
        lpSecurityDescriptor: (descriptor as *mut SECURITY_DESCRIPTOR).cast::<c_void>(),
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
        io::Error::other("Windows logging API failure")
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

struct LocalSecurityDescriptor(PSECURITY_DESCRIPTOR);

impl Drop for LocalSecurityDescriptor {
    fn drop(&mut self) {
        let _ = unsafe { LocalFree(Some(HLOCAL(self.0.0))) };
    }
}
