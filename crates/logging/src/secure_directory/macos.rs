use std::ffi::{CString, OsStr, c_void};
use std::fs::File;
use std::io::{self, Seek, SeekFrom};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path};

use crate::secure_directory::{
    map_io, validate_file_name, validate_log_root_path, validate_run_directory_path,
};
use crate::{LogError, LogOperation, LogStream};

const ACL_TYPE_EXTENDED: libc::c_int = 0x100;
const ACL_FIRST_ENTRY: libc::c_int = 0;
const ACL_NEXT_ENTRY: libc::c_int = -1;
const ACL_EXTENDED_ALLOW: libc::c_int = 1;
const ACL_EXTENDED_DENY: libc::c_int = 2;

unsafe extern "C" {
    fn acl_delete_fd_np(fd: libc::c_int, acl_type: libc::c_int) -> libc::c_int;
    fn acl_get_fd_np(fd: libc::c_int, acl_type: libc::c_int) -> *mut c_void;
    fn acl_get_entry(
        acl: *mut c_void,
        entry_id: libc::c_int,
        entry: *mut *mut c_void,
    ) -> libc::c_int;
    fn acl_get_tag_type(entry: *mut c_void, tag_type: *mut libc::c_int) -> libc::c_int;
    fn acl_free(object: *mut c_void) -> libc::c_int;
    fn __error() -> *mut libc::c_int;
}

pub(crate) struct SecureLogRoot {
    directory: File,
}

impl SecureLogRoot {
    pub(crate) fn open(path: &Path) -> Result<Self, LogError> {
        validate_log_root_path(path)?;
        let directory = open_absolute_directory(path)
            .map_err(|error| map_io(None, LogOperation::ValidateRetentionLogRoot, &error))?;
        validate_private_parent(&directory)
            .map_err(|error| map_io(None, LogOperation::ValidateRetentionLogRoot, &error))?;
        Ok(Self { directory })
    }

    pub(crate) fn open_run_existing(&self, run_id: &str) -> Result<SecureRunDirectory, LogError> {
        self.open_run(run_id)
    }

    pub(crate) fn open_run_for_retention(
        &self,
        run_id: &str,
    ) -> Result<SecureRunDirectory, LogError> {
        self.open_run(run_id)
    }

    fn open_run(&self, run_id: &str) -> Result<SecureRunDirectory, LogError> {
        validate_private_parent(&self.directory)
            .map_err(|error| map_io(None, LogOperation::ValidateRetentionLogRoot, &error))?;
        validate_file_name(run_id)?;
        let component = CString::new(run_id).map_err(|error| {
            map_io(
                None,
                LogOperation::ValidateRetentionRunId,
                &io::Error::new(io::ErrorKind::InvalidInput, error),
            )
        })?;
        let directory = open_directory_at(&self.directory, &component)
            .map_err(|error| map_io(None, LogOperation::InspectRunDirectory, &error))?;
        validate_private_run_directory(&directory)
            .map_err(|error| map_io(None, LogOperation::InspectRunDirectory, &error))?;
        let parent = self
            .directory
            .try_clone()
            .map_err(|error| map_io(None, LogOperation::InspectRunDirectory, &error))?;
        Ok(SecureRunDirectory {
            parent,
            component,
            directory,
        })
    }
}

pub(crate) struct SecureRunDirectory {
    parent: File,
    component: CString,
    directory: File,
}

impl SecureRunDirectory {
    pub(crate) fn prepare(path: &Path) -> Result<Self, LogError> {
        validate_run_directory_path(path)?;
        let parent_path = path.parent().ok_or_else(|| {
            LogError::configuration(
                LogOperation::ValidateRunDirectory,
                crate::LogErrorKind::InvalidPath,
            )
        })?;
        let parent = open_absolute_directory(parent_path)
            .map_err(|error| map_io(None, LogOperation::InspectRunDirectory, &error))?;
        validate_private_parent(&parent)
            .map_err(|error| map_io(None, LogOperation::InspectRunDirectory, &error))?;

        let component = component_c_string(path.file_name().expect("validated run directory"))
            .map_err(|error| map_io(None, LogOperation::ValidateRunDirectory, &error))?;
        match open_directory_at(&parent, &component) {
            Ok(directory) => {
                secure_run_directory(&directory)
                    .map_err(|error| map_io(None, LogOperation::SecureRunDirectory, &error))?;
                Ok(Self {
                    parent,
                    component,
                    directory,
                })
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                mkdir_at(&parent, &component)
                    .map_err(|error| map_io(None, LogOperation::CreateRunDirectory, &error))?;
                let directory = open_directory_at(&parent, &component)
                    .map_err(|error| map_io(None, LogOperation::InspectRunDirectory, &error))?;
                secure_run_directory(&directory)
                    .map_err(|error| map_io(None, LogOperation::SecureRunDirectory, &error))?;
                Ok(Self {
                    parent,
                    component,
                    directory,
                })
            }
            Err(error) => Err(map_io(None, LogOperation::InspectRunDirectory, &error)),
        }
    }

    pub(crate) fn open_existing(path: &Path) -> Result<Self, LogError> {
        validate_run_directory_path(path)?;
        let parent_path = path.parent().ok_or_else(|| {
            LogError::configuration(
                LogOperation::ValidateRunDirectory,
                crate::LogErrorKind::InvalidPath,
            )
        })?;
        let parent = open_absolute_directory(parent_path)
            .map_err(|error| map_io(None, LogOperation::InspectRunDirectory, &error))?;
        validate_private_parent(&parent)
            .map_err(|error| map_io(None, LogOperation::InspectRunDirectory, &error))?;
        let component = component_c_string(path.file_name().expect("validated run directory"))
            .map_err(|error| map_io(None, LogOperation::ValidateRunDirectory, &error))?;
        let directory = open_directory_at(&parent, &component)
            .map_err(|error| map_io(None, LogOperation::InspectRunDirectory, &error))?;
        validate_private_run_directory(&directory)
            .map_err(|error| map_io(None, LogOperation::InspectRunDirectory, &error))?;
        Ok(Self {
            parent,
            component,
            directory,
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
        let file_name = CString::new(file_name).map_err(|error| {
            map_io(
                stream,
                operation,
                &io::Error::new(io::ErrorKind::InvalidInput, error),
            )
        })?;
        let file = open_file_at(&self.directory, &file_name, true)
            .map_err(|error| map_io(stream, operation, &error))?;
        secure_log_file(&file)
            .map_err(|error| map_io(stream, LogOperation::SecureLogFile, &error))?;
        if truncate {
            file.set_len(0)
                .map_err(|error| map_io(stream, operation, &error))?;
        }
        let mut file = file;
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
        let file_name = CString::new(file_name).map_err(|error| {
            map_io(
                stream,
                operation,
                &io::Error::new(io::ErrorKind::InvalidInput, error),
            )
        })?;
        let file = match open_file_at_read_only(&self.directory, &file_name) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(map_io(stream, operation, &error)),
        };
        validate_private_log_file(&file).map_err(|error| map_io(stream, operation, &error))?;
        Ok(Some(file))
    }

    pub(crate) fn create_new_file(
        &self,
        file_name: &str,
        stream: Option<LogStream>,
        operation: LogOperation,
    ) -> Result<File, LogError> {
        validate_file_name(file_name)?;
        let file_name = CString::new(file_name).map_err(|error| {
            map_io(
                stream,
                operation,
                &io::Error::new(io::ErrorKind::InvalidInput, error),
            )
        })?;
        let file = open_file_at_create_new(&self.directory, &file_name)
            .map_err(|error| map_io(stream, operation, &error))?;
        secure_log_file(&file)
            .map_err(|error| map_io(stream, LogOperation::SecureLogFile, &error))?;
        Ok(file)
    }

    pub(crate) fn inspect_file(
        &self,
        file_name: &str,
        stream: Option<LogStream>,
        operation: LogOperation,
    ) -> Result<Option<u64>, LogError> {
        validate_file_name(file_name)?;
        let file_name = CString::new(file_name).map_err(|error| {
            map_io(
                stream,
                operation,
                &io::Error::new(io::ErrorKind::InvalidInput, error),
            )
        })?;
        let file = match open_file_at(&self.directory, &file_name, false) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(map_io(stream, operation, &error)),
        };
        secure_log_file(&file)
            .map_err(|error| map_io(stream, LogOperation::SecureLogFile, &error))?;
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
        let file_name = CString::new(file_name).map_err(|error| {
            map_io(
                stream,
                operation,
                &io::Error::new(io::ErrorKind::InvalidInput, error),
            )
        })?;
        unlink_at(&self.directory, &file_name).map_err(|error| map_io(stream, operation, &error))
    }

    pub(crate) fn remove_file_for_retention(
        &self,
        file_name: &str,
        stream: Option<LogStream>,
        operation: LogOperation,
    ) -> Result<Option<u64>, LogError> {
        validate_file_name(file_name)?;
        let file_name = CString::new(file_name).map_err(|error| {
            map_io(
                stream,
                operation,
                &io::Error::new(io::ErrorKind::InvalidInput, error),
            )
        })?;
        let file = match open_file_at_read_only(&self.directory, &file_name) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(map_io(stream, operation, &error)),
        };
        validate_private_log_file(&file).map_err(|error| map_io(stream, operation, &error))?;
        let length = file
            .metadata()
            .map_err(|error| map_io(stream, operation, &error))?
            .len();
        validate_file_name_identity(&self.directory, &file_name, &file)
            .map_err(|error| map_io(stream, operation, &error))?;
        unlink_at(&self.directory, &file_name)
            .map_err(|error| map_io(stream, operation, &error))?;
        Ok(Some(length))
    }

    pub(crate) fn remove_run_directory(self, operation: LogOperation) -> Result<(), LogError> {
        self.directory
            .sync_all()
            .map_err(|error| map_io(None, operation, &error))?;
        validate_directory_name_identity(&self.parent, &self.component, &self.directory)
            .map_err(|error| map_io(None, operation, &error))?;
        unlink_directory_at(&self.parent, &self.component)
            .map_err(|error| map_io(None, operation, &error))?;
        self.parent
            .sync_all()
            .map_err(|error| map_io(None, operation, &error))
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
        let source = CString::new(source).map_err(|error| {
            map_io(
                stream,
                operation,
                &io::Error::new(io::ErrorKind::InvalidInput, error),
            )
        })?;
        let destination = CString::new(destination).map_err(|error| {
            map_io(
                stream,
                operation,
                &io::Error::new(io::ErrorKind::InvalidInput, error),
            )
        })?;
        rename_at(&self.directory, &source, &destination)
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
        let source = CString::new(source).map_err(|error| {
            map_io(
                stream,
                operation,
                &io::Error::new(io::ErrorKind::InvalidInput, error),
            )
        })?;
        let destination = CString::new(destination).map_err(|error| {
            map_io(
                stream,
                operation,
                &io::Error::new(io::ErrorKind::InvalidInput, error),
            )
        })?;
        let source_file = open_file_at_read_only(&self.directory, &source)
            .map_err(|error| map_io(stream, operation, &error))?;
        validate_private_log_file(&source_file)
            .map_err(|error| map_io(stream, operation, &error))?;
        let _ = self.inspect_file(
            destination.to_str().map_err(|_| {
                LogError::configuration(operation, crate::LogErrorKind::InvalidPath)
            })?,
            stream,
            operation,
        )?;
        validate_file_name_identity(&self.directory, &source, &source_file)
            .map_err(|error| map_io(stream, operation, &error))?;
        rename_at(&self.directory, &source, &destination)
            .map_err(|error| map_io(stream, operation, &error))?;
        let published = open_file_at_read_only(&self.directory, &destination)
            .map_err(|error| map_io(stream, operation, &error))?;
        validate_private_log_file(&published).map_err(|error| map_io(stream, operation, &error))?;
        validate_same_identity(&source_file, &published)
            .map_err(|error| map_io(stream, operation, &error))
    }

    pub(crate) fn sync(
        &self,
        stream: Option<LogStream>,
        operation: LogOperation,
    ) -> Result<(), LogError> {
        self.directory
            .sync_all()
            .map_err(|error| map_io(stream, operation, &error))
    }
}

fn open_absolute_directory(path: &Path) -> io::Result<File> {
    let mut directory = open_root_directory()?;
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(component) => {
                let component = component_c_string(component)?;
                directory = open_directory_at(&directory, &component)?;
            }
            Component::Prefix(_) | Component::CurDir | Component::ParentDir => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid absolute directory component",
                ));
            }
        }
    }
    Ok(directory)
}

fn open_root_directory() -> io::Result<File> {
    let root = c"/";
    loop {
        let fd = unsafe {
            libc::open(
                root.as_ptr(),
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

fn component_c_string(component: &OsStr) -> io::Result<CString> {
    CString::new(component.as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "path component contains a NUL byte",
        )
    })
}

fn open_directory_at(parent: &File, component: &CString) -> io::Result<File> {
    loop {
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                component.as_ptr(),
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

fn mkdir_at(parent: &File, component: &CString) -> io::Result<()> {
    loop {
        if unsafe { libc::mkdirat(parent.as_raw_fd(), component.as_ptr(), 0o700) } == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        if error.kind() == io::ErrorKind::AlreadyExists {
            return Ok(());
        }
        return Err(error);
    }
}

fn open_file_at(parent: &File, file_name: &CString, create: bool) -> io::Result<File> {
    let mut flags = libc::O_RDWR | libc::O_APPEND | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    if create {
        flags |= libc::O_CREAT;
    }
    loop {
        let fd = unsafe { libc::openat(parent.as_raw_fd(), file_name.as_ptr(), flags, 0o600) };
        if fd >= 0 {
            return Ok(unsafe { File::from_raw_fd(fd) });
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

fn open_file_at_create_new(parent: &File, file_name: &CString) -> io::Result<File> {
    let flags = libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    loop {
        let fd = unsafe { libc::openat(parent.as_raw_fd(), file_name.as_ptr(), flags, 0o600) };
        if fd >= 0 {
            return Ok(unsafe { File::from_raw_fd(fd) });
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

fn open_file_at_read_only(parent: &File, file_name: &CString) -> io::Result<File> {
    let flags = libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    loop {
        let fd = unsafe { libc::openat(parent.as_raw_fd(), file_name.as_ptr(), flags) };
        if fd >= 0 {
            return Ok(unsafe { File::from_raw_fd(fd) });
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

fn unlink_at(parent: &File, file_name: &CString) -> io::Result<()> {
    loop {
        if unsafe { libc::unlinkat(parent.as_raw_fd(), file_name.as_ptr(), 0) } == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        if error.kind() == io::ErrorKind::NotFound {
            return Ok(());
        }
        return Err(error);
    }
}

fn unlink_directory_at(parent: &File, component: &CString) -> io::Result<()> {
    loop {
        if unsafe { libc::unlinkat(parent.as_raw_fd(), component.as_ptr(), libc::AT_REMOVEDIR) }
            == 0
        {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        if error.kind() == io::ErrorKind::NotFound {
            return Ok(());
        }
        return Err(error);
    }
}

fn validate_file_name_identity(
    parent: &File,
    file_name: &CString,
    expected: &File,
) -> io::Result<()> {
    let current = open_file_at_read_only(parent, file_name)?;
    validate_private_log_file(&current)?;
    validate_same_identity(expected, &current)
}

fn validate_directory_name_identity(
    parent: &File,
    component: &CString,
    expected: &File,
) -> io::Result<()> {
    let current = open_directory_at(parent, component)?;
    validate_private_run_directory(&current)?;
    validate_same_identity(expected, &current)
}

fn validate_same_identity(expected: &File, current: &File) -> io::Result<()> {
    let expected = expected.metadata()?;
    let current = current.metadata()?;
    if expected.dev() == current.dev() && expected.ino() == current.ino() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "sensitive path identity changed during retention",
        ))
    }
}

fn rename_at(parent: &File, source: &CString, destination: &CString) -> io::Result<()> {
    loop {
        if unsafe {
            libc::renameat(
                parent.as_raw_fd(),
                source.as_ptr(),
                parent.as_raw_fd(),
                destination.as_ptr(),
            )
        } == 0
        {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

fn validate_private_parent(directory: &File) -> io::Result<()> {
    let metadata = validate_owned_directory(directory)?;
    if metadata.mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "run log parent permissions are not private",
        ));
    }
    if has_allow_extended_acl(directory.as_raw_fd())? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "run log parent has an allow ACL",
        ));
    }
    Ok(())
}

fn secure_run_directory(directory: &File) -> io::Result<()> {
    validate_owned_directory(directory)?;
    clear_extended_acl(directory.as_raw_fd())?;
    fchmod(directory.as_raw_fd(), 0o700)
}

fn validate_private_run_directory(directory: &File) -> io::Result<()> {
    let metadata = validate_owned_directory(directory)?;
    if metadata.mode() & 0o777 != 0o700 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "run log directory permissions are not private",
        ));
    }
    if has_allow_extended_acl(directory.as_raw_fd())? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "run log directory has an allow ACL",
        ));
    }
    Ok(())
}

fn validate_owned_directory(directory: &File) -> io::Result<std::fs::Metadata> {
    let metadata = directory.metadata()?;
    if !metadata.is_dir() || metadata.uid() != unsafe { libc::geteuid() } {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "run log directory ownership or type is invalid",
        ));
    }
    Ok(metadata)
}

fn secure_log_file(file: &File) -> io::Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.uid() != unsafe { libc::geteuid() } || metadata.nlink() != 1
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "run log file ownership, type, or link count is invalid",
        ));
    }
    clear_extended_acl(file.as_raw_fd())?;
    fchmod(file.as_raw_fd(), 0o600)
}

fn validate_private_log_file(file: &File) -> io::Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.nlink() != 1
        || metadata.mode() & 0o777 != 0o600
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "run log file ownership, type, links, or permissions are invalid",
        ));
    }
    if has_allow_extended_acl(file.as_raw_fd())? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "run log file has an allow ACL",
        ));
    }
    Ok(())
}

fn has_allow_extended_acl(fd: libc::c_int) -> io::Result<bool> {
    clear_errno();
    let acl = unsafe { acl_get_fd_np(fd, ACL_TYPE_EXTENDED) };
    if acl.is_null() {
        return no_acl_or_error();
    }
    let inspection = inspect_acl_entries(acl);
    let free_status = unsafe { acl_free(acl) };
    if free_status != 0 {
        return Err(io::Error::last_os_error());
    }
    inspection
}

fn inspect_acl_entries(acl: *mut c_void) -> io::Result<bool> {
    let mut entry_id = ACL_FIRST_ENTRY;
    loop {
        let mut entry = std::ptr::null_mut::<c_void>();
        clear_errno();
        let status = unsafe { acl_get_entry(acl, entry_id, &mut entry) };
        match status {
            0 => return Ok(false),
            1 if entry.is_null() => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "extended ACL returned an invalid entry",
                ));
            }
            1 => {}
            _ => return Err(io::Error::last_os_error()),
        }

        let mut tag_type = 0;
        clear_errno();
        if unsafe { acl_get_tag_type(entry, &mut tag_type) } != 0 {
            return Err(io::Error::last_os_error());
        }
        match tag_type {
            ACL_EXTENDED_ALLOW => return Ok(true),
            ACL_EXTENDED_DENY => entry_id = ACL_NEXT_ENTRY,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "extended ACL contains an unknown entry type",
                ));
            }
        }
    }
}

fn clear_extended_acl(fd: libc::c_int) -> io::Result<()> {
    clear_errno();
    if unsafe { acl_delete_fd_np(fd, ACL_TYPE_EXTENDED) } == 0 {
        return Ok(());
    }
    match io::Error::last_os_error() {
        error if error.raw_os_error() == Some(libc::ENOATTR) => Ok(()),
        error => Err(error),
    }
}

fn no_acl_or_error() -> io::Result<bool> {
    match io::Error::last_os_error() {
        error if error.raw_os_error() == Some(libc::ENOATTR) => Ok(false),
        error => Err(error),
    }
}

fn fchmod(fd: libc::c_int, mode: libc::mode_t) -> io::Result<()> {
    if unsafe { libc::fchmod(fd, mode) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn clear_errno() {
    unsafe { *__error() = 0 };
}
