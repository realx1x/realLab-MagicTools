use std::ffi::{CStr, CString, OsStr, c_void};
use std::fs::File;
use std::io;
use std::mem::{MaybeUninit, size_of};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::ptr::null_mut;

use crate::database_path::DatabaseArtifact;

const APPLICATION_DIRECTORY: &str = "DevProcessManager";
const DATA_DIRECTORY: &str = "data";
const DATABASE_FILE_NAME: &str = "supervisor.sqlite3";
const ACL_TYPE_EXTENDED: libc::c_int = 0x100;
const ACL_FIRST_ENTRY: libc::c_int = 0;
const ACL_NEXT_ENTRY: libc::c_int = -1;
const ACL_EXTENDED_ALLOW: libc::c_int = 1;
const ACL_EXTENDED_DENY: libc::c_int = 2;
const FSID_BYTES: usize = size_of::<libc::fsid_t>();

#[derive(Clone, Copy, Eq, PartialEq)]
struct FileSystemIdentity([u8; FSID_BYTES]);

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

pub(super) fn prepare_private_database_root() -> io::Result<PathBuf> {
    let home = current_user_home()?;
    let root = expected_database_root(&home);
    let expected_uid = unsafe { libc::geteuid() };
    let mut directory = open_absolute_directory(&home)?;
    validate_parent_directory(&directory, expected_uid)?;

    for component in ["Library", "Application Support"] {
        directory = open_or_create_directory_at(&directory, OsStr::new(component))?;
        validate_parent_directory(&directory, expected_uid)?;
    }
    validate_local_file_system(&directory)?;
    let mut private_file_system = None;
    for component in [APPLICATION_DIRECTORY, DATA_DIRECTORY] {
        directory = open_or_create_directory_at(&directory, OsStr::new(component))?;
        secure_owned_directory(&directory, expected_uid)?;
        validate_private_directory(&directory, expected_uid)?;
        let current = validate_local_file_system(&directory)?;
        if private_file_system.is_some_and(|expected| expected != current) {
            return Err(non_local_database_error());
        }
        private_file_system = Some(current);
    }
    Ok(root)
}

pub(super) fn validate_private_database_root(root: &Path) -> io::Result<()> {
    let home = current_user_home()?;
    if root != expected_database_root(&home) {
        return Err(invalid_database_root());
    }
    let application_root = root.parent().ok_or_else(invalid_database_root)?;
    let expected_uid = unsafe { libc::geteuid() };
    let application_directory = open_absolute_directory(application_root)?;
    validate_private_directory(&application_directory, expected_uid)?;
    let application_file_system = validate_local_file_system(&application_directory)?;
    let data_directory = open_absolute_directory(root)?;
    validate_private_directory(&data_directory, expected_uid)?;
    let data_file_system = validate_local_file_system(&data_directory)?;
    if application_file_system != data_file_system {
        return Err(non_local_database_error());
    }
    Ok(())
}

pub(super) fn harden_existing_database_files(root: &Path, database: &Path) -> io::Result<()> {
    validate_database_file_path(root, database)?;
    validate_private_database_root(root)?;
    let directory = open_absolute_directory(root)?;
    validate_local_file_system(&directory)?;
    let expected_uid = unsafe { libc::geteuid() };
    for artifact in DatabaseArtifact::RECOVERY_FILES {
        let name = artifact_name(artifact);
        if let Some(file) = open_optional_file_at(&directory, &name)? {
            secure_private_file(&file, expected_uid)?;
            validate_private_file(&file, expected_uid)?;
            validate_same_file_system(&directory, &file)?;
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
    let directory = open_absolute_directory(root)?;
    validate_local_file_system(&directory)?;
    let name = artifact_name(artifact);
    let flags = libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    let file = loop {
        let fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags, 0o600) };
        if fd >= 0 {
            break unsafe { File::from_raw_fd(fd) };
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    };
    let expected_uid = unsafe { libc::geteuid() };
    secure_private_file(&file, expected_uid)?;
    validate_private_file(&file, expected_uid)?;
    validate_same_file_system(&directory, &file)?;
    Ok(file)
}

pub(super) fn validate_database_artifact_identity(
    root: &Path,
    artifact: DatabaseArtifact,
    expected: &File,
) -> io::Result<()> {
    validate_private_database_root(root)?;
    let expected_uid = unsafe { libc::geteuid() };
    validate_private_file(expected, expected_uid)?;
    let directory = open_absolute_directory(root)?;
    validate_same_file_system(&directory, expected)?;
    let current = open_database_artifact_file(root, artifact)?
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "a database artifact is missing"))?;
    validate_same_file(expected, &current)
}

pub(super) fn remove_database_artifact(root: &Path, artifact: DatabaseArtifact) -> io::Result<()> {
    validate_private_database_root(root)?;
    let directory = open_absolute_directory(root)?;
    validate_local_file_system(&directory)?;
    let name = artifact_name(artifact);
    let Some(expected) = open_optional_file_at_read_only(&directory, &name)? else {
        return Ok(());
    };
    validate_private_file(&expected, unsafe { libc::geteuid() })?;
    validate_same_file_system(&directory, &expected)?;
    validate_file_name_identity(&directory, &name, &expected)?;
    unlink_at(&directory, &name)
}

pub(super) fn discard_sqlite_database_artifact(
    root: &Path,
    artifact: DatabaseArtifact,
) -> io::Result<()> {
    validate_private_database_root(root)?;
    let directory = open_absolute_directory(root)?;
    validate_local_file_system(&directory)?;
    let name = artifact_name(artifact);
    let Some(file) = open_optional_file_at(&directory, &name)? else {
        return Ok(());
    };
    let expected_uid = unsafe { libc::geteuid() };
    validate_private_file(&file, expected_uid)?;
    validate_same_file_system(&directory, &file)?;
    file.set_len(0)?;
    file.sync_all()?;
    validate_file_name_identity(&directory, &name, &file)?;
    unlink_at(&directory, &name)?;
    directory.sync_all()
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
    validate_private_database_root(root)?;
    let directory = open_absolute_directory(root)?;
    validate_local_file_system(&directory)?;
    directory.sync_all()
}

pub(super) fn acquire_database_repository_lock(root: &Path) -> io::Result<File> {
    validate_private_database_root(root)?;
    let directory = open_absolute_directory(root)?;
    validate_local_file_system(&directory)?;
    let name = artifact_name(DatabaseArtifact::MigrationLock);
    let flags = libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    let file = loop {
        let fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags, 0o600) };
        if fd >= 0 {
            break unsafe { File::from_raw_fd(fd) };
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    };
    let expected_uid = unsafe { libc::geteuid() };
    secure_private_file(&file, expected_uid)?;
    validate_private_file(&file, expected_uid)?;
    validate_same_file_system(&directory, &file)?;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(io::Error::last_os_error());
    }
    file.set_len(0)?;
    file.sync_all()?;
    Ok(file)
}

fn expected_database_root(home: &Path) -> PathBuf {
    home.join("Library")
        .join("Application Support")
        .join(APPLICATION_DIRECTORY)
        .join(DATA_DIRECTORY)
}

fn validate_database_file_path(root: &Path, database: &Path) -> io::Result<()> {
    if database.parent() != Some(root)
        || database.file_name() != Some(OsStr::new(DATABASE_FILE_NAME))
    {
        return Err(invalid_database_root());
    }
    Ok(())
}

fn artifact_name(artifact: DatabaseArtifact) -> CString {
    CString::new(artifact.file_name()).expect("fixed database artifact file name")
}

fn open_database_artifact_file(
    root: &Path,
    artifact: DatabaseArtifact,
) -> io::Result<Option<File>> {
    let directory = open_absolute_directory(root)?;
    validate_local_file_system(&directory)?;
    let name = artifact_name(artifact);
    let Some(file) = open_optional_file_at_read_only(&directory, &name)? else {
        return Ok(None);
    };
    validate_private_file(&file, unsafe { libc::geteuid() })?;
    validate_same_file_system(&directory, &file)?;
    Ok(Some(file))
}

fn open_optional_file_at_read_only(parent: &File, name: &CString) -> io::Result<Option<File>> {
    let flags = libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    loop {
        let fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
        if fd >= 0 {
            return Ok(Some(unsafe { File::from_raw_fd(fd) }));
        }
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        if error.kind() == io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(error);
    }
}

fn replace_database_artifact(
    root: &Path,
    source: DatabaseArtifact,
    destination: DatabaseArtifact,
    expected: &File,
) -> io::Result<()> {
    validate_database_artifact_identity(root, source, expected)?;
    let directory = open_absolute_directory(root)?;
    validate_local_file_system(&directory)?;
    let source_name = artifact_name(source);
    let destination_name = artifact_name(destination);
    if let Some(destination_file) = open_optional_file_at_read_only(&directory, &destination_name)?
    {
        validate_private_file(&destination_file, unsafe { libc::geteuid() })?;
        validate_same_file_system(&directory, &destination_file)?;
    }
    rename_at(&directory, &source_name, &destination_name)?;
    let published =
        open_optional_file_at_read_only(&directory, &destination_name)?.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "a published database artifact is missing",
            )
        })?;
    validate_private_file(&published, unsafe { libc::geteuid() })?;
    validate_same_file_system(&directory, &published)?;
    validate_same_file(expected, &published)
}

fn validate_file_name_identity(parent: &File, name: &CString, expected: &File) -> io::Result<()> {
    let current = open_optional_file_at_read_only(parent, name)?
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "a database artifact is missing"))?;
    validate_private_file(&current, unsafe { libc::geteuid() })?;
    validate_same_file_system(parent, expected)?;
    validate_same_file_system(parent, &current)?;
    validate_same_file(expected, &current)
}

fn validate_same_file(expected: &File, current: &File) -> io::Result<()> {
    if validate_local_file_system(expected)? != validate_local_file_system(current)? {
        return Err(non_local_database_error());
    }
    let expected = expected.metadata()?;
    let current = current.metadata()?;
    if expected.dev() == current.dev() && expected.ino() == current.ino() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "a database artifact identity changed",
        ))
    }
}

fn validate_local_file_system(file: &File) -> io::Result<FileSystemIdentity> {
    let mut status = MaybeUninit::<libc::statfs>::uninit();
    if unsafe { libc::fstatfs(file.as_raw_fd(), status.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let status = unsafe { status.assume_init() };
    if status.f_flags & (libc::MNT_LOCAL as u32) == 0 {
        return Err(non_local_database_error());
    }
    let mut bytes = [0_u8; FSID_BYTES];
    unsafe {
        std::ptr::copy_nonoverlapping(
            (&raw const status.f_fsid).cast::<u8>(),
            bytes.as_mut_ptr(),
            FSID_BYTES,
        );
    }
    Ok(FileSystemIdentity(bytes))
}

fn validate_same_file_system(parent: &File, child: &File) -> io::Result<()> {
    if validate_local_file_system(parent)? == validate_local_file_system(child)? {
        Ok(())
    } else {
        Err(non_local_database_error())
    }
}

fn non_local_database_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "the private database must use one local file system",
    )
}

fn unlink_at(parent: &File, name: &CString) -> io::Result<()> {
    loop {
        if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0) } == 0 {
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

fn current_user_home() -> io::Result<PathBuf> {
    const FALLBACK_BUFFER_BYTES: usize = 16 * 1024;
    const MAX_BUFFER_BYTES: usize = 1024 * 1024;

    let configured = unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
    let mut buffer_len = if configured > 0 {
        usize::try_from(configured)
            .unwrap_or(MAX_BUFFER_BYTES)
            .clamp(1, MAX_BUFFER_BYTES)
    } else {
        FALLBACK_BUFFER_BYTES
    };

    loop {
        let mut buffer = vec![0_u8; buffer_len];
        let mut entry = unsafe { std::mem::zeroed::<libc::passwd>() };
        let mut result = null_mut::<libc::passwd>();
        let status = unsafe {
            libc::getpwuid_r(
                libc::geteuid(),
                &mut entry,
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut result,
            )
        };
        if status == libc::ERANGE && buffer_len < MAX_BUFFER_BYTES {
            buffer_len = buffer_len.saturating_mul(2).min(MAX_BUFFER_BYTES);
            continue;
        }
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status));
        }
        if result.is_null() || entry.pw_dir.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "the current user's home directory is unavailable",
            ));
        }
        let home = PathBuf::from(std::ffi::OsString::from_vec(
            unsafe { CStr::from_ptr(entry.pw_dir) }.to_bytes().to_vec(),
        ));
        if !home.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the current user's home directory is not absolute",
            ));
        }
        return Ok(home);
    }
}

fn open_absolute_directory(path: &Path) -> io::Result<File> {
    if !path.is_absolute() {
        return Err(invalid_database_root());
    }
    let mut directory = open_root_directory()?;
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(component) => {
                directory = open_directory_at(&directory, component)?;
            }
            Component::Prefix(_) | Component::CurDir | Component::ParentDir => {
                return Err(invalid_database_root());
            }
        }
    }
    Ok(directory)
}

fn open_root_directory() -> io::Result<File> {
    loop {
        let fd = unsafe {
            libc::open(
                c"/".as_ptr(),
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

fn open_or_create_directory_at(parent: &File, component: &OsStr) -> io::Result<File> {
    match open_directory_at(parent, component) {
        Ok(directory) => Ok(directory),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            mkdir_at(parent, component)?;
            open_directory_at(parent, component)
        }
        Err(error) => Err(error),
    }
}

fn open_directory_at(parent: &File, component: &OsStr) -> io::Result<File> {
    let component = component_c_string(component)?;
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

fn mkdir_at(parent: &File, component: &OsStr) -> io::Result<()> {
    let component = component_c_string(component)?;
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

fn open_optional_file_at(parent: &File, name: &CString) -> io::Result<Option<File>> {
    let flags = libc::O_RDWR | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    loop {
        let fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
        if fd >= 0 {
            return Ok(Some(unsafe { File::from_raw_fd(fd) }));
        }
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        if error.kind() == io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(error);
    }
}

fn component_c_string(component: &OsStr) -> io::Result<CString> {
    if Path::new(component).components().count() != 1
        || component.as_bytes() == b"."
        || component.as_bytes() == b".."
    {
        return Err(invalid_database_root());
    }
    CString::new(component.as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "a private database path contains a NUL byte",
        )
    })
}

fn validate_parent_directory(directory: &File, expected_uid: libc::uid_t) -> io::Result<()> {
    let metadata = validate_owned_directory(directory, expected_uid)?;
    if metadata.mode() & 0o022 != 0 || has_allow_extended_acl(directory.as_raw_fd())? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "a database parent directory permits access by another user",
        ));
    }
    Ok(())
}

fn secure_owned_directory(directory: &File, expected_uid: libc::uid_t) -> io::Result<()> {
    validate_owned_directory(directory, expected_uid)?;
    clear_extended_acl(directory.as_raw_fd())?;
    fchmod(directory.as_raw_fd(), 0o700)
}

fn validate_private_directory(directory: &File, expected_uid: libc::uid_t) -> io::Result<()> {
    let metadata = validate_owned_directory(directory, expected_uid)?;
    if metadata.mode() & 0o777 != 0o700 || has_allow_extended_acl(directory.as_raw_fd())? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "a private database directory is not restricted to the current user",
        ));
    }
    Ok(())
}

fn validate_owned_directory(
    directory: &File,
    expected_uid: libc::uid_t,
) -> io::Result<std::fs::Metadata> {
    let metadata = directory.metadata()?;
    if !metadata.is_dir() || metadata.uid() != expected_uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "a database directory has invalid ownership or type",
        ));
    }
    Ok(metadata)
}

fn secure_private_file(file: &File, expected_uid: libc::uid_t) -> io::Result<()> {
    validate_owned_file(file, expected_uid)?;
    clear_extended_acl(file.as_raw_fd())?;
    fchmod(file.as_raw_fd(), 0o600)
}

fn validate_private_file(file: &File, expected_uid: libc::uid_t) -> io::Result<()> {
    let metadata = validate_owned_file(file, expected_uid)?;
    if metadata.permissions().mode() & 0o777 != 0o600 || has_allow_extended_acl(file.as_raw_fd())? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "a private database file is not restricted to the current user",
        ));
    }
    Ok(())
}

fn validate_owned_file(file: &File, expected_uid: libc::uid_t) -> io::Result<std::fs::Metadata> {
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.uid() != expected_uid || metadata.nlink() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "a database file has invalid ownership, type, or link count",
        ));
    }
    Ok(metadata)
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
        let mut entry = null_mut::<c_void>();
        clear_errno();
        let status = unsafe { acl_get_entry(acl, entry_id, &mut entry) };
        match status {
            0 => return Ok(false),
            1 if entry.is_null() => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "an extended ACL returned an invalid entry",
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
                    "an extended ACL contains an unknown entry type",
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

fn invalid_database_root() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "the database path is outside the fixed current-user data root",
    )
}
