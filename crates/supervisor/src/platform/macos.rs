use std::ffi::{CStr, CString, OsStr, c_void};
use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::ptr::null_mut;

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

pub(super) fn current_user_runtime_root() -> io::Result<PathBuf> {
    let home = current_user_home()?;
    Ok(home
        .join("Library")
        .join("Application Support")
        .join("DevProcessManager")
        .join("runtime"))
}

pub(super) fn prepare_runtime_directory(path: &Path) -> io::Result<()> {
    let home = current_user_home()?;
    let expected = home
        .join("Library")
        .join("Application Support")
        .join("DevProcessManager")
        .join("runtime");
    if path != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "runtime directory is outside the current user's fixed application root",
        ));
    }

    let expected_uid = unsafe { libc::geteuid() };
    let mut directory = open_private_directory(&home)?;
    validate_parent_directory(&directory, expected_uid)?;

    for component in ["Library", "Application Support"] {
        directory = open_or_create_directory_at(&directory, OsStr::new(component))?;
        validate_parent_directory(&directory, expected_uid)?;
    }

    for component in ["DevProcessManager", "runtime"] {
        directory = open_or_create_directory_at(&directory, OsStr::new(component))?;
        secure_owned_directory(&directory, expected_uid)?;
    }

    Ok(())
}

pub(super) fn open_private_file(path: &Path, truncate: bool) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "sensitive path is not a regular file",
        ));
    }
    validate_owner(&metadata, unsafe { libc::geteuid() })?;
    clear_extended_acl(file.as_raw_fd())?;
    fchmod(file.as_raw_fd(), 0o600)?;
    if truncate {
        file.set_len(0)?;
    }
    Ok(file)
}

pub(super) fn atomic_replace(source: &Path, destination: &Path) -> io::Result<()> {
    let parent = destination
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "token has no parent"))?;
    let parent_directory = open_private_directory(parent)?;
    std::fs::rename(source, destination)?;
    parent_directory.sync_all()
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

        let home = PathBuf::from(OsStr::from_bytes(
            unsafe { CStr::from_ptr(entry.pw_dir) }.to_bytes(),
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

fn mkdir_at(parent: &File, component: &OsStr) -> io::Result<()> {
    let component = path_component_c_string(component)?;
    loop {
        let status = unsafe { libc::mkdirat(parent.as_raw_fd(), component.as_ptr(), 0o700) };
        if status == 0 {
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

fn open_directory_at(parent: &File, component: &OsStr) -> io::Result<File> {
    let component = path_component_c_string(component)?;
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

fn path_component_c_string(component: &OsStr) -> io::Result<CString> {
    if Path::new(component).components().count() != 1
        || component.as_bytes() == b"."
        || component.as_bytes() == b".."
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "runtime path contains an invalid directory component",
        ));
    }
    CString::new(component.as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "runtime path contains a NUL byte",
        )
    })
}

fn validate_parent_directory(directory: &File, expected_uid: libc::uid_t) -> io::Result<()> {
    let metadata = validate_directory(directory, expected_uid)?;
    if metadata.mode() & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "runtime parent directory is writable by group or other users",
        ));
    }
    if has_allow_extended_acl(directory.as_raw_fd())? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "runtime parent directory grants access through an extended ACL",
        ));
    }
    Ok(())
}

fn secure_owned_directory(directory: &File, expected_uid: libc::uid_t) -> io::Result<()> {
    validate_directory(directory, expected_uid)?;
    clear_extended_acl(directory.as_raw_fd())?;
    fchmod(directory.as_raw_fd(), 0o700)
}

fn validate_directory(
    directory: &File,
    expected_uid: libc::uid_t,
) -> io::Result<std::fs::Metadata> {
    let metadata = directory.metadata()?;
    if !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "sensitive path is not a regular directory",
        ));
    }
    validate_owner(&metadata, expected_uid)?;
    Ok(metadata)
}

fn validate_owner(metadata: &std::fs::Metadata, expected_uid: libc::uid_t) -> io::Result<()> {
    if metadata.uid() != expected_uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "sensitive path is not owned by the current user",
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
        let mut entry = null_mut::<c_void>();
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

fn open_private_directory(path: &Path) -> io::Result<File> {
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open(path)?;
    validate_directory(&directory, unsafe { libc::geteuid() })?;
    Ok(directory)
}
