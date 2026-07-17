use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

#[cfg(target_os = "macos")]
mod macos;
#[cfg(windows)]
mod windows;

#[cfg(target_os = "macos")]
use macos as implementation;
#[cfg(windows)]
use windows as implementation;

pub(crate) fn current_user_runtime_root() -> io::Result<PathBuf> {
    implementation::current_user_runtime_root()
}
pub(crate) fn prepare_runtime_directory(path: &Path) -> io::Result<()> {
    implementation::prepare_runtime_directory(path)
}

pub(crate) fn open_private_file(path: &Path, truncate: bool) -> io::Result<File> {
    implementation::open_private_file(path, truncate)
}

pub(crate) fn atomic_replace(source: &Path, destination: &Path) -> io::Result<()> {
    implementation::atomic_replace(source, destination)
}
