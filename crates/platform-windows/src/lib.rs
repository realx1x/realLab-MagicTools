//! Windows process discovery adapter.

#![forbid(unsafe_op_in_unsafe_fn)]

#[cfg(all(windows, not(target_arch = "x86_64")))]
compile_error!("platform-windows V1 supports only Windows x86_64");

#[cfg(all(windows, target_arch = "x86_64"))]
mod credentials;

#[cfg(all(windows, target_arch = "x86_64"))]
mod external;

#[cfg(all(windows, target_arch = "x86_64"))]
mod managed;

#[cfg(all(windows, target_arch = "x86_64"))]
mod native;

#[cfg(all(windows, target_arch = "x86_64"))]
mod ports;

#[cfg(all(windows, target_arch = "x86_64"))]
mod windows;

#[cfg(all(windows, target_arch = "x86_64"))]
pub use credentials::WindowsCredentialStore;

#[cfg(all(windows, target_arch = "x86_64"))]
pub use external::{WindowsExternalStopResult, stop_external_process};

#[cfg(all(windows, target_arch = "x86_64"))]
pub use managed::{
    SuspendedWindowsManagedProcess, WindowsManagedExitPoll, WindowsManagedLaunchError,
    WindowsManagedLaunchRequest, WindowsManagedProcess, WindowsManagedRecoveryProbe,
    WindowsManagedStdio, WindowsManagedStopSignalResult, WindowsManagedTerminalOutput,
    prepare_suspended_into_job, probe_managed_process_recovery,
};

#[cfg(all(windows, target_arch = "x86_64"))]
pub use windows::WindowsDiscoveryBackend;
