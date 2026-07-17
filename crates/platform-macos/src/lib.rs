//! macOS process discovery adapter.

#![forbid(unsafe_op_in_unsafe_fn)]

#[cfg(all(target_os = "macos", not(target_pointer_width = "64")))]
compile_error!("platform-macos V1 supports only 64-bit macOS targets");

#[cfg(all(target_os = "macos", target_pointer_width = "64"))]
mod credentials;

#[cfg(all(target_os = "macos", target_pointer_width = "64"))]
mod external;

#[cfg(all(target_os = "macos", target_pointer_width = "64"))]
mod macos;

#[cfg(all(target_os = "macos", target_pointer_width = "64"))]
mod managed;

#[cfg(all(target_os = "macos", target_pointer_width = "64"))]
mod native;

#[cfg(all(target_os = "macos", target_pointer_width = "64"))]
pub use credentials::MacosCredentialStore;

#[cfg(all(target_os = "macos", target_pointer_width = "64"))]
pub use external::{MacosExternalStopResult, stop_external_process};

#[cfg(all(target_os = "macos", target_pointer_width = "64"))]
pub use managed::{
    MacosManagedExitPoll, MacosManagedLaunchError, MacosManagedLaunchRequest, MacosManagedProcess,
    MacosManagedRecoveryProbe, MacosManagedStdio, MacosManagedStopSignalResult,
    MacosManagedTerminalOutput, RecoveredMacosProcessGroup, SuspendedMacosManagedProcess,
    prepare_suspended_process_group, probe_recovered_process_group,
};

#[cfg(all(target_os = "macos", target_pointer_width = "64"))]
pub use macos::MacosDiscoveryBackend;
