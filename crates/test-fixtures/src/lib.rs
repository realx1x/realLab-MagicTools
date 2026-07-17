//! Explicitly authorized lifecycle, networking, and logging fixtures.
//!
//! The fixture runtime is intentionally not part of this library's public API. It is
//! compiled here only for target coverage when Cargo checks the library test target.

#[cfg(all(
    test,
    any(
        all(windows, target_arch = "x86_64"),
        all(
            target_os = "macos",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    )
))]
#[allow(dead_code)]
#[path = "runtime/mod.rs"]
mod runtime;
