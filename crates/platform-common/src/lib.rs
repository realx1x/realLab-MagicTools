//! Shared platform adapter contracts.

pub mod credentials;
mod sensitive;

pub use sensitive::is_sensitive_field_name;
