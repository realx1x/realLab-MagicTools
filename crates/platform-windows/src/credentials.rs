use std::ffi::c_void;
use std::ptr::NonNull;
use std::sync::atomic::{Ordering, compiler_fence};

use domain::{AppError, ErrorCode};
use platform_common::credentials::{
    CredentialDeleteOutcome, CredentialReference, SecretBytes, SecretStore,
};
use windows::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_NOT_FOUND, WIN32_ERROR};
use windows::Win32::Security::Credentials::{
    CRED_MAX_CREDENTIAL_BLOB_SIZE, CRED_MAX_GENERIC_TARGET_NAME_LENGTH, CRED_PERSIST_LOCAL_MACHINE,
    CRED_TYPE_GENERIC, CREDENTIALW, CredDeleteW, CredFree, CredReadW, CredWriteW,
};
use windows::core::{Error as WindowsError, HRESULT, PCWSTR, PWSTR};

const TARGET_PREFIX: &str = "MagicTools/profile-env/";

#[derive(Clone, Copy, Debug, Default)]
pub struct WindowsCredentialStore;

impl WindowsCredentialStore {
    pub const fn new() -> Self {
        Self
    }
}

impl SecretStore for WindowsCredentialStore {
    fn put(&self, reference: &CredentialReference, secret: &SecretBytes) -> Result<(), AppError> {
        let mut target_name = target_name(reference)?;
        let blob_size = credential_blob_size(secret.expose().len())?;
        let credential = CREDENTIALW {
            Type: CRED_TYPE_GENERIC,
            TargetName: PWSTR(target_name.as_mut_ptr()),
            CredentialBlobSize: blob_size,
            CredentialBlob: secret.expose().as_ptr().cast_mut(),
            Persist: CRED_PERSIST_LOCAL_MACHINE,
            ..Default::default()
        };

        // CredWriteW copies the target and blob before returning.
        unsafe { CredWriteW(&credential, 0) }.map_err(|error| credential_api_error("write", &error))
    }

    fn get(&self, reference: &CredentialReference) -> Result<SecretBytes, AppError> {
        let target_name = target_name(reference)?;
        let mut raw_credential = std::ptr::null_mut();
        // A successful CredReadW call transfers an allocated buffer that must
        // be released with CredFree.
        if let Err(error) = unsafe {
            CredReadW(
                PCWSTR(target_name.as_ptr()),
                CRED_TYPE_GENERIC,
                None,
                &mut raw_credential,
            )
        } {
            if is_win32_error(&error, ERROR_NOT_FOUND) {
                return Err(credential_not_found());
            }
            return Err(credential_api_error("read", &error));
        }

        let mut credential = CredentialBuffer::new(raw_credential)?;
        let value = credential.copy_blob()?;
        secret_from_credential(value)
    }

    fn delete(&self, reference: &CredentialReference) -> Result<CredentialDeleteOutcome, AppError> {
        let target_name = target_name(reference)?;
        match unsafe { CredDeleteW(PCWSTR(target_name.as_ptr()), CRED_TYPE_GENERIC, None) } {
            Ok(()) => Ok(CredentialDeleteOutcome::Deleted),
            Err(error) if is_win32_error(&error, ERROR_NOT_FOUND) => {
                Ok(CredentialDeleteOutcome::NotFound)
            }
            Err(error) => Err(credential_api_error("delete", &error)),
        }
    }
}

struct CredentialBuffer {
    value: NonNull<CREDENTIALW>,
    clear_blob_bytes: usize,
}

impl CredentialBuffer {
    fn new(value: *mut CREDENTIALW) -> Result<Self, AppError> {
        NonNull::new(value)
            .map(|value| Self {
                value,
                clear_blob_bytes: 0,
            })
            .ok_or_else(|| {
                invalid_credential_buffer("credential API returned a null result buffer")
            })
    }

    fn copy_blob(&mut self) -> Result<SensitiveBuffer, AppError> {
        // The allocation remains owned by this guard for the duration of the
        // structure and blob reads.
        let credential = unsafe { self.value.as_ref() };
        if credential.Type != CRED_TYPE_GENERIC {
            return Err(invalid_credential_buffer(
                "credential API returned an unexpected credential type",
            ));
        }

        let size = usize::try_from(credential.CredentialBlobSize)
            .map_err(|_| invalid_credential_buffer("credential blob size cannot be represented"))?;
        let maximum = usize::try_from(CRED_MAX_CREDENTIAL_BLOB_SIZE).map_err(|_| {
            invalid_credential_buffer("credential blob limit cannot be represented")
        })?;
        if size > maximum {
            return Err(invalid_credential_buffer(
                "credential blob exceeds the platform limit",
            ));
        }
        if size == 0 {
            return Ok(SensitiveBuffer::new(Vec::new()));
        }
        if credential.CredentialBlob.is_null() {
            return Err(invalid_credential_buffer(
                "credential API returned a null blob",
            ));
        }
        self.clear_blob_bytes = size;

        // The validated blob lies within the CredReadW allocation and is
        // copied before the allocation guard is dropped.
        let bytes = unsafe { std::slice::from_raw_parts(credential.CredentialBlob, size) };
        Ok(SensitiveBuffer::new(bytes.to_vec()))
    }
}

impl Drop for CredentialBuffer {
    fn drop(&mut self) {
        if self.clear_blob_bytes > 0 {
            let credential = unsafe { self.value.as_ref() };
            for offset in 0..self.clear_blob_bytes {
                // copy_blob records this length only after validating the
                // blob pointer and the platform size limit.
                unsafe { std::ptr::write_volatile(credential.CredentialBlob.add(offset), 0) };
            }
            compiler_fence(Ordering::SeqCst);
        }
        // CredReadW documents CredFree as the matching allocator release.
        unsafe { CredFree(self.value.as_ptr().cast::<c_void>()) };
    }
}

struct SensitiveBuffer {
    bytes: Option<Vec<u8>>,
}

impl SensitiveBuffer {
    fn new(bytes: Vec<u8>) -> Self {
        Self { bytes: Some(bytes) }
    }

    fn expose(&self) -> &[u8] {
        self.bytes.as_deref().unwrap_or_default()
    }

    fn take(&mut self) -> Vec<u8> {
        self.bytes.take().unwrap_or_default()
    }
}

impl Drop for SensitiveBuffer {
    fn drop(&mut self) {
        if let Some(bytes) = &mut self.bytes {
            for byte in bytes {
                unsafe { std::ptr::write_volatile(byte, 0) };
            }
            compiler_fence(Ordering::SeqCst);
        }
    }
}

fn target_name(reference: &CredentialReference) -> Result<Vec<u16>, AppError> {
    let value = format!("{TARGET_PREFIX}{}", reference.as_str());
    if value.contains('\0') {
        return Err(invalid_target_name("contains NUL"));
    }

    let mut encoded: Vec<u16> = value.encode_utf16().collect();
    let maximum = usize::try_from(CRED_MAX_GENERIC_TARGET_NAME_LENGTH)
        .map_err(|_| invalid_target_name("platform target length cannot be represented"))?;
    if encoded.len() > maximum {
        return Err(invalid_target_name("exceeds the platform target length"));
    }
    encoded.push(0);
    Ok(encoded)
}

fn credential_blob_size(size: usize) -> Result<u32, AppError> {
    let converted = u32::try_from(size)
        .map_err(|_| invalid_secret_size("cannot be represented by the credential API"))?;
    if converted > CRED_MAX_CREDENTIAL_BLOB_SIZE {
        return Err(invalid_secret_size("exceeds the platform credential limit"));
    }
    Ok(converted)
}

fn secret_from_credential(mut value: SensitiveBuffer) -> Result<SecretBytes, AppError> {
    if value.expose().contains(&0) || std::str::from_utf8(value.expose()).is_err() {
        return Err(invalid_credential_buffer(
            "stored credential is not valid UTF-8 secret data",
        ));
    }

    // This call cannot fail after the platform size and content validation
    // above. Keep the error mapped to a platform response if the shared
    // contract is tightened in the future.
    SecretBytes::from_bytes(value.take()).map_err(|_| {
        invalid_credential_buffer("stored credential does not satisfy the secret contract")
    })
}

fn is_win32_error(error: &WindowsError, code: WIN32_ERROR) -> bool {
    error.code() == HRESULT::from_win32(code.0)
}

fn credential_not_found() -> AppError {
    AppError::new(ErrorCode::NotFound, "system credential was not found")
}

fn credential_api_error(operation: &'static str, source: &WindowsError) -> AppError {
    let access_denied = is_win32_error(source, ERROR_ACCESS_DENIED);
    let mut error = AppError::new(
        if access_denied {
            ErrorCode::AccessDenied
        } else {
            ErrorCode::PlatformError
        },
        if access_denied {
            "system credential access was denied"
        } else {
            "Windows credential operation failed"
        },
    );
    error.retryable = !access_denied;
    error.details.insert("operation".into(), operation.into());
    error.details.insert(
        "hresult".into(),
        format!("0x{:08X}", source.code().0 as u32),
    );
    error
}

fn invalid_target_name(reason: &'static str) -> AppError {
    let mut error = AppError::new(
        ErrorCode::InvalidArgument,
        "invalid Windows credential target",
    );
    error.details.insert("reason".into(), reason.into());
    error
}

fn invalid_secret_size(reason: &'static str) -> AppError {
    let mut error = AppError::new(
        ErrorCode::InvalidArgument,
        "invalid Windows credential secret",
    );
    error.details.insert("reason".into(), reason.into());
    error
}

fn invalid_credential_buffer(reason: &'static str) -> AppError {
    let mut error = AppError::new(
        ErrorCode::PlatformError,
        "Windows credential data is invalid",
    );
    error.details.insert("reason".into(), reason.into());
    error
}
