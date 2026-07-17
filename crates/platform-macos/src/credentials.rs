use std::ffi::{c_char, c_void};
use std::ptr::{self, NonNull};

use domain::{AppError, ErrorCode};
use platform_common::credentials::{
    CredentialDeleteOutcome, CredentialReference, MAX_CREDENTIAL_SECRET_BYTES, SecretBytes,
    SecretStore,
};

const SERVICE_NAME: &[u8] = b"com.local.devprocessmanager.profile-env";

const ERR_SEC_SUCCESS: i32 = 0;
const ERR_SEC_USER_CANCELED: i32 = -128;
const ERR_SEC_NOT_AVAILABLE: i32 = -25_291;
const ERR_SEC_READ_ONLY: i32 = -25_292;
const ERR_SEC_AUTH_FAILED: i32 = -25_293;
const ERR_SEC_DUPLICATE_ITEM: i32 = -25_299;
const ERR_SEC_ITEM_NOT_FOUND: i32 = -25_300;
const ERR_SEC_INTERACTION_NOT_ALLOWED: i32 = -25_308;

/// Generic-password storage in the current user's default macOS Keychain.
#[derive(Clone, Copy, Debug, Default)]
pub struct MacosCredentialStore;

impl MacosCredentialStore {
    pub const fn new() -> Self {
        Self
    }
}

impl SecretStore for MacosCredentialStore {
    fn put(&self, reference: &CredentialReference, secret: &SecretBytes) -> Result<(), AppError> {
        let account = reference.as_str().as_bytes();
        if let Some(item) = find_item(account)? {
            return modify_item(&item, secret.expose());
        }

        match add_item(account, secret.expose())? {
            AddOutcome::Added => Ok(()),
            AddOutcome::AlreadyExists => {
                let item = find_item(account)?.ok_or_else(|| {
                    keychain_state_error(
                        "addGenericPassword",
                        "duplicate item disappeared before overwrite",
                    )
                })?;
                modify_item(&item, secret.expose())
            }
        }
    }

    fn get(&self, reference: &CredentialReference) -> Result<SecretBytes, AppError> {
        let account = reference.as_str().as_bytes();
        let service_length = native_length(SERVICE_NAME.len(), "findGenericPassword")?;
        let account_length = native_length(account.len(), "findGenericPassword")?;
        let mut password_length = 0_u32;
        let mut password_data = ptr::null_mut();
        let mut item = ptr::null_mut();

        // Safety: all byte slices remain live for the call, explicit lengths
        // match them, and each out pointer addresses initialized writable data.
        let status = unsafe {
            SecKeychainFindGenericPassword(
                ptr::null(),
                service_length,
                SERVICE_NAME.as_ptr().cast(),
                account_length,
                account.as_ptr().cast(),
                &mut password_length,
                &mut password_data,
                &mut item,
            )
        };
        let password = KeychainPasswordBuffer::from_raw(password_data, password_length);
        let item = KeychainItem::from_raw(item);

        match status {
            ERR_SEC_SUCCESS => {
                let _item = item.ok_or_else(|| {
                    keychain_state_error(
                        "findGenericPassword",
                        "Keychain returned no item for a successful lookup",
                    )
                })?;
                let password = password?;
                if password.len() > MAX_CREDENTIAL_SECRET_BYTES {
                    return Err(keychain_state_error(
                        "findGenericPassword",
                        "stored password exceeds the portable credential size",
                    ));
                }
                let password_bytes = password.as_bytes()?;
                if password_bytes.contains(&0) || std::str::from_utf8(password_bytes).is_err() {
                    return Err(keychain_state_error(
                        "findGenericPassword",
                        "stored password violates the portable credential format",
                    ));
                }
                SecretBytes::from_bytes(password_bytes.to_vec()).map_err(|_| {
                    keychain_state_error(
                        "findGenericPassword",
                        "stored password violates the portable credential format",
                    )
                })
            }
            ERR_SEC_ITEM_NOT_FOUND => Err(keychain_error("findGenericPassword", status)),
            _ => Err(keychain_error("findGenericPassword", status)),
        }
    }

    fn delete(&self, reference: &CredentialReference) -> Result<CredentialDeleteOutcome, AppError> {
        let Some(item) = find_item(reference.as_str().as_bytes())? else {
            return Ok(CredentialDeleteOutcome::NotFound);
        };

        // Safety: the RAII guard owns a live item reference for this call.
        let status = unsafe { SecKeychainItemDelete(item.as_ptr()) };
        match status {
            ERR_SEC_SUCCESS => Ok(CredentialDeleteOutcome::Deleted),
            ERR_SEC_ITEM_NOT_FOUND => Ok(CredentialDeleteOutcome::NotFound),
            _ => Err(keychain_error("deleteItem", status)),
        }
    }
}

enum AddOutcome {
    Added,
    AlreadyExists,
}

fn find_item(account: &[u8]) -> Result<Option<KeychainItem>, AppError> {
    let service_length = native_length(SERVICE_NAME.len(), "findGenericPassword")?;
    let account_length = native_length(account.len(), "findGenericPassword")?;
    let mut item = ptr::null_mut();

    // Safety: the service and account slices remain live for the call, their
    // explicit lengths match, and item is a writable out pointer.
    let status = unsafe {
        SecKeychainFindGenericPassword(
            ptr::null(),
            service_length,
            SERVICE_NAME.as_ptr().cast(),
            account_length,
            account.as_ptr().cast(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut item,
        )
    };
    let item = KeychainItem::from_raw(item);

    match status {
        ERR_SEC_SUCCESS => item.map(Some).ok_or_else(|| {
            keychain_state_error(
                "findGenericPassword",
                "Keychain returned no item for a successful lookup",
            )
        }),
        ERR_SEC_ITEM_NOT_FOUND => Ok(None),
        _ => Err(keychain_error("findGenericPassword", status)),
    }
}

fn add_item(account: &[u8], secret: &[u8]) -> Result<AddOutcome, AppError> {
    let service_length = native_length(SERVICE_NAME.len(), "addGenericPassword")?;
    let account_length = native_length(account.len(), "addGenericPassword")?;
    let secret_length = native_length(secret.len(), "addGenericPassword")?;
    let mut item = ptr::null_mut();

    // Safety: every non-empty byte slice remains live for the call, its
    // explicit length matches, and item is a writable out pointer.
    let status = unsafe {
        SecKeychainAddGenericPassword(
            ptr::null(),
            service_length,
            SERVICE_NAME.as_ptr().cast(),
            account_length,
            account.as_ptr().cast(),
            secret_length,
            bytes_pointer(secret),
            &mut item,
        )
    };
    let item = KeychainItem::from_raw(item);

    match status {
        ERR_SEC_SUCCESS => {
            let _item = item.ok_or_else(|| {
                keychain_state_error(
                    "addGenericPassword",
                    "Keychain returned no item for a successful insert",
                )
            })?;
            Ok(AddOutcome::Added)
        }
        ERR_SEC_DUPLICATE_ITEM => Ok(AddOutcome::AlreadyExists),
        _ => Err(keychain_error("addGenericPassword", status)),
    }
}

fn modify_item(item: &KeychainItem, secret: &[u8]) -> Result<(), AppError> {
    let secret_length = native_length(secret.len(), "modifyItem")?;
    // Safety: item owns a live Keychain reference and the secret slice remains
    // live with the supplied length for the duration of the call.
    let status = unsafe {
        SecKeychainItemModifyAttributesAndData(
            item.as_ptr(),
            ptr::null(),
            secret_length,
            bytes_pointer(secret),
        )
    };
    if status == ERR_SEC_SUCCESS {
        Ok(())
    } else {
        Err(keychain_error("modifyItem", status))
    }
}

fn bytes_pointer(bytes: &[u8]) -> *const c_void {
    if bytes.is_empty() {
        ptr::null()
    } else {
        bytes.as_ptr().cast()
    }
}

fn native_length(length: usize, operation: &'static str) -> Result<u32, AppError> {
    u32::try_from(length).map_err(|_| {
        keychain_state_error(operation, "input exceeds the native Keychain length limit")
    })
}

fn keychain_error(operation: &'static str, status: i32) -> AppError {
    let code = match status {
        ERR_SEC_ITEM_NOT_FOUND => ErrorCode::NotFound,
        ERR_SEC_USER_CANCELED
        | ERR_SEC_READ_ONLY
        | ERR_SEC_AUTH_FAILED
        | ERR_SEC_INTERACTION_NOT_ALLOWED => ErrorCode::AccessDenied,
        _ => ErrorCode::PlatformError,
    };
    let message = match code {
        ErrorCode::NotFound => "macOS Keychain credential was not found",
        ErrorCode::AccessDenied => "macOS Keychain access was denied",
        _ => "macOS Keychain operation failed",
    };
    let mut error = AppError::new(code, message);
    error.details.insert("operation".into(), operation.into());
    error.details.insert("osStatus".into(), status.to_string());
    error.retryable = status == ERR_SEC_NOT_AVAILABLE;
    error
}

fn keychain_state_error(operation: &'static str, reason: &'static str) -> AppError {
    let mut error = AppError::new(
        ErrorCode::PlatformError,
        "macOS Keychain returned an invalid result",
    );
    error.details.insert("operation".into(), operation.into());
    error.details.insert("reason".into(), reason.into());
    error
}

struct KeychainItem(NonNull<c_void>);

impl KeychainItem {
    fn from_raw(item: *mut c_void) -> Option<Self> {
        NonNull::new(item).map(Self)
    }

    fn as_ptr(&self) -> *mut c_void {
        self.0.as_ptr()
    }
}

impl Drop for KeychainItem {
    fn drop(&mut self) {
        // Safety: this guard was constructed from a retained item reference
        // returned by Security.framework and releases it exactly once.
        unsafe { CFRelease(self.0.as_ptr().cast_const()) };
    }
}

struct KeychainPasswordBuffer {
    data: *mut c_void,
    length: u32,
}

impl KeychainPasswordBuffer {
    fn from_raw(data: *mut c_void, length: u32) -> Result<Self, AppError> {
        if data.is_null() && length != 0 {
            return Err(keychain_state_error(
                "findGenericPassword",
                "Keychain returned a null password buffer with a nonzero length",
            ));
        }
        Ok(Self { data, length })
    }

    fn len(&self) -> usize {
        self.length as usize
    }

    fn as_bytes(&self) -> Result<&[u8], AppError> {
        if self.length == 0 {
            return Ok(&[]);
        }
        let length = self.len();
        // Safety: Security.framework returned this buffer with exactly length
        // initialized password bytes and the guard keeps it live for the read.
        let bytes = unsafe { std::slice::from_raw_parts(self.data.cast::<u8>(), length) };
        Ok(bytes)
    }
}

impl Drop for KeychainPasswordBuffer {
    fn drop(&mut self) {
        // Safety: this is the exact buffer returned by the matching Keychain
        // lookup and it is handed back to Security.framework exactly once.
        if !self.data.is_null() {
            unsafe {
                let _ = SecKeychainItemFreeContent(ptr::null_mut(), self.data);
            }
        }
    }
}

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    fn SecKeychainAddGenericPassword(
        keychain: *const c_void,
        service_name_length: u32,
        service_name: *const c_char,
        account_name_length: u32,
        account_name: *const c_char,
        password_length: u32,
        password_data: *const c_void,
        item: *mut *mut c_void,
    ) -> i32;

    fn SecKeychainFindGenericPassword(
        keychain_or_array: *const c_void,
        service_name_length: u32,
        service_name: *const c_char,
        account_name_length: u32,
        account_name: *const c_char,
        password_length: *mut u32,
        password_data: *mut *mut c_void,
        item: *mut *mut c_void,
    ) -> i32;

    fn SecKeychainItemDelete(item: *mut c_void) -> i32;

    fn SecKeychainItemFreeContent(attributes: *mut c_void, data: *mut c_void) -> i32;

    fn SecKeychainItemModifyAttributesAndData(
        item: *mut c_void,
        attributes: *const c_void,
        length: u32,
        data: *const c_void,
    ) -> i32;
}

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFRelease(value: *const c_void);
}
