use std::sync::atomic::{Ordering, compiler_fence};

use domain::{AppError, ErrorCode};
use sha2::{Digest, Sha256};

pub const MAX_CREDENTIAL_SECRET_BYTES: usize = 2_560;
pub const MAX_CREDENTIAL_PROFILE_ID_BYTES: usize = 256;
pub const MAX_CREDENTIAL_ENVIRONMENT_NAME_BYTES: usize = 256;

const REFERENCE_PREFIX: &str = "mtcred1:";
const INTERNAL_REFERENCE_PREFIX: &str = "mtcred-internal1:";
const HASH_HEX_BYTES: usize = 64;
const RANDOM_BYTES: usize = 32;
const REFERENCE_BYTES: usize = REFERENCE_PREFIX.len() + HASH_HEX_BYTES + 1 + HASH_HEX_BYTES;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InternalCredentialPurpose {
    ProfileSaveRequestHmacKeyV1,
}

impl InternalCredentialPurpose {
    fn label(self) -> &'static str {
        match self {
            Self::ProfileSaveRequestHmacKeyV1 => "profile-save-request-hmac-key-v1",
        }
    }
}

/// Secret material kept out of serialization, cloning, and debug output.
pub struct SecretBytes {
    bytes: Vec<u8>,
}

impl SecretBytes {
    pub fn from_utf8(value: String) -> Result<Self, AppError> {
        Self::from_bytes(value.into_bytes())
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, AppError> {
        if bytes.len() > MAX_CREDENTIAL_SECRET_BYTES {
            return Err(invalid_secret(
                "exceeds the portable system credential size",
            ));
        }
        if bytes.contains(&0) {
            return Err(invalid_secret("must not contain NUL"));
        }
        if std::str::from_utf8(&bytes).is_err() {
            return Err(invalid_secret("must contain valid UTF-8"));
        }
        Ok(Self { bytes })
    }

    /// Exposes secret bytes only at the platform boundary that needs them.
    pub fn expose(&self) -> &[u8] {
        &self.bytes
    }

    pub fn expose_utf8(&self) -> &str {
        std::str::from_utf8(&self.bytes).expect("SecretBytes validates UTF-8 at construction")
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        for byte in &mut self.bytes {
            // Volatile writes keep this best-effort clearing step from being
            // optimized away. Copies made by operating-system APIs remain
            // governed by those APIs.
            unsafe { std::ptr::write_volatile(byte, 0) };
        }
        compiler_fence(Ordering::SeqCst);
    }
}

#[derive(Clone, Eq, Hash, PartialEq)]
pub struct CredentialSlot {
    profile_id: String,
    environment_name: String,
}

impl CredentialSlot {
    pub fn new(profile_id: String, environment_name: String) -> Result<Self, AppError> {
        validate_profile_id(&profile_id)?;
        validate_environment_name(&environment_name)?;
        Ok(Self {
            profile_id,
            environment_name,
        })
    }

    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }

    pub fn environment_name(&self) -> &str {
        &self.environment_name
    }

    fn digest(&self) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(b"MagicTools credential slot v1\0");
        digest.update((self.profile_id.len() as u64).to_be_bytes());
        digest.update(self.profile_id.as_bytes());
        digest.update((self.environment_name.len() as u64).to_be_bytes());
        digest.update(self.environment_name.as_bytes());
        digest.finalize().into()
    }
}

/// Opaque, non-secret reference stored in SQLite. Its slot hash prevents a
/// client from moving a credential reference to another profile or variable.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct CredentialReference {
    value: String,
}

impl CredentialReference {
    pub fn generate(slot: &CredentialSlot) -> Result<Self, AppError> {
        let mut random = [0_u8; RANDOM_BYTES];
        getrandom::fill(&mut random).map_err(|error| {
            let mut result = AppError::new(
                ErrorCode::Internal,
                "failed to generate a system credential reference",
            );
            result.details.insert("reason".into(), error.to_string());
            result
        })?;
        let value = format!(
            "{REFERENCE_PREFIX}{}:{}",
            encode_lower_hex(&slot.digest()),
            encode_lower_hex(&random)
        );
        random.fill(0);
        Ok(Self { value })
    }

    pub fn for_internal_purpose(purpose: InternalCredentialPurpose) -> Self {
        let label = purpose.label();
        let mut digest = Sha256::new();
        digest.update(b"MagicTools internal credential reference v1\0");
        digest.update((label.len() as u64).to_be_bytes());
        digest.update(label.as_bytes());
        let value = format!(
            "{INTERNAL_REFERENCE_PREFIX}{}",
            encode_lower_hex(&digest.finalize())
        );
        Self { value }
    }

    pub fn parse(value: &str) -> Result<Self, AppError> {
        if value.len() != REFERENCE_BYTES {
            return Err(invalid_reference("has an invalid length"));
        }
        let Some(body) = value.strip_prefix(REFERENCE_PREFIX) else {
            return Err(invalid_reference("uses an unsupported version"));
        };
        let Some((slot_hash, random)) = body.split_once(':') else {
            return Err(invalid_reference("has an invalid structure"));
        };
        if !valid_lower_hex(slot_hash, HASH_HEX_BYTES) || !valid_lower_hex(random, HASH_HEX_BYTES) {
            return Err(invalid_reference(
                "must use canonical lowercase hexadecimal fields",
            ));
        }
        Ok(Self {
            value: value.to_owned(),
        })
    }

    pub fn as_str(&self) -> &str {
        &self.value
    }

    pub fn belongs_to(&self, slot: &CredentialSlot) -> bool {
        let Some(body) = self.value.strip_prefix(REFERENCE_PREFIX) else {
            return false;
        };
        let Some((slot_hash, _)) = body.split_once(':') else {
            return false;
        };
        slot_hash.as_bytes() == encode_lower_hex(&slot.digest()).as_bytes()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialDeleteOutcome {
    Deleted,
    NotFound,
}

pub trait SecretStore: Send + Sync {
    fn put(&self, reference: &CredentialReference, secret: &SecretBytes) -> Result<(), AppError>;

    fn get(&self, reference: &CredentialReference) -> Result<SecretBytes, AppError>;

    fn delete(&self, reference: &CredentialReference) -> Result<CredentialDeleteOutcome, AppError>;
}

fn validate_profile_id(value: &str) -> Result<(), AppError> {
    if value.is_empty()
        || value.trim().is_empty()
        || value.len() > MAX_CREDENTIAL_PROFILE_ID_BYTES
        || value.contains('\0')
    {
        return Err(invalid_reference("uses an invalid profile identity"));
    }
    Ok(())
}

fn validate_environment_name(value: &str) -> Result<(), AppError> {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return Err(invalid_reference("uses an empty environment name"));
    };
    if value.len() > MAX_CREDENTIAL_ENVIRONMENT_NAME_BYTES
        || !(first.is_ascii_alphabetic() || first == b'_')
        || !bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(invalid_reference("uses an invalid environment name"));
    }
    Ok(())
}

fn encode_lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn valid_lower_hex(value: &str, expected_bytes: usize) -> bool {
    value.len() == expected_bytes
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn invalid_reference(reason: &'static str) -> AppError {
    let mut error = AppError::new(
        ErrorCode::InvalidArgument,
        "invalid system credential reference",
    );
    error
        .details
        .insert("field".into(), "credentialReference".into());
    error.details.insert("reason".into(), reason.into());
    error
}

fn invalid_secret(reason: &'static str) -> AppError {
    let mut error = AppError::new(
        ErrorCode::InvalidArgument,
        "invalid system credential secret",
    );
    error.details.insert("field".into(), "secret".into());
    error.details.insert("reason".into(), reason.into());
    error
}
