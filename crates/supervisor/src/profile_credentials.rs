use domain::{
    AppError, CredentialReferenceLaunchEnvironmentValue, DeleteLaunchProfileRequest,
    DeleteLaunchProfileResponse, ErrorCode, LaunchEnvironmentEntry, LaunchEnvironmentValue,
    LaunchProfile, LaunchProfileInput, ListLaunchProfilesRequest, ListLaunchProfilesResponse,
    SaveLaunchProfileRequest, SaveLaunchProfileWithSecretsRequest,
};
use platform_common::credentials::{
    CredentialReference, CredentialSlot, InternalCredentialPurpose, SecretBytes, SecretStore,
};
use storage::{
    PreparedCatalogMutation, PrivateDatabasePath, ProfileSecretCredential, SupervisorRepository,
    launch_profile_save_request_hmac_sha256,
};

#[cfg(target_os = "macos")]
type SystemCredentialStore = platform_macos::MacosCredentialStore;
#[cfg(windows)]
type SystemCredentialStore = platform_windows::WindowsCredentialStore;

const CREDENTIAL_CLEANUP_BATCH_SIZE: u16 = 64;
const MAX_CREDENTIAL_CLEANUP_PASSES: usize = 4;
const PROFILE_MUTATION_HMAC_KEY_BYTES: usize = 32;
const PROFILE_MUTATION_HMAC_KEY_HEX_BYTES: usize = PROFILE_MUTATION_HMAC_KEY_BYTES * 2;

struct ProfileMutationHmacKey([u8; PROFILE_MUTATION_HMAC_KEY_BYTES]);

impl ProfileMutationHmacKey {
    fn expose(&self) -> &[u8; PROFILE_MUTATION_HMAC_KEY_BYTES] {
        &self.0
    }
}

impl Drop for ProfileMutationHmacKey {
    fn drop(&mut self) {
        for byte in &mut self.0 {
            unsafe { std::ptr::write_volatile(byte, 0) };
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum CredentialCleanupStatus {
    Complete { acknowledged: u16 },
    Pending { acknowledged: u16 },
    Deferred { acknowledged: u16, error: AppError },
}

pub struct ProfileMutation<T> {
    value: T,
    credential_cleanup: CredentialCleanupStatus,
}

impl<T> ProfileMutation<T> {
    pub fn value(&self) -> &T {
        &self.value
    }

    pub fn credential_cleanup(&self) -> &CredentialCleanupStatus {
        &self.credential_cleanup
    }

    pub fn into_parts(self) -> (T, CredentialCleanupStatus) {
        (self.value, self.credential_cleanup)
    }
}

/// Supervisor-owned profile boundary that always pairs SQLite mutations with
/// the current platform's private system credential store.
pub struct ProfileService {
    repository: SupervisorRepository,
    credential_store: SystemCredentialStore,
    profile_mutation_hmac_key: ProfileMutationHmacKey,
    startup_cleanup: CredentialCleanupStatus,
}

impl ProfileService {
    pub async fn open(database_path: PrivateDatabasePath) -> Result<Self, AppError> {
        let repository = SupervisorRepository::open(database_path).await?;
        let credential_store = SystemCredentialStore::new();
        let profile_mutation_hmac_key =
            match initialize_profile_mutation_hmac_key(&repository, &credential_store).await {
                Ok(key) => key,
                Err(error) => {
                    repository.close().await;
                    return Err(error);
                }
            };
        let mut service = Self {
            repository,
            credential_store,
            profile_mutation_hmac_key,
            startup_cleanup: CredentialCleanupStatus::Complete { acknowledged: 0 },
        };
        service.startup_cleanup = service.drain_credential_cleanup().await;
        Ok(service)
    }

    pub fn startup_cleanup(&self) -> &CredentialCleanupStatus {
        &self.startup_cleanup
    }

    pub(crate) async fn profile(&self, profile_id: &str) -> Result<LaunchProfile, AppError> {
        self.repository.launch_profile(profile_id).await
    }

    pub(crate) async fn list(
        &self,
        request: &ListLaunchProfilesRequest,
    ) -> Result<ListLaunchProfilesResponse, AppError> {
        self.repository.launch_profiles(request).await
    }

    pub(crate) async fn replay_save(
        &self,
        operation_id: &str,
        method: &str,
        request: &SaveLaunchProfileWithSecretsRequest,
    ) -> Result<Option<LaunchProfile>, AppError> {
        let request_hmac = launch_profile_save_request_hmac_sha256(
            request,
            self.profile_mutation_hmac_key.expose(),
        )?;
        self.repository
            .replay_launch_profile_save(operation_id, method, request, &request_hmac)
            .await
    }

    pub(crate) async fn replay_delete(
        &self,
        operation_id: &str,
        method: &str,
        request: &DeleteLaunchProfileRequest,
    ) -> Result<Option<DeleteLaunchProfileResponse>, AppError> {
        self.repository
            .replay_catalog_mutation(
                operation_id,
                method,
                request,
                lifecycle::validate_delete_launch_profile_response,
            )
            .await
    }

    pub async fn save(
        &mut self,
        operation_id: &str,
        method: &str,
        request: SaveLaunchProfileWithSecretsRequest,
        server_profile: LaunchProfile,
    ) -> Result<ProfileMutation<LaunchProfile>, AppError> {
        let result = save_launch_profile_with_secrets(
            &mut self.repository,
            &self.credential_store,
            &self.profile_mutation_hmac_key,
            operation_id,
            method,
            request,
            server_profile,
        )
        .await;
        let credential_cleanup = self.drain_credential_cleanup().await;
        match result {
            Ok(profile) => Ok(ProfileMutation {
                value: profile,
                credential_cleanup,
            }),
            Err(mut error) => {
                error.details.insert(
                    "credentialCleanup".into(),
                    credential_cleanup_label(&credential_cleanup).into(),
                );
                Err(error)
            }
        }
    }

    pub async fn delete(
        &mut self,
        operation_id: &str,
        method: &str,
        request: &DeleteLaunchProfileRequest,
        recorded_at: &str,
    ) -> Result<ProfileMutation<DeleteLaunchProfileResponse>, AppError> {
        let result = match self
            .repository
            .prepare_delete_launch_profile(operation_id, method, request, recorded_at)
            .await
        {
            Ok(prepared) => commit_profile_mutation(prepared, operation_id).await,
            Err(error) => Err(error),
        };
        let credential_cleanup = self.drain_credential_cleanup().await;
        match result {
            Ok(response) => Ok(ProfileMutation {
                value: response,
                credential_cleanup,
            }),
            Err(mut error) => {
                error.details.insert(
                    "credentialCleanup".into(),
                    credential_cleanup_label(&credential_cleanup).into(),
                );
                Err(error)
            }
        }
    }

    pub async fn drain_credential_cleanup(&mut self) -> CredentialCleanupStatus {
        let mut acknowledged = 0_u16;
        for _ in 0..MAX_CREDENTIAL_CLEANUP_PASSES {
            match self
                .repository
                .drain_credential_cleanup(&self.credential_store, CREDENTIAL_CLEANUP_BATCH_SIZE)
                .await
            {
                Ok(count) => {
                    acknowledged = acknowledged.saturating_add(count);
                    if count < CREDENTIAL_CLEANUP_BATCH_SIZE {
                        return CredentialCleanupStatus::Complete { acknowledged };
                    }
                }
                Err(error) => {
                    return CredentialCleanupStatus::Deferred {
                        acknowledged,
                        error,
                    };
                }
            }
        }
        match self
            .repository
            .drain_credential_cleanup(&self.credential_store, 1)
            .await
        {
            Ok(0) => CredentialCleanupStatus::Complete { acknowledged },
            Ok(count) => CredentialCleanupStatus::Pending {
                acknowledged: acknowledged.saturating_add(count),
            },
            Err(error) => CredentialCleanupStatus::Deferred {
                acknowledged,
                error,
            },
        }
    }

    pub(crate) fn launch_resources(&mut self) -> (&mut SupervisorRepository, &dyn SecretStore) {
        (&mut self.repository, &self.credential_store)
    }

    pub(crate) fn repository_mut(&mut self) -> &mut SupervisorRepository {
        &mut self.repository
    }
}

async fn initialize_profile_mutation_hmac_key(
    repository: &SupervisorRepository,
    credential_store: &dyn SecretStore,
) -> Result<ProfileMutationHmacKey, AppError> {
    let has_profile_save_mutations = repository.has_launch_profile_save_mutations().await?;
    let reference = CredentialReference::for_internal_purpose(
        InternalCredentialPurpose::ProfileSaveRequestHmacKeyV1,
    );
    match credential_store.get(&reference) {
        Ok(secret) => decode_profile_mutation_hmac_key(&secret),
        Err(error) if error.code == ErrorCode::NotFound && has_profile_save_mutations => {
            Err(missing_profile_mutation_hmac_key())
        }
        Err(error) if error.code == ErrorCode::NotFound => {
            create_profile_mutation_hmac_key(credential_store, &reference)?;
            let persisted = credential_store.get(&reference)?;
            decode_profile_mutation_hmac_key(&persisted)
        }
        Err(error) => Err(error),
    }
}

fn create_profile_mutation_hmac_key(
    credential_store: &dyn SecretStore,
    reference: &CredentialReference,
) -> Result<(), AppError> {
    let mut key = [0_u8; PROFILE_MUTATION_HMAC_KEY_BYTES];
    if let Err(source) = getrandom::fill(&mut key) {
        wipe_secret_bytes(&mut key);
        let mut error = AppError::new(
            ErrorCode::PlatformError,
            "failed to generate the profile mutation authentication key",
        );
        error.retryable = true;
        error.details.insert("reason".into(), source.to_string());
        return Err(error);
    }
    let encoded = encode_lower_hex(&key);
    wipe_secret_bytes(&mut key);
    let secret =
        SecretBytes::from_utf8(encoded).map_err(|_| invalid_profile_mutation_hmac_key())?;
    credential_store.put(reference, &secret)
}

fn decode_profile_mutation_hmac_key(
    secret: &SecretBytes,
) -> Result<ProfileMutationHmacKey, AppError> {
    let encoded = secret.expose();
    if encoded.len() != PROFILE_MUTATION_HMAC_KEY_HEX_BYTES {
        return Err(invalid_profile_mutation_hmac_key());
    }
    let mut key = [0_u8; PROFILE_MUTATION_HMAC_KEY_BYTES];
    for index in 0..key.len() {
        let high = decode_lower_hex_nibble(encoded[index * 2]);
        let low = decode_lower_hex_nibble(encoded[index * 2 + 1]);
        let (Some(high), Some(low)) = (high, low) else {
            wipe_secret_bytes(&mut key);
            return Err(invalid_profile_mutation_hmac_key());
        };
        key[index] = (high << 4) | low;
    }
    Ok(ProfileMutationHmacKey(key))
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

fn decode_lower_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn wipe_secret_bytes(bytes: &mut [u8]) {
    for byte in bytes {
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

fn missing_profile_mutation_hmac_key() -> AppError {
    let mut error = AppError::new(
        ErrorCode::StorageError,
        "profile mutation replay authentication key is missing",
    );
    error
        .details
        .insert("state".into(), "missingKeyWithExistingLedger".into());
    error
}

fn invalid_profile_mutation_hmac_key() -> AppError {
    let mut error = AppError::new(
        ErrorCode::PlatformError,
        "profile mutation replay authentication key is invalid",
    );
    error
        .details
        .insert("state".into(), "invalidCredentialMaterial".into());
    error
}

/// Materializes write-only environment secrets into system-backed references
/// and persists only the resulting reference-bearing profile.
async fn save_launch_profile_with_secrets(
    repository: &mut SupervisorRepository,
    credential_store: &dyn SecretStore,
    profile_mutation_hmac_key: &ProfileMutationHmacKey,
    operation_id: &str,
    method: &str,
    request: SaveLaunchProfileWithSecretsRequest,
    mut server_profile: LaunchProfile,
) -> Result<LaunchProfile, AppError> {
    lifecycle::validate_save_launch_profile_with_secrets_request(&request)?;
    ensure_initial_input_matches(&request.request, &server_profile)?;
    lifecycle::validate_launch_profile(&server_profile)?;
    let original_request_hmac =
        launch_profile_save_request_hmac_sha256(&request, profile_mutation_hmac_key.expose())?;

    let SaveLaunchProfileWithSecretsRequest {
        mut request,
        secret_environment,
    } = request;
    let mut secret_credentials = Vec::with_capacity(secret_environment.len());
    for mut entry in secret_environment {
        let slot = CredentialSlot::new(server_profile.id.clone(), entry.name.clone())?;
        let reference = CredentialReference::generate(&slot)?;
        repository.stage_credential_cleanup(&reference).await?;

        let secret = SecretBytes::from_utf8(std::mem::take(&mut entry.secret))?;
        credential_store.put(&reference, &secret)?;
        drop(secret);
        let name = std::mem::take(&mut entry.name);
        let credential_reference = reference.as_str().to_owned();
        secret_credentials.push(ProfileSecretCredential {
            name: name.clone(),
            credential_reference: credential_reference.clone(),
        });
        replace_environment_secret(&mut server_profile.input, name, credential_reference);
    }
    server_profile
        .input
        .environment
        .sort_by(|left, right| left.name.cmp(&right.name));
    replace_request_input(&mut request, server_profile.input.clone());
    let prepared = repository
        .prepare_save_launch_profile(
            operation_id,
            method,
            &original_request_hmac,
            &request,
            &server_profile,
            &secret_credentials,
            credential_store,
        )
        .await?;
    commit_profile_mutation(prepared, operation_id).await
}

async fn commit_profile_mutation<T>(
    prepared: PreparedCatalogMutation<T>,
    operation_id: &str,
) -> Result<T, AppError> {
    prepared.commit().await.map_err(|mut error| {
        error.operation_id = Some(operation_id.to_owned());
        error.retryable = true;
        error
            .details
            .insert("profileMutationFailurePhase".into(), "commit".into());
        error
    })
}

fn credential_cleanup_label(status: &CredentialCleanupStatus) -> &'static str {
    match status {
        CredentialCleanupStatus::Complete { .. } => "complete",
        CredentialCleanupStatus::Pending { .. } => "pending",
        CredentialCleanupStatus::Deferred { .. } => "deferred",
    }
}

fn ensure_initial_input_matches(
    request: &SaveLaunchProfileRequest,
    server_profile: &LaunchProfile,
) -> Result<(), AppError> {
    let (profile_id, input) = match request {
        SaveLaunchProfileRequest::Create(request) => (None, &request.input),
        SaveLaunchProfileRequest::Update(request) => {
            (Some(request.profile_id.as_str()), &request.input)
        }
    };
    if profile_id.is_some_and(|profile_id| profile_id != server_profile.id)
        || input != &server_profile.input
    {
        let mut error = AppError::new(
            ErrorCode::Internal,
            "server-owned launch profile does not match the secret save request",
        );
        error.details.insert("field".into(), "input".into());
        return Err(error);
    }
    Ok(())
}

fn replace_environment_secret(
    input: &mut LaunchProfileInput,
    name: String,
    credential_reference: String,
) {
    let value =
        LaunchEnvironmentValue::CredentialReference(CredentialReferenceLaunchEnvironmentValue {
            credential_reference,
        });
    let windows = cfg!(windows);
    if let Some(existing) = input
        .environment
        .iter_mut()
        .find(|entry| environment_names_equal(&entry.name, &name, windows))
    {
        existing.name = name;
        existing.value = value;
    } else {
        input
            .environment
            .push(LaunchEnvironmentEntry { name, value });
    }
}

fn replace_request_input(request: &mut SaveLaunchProfileRequest, input: LaunchProfileInput) {
    match request {
        SaveLaunchProfileRequest::Create(request) => request.input = input,
        SaveLaunchProfileRequest::Update(request) => request.input = input,
    }
}

fn environment_names_equal(left: &str, right: &str, windows: bool) -> bool {
    if windows {
        left.eq_ignore_ascii_case(right)
    } else {
        left == right
    }
}
