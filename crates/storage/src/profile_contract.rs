use std::collections::HashSet;

use domain::{
    AppError, CreateLaunchProfileRequest, DeleteLaunchProfileRequest, DeleteLaunchProfileResponse,
    DirectLaunch, ErrorCode, LaunchEnvironmentEntry as DomainEnvironmentEntry,
    LaunchEnvironmentValue, LaunchExecution, LaunchProfile as DomainLaunchProfile,
    LaunchProfileInput, ListLaunchProfilesRequest, ListLaunchProfilesResponse,
    SaveLaunchProfileRequest, SaveLaunchProfileWithSecretsRequest, ShellKind, ShellLaunch,
    UpdateLaunchProfileRequest,
};
use platform_common::credentials::{CredentialReference, CredentialSlot, SecretStore};
use serde::{Deserialize, Serialize};

use crate::error::storage_error;
use crate::models::{
    LaunchProfile as StoredLaunchProfile, LaunchProfileCursor, LaunchProfileEnvironment,
    LaunchProfileWithEnvironment,
};
use crate::project_rule_contract::{
    canonical_typed_request_hmac_sha256, canonical_typed_request_sha256,
    insert_catalog_mutation_result, reserve_catalog_mutation, serialize_catalog_mutation_result,
};
use crate::{PreparedCatalogMutation, StorageResult, SupervisorRepository};

const CURSOR_PREFIX: &str = "lpc1|";
const MAX_PROFILE_ID_BYTES: usize = 256;
const MAX_PROFILE_REPLAY_CREDENTIALS: usize = 256;

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LaunchProfileSaveReplay {
    profile_id: String,
    created_at: String,
    updated_at: String,
    secret_credentials: Vec<ProfileSecretCredential>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProfileSecretCredential {
    pub name: String,
    pub credential_reference: String,
}

pub fn launch_profile_save_request_hmac_sha256(
    request: &SaveLaunchProfileWithSecretsRequest,
    key: &[u8; 32],
) -> StorageResult<[u8; 32]> {
    lifecycle::validate_save_launch_profile_with_secrets_request(request)?;
    canonical_typed_request_hmac_sha256(request, key)
}

impl SupervisorRepository {
    pub async fn has_launch_profile_save_mutations(&self) -> StorageResult<bool> {
        sqlx::query_scalar::<_, i64>(
            "SELECT EXISTS(SELECT 1 FROM catalog_mutation_ledger \
             WHERE method = 'profile.save')",
        )
        .fetch_one(&self.pool)
        .await
        .map(|present| present != 0)
        .map_err(|error| storage_error("check launch profile save mutation ledger", error))
    }

    pub async fn replay_launch_profile_save(
        &self,
        operation_id: &str,
        method: &str,
        request: &SaveLaunchProfileWithSecretsRequest,
        request_hmac: &[u8; 32],
    ) -> StorageResult<Option<DomainLaunchProfile>> {
        let Some(replay) = self
            .replay_catalog_mutation_digest(
                operation_id,
                method,
                request_hmac,
                validate_launch_profile_save_replay,
            )
            .await?
        else {
            return Ok(None);
        };
        let mut input = match &request.request {
            SaveLaunchProfileRequest::Create(request) => request.input.clone(),
            SaveLaunchProfileRequest::Update(request) => {
                if request.profile_id != replay.profile_id {
                    return Err(invalid_profile_save_replay(
                        operation_id,
                        "profile identity does not match the replay request",
                    ));
                }
                request.input.clone()
            }
        };
        apply_replayed_credential_references(operation_id, request, &replay, &mut input)?;
        let profile = DomainLaunchProfile {
            id: replay.profile_id,
            input,
            created_at: replay.created_at,
            updated_at: replay.updated_at,
        };
        lifecycle::validate_launch_profile(&profile)
            .map_err(|error| invalid_profile_save_replay(operation_id, error.message.as_str()))?;
        Ok(Some(profile))
    }

    /// Persists a server-owned profile that was built from the matching IPC
    /// request. IDs and timestamps never come from the request DTO.
    pub async fn prepare_save_launch_profile(
        &mut self,
        operation_id: &str,
        method: &str,
        original_request_hmac: &[u8; 32],
        request: &SaveLaunchProfileRequest,
        profile: &DomainLaunchProfile,
        secret_credentials: &[ProfileSecretCredential],
        credential_store: &dyn SecretStore,
    ) -> StorageResult<PreparedCatalogMutation<DomainLaunchProfile>> {
        lifecycle::validate_save_launch_profile_request(request)?;
        lifecycle::validate_launch_profile(profile).map_err(invalid_server_profile_validation)?;

        match request {
            SaveLaunchProfileRequest::Create(CreateLaunchProfileRequest { input }) => {
                ensure_input_matches(input, profile)?;
                if profile.created_at != profile.updated_at {
                    return Err(invalid_server_profile(
                        "createdAt",
                        "must equal updatedAt when a profile is created",
                    ));
                }
            }
            SaveLaunchProfileRequest::Update(UpdateLaunchProfileRequest {
                profile_id,
                input,
                ..
            }) => {
                ensure_input_matches(input, profile)?;
                if &profile.id != profile_id {
                    return Err(invalid_server_profile(
                        "profileId",
                        "does not match the server-owned profile identity",
                    ));
                }
            }
        }

        let credential_references = validate_credential_references(profile, credential_store)?;
        let (stored, environment) = domain_to_stored(profile)?;
        let replay = launch_profile_save_replay(profile, secret_credentials)?;
        let result_json = serialize_catalog_mutation_result(&replay)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|error| storage_error("begin launch profile save", error))?;
        reserve_catalog_mutation(
            &mut transaction,
            operation_id,
            method,
            original_request_hmac,
        )
        .await?;
        match request {
            SaveLaunchProfileRequest::Create(_) => {
                self.insert_stored_launch_profile(
                    &mut transaction,
                    &stored,
                    &environment,
                    &credential_references,
                )
                .await?;
            }
            SaveLaunchProfileRequest::Update(UpdateLaunchProfileRequest {
                expected_updated_at,
                ..
            }) => {
                self.update_stored_launch_profile(
                    &mut transaction,
                    &stored,
                    &environment,
                    expected_updated_at,
                    &credential_references,
                )
                .await?;
            }
        }
        insert_catalog_mutation_result(
            &mut transaction,
            operation_id,
            method,
            original_request_hmac,
            &result_json,
            &profile.updated_at,
        )
        .await?;
        Ok(PreparedCatalogMutation::new(transaction, profile.clone()))
    }

    pub async fn launch_profile(&self, id: &str) -> StorageResult<DomainLaunchProfile> {
        validate_profile_id(id)?;
        stored_to_domain(self.stored_launch_profile(id).await?)
    }

    pub async fn launch_profiles(
        &self,
        request: &ListLaunchProfilesRequest,
    ) -> StorageResult<ListLaunchProfilesResponse> {
        lifecycle::validate_list_launch_profiles_request(request)?;
        let cursor = request.cursor.as_deref().map(decode_cursor).transpose()?;
        let (cursor_name, cursor_id) = cursor
            .as_ref()
            .map(|cursor| (Some(cursor.name.as_str()), Some(cursor.id.as_str())))
            .unwrap_or((None, None));
        let page = self
            .stored_launch_profiles(cursor_name, cursor_id, request.limit)
            .await?;
        let profiles = page
            .items
            .into_iter()
            .map(stored_to_domain)
            .collect::<StorageResult<Vec<_>>>()?;
        let next_cursor = page.next_cursor.as_ref().map(encode_cursor);
        let response = ListLaunchProfilesResponse {
            profiles,
            next_cursor,
        };
        lifecycle::validate_list_launch_profiles_response(&response)
            .map_err(invalid_stored_profile)?;
        Ok(response)
    }

    pub async fn prepare_delete_launch_profile(
        &mut self,
        operation_id: &str,
        method: &str,
        request: &DeleteLaunchProfileRequest,
        recorded_at: &str,
    ) -> StorageResult<PreparedCatalogMutation<DeleteLaunchProfileResponse>> {
        lifecycle::validate_delete_launch_profile_request(request)?;
        lifecycle::validate_canonical_utc_timestamp("recordedAt", recorded_at)?;
        let response = DeleteLaunchProfileResponse {
            profile_id: request.profile_id.clone(),
        };
        lifecycle::validate_delete_launch_profile_response(&response)?;
        let request_sha256 = canonical_typed_request_sha256(request)?;
        let result_json = serialize_catalog_mutation_result(&response)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|error| storage_error("begin launch profile delete", error))?;
        reserve_catalog_mutation(&mut transaction, operation_id, method, &request_sha256).await?;
        self.delete_stored_launch_profile(
            &mut transaction,
            &request.profile_id,
            &request.expected_updated_at,
        )
        .await?;
        insert_catalog_mutation_result(
            &mut transaction,
            operation_id,
            method,
            &request_sha256,
            &result_json,
            recorded_at,
        )
        .await?;
        Ok(PreparedCatalogMutation::new(transaction, response))
    }
}

fn launch_profile_save_replay(
    profile: &DomainLaunchProfile,
    secret_credentials: &[ProfileSecretCredential],
) -> StorageResult<LaunchProfileSaveReplay> {
    let replay = LaunchProfileSaveReplay {
        profile_id: profile.id.clone(),
        created_at: profile.created_at.clone(),
        updated_at: profile.updated_at.clone(),
        secret_credentials: secret_credentials.to_vec(),
    };
    validate_launch_profile_save_replay(&replay)?;
    for credential in secret_credentials {
        let matching = profile.input.environment.iter().find(|entry| {
            environment_names_equal(&entry.name, &credential.name)
                && matches!(
                    &entry.value,
                    LaunchEnvironmentValue::CredentialReference(value)
                        if value.credential_reference == credential.credential_reference
                )
        });
        if matching.is_none() {
            return Err(invalid_server_profile(
                "environment",
                "does not contain a materialized secret credential",
            ));
        }
    }
    Ok(replay)
}

fn validate_launch_profile_save_replay(replay: &LaunchProfileSaveReplay) -> StorageResult<()> {
    validate_profile_id(&replay.profile_id)?;
    lifecycle::validate_canonical_utc_timestamp("createdAt", &replay.created_at)?;
    lifecycle::validate_canonical_utc_timestamp("updatedAt", &replay.updated_at)?;
    if replay.created_at > replay.updated_at {
        return Err(invalid_server_profile(
            "updatedAt",
            "must not be earlier than createdAt",
        ));
    }
    if replay.secret_credentials.len() > MAX_PROFILE_REPLAY_CREDENTIALS {
        return Err(invalid_server_profile(
            "secretCredentials",
            "exceeds the supported entry count",
        ));
    }
    let mut names = HashSet::with_capacity(replay.secret_credentials.len());
    for credential in &replay.secret_credentials {
        let key = environment_name_key(&credential.name);
        if !names.insert(key) {
            return Err(invalid_server_profile(
                "secretCredentials",
                "contains duplicate environment names",
            ));
        }
        let slot = CredentialSlot::new(replay.profile_id.clone(), credential.name.clone())
            .map_err(|_| {
                invalid_server_profile("secretCredentials.name", "is not a valid credential slot")
            })?;
        let reference =
            CredentialReference::parse(&credential.credential_reference).map_err(|_| {
                invalid_server_profile("secretCredentials.credentialReference", "is not canonical")
            })?;
        if !reference.belongs_to(&slot) {
            return Err(invalid_server_profile(
                "secretCredentials.credentialReference",
                "does not belong to the profile environment slot",
            ));
        }
    }
    Ok(())
}

fn apply_replayed_credential_references(
    operation_id: &str,
    request: &SaveLaunchProfileWithSecretsRequest,
    replay: &LaunchProfileSaveReplay,
    input: &mut LaunchProfileInput,
) -> StorageResult<()> {
    let mut expected_names = request
        .secret_environment
        .iter()
        .map(|entry| environment_name_key(&entry.name))
        .collect::<HashSet<_>>();
    if expected_names.len() != request.secret_environment.len()
        || expected_names.len() != replay.secret_credentials.len()
    {
        return Err(invalid_profile_save_replay(
            operation_id,
            "secret credential names do not match the replay request",
        ));
    }
    for credential in &replay.secret_credentials {
        if !expected_names.remove(&environment_name_key(&credential.name)) {
            return Err(invalid_profile_save_replay(
                operation_id,
                "secret credential names do not match the replay request",
            ));
        }
        replace_environment_credential(
            input,
            credential.name.clone(),
            credential.credential_reference.clone(),
        );
    }
    if !expected_names.is_empty() {
        return Err(invalid_profile_save_replay(
            operation_id,
            "a secret credential is missing from the stored replay",
        ));
    }
    input
        .environment
        .sort_by(|left, right| left.name.cmp(&right.name));
    match &request.request {
        SaveLaunchProfileRequest::Create(_) if replay.created_at != replay.updated_at => {
            return Err(invalid_profile_save_replay(
                operation_id,
                "create replay timestamps do not match",
            ));
        }
        SaveLaunchProfileRequest::Update(request)
            if replay.updated_at == request.expected_updated_at =>
        {
            return Err(invalid_profile_save_replay(
                operation_id,
                "update replay timestamp did not advance",
            ));
        }
        SaveLaunchProfileRequest::Create(_) | SaveLaunchProfileRequest::Update(_) => {}
    }
    validate_replayed_profile_credentials(operation_id, &replay.profile_id, input)
}

fn validate_replayed_profile_credentials(
    operation_id: &str,
    profile_id: &str,
    input: &LaunchProfileInput,
) -> StorageResult<()> {
    for entry in &input.environment {
        let LaunchEnvironmentValue::CredentialReference(value) = &entry.value else {
            continue;
        };
        let slot =
            CredentialSlot::new(profile_id.to_owned(), entry.name.clone()).map_err(|_| {
                invalid_profile_save_replay(operation_id, "response credential slot is invalid")
            })?;
        let reference = CredentialReference::parse(&value.credential_reference).map_err(|_| {
            invalid_profile_save_replay(operation_id, "response credential reference is invalid")
        })?;
        if !reference.belongs_to(&slot) {
            return Err(invalid_profile_save_replay(
                operation_id,
                "response credential reference belongs to another slot",
            ));
        }
    }
    Ok(())
}

fn replace_environment_credential(
    input: &mut LaunchProfileInput,
    name: String,
    credential_reference: String,
) {
    let value = LaunchEnvironmentValue::CredentialReference(
        domain::CredentialReferenceLaunchEnvironmentValue {
            credential_reference,
        },
    );
    if let Some(existing) = input
        .environment
        .iter_mut()
        .find(|entry| environment_names_equal(&entry.name, &name))
    {
        existing.name = name;
        existing.value = value;
    } else {
        input
            .environment
            .push(DomainEnvironmentEntry { name, value });
    }
}

fn environment_names_equal(left: &str, right: &str) -> bool {
    if cfg!(windows) {
        left.eq_ignore_ascii_case(right)
    } else {
        left == right
    }
}

fn environment_name_key(value: &str) -> String {
    if cfg!(windows) {
        value.to_ascii_uppercase()
    } else {
        value.to_owned()
    }
}

fn invalid_profile_save_replay(operation_id: &str, reason: &str) -> AppError {
    let mut error = AppError::new(
        ErrorCode::StorageError,
        "stored launch profile mutation replay is invalid",
    );
    error.operation_id = Some(operation_id.to_owned());
    error.details.insert("reason".into(), reason.to_owned());
    error
}

fn validate_credential_references(
    profile: &DomainLaunchProfile,
    credential_store: &dyn SecretStore,
) -> StorageResult<Vec<CredentialReference>> {
    let mut references = Vec::new();
    for entry in &profile.input.environment {
        let LaunchEnvironmentValue::CredentialReference(value) = &entry.value else {
            continue;
        };
        let slot = CredentialSlot::new(profile.id.clone(), entry.name.clone()).map_err(|_| {
            invalid_server_profile(
                "environment",
                "contains an invalid server-owned credential slot",
            )
        })?;
        let reference = CredentialReference::parse(&value.credential_reference)
            .map_err(|_| invalid_profile_credential_reference("is not a canonical reference"))?;
        if !reference.belongs_to(&slot) {
            return Err(invalid_profile_credential_reference(
                "does not belong to this profile and environment variable",
            ));
        }

        let secret = credential_store
            .get(&reference)
            .map_err(credential_verification_error)?;
        drop(secret);
        references.push(reference);
    }
    Ok(references)
}

fn invalid_profile_credential_reference(reason: &'static str) -> AppError {
    let mut error = AppError::new(
        ErrorCode::InvalidArgument,
        "launch profile credential reference is invalid",
    );
    error
        .details
        .insert("field".into(), "environment.credentialReference".into());
    error.details.insert("reason".into(), reason.into());
    error
}

fn credential_verification_error(source: AppError) -> AppError {
    let mut error = AppError::new(
        source.code,
        "system credential reference could not be verified",
    );
    error.retryable = source.retryable;
    error
}

fn ensure_input_matches(
    request_input: &LaunchProfileInput,
    profile: &DomainLaunchProfile,
) -> StorageResult<()> {
    if request_input == &profile.input {
        Ok(())
    } else {
        Err(invalid_server_profile(
            "input",
            "does not match the validated request payload",
        ))
    }
}

fn domain_to_stored(
    profile: &DomainLaunchProfile,
) -> StorageResult<(StoredLaunchProfile, Vec<LaunchProfileEnvironment>)> {
    let (execution_mode, executable, arguments_json, shell) = match &profile.input.execution {
        LaunchExecution::Direct(configuration) => (
            "DIRECT".to_owned(),
            configuration.executable.clone(),
            serde_json::to_string(&configuration.argv)
                .map_err(|error| contract_serialization_error("argv", error))?,
            None,
        ),
        LaunchExecution::Shell(configuration) => (
            "SHELL".to_owned(),
            configuration.command.clone(),
            "[]".to_owned(),
            Some(shell_to_storage(configuration.shell).to_owned()),
        ),
    };
    let environment = profile
        .input
        .environment
        .iter()
        .map(|entry| LaunchProfileEnvironment {
            profile_id: profile.id.clone(),
            name: entry.name.clone(),
            value: match &entry.value {
                LaunchEnvironmentValue::Plain(value) => Some(value.value.clone()),
                LaunchEnvironmentValue::CredentialReference(_) => None,
            },
            credential_ref: match &entry.value {
                LaunchEnvironmentValue::Plain(_) => None,
                LaunchEnvironmentValue::CredentialReference(value) => {
                    Some(value.credential_reference.clone())
                }
            },
        })
        .collect();
    Ok((
        StoredLaunchProfile {
            id: profile.id.clone(),
            project_id: profile.input.project_id.clone(),
            name: profile.input.name.clone(),
            execution_mode,
            executable,
            arguments_json,
            working_directory: profile.input.working_directory.clone(),
            shell,
            interactive: profile.input.interactive,
            stop_timeout_ms: i64::from(profile.input.stop_timeout_ms),
            created_at: profile.created_at.clone(),
            updated_at: profile.updated_at.clone(),
        },
        environment,
    ))
}

fn stored_to_domain(stored: LaunchProfileWithEnvironment) -> StorageResult<DomainLaunchProfile> {
    let profile_id = stored.profile.id.clone();
    let arguments = serde_json::from_str::<Vec<String>>(&stored.profile.arguments_json)
        .map_err(|error| corrupt_profile(&profile_id, "argumentsJson", error.to_string()))?;
    let execution = match stored.profile.execution_mode.as_str() {
        "DIRECT" if stored.profile.shell.is_none() => LaunchExecution::Direct(DirectLaunch {
            executable: stored.profile.executable.clone(),
            argv: arguments,
        }),
        "SHELL" if arguments.is_empty() => {
            let shell = stored
                .profile
                .shell
                .as_deref()
                .and_then(shell_from_storage)
                .ok_or_else(|| {
                    corrupt_profile(&profile_id, "shell", "invalid stored shell".into())
                })?;
            LaunchExecution::Shell(ShellLaunch {
                shell,
                command: stored.profile.executable.clone(),
            })
        }
        _ => {
            return Err(corrupt_profile(
                &profile_id,
                "executionMode",
                "stored mode, shell, and arguments are inconsistent".into(),
            ));
        }
    };
    let environment = stored
        .environment
        .into_iter()
        .map(|entry| stored_environment_to_domain(&profile_id, entry))
        .collect::<StorageResult<Vec<_>>>()?;
    let stop_timeout_ms = u32::try_from(stored.profile.stop_timeout_ms).map_err(|_| {
        corrupt_profile(
            &profile_id,
            "stopTimeoutMs",
            "stored timeout is outside the domain range".into(),
        )
    })?;
    let profile = DomainLaunchProfile {
        id: profile_id.clone(),
        input: LaunchProfileInput {
            project_id: stored.profile.project_id,
            name: stored.profile.name,
            execution,
            working_directory: stored.profile.working_directory,
            environment,
            interactive: stored.profile.interactive,
            stop_timeout_ms,
        },
        created_at: stored.profile.created_at,
        updated_at: stored.profile.updated_at,
    };
    lifecycle::validate_launch_profile(&profile).map_err(invalid_stored_profile)?;
    Ok(profile)
}

fn stored_environment_to_domain(
    profile_id: &str,
    entry: LaunchProfileEnvironment,
) -> StorageResult<DomainEnvironmentEntry> {
    if entry.profile_id != profile_id {
        return Err(corrupt_profile(
            profile_id,
            "environment.profileId",
            "environment row belongs to another profile".into(),
        ));
    }
    let value = match (entry.value, entry.credential_ref) {
        (Some(value), None) => {
            LaunchEnvironmentValue::Plain(domain::PlainLaunchEnvironmentValue { value })
        }
        (None, Some(credential_reference)) => LaunchEnvironmentValue::CredentialReference(
            domain::CredentialReferenceLaunchEnvironmentValue {
                credential_reference,
            },
        ),
        _ => {
            return Err(corrupt_profile(
                profile_id,
                "environment",
                "stored value and credential reference are not exclusive".into(),
            ));
        }
    };
    Ok(DomainEnvironmentEntry {
        name: entry.name,
        value,
    })
}

fn shell_to_storage(shell: ShellKind) -> &'static str {
    match shell {
        ShellKind::PowerShell => "POWERSHELL",
        ShellKind::Cmd => "CMD",
        ShellKind::Zsh => "ZSH",
    }
}

fn shell_from_storage(value: &str) -> Option<ShellKind> {
    match value {
        "POWERSHELL" => Some(ShellKind::PowerShell),
        "CMD" => Some(ShellKind::Cmd),
        "ZSH" => Some(ShellKind::Zsh),
        _ => None,
    }
}

fn encode_cursor(cursor: &LaunchProfileCursor) -> String {
    format!(
        "{CURSOR_PREFIX}{}|{}{}",
        cursor.name.len(),
        cursor.name,
        cursor.id
    )
}

fn decode_cursor(value: &str) -> StorageResult<LaunchProfileCursor> {
    let body = value
        .strip_prefix(CURSOR_PREFIX)
        .ok_or_else(|| invalid_cursor("uses an unsupported cursor version"))?;
    let (name_length, payload) = body
        .split_once('|')
        .ok_or_else(|| invalid_cursor("is malformed"))?;
    let name_length = name_length
        .parse::<usize>()
        .ok()
        .filter(|length| *length <= payload.len())
        .ok_or_else(|| invalid_cursor("contains an invalid name length"))?;
    let name = payload
        .get(..name_length)
        .ok_or_else(|| invalid_cursor("splits a UTF-8 sequence"))?;
    let id = payload
        .get(name_length..)
        .filter(|id| !id.is_empty())
        .ok_or_else(|| invalid_cursor("does not contain a profile ID"))?;
    let cursor = LaunchProfileCursor {
        name: name.to_owned(),
        id: id.to_owned(),
    };
    if encode_cursor(&cursor) != value {
        return Err(invalid_cursor("is not canonical"));
    }
    Ok(cursor)
}

fn validate_profile_id(id: &str) -> StorageResult<()> {
    if id.is_empty() || id.trim().is_empty() || id.len() > MAX_PROFILE_ID_BYTES || id.contains('\0')
    {
        let mut error = AppError::new(ErrorCode::InvalidArgument, "launch profile ID is invalid");
        error.details.insert("field".into(), "profileId".into());
        error.details.insert(
            "reason".into(),
            "must be a bounded non-empty identifier".into(),
        );
        Err(error)
    } else {
        Ok(())
    }
}

fn contract_serialization_error(field: &'static str, error: serde_json::Error) -> AppError {
    let mut result = AppError::new(ErrorCode::Internal, "launch profile serialization failed");
    result.details.insert("field".into(), field.into());
    result.details.insert("cause".into(), error.to_string());
    result
}

fn invalid_server_profile(field: &'static str, reason: &'static str) -> AppError {
    let mut error = AppError::new(
        ErrorCode::Internal,
        "server-owned launch profile is invalid",
    );
    error.details.insert("field".into(), field.into());
    error.details.insert("reason".into(), reason.into());
    error
}

fn invalid_server_profile_validation(source: AppError) -> AppError {
    let mut error = AppError::new(
        ErrorCode::Internal,
        "server-owned launch profile is invalid",
    );
    if let Some(field) = source.details.get("field") {
        error.details.insert("field".into(), field.clone());
    }
    error.details.insert(
        "reason".into(),
        source
            .details
            .get("reason")
            .cloned()
            .unwrap_or(source.message),
    );
    error
}

fn invalid_cursor(reason: &'static str) -> AppError {
    let mut error = AppError::new(
        ErrorCode::InvalidArgument,
        "launch profile cursor is invalid",
    );
    error.details.insert("field".into(), "cursor".into());
    error.details.insert("reason".into(), reason.into());
    error
}

fn invalid_stored_profile(source: AppError) -> AppError {
    let field = source.details.get("field").cloned();
    let mut error = AppError::new(ErrorCode::StorageError, "stored launch profile is invalid");
    error.details.insert("reason".into(), source.message);
    if let Some(field) = field {
        error.details.insert("field".into(), field);
    }
    error
}

fn corrupt_profile(profile_id: &str, field: &'static str, reason: String) -> AppError {
    let mut error = AppError::new(ErrorCode::StorageError, "stored launch profile is invalid");
    error.details.insert("profileId".into(), profile_id.into());
    error.details.insert("field".into(), field.into());
    error.details.insert("reason".into(), reason);
    error
}
