use discovery::{
    ClassificationEngine, ClassificationRule as DiscoveryClassificationRule,
    ClassificationRuleAction as DiscoveryClassificationRuleAction,
    ClassificationRuleMatcher as DiscoveryClassificationRuleMatcher, ClassificationRulesSnapshot,
    DEFAULT_DEVELOPMENT_THRESHOLD, NormalizedPathKey, NormalizedProjectRoot, ProjectCatalog,
    ProjectCatalogSnapshot, ProjectContextSnapshot, RegisteredProject,
};
use domain::{
    AppError, ClassificationRuleAction, ClassificationRuleInput, ClassificationRuleMatcherKind,
    ClassificationRuleSummary, CreateClassificationRuleRequest, CreateProjectRequest,
    DeleteClassificationRuleRequest, DeleteClassificationRuleResponse, DeleteProjectRequest,
    DeleteProjectResponse, ErrorCode, ListClassificationRulesRequest,
    ListClassificationRulesResponse, ListProjectsRequest, ListProjectsResponse, ProjectSummary,
    SaveClassificationRuleRequest, SaveProjectRequest, UpdateClassificationRuleRequest,
    UpdateProjectRequest,
};
use hmac::{Hmac, Mac};
use serde::{Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use sqlx::{Sqlite, Transaction};
use std::io::{self, Write};

use crate::error::{not_found, storage_error};
use crate::{
    ClassificationRule as StoredClassificationRule, Project as StoredProject, StorageResult,
    SupervisorRepository,
};

const PROJECT_CURSOR_PREFIX: &str = "prc1|";
const RULE_CURSOR_PREFIX: &str = "crc1|";
const MAX_CATALOG_OPERATION_ID_BYTES: usize = 128;
const MAX_CATALOG_MUTATION_LEDGER_ENTRIES: i64 = 16_384;
const MAX_CATALOG_MUTATION_RESULT_BYTES: usize = 256 * 1024;

/// An entity write and its durable idempotency result held in one uncommitted
/// SQLite transaction. The Supervisor publishes the prospective discovery
/// context before choosing whether to commit or roll back this value.
pub struct PreparedCatalogMutation<T> {
    transaction: Transaction<'static, Sqlite>,
    result: T,
}

impl<T> PreparedCatalogMutation<T> {
    pub(crate) fn new(transaction: Transaction<'static, Sqlite>, result: T) -> Self {
        Self {
            transaction,
            result,
        }
    }

    pub async fn commit(self) -> StorageResult<T> {
        let Self {
            transaction,
            result,
        } = self;
        transaction
            .commit()
            .await
            .map_err(|error| storage_error("commit catalog mutation", error))?;
        Ok(result)
    }

    pub async fn rollback(self) -> StorageResult<()> {
        self.transaction
            .rollback()
            .await
            .map_err(|error| storage_error("roll back catalog mutation", error))
    }
}

struct ProjectCursor {
    id: String,
    name: String,
}

struct ClassificationRuleCursor {
    id: String,
    priority: i32,
}

impl SupervisorRepository {
    /// Returns a previously committed successful result only when both the RPC
    /// method and the canonical typed request hash match the original call.
    /// Stored DTOs are deserialized and lifecycle-validated before replay.
    pub async fn replay_catalog_mutation<Request, ResultDto>(
        &self,
        operation_id: &str,
        method: &str,
        request: &Request,
        validate_result: fn(&ResultDto) -> Result<(), AppError>,
    ) -> StorageResult<Option<ResultDto>>
    where
        Request: Serialize + ?Sized,
        ResultDto: DeserializeOwned,
    {
        let request_sha256 = canonical_typed_request_sha256(request)?;
        self.replay_catalog_mutation_digest(operation_id, method, &request_sha256, validate_result)
            .await
    }

    pub(crate) async fn replay_catalog_mutation_digest<ResultDto>(
        &self,
        operation_id: &str,
        method: &str,
        request_digest: &[u8; 32],
        validate_result: fn(&ResultDto) -> Result<(), AppError>,
    ) -> StorageResult<Option<ResultDto>>
    where
        ResultDto: DeserializeOwned,
    {
        validate_catalog_mutation_identity(operation_id, method)?;
        let stored = sqlx::query_as::<_, (String, Vec<u8>, String)>(
            "SELECT method, request_sha256, result_json FROM catalog_mutation_ledger \
             WHERE operation_id = ?",
        )
        .bind(operation_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| storage_error("read catalog mutation replay", error))?;
        let Some((stored_method, stored_sha256, result_json)) = stored else {
            return Ok(None);
        };
        require_catalog_mutation_match(
            operation_id,
            method,
            request_digest,
            &stored_method,
            &stored_sha256,
        )?;
        let result = serde_json::from_str::<ResultDto>(&result_json).map_err(|_| {
            corrupt_catalog_mutation_result(operation_id, "is not the expected DTO")
        })?;
        validate_result(&result).map_err(|error| {
            corrupt_catalog_mutation_result(operation_id, error.message.as_str())
        })?;
        Ok(Some(result))
    }

    pub async fn list_projects(
        &self,
        request: &ListProjectsRequest,
    ) -> StorageResult<ListProjectsResponse> {
        lifecycle::validate_list_projects_request(request)?;
        let cursor = request
            .cursor
            .as_deref()
            .map(decode_project_cursor)
            .transpose()?;
        let fetch_limit = i64::from(request.limit) + 1;
        let mut stored = match cursor.as_ref() {
            Some(cursor) => sqlx::query_as::<_, StoredProject>(
                "SELECT id, name, root_directory, normalized_path, created_at, updated_at \
                     FROM projects WHERE name COLLATE BINARY > ? \
                     OR (name COLLATE BINARY = ? AND id COLLATE BINARY > ?) \
                     ORDER BY name COLLATE BINARY, id COLLATE BINARY LIMIT ?",
            )
            .bind(&cursor.name)
            .bind(&cursor.name)
            .bind(&cursor.id)
            .bind(fetch_limit)
            .fetch_all(&self.pool)
            .await
            .map_err(|error| storage_error("list project page", error))?,
            None => sqlx::query_as::<_, StoredProject>(
                "SELECT id, name, root_directory, normalized_path, created_at, updated_at \
                     FROM projects ORDER BY name COLLATE BINARY, id COLLATE BINARY LIMIT ?",
            )
            .bind(fetch_limit)
            .fetch_all(&self.pool)
            .await
            .map_err(|error| storage_error("list project page", error))?,
        };
        let has_more = stored.len() > usize::from(request.limit);
        if has_more {
            stored.pop();
        }
        let projects = stored
            .into_iter()
            .map(stored_project_to_summary)
            .collect::<StorageResult<Vec<_>>>()?;
        let next_cursor = has_more
            .then(|| projects.last().map(project_cursor_from_summary))
            .flatten()
            .map(|cursor| encode_project_cursor(&cursor));
        let response = ListProjectsResponse {
            projects,
            next_cursor,
        };
        lifecycle::validate_list_projects_response(&response).map_err(corrupt_project_contract)?;
        Ok(response)
    }

    /// Persists a server-owned summary and a platform-normalized root that
    /// cannot be manufactured by an IPC payload.
    pub async fn prepare_save_project(
        &mut self,
        operation_id: &str,
        method: &str,
        request: &SaveProjectRequest,
        summary: &ProjectSummary,
        trusted_root: &NormalizedProjectRoot,
    ) -> StorageResult<PreparedCatalogMutation<ProjectSummary>> {
        lifecycle::validate_save_project_request(request)?;
        lifecycle::validate_project_summary(summary).map_err(invalid_server_project_validation)?;
        ensure_project_request_matches(request, summary, trusted_root)?;
        let stored = project_summary_to_stored(summary, trusted_root)?;
        let result_json = serialize_catalog_mutation_result(summary)?;
        let request_sha256 = canonical_typed_request_sha256(request)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|error| storage_error("begin project save", error))?;
        reserve_catalog_mutation(&mut transaction, operation_id, method, &request_sha256).await?;

        match request {
            SaveProjectRequest::Create(_) => {
                sqlx::query(
                    "INSERT INTO projects \
                     (id, name, root_directory, normalized_path, created_at, updated_at) \
                     VALUES (?, ?, ?, ?, ?, ?)",
                )
                .bind(&stored.id)
                .bind(&stored.name)
                .bind(&stored.root_directory)
                .bind(&stored.normalized_path)
                .bind(&stored.created_at)
                .bind(&stored.updated_at)
                .execute(&mut *transaction)
                .await
                .map_err(|error| storage_error("insert project", error))?;
            }
            SaveProjectRequest::Update(UpdateProjectRequest {
                expected_updated_at,
                ..
            }) => {
                let current = project_row(&mut transaction, &summary.id).await?;
                let current_summary = stored_project_to_summary(current.clone())?;
                require_expected_version(
                    "project",
                    "projectId",
                    &summary.id,
                    expected_updated_at,
                    &current_summary.updated_at,
                )?;
                if summary.created_at != current_summary.created_at {
                    return Err(invalid_server_project(
                        "createdAt",
                        "must preserve the stored project creation timestamp",
                    ));
                }
                if summary.updated_at <= current_summary.updated_at {
                    return Err(invalid_server_project(
                        "updatedAt",
                        "must be later than the stored project version timestamp",
                    ));
                }
                let result = sqlx::query(
                    "UPDATE projects SET name = ?, root_directory = ?, normalized_path = ?, \
                     updated_at = ? WHERE id = ? AND updated_at = ?",
                )
                .bind(&stored.name)
                .bind(&stored.root_directory)
                .bind(&stored.normalized_path)
                .bind(&stored.updated_at)
                .bind(&stored.id)
                .bind(expected_updated_at)
                .execute(&mut *transaction)
                .await
                .map_err(|error| storage_error("update project with version", error))?;
                if result.rows_affected() != 1 {
                    return Err(version_conflict(
                        "project",
                        "projectId",
                        &stored.id,
                        expected_updated_at,
                        &current_summary.updated_at,
                    ));
                }
            }
        }
        insert_catalog_mutation_result(
            &mut transaction,
            operation_id,
            method,
            &request_sha256,
            &result_json,
            &summary.updated_at,
        )
        .await?;
        Ok(PreparedCatalogMutation {
            transaction,
            result: summary.clone(),
        })
    }

    pub async fn project_summary(&self, project_id: &str) -> StorageResult<ProjectSummary> {
        let stored = sqlx::query_as::<_, StoredProject>(
            "SELECT id, name, root_directory, normalized_path, created_at, updated_at \
             FROM projects WHERE id = ?",
        )
        .bind(project_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| storage_error("read project summary", error))?
        .ok_or_else(|| not_found("project", project_id))?;
        stored_project_to_summary(stored)
    }

    pub async fn prepare_delete_project_if_version(
        &mut self,
        operation_id: &str,
        method: &str,
        request: &DeleteProjectRequest,
        recorded_at: &str,
    ) -> StorageResult<PreparedCatalogMutation<DeleteProjectResponse>> {
        lifecycle::validate_delete_project_request(request)?;
        lifecycle::validate_canonical_utc_timestamp("recordedAt", recorded_at)
            .map_err(invalid_server_project_validation)?;
        let response = DeleteProjectResponse {
            project_id: request.project_id.clone(),
        };
        lifecycle::validate_delete_project_response(&response)
            .map_err(invalid_server_project_validation)?;
        let result_json = serialize_catalog_mutation_result(&response)?;
        let request_sha256 = canonical_typed_request_sha256(request)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|error| storage_error("begin project delete", error))?;
        reserve_catalog_mutation(&mut transaction, operation_id, method, &request_sha256).await?;
        let current = project_row(&mut transaction, &request.project_id).await?;
        let current_summary = stored_project_to_summary(current)?;
        require_expected_version(
            "project",
            "projectId",
            &request.project_id,
            &request.expected_updated_at,
            &current_summary.updated_at,
        )?;
        let has_profiles = sqlx::query_scalar::<_, i64>(
            "SELECT EXISTS(SELECT 1 FROM launch_profiles WHERE project_id = ?)",
        )
        .bind(&request.project_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|error| storage_error("check project launch profile references", error))?
            != 0;
        let has_rules = sqlx::query_scalar::<_, i64>(
            "SELECT EXISTS(SELECT 1 FROM classification_rules WHERE project_id = ?)",
        )
        .bind(&request.project_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|error| storage_error("check project rule references", error))?
            != 0;
        if has_profiles || has_rules {
            return Err(project_in_use(&request.project_id, has_profiles, has_rules));
        }
        let result = sqlx::query("DELETE FROM projects WHERE id = ? AND updated_at = ?")
            .bind(&request.project_id)
            .bind(&request.expected_updated_at)
            .execute(&mut *transaction)
            .await
            .map_err(|error| storage_error("delete project with version", error))?;
        if result.rows_affected() != 1 {
            return Err(version_conflict(
                "project",
                "projectId",
                &request.project_id,
                &request.expected_updated_at,
                &current_summary.updated_at,
            ));
        }
        insert_catalog_mutation_result(
            &mut transaction,
            operation_id,
            method,
            &request_sha256,
            &result_json,
            recorded_at,
        )
        .await?;
        Ok(PreparedCatalogMutation {
            transaction,
            result: response,
        })
    }

    pub async fn list_classification_rules(
        &self,
        request: &ListClassificationRulesRequest,
    ) -> StorageResult<ListClassificationRulesResponse> {
        lifecycle::validate_list_classification_rules_request(request)?;
        let cursor = request
            .cursor
            .as_deref()
            .map(decode_classification_rule_cursor)
            .transpose()?;
        let fetch_limit = i64::from(request.limit) + 1;
        let mut stored = match cursor.as_ref() {
            Some(cursor) => sqlx::query_as::<_, StoredClassificationRule>(
                "SELECT id, rule_type, pattern, action, project_id, priority, enabled, \
                     created_at, updated_at FROM classification_rules WHERE priority < ? \
                     OR (priority = ? AND id COLLATE BINARY > ?) \
                     ORDER BY priority DESC, id COLLATE BINARY LIMIT ?",
            )
            .bind(cursor.priority)
            .bind(cursor.priority)
            .bind(&cursor.id)
            .bind(fetch_limit)
            .fetch_all(&self.pool)
            .await
            .map_err(|error| storage_error("list classification rule page", error))?,
            None => sqlx::query_as::<_, StoredClassificationRule>(
                "SELECT id, rule_type, pattern, action, project_id, priority, enabled, \
                     created_at, updated_at FROM classification_rules \
                     ORDER BY priority DESC, id COLLATE BINARY LIMIT ?",
            )
            .bind(fetch_limit)
            .fetch_all(&self.pool)
            .await
            .map_err(|error| storage_error("list classification rule page", error))?,
        };
        let has_more = stored.len() > usize::from(request.limit);
        if has_more {
            stored.pop();
        }
        let rules = stored
            .into_iter()
            .map(stored_rule_to_summary)
            .collect::<StorageResult<Vec<_>>>()?;
        let next_cursor = has_more
            .then(|| rules.last().map(rule_cursor_from_summary))
            .flatten()
            .map(|cursor| encode_classification_rule_cursor(&cursor));
        let response = ListClassificationRulesResponse { rules, next_cursor };
        lifecycle::validate_list_classification_rules_response(&response)
            .map_err(corrupt_rule_contract)?;
        Ok(response)
    }

    pub async fn prepare_save_classification_rule(
        &mut self,
        operation_id: &str,
        method: &str,
        request: &SaveClassificationRuleRequest,
        summary: &ClassificationRuleSummary,
    ) -> StorageResult<PreparedCatalogMutation<ClassificationRuleSummary>> {
        lifecycle::validate_save_classification_rule_request(request)?;
        lifecycle::validate_classification_rule_summary(summary)
            .map_err(invalid_server_rule_validation)?;
        ensure_rule_request_matches(request, summary)?;
        let stored = classification_rule_summary_to_stored(summary);
        let result_json = serialize_catalog_mutation_result(summary)?;
        let request_sha256 = canonical_typed_request_sha256(request)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|error| storage_error("begin classification rule save", error))?;
        reserve_catalog_mutation(&mut transaction, operation_id, method, &request_sha256).await?;

        match request {
            SaveClassificationRuleRequest::Create(_) => {
                sqlx::query(
                    "INSERT INTO classification_rules \
                     (id, rule_type, pattern, action, project_id, priority, enabled, \
                      created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                )
                .bind(&stored.id)
                .bind(&stored.rule_type)
                .bind(&stored.pattern)
                .bind(&stored.action)
                .bind(&stored.project_id)
                .bind(stored.priority)
                .bind(stored.enabled)
                .bind(&stored.created_at)
                .bind(&stored.updated_at)
                .execute(&mut *transaction)
                .await
                .map_err(|error| storage_error("insert classification rule", error))?;
            }
            SaveClassificationRuleRequest::Update(UpdateClassificationRuleRequest {
                expected_updated_at,
                ..
            }) => {
                let current = classification_rule_row(&mut transaction, &summary.id).await?;
                let current_summary = stored_rule_to_summary(current.clone())?;
                require_expected_version(
                    "classificationRule",
                    "ruleId",
                    &summary.id,
                    expected_updated_at,
                    &current_summary.updated_at,
                )?;
                if summary.created_at != current_summary.created_at {
                    return Err(invalid_server_rule(
                        "createdAt",
                        "must preserve the stored classification rule creation timestamp",
                    ));
                }
                if summary.updated_at <= current_summary.updated_at {
                    return Err(invalid_server_rule(
                        "updatedAt",
                        "must be later than the stored classification rule version timestamp",
                    ));
                }
                let result = sqlx::query(
                    "UPDATE classification_rules SET rule_type = ?, pattern = ?, action = ?, \
                     project_id = ?, priority = ?, enabled = ?, updated_at = ? \
                     WHERE id = ? AND updated_at = ?",
                )
                .bind(&stored.rule_type)
                .bind(&stored.pattern)
                .bind(&stored.action)
                .bind(&stored.project_id)
                .bind(stored.priority)
                .bind(stored.enabled)
                .bind(&stored.updated_at)
                .bind(&stored.id)
                .bind(expected_updated_at)
                .execute(&mut *transaction)
                .await
                .map_err(|error| storage_error("update classification rule with version", error))?;
                if result.rows_affected() != 1 {
                    return Err(version_conflict(
                        "classificationRule",
                        "ruleId",
                        &stored.id,
                        expected_updated_at,
                        &current_summary.updated_at,
                    ));
                }
            }
        }
        insert_catalog_mutation_result(
            &mut transaction,
            operation_id,
            method,
            &request_sha256,
            &result_json,
            &summary.updated_at,
        )
        .await?;
        Ok(PreparedCatalogMutation {
            transaction,
            result: summary.clone(),
        })
    }

    pub async fn classification_rule_summary(
        &self,
        rule_id: &str,
    ) -> StorageResult<ClassificationRuleSummary> {
        let stored = sqlx::query_as::<_, StoredClassificationRule>(
            "SELECT id, rule_type, pattern, action, project_id, priority, enabled, \
             created_at, updated_at FROM classification_rules WHERE id = ?",
        )
        .bind(rule_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| storage_error("read classification rule summary", error))?
        .ok_or_else(|| not_found("classificationRule", rule_id))?;
        stored_rule_to_summary(stored)
    }

    pub async fn prepare_delete_classification_rule_if_version(
        &mut self,
        operation_id: &str,
        method: &str,
        request: &DeleteClassificationRuleRequest,
        recorded_at: &str,
    ) -> StorageResult<PreparedCatalogMutation<DeleteClassificationRuleResponse>> {
        lifecycle::validate_delete_classification_rule_request(request)?;
        lifecycle::validate_canonical_utc_timestamp("recordedAt", recorded_at)
            .map_err(invalid_server_rule_validation)?;
        let response = DeleteClassificationRuleResponse {
            rule_id: request.rule_id.clone(),
        };
        lifecycle::validate_delete_classification_rule_response(&response)
            .map_err(invalid_server_rule_validation)?;
        let result_json = serialize_catalog_mutation_result(&response)?;
        let request_sha256 = canonical_typed_request_sha256(request)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|error| storage_error("begin classification rule delete", error))?;
        reserve_catalog_mutation(&mut transaction, operation_id, method, &request_sha256).await?;
        let current = classification_rule_row(&mut transaction, &request.rule_id).await?;
        let current_summary = stored_rule_to_summary(current)?;
        require_expected_version(
            "classificationRule",
            "ruleId",
            &request.rule_id,
            &request.expected_updated_at,
            &current_summary.updated_at,
        )?;
        let result =
            sqlx::query("DELETE FROM classification_rules WHERE id = ? AND updated_at = ?")
                .bind(&request.rule_id)
                .bind(&request.expected_updated_at)
                .execute(&mut *transaction)
                .await
                .map_err(|error| storage_error("delete classification rule with version", error))?;
        if result.rows_affected() != 1 {
            return Err(version_conflict(
                "classificationRule",
                "ruleId",
                &request.rule_id,
                &request.expected_updated_at,
                &current_summary.updated_at,
            ));
        }
        insert_catalog_mutation_result(
            &mut transaction,
            operation_id,
            method,
            &request_sha256,
            &result_json,
            recorded_at,
        )
        .await?;
        Ok(PreparedCatalogMutation {
            transaction,
            result: response,
        })
    }

    /// Builds only from validated stored rows. Any malformed path key, closed
    /// enum, relation, or capacity is a storage-integrity failure.
    pub async fn project_context_snapshot(&self) -> StorageResult<ProjectContextSnapshot> {
        let stored_projects = self.projects().await?;
        let mut registered_projects = Vec::with_capacity(stored_projects.len());
        for stored in stored_projects {
            let (summary, normalized_path) = stored_project_to_parts(stored)?;
            registered_projects.push(RegisteredProject {
                id: summary.id,
                root_directory: summary.input.root_directory,
                normalized_path,
            });
        }
        let catalog = ProjectCatalogSnapshot {
            projects: registered_projects,
        };
        ProjectCatalog::new(catalog.clone()).map_err(corrupt_project_context)?;

        let mut known_project_ids = catalog
            .projects
            .iter()
            .map(|project| project.id.clone())
            .collect::<Vec<_>>();
        known_project_ids.sort();
        let stored_rules = self.classification_rules().await?;
        let rules = stored_rules
            .into_iter()
            .map(stored_rule_to_discovery)
            .collect::<StorageResult<Vec<_>>>()?;
        let classification_rules = ClassificationRulesSnapshot {
            development_threshold: DEFAULT_DEVELOPMENT_THRESHOLD,
            known_project_ids,
            rules,
        };
        ClassificationEngine::new(classification_rules.clone()).map_err(corrupt_project_context)?;
        Ok(ProjectContextSnapshot {
            catalog,
            classification_rules,
        })
    }
}

pub(crate) fn canonical_typed_request_sha256<Request>(request: &Request) -> StorageResult<[u8; 32]>
where
    Request: Serialize + ?Sized,
{
    // These closed typed DTOs contain only structs, enums, sequences, and
    // scalars. serde_json therefore emits one deterministic representation
    // independent of the original wire object's key order.
    let mut digest = Sha256::new();
    serde_json::to_writer(Sha256Writer(&mut digest), request)
        .map_err(|error| storage_error("serialize canonical catalog request", error))?;
    Ok(digest.finalize().into())
}

pub(crate) fn canonical_typed_request_hmac_sha256<Request>(
    request: &Request,
    key: &[u8; 32],
) -> StorageResult<[u8; 32]>
where
    Request: Serialize + ?Sized,
{
    let mut digest = Hmac::<Sha256>::new_from_slice(key)
        .map_err(|error| storage_error("initialize catalog request HMAC", error))?;
    serde_json::to_writer(HmacSha256Writer(&mut digest), request)
        .map_err(|error| storage_error("serialize canonical catalog request HMAC", error))?;
    Ok(digest.finalize().into_bytes().into())
}

struct Sha256Writer<'digest>(&'digest mut Sha256);

impl Write for Sha256Writer<'_> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.0.update(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct HmacSha256Writer<'digest>(&'digest mut Hmac<Sha256>);

impl Write for HmacSha256Writer<'_> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        Mac::update(self.0, buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(crate) fn serialize_catalog_mutation_result<ResultDto>(
    result: &ResultDto,
) -> StorageResult<String>
where
    ResultDto: Serialize + ?Sized,
{
    let result_json = serde_json::to_string(result)
        .map_err(|error| storage_error("serialize catalog mutation result", error))?;
    validate_catalog_mutation_result_size(&result_json, None, None)?;
    Ok(result_json)
}

pub(crate) async fn reserve_catalog_mutation(
    transaction: &mut Transaction<'_, Sqlite>,
    operation_id: &str,
    method: &str,
    request_sha256: &[u8; 32],
) -> StorageResult<()> {
    validate_catalog_mutation_identity(operation_id, method)?;
    let stored = sqlx::query_as::<_, (String, Vec<u8>)>(
        "SELECT method, request_sha256 FROM catalog_mutation_ledger WHERE operation_id = ?",
    )
    .bind(operation_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| storage_error("check catalog mutation operation", error))?;
    if let Some((stored_method, stored_sha256)) = stored {
        require_catalog_mutation_match(
            operation_id,
            method,
            request_sha256,
            &stored_method,
            &stored_sha256,
        )?;
        let mut error = AppError::new(
            ErrorCode::Conflict,
            "catalog mutation was already committed before preparation",
        );
        error.operation_id = Some(operation_id.to_owned());
        error.details.insert("method".into(), method.to_owned());
        return Err(error);
    }
    let count = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM catalog_mutation_ledger")
        .fetch_one(&mut **transaction)
        .await
        .map_err(|error| storage_error("count catalog mutation ledger", error))?;
    if count >= MAX_CATALOG_MUTATION_LEDGER_ENTRIES {
        let mut error = AppError::new(
            ErrorCode::StorageError,
            "catalog mutation ledger capacity is exhausted",
        );
        error.operation_id = Some(operation_id.to_owned());
        error.details.insert(
            "limit".into(),
            MAX_CATALOG_MUTATION_LEDGER_ENTRIES.to_string(),
        );
        error.details.insert("method".into(), method.to_owned());
        return Err(error);
    }
    Ok(())
}

pub(crate) async fn insert_catalog_mutation_result(
    transaction: &mut Transaction<'_, Sqlite>,
    operation_id: &str,
    method: &str,
    request_sha256: &[u8; 32],
    result_json: &str,
    recorded_at: &str,
) -> StorageResult<()> {
    validate_catalog_mutation_result_size(result_json, Some(operation_id), Some(method))?;
    sqlx::query(
        "INSERT INTO catalog_mutation_ledger \
         (operation_id, method, request_sha256, result_json, recorded_at) \
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(operation_id)
    .bind(method)
    .bind(request_sha256.as_slice())
    .bind(result_json)
    .bind(recorded_at)
    .execute(&mut **transaction)
    .await
    .map_err(|error| storage_error("record catalog mutation result", error))?;
    Ok(())
}

fn validate_catalog_mutation_result_size(
    result_json: &str,
    operation_id: Option<&str>,
    method: Option<&str>,
) -> StorageResult<()> {
    if result_json.len() <= MAX_CATALOG_MUTATION_RESULT_BYTES {
        return Ok(());
    }
    let mut error = AppError::new(
        ErrorCode::StorageError,
        "catalog mutation result exceeds the durable replay limit",
    );
    error.operation_id = operation_id.map(str::to_owned);
    error.details.insert(
        "limitBytes".into(),
        MAX_CATALOG_MUTATION_RESULT_BYTES.to_string(),
    );
    error
        .details
        .insert("actualBytes".into(), result_json.len().to_string());
    if let Some(method) = method {
        error.details.insert("method".into(), method.to_owned());
    }
    Err(error)
}

fn validate_catalog_mutation_identity(operation_id: &str, method: &str) -> StorageResult<()> {
    if operation_id.trim().is_empty()
        || operation_id.len() > MAX_CATALOG_OPERATION_ID_BYTES
        || operation_id.contains('\0')
        || !operation_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        let mut error = AppError::new(
            ErrorCode::InvalidArgument,
            "catalog mutation operation ID is invalid",
        );
        error.details.insert("field".into(), "operationId".into());
        return Err(error);
    }
    if !matches!(
        method,
        "project.save"
            | "project.delete"
            | "rule.save"
            | "rule.delete"
            | "profile.save"
            | "profile.delete"
    ) {
        let mut error = AppError::new(
            ErrorCode::InvalidArgument,
            "catalog mutation method is invalid",
        );
        error.operation_id = Some(operation_id.to_owned());
        error.details.insert("field".into(), "method".into());
        return Err(error);
    }
    Ok(())
}

fn require_catalog_mutation_match(
    operation_id: &str,
    requested_method: &str,
    requested_sha256: &[u8; 32],
    stored_method: &str,
    stored_sha256: &[u8],
) -> StorageResult<()> {
    if requested_method == stored_method && requested_sha256.as_slice() == stored_sha256 {
        return Ok(());
    }
    let mut error = AppError::new(
        ErrorCode::Conflict,
        "catalog mutation operation ID was already used for a different request",
    );
    error.operation_id = Some(operation_id.to_owned());
    error
        .details
        .insert("requestedMethod".into(), requested_method.to_owned());
    error
        .details
        .insert("recordedMethod".into(), stored_method.to_owned());
    error.details.insert(
        "requestHashMatches".into(),
        (requested_sha256.as_slice() == stored_sha256).to_string(),
    );
    Err(error)
}

fn corrupt_catalog_mutation_result(operation_id: &str, reason: &str) -> AppError {
    let mut error = AppError::new(
        ErrorCode::StorageError,
        "stored catalog mutation result is invalid",
    );
    error.operation_id = Some(operation_id.to_owned());
    error.details.insert("reason".into(), reason.to_owned());
    error
}

fn ensure_project_request_matches(
    request: &SaveProjectRequest,
    summary: &ProjectSummary,
    trusted_root: &NormalizedProjectRoot,
) -> StorageResult<()> {
    let request_input = match request {
        SaveProjectRequest::Create(CreateProjectRequest { input }) => {
            if summary.created_at != summary.updated_at {
                return Err(invalid_server_project(
                    "createdAt",
                    "must equal updatedAt when a project is created",
                ));
            }
            input
        }
        SaveProjectRequest::Update(UpdateProjectRequest {
            project_id, input, ..
        }) => {
            if project_id != &summary.id {
                return Err(invalid_server_project(
                    "projectId",
                    "does not match the server-owned project identity",
                ));
            }
            input
        }
    };
    if request_input.name != summary.input.name {
        return Err(invalid_server_project(
            "input.name",
            "does not match the validated request payload",
        ));
    }
    if summary.input.root_directory != trusted_root.canonical_root_directory() {
        return Err(invalid_server_project(
            "input.rootDirectory",
            "does not match the trusted platform-normalized project root",
        ));
    }
    Ok(())
}

fn ensure_rule_request_matches(
    request: &SaveClassificationRuleRequest,
    summary: &ClassificationRuleSummary,
) -> StorageResult<()> {
    let request_input = match request {
        SaveClassificationRuleRequest::Create(CreateClassificationRuleRequest { input }) => {
            if summary.created_at != summary.updated_at {
                return Err(invalid_server_rule(
                    "createdAt",
                    "must equal updatedAt when a classification rule is created",
                ));
            }
            input
        }
        SaveClassificationRuleRequest::Update(UpdateClassificationRuleRequest {
            rule_id,
            input,
            ..
        }) => {
            if rule_id != &summary.id {
                return Err(invalid_server_rule(
                    "ruleId",
                    "does not match the server-owned classification rule identity",
                ));
            }
            input
        }
    };
    if request_input != &summary.input {
        return Err(invalid_server_rule(
            "input",
            "does not match the validated request payload",
        ));
    }
    Ok(())
}

fn project_summary_to_stored(
    summary: &ProjectSummary,
    trusted_root: &NormalizedProjectRoot,
) -> StorageResult<StoredProject> {
    if summary.input.root_directory != trusted_root.canonical_root_directory() {
        return Err(invalid_server_project(
            "input.rootDirectory",
            "does not match the trusted platform-normalized project root",
        ));
    }
    Ok(StoredProject {
        id: summary.id.clone(),
        name: summary.input.name.clone(),
        root_directory: trusted_root.canonical_root_directory().to_owned(),
        normalized_path: trusted_root.normalized_path().to_storage_string(),
        created_at: summary.created_at.clone(),
        updated_at: summary.updated_at.clone(),
    })
}

fn stored_project_to_summary(stored: StoredProject) -> StorageResult<ProjectSummary> {
    stored_project_to_parts(stored).map(|(summary, _)| summary)
}

fn stored_project_to_parts(
    stored: StoredProject,
) -> StorageResult<(ProjectSummary, NormalizedPathKey)> {
    let normalized_path = NormalizedPathKey::from_storage_string(&stored.normalized_path)
        .map_err(corrupt_project_contract)?;
    NormalizedProjectRoot::from_platform_observation(
        stored.root_directory.clone(),
        normalized_path.clone(),
    )
    .map_err(corrupt_project_contract)?;
    let summary = ProjectSummary {
        id: stored.id,
        input: domain::ProjectInput {
            name: stored.name,
            root_directory: stored.root_directory,
        },
        created_at: stored.created_at,
        updated_at: stored.updated_at,
    };
    lifecycle::validate_project_summary(&summary).map_err(corrupt_project_contract)?;
    Ok((summary, normalized_path))
}

fn classification_rule_summary_to_stored(
    summary: &ClassificationRuleSummary,
) -> StoredClassificationRule {
    let (action, project_id) = action_to_storage(&summary.input.action);
    StoredClassificationRule {
        id: summary.id.clone(),
        rule_type: matcher_kind_to_storage(summary.input.matcher_kind).to_owned(),
        pattern: summary.input.pattern.clone(),
        action: action.to_owned(),
        project_id,
        priority: i64::from(summary.input.priority),
        enabled: summary.input.enabled,
        created_at: summary.created_at.clone(),
        updated_at: summary.updated_at.clone(),
    }
}

fn stored_rule_to_summary(
    stored: StoredClassificationRule,
) -> StorageResult<ClassificationRuleSummary> {
    let priority = i32::try_from(stored.priority).map_err(|_| {
        corrupt_rule_field(
            "priority",
            "is outside the public classification rule priority range",
        )
    })?;
    let summary = ClassificationRuleSummary {
        id: stored.id,
        input: ClassificationRuleInput {
            matcher_kind: matcher_kind_from_storage(&stored.rule_type)?,
            pattern: stored.pattern,
            action: action_from_storage(&stored.action, stored.project_id)?,
            priority,
            enabled: stored.enabled,
        },
        created_at: stored.created_at,
        updated_at: stored.updated_at,
    };
    lifecycle::validate_classification_rule_summary(&summary).map_err(corrupt_rule_contract)?;
    Ok(summary)
}

fn stored_rule_to_discovery(
    stored: StoredClassificationRule,
) -> StorageResult<DiscoveryClassificationRule> {
    let summary = stored_rule_to_summary(stored)?;
    let pattern = summary.input.pattern;
    let matcher = match summary.input.matcher_kind {
        ClassificationRuleMatcherKind::ExecutableNameExact => {
            DiscoveryClassificationRuleMatcher::ExecutableNameExact(pattern)
        }
        ClassificationRuleMatcherKind::ExecutablePathExact => {
            DiscoveryClassificationRuleMatcher::ExecutablePathExact(pattern)
        }
        ClassificationRuleMatcherKind::CommandLineContains => {
            DiscoveryClassificationRuleMatcher::CommandLineContains(pattern)
        }
        ClassificationRuleMatcherKind::WorkingDirectoryPrefix => {
            DiscoveryClassificationRuleMatcher::WorkingDirectoryPrefix(pattern)
        }
    };
    let action = match summary.input.action {
        ClassificationRuleAction::Include => DiscoveryClassificationRuleAction::Include,
        ClassificationRuleAction::Exclude => DiscoveryClassificationRuleAction::Exclude,
        ClassificationRuleAction::AssignProject { project_id } => {
            DiscoveryClassificationRuleAction::AssignProject(project_id)
        }
    };
    Ok(DiscoveryClassificationRule {
        id: summary.id,
        matcher,
        action,
        priority: i64::from(summary.input.priority),
        enabled: summary.input.enabled,
    })
}

fn matcher_kind_to_storage(kind: ClassificationRuleMatcherKind) -> &'static str {
    match kind {
        ClassificationRuleMatcherKind::ExecutableNameExact => "EXECUTABLE_NAME_EXACT",
        ClassificationRuleMatcherKind::ExecutablePathExact => "EXECUTABLE_PATH_EXACT",
        ClassificationRuleMatcherKind::CommandLineContains => "COMMAND_LINE_CONTAINS",
        ClassificationRuleMatcherKind::WorkingDirectoryPrefix => "WORKING_DIRECTORY_PREFIX",
    }
}

fn matcher_kind_from_storage(value: &str) -> StorageResult<ClassificationRuleMatcherKind> {
    match value {
        "EXECUTABLE_NAME_EXACT" => Ok(ClassificationRuleMatcherKind::ExecutableNameExact),
        "EXECUTABLE_PATH_EXACT" => Ok(ClassificationRuleMatcherKind::ExecutablePathExact),
        "COMMAND_LINE_CONTAINS" => Ok(ClassificationRuleMatcherKind::CommandLineContains),
        "WORKING_DIRECTORY_PREFIX" => Ok(ClassificationRuleMatcherKind::WorkingDirectoryPrefix),
        _ => Err(corrupt_rule_field(
            "matcherKind",
            "contains an unknown stored matcher kind",
        )),
    }
}

fn action_to_storage(action: &ClassificationRuleAction) -> (&'static str, Option<String>) {
    match action {
        ClassificationRuleAction::Include => ("INCLUDE", None),
        ClassificationRuleAction::Exclude => ("EXCLUDE", None),
        ClassificationRuleAction::AssignProject { project_id } => {
            ("ASSIGN_PROJECT", Some(project_id.clone()))
        }
    }
}

fn action_from_storage(
    action: &str,
    project_id: Option<String>,
) -> StorageResult<ClassificationRuleAction> {
    match (action, project_id) {
        ("INCLUDE", None) => Ok(ClassificationRuleAction::Include),
        ("EXCLUDE", None) => Ok(ClassificationRuleAction::Exclude),
        ("ASSIGN_PROJECT", Some(project_id)) => {
            Ok(ClassificationRuleAction::AssignProject { project_id })
        }
        _ => Err(corrupt_rule_field(
            "action",
            "stored action and project relation are inconsistent",
        )),
    }
}

async fn project_row(
    transaction: &mut Transaction<'_, Sqlite>,
    project_id: &str,
) -> StorageResult<StoredProject> {
    sqlx::query_as::<_, StoredProject>(
        "SELECT id, name, root_directory, normalized_path, created_at, updated_at \
         FROM projects WHERE id = ?",
    )
    .bind(project_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| storage_error("read project version", error))?
    .ok_or_else(|| not_found("project", project_id))
}

async fn classification_rule_row(
    transaction: &mut Transaction<'_, Sqlite>,
    rule_id: &str,
) -> StorageResult<StoredClassificationRule> {
    sqlx::query_as::<_, StoredClassificationRule>(
        "SELECT id, rule_type, pattern, action, project_id, priority, enabled, \
         created_at, updated_at FROM classification_rules WHERE id = ?",
    )
    .bind(rule_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| storage_error("read classification rule version", error))?
    .ok_or_else(|| not_found("classificationRule", rule_id))
}

fn project_cursor_from_summary(summary: &ProjectSummary) -> ProjectCursor {
    ProjectCursor {
        id: summary.id.clone(),
        name: summary.input.name.clone(),
    }
}

fn encode_project_cursor(cursor: &ProjectCursor) -> String {
    format!(
        "{PROJECT_CURSOR_PREFIX}{}|{}{}",
        cursor.name.len(),
        cursor.name,
        cursor.id
    )
}

fn decode_project_cursor(value: &str) -> StorageResult<ProjectCursor> {
    let body = value
        .strip_prefix(PROJECT_CURSOR_PREFIX)
        .ok_or_else(|| invalid_cursor("project", "uses an unsupported cursor version"))?;
    let (name_length, payload) = body
        .split_once('|')
        .ok_or_else(|| invalid_cursor("project", "is malformed"))?;
    let name_length = name_length
        .parse::<usize>()
        .ok()
        .filter(|length| *length <= payload.len())
        .ok_or_else(|| invalid_cursor("project", "contains an invalid name length"))?;
    let name = payload
        .get(..name_length)
        .ok_or_else(|| invalid_cursor("project", "splits a UTF-8 sequence"))?;
    let id = payload
        .get(name_length..)
        .filter(|id| !id.is_empty())
        .ok_or_else(|| invalid_cursor("project", "does not contain a project ID"))?;
    let cursor = ProjectCursor {
        id: id.to_owned(),
        name: name.to_owned(),
    };
    if encode_project_cursor(&cursor) != value {
        return Err(invalid_cursor("project", "is not canonical"));
    }
    Ok(cursor)
}

fn rule_cursor_from_summary(summary: &ClassificationRuleSummary) -> ClassificationRuleCursor {
    ClassificationRuleCursor {
        id: summary.id.clone(),
        priority: summary.input.priority,
    }
}

fn encode_classification_rule_cursor(cursor: &ClassificationRuleCursor) -> String {
    format!("{RULE_CURSOR_PREFIX}{}|{}", cursor.priority, cursor.id)
}

fn decode_classification_rule_cursor(value: &str) -> StorageResult<ClassificationRuleCursor> {
    let body = value.strip_prefix(RULE_CURSOR_PREFIX).ok_or_else(|| {
        invalid_cursor("classificationRule", "uses an unsupported cursor version")
    })?;
    let (priority, id) = body
        .split_once('|')
        .filter(|(_, id)| !id.is_empty())
        .ok_or_else(|| invalid_cursor("classificationRule", "is malformed"))?;
    let priority = priority
        .parse::<i32>()
        .map_err(|_| invalid_cursor("classificationRule", "contains an invalid priority"))?;
    let cursor = ClassificationRuleCursor {
        id: id.to_owned(),
        priority,
    };
    if encode_classification_rule_cursor(&cursor) != value {
        return Err(invalid_cursor("classificationRule", "is not canonical"));
    }
    Ok(cursor)
}

fn require_expected_version(
    entity: &'static str,
    id_field: &'static str,
    id: &str,
    expected_updated_at: &str,
    actual_updated_at: &str,
) -> StorageResult<()> {
    if expected_updated_at == actual_updated_at {
        Ok(())
    } else {
        Err(version_conflict(
            entity,
            id_field,
            id,
            expected_updated_at,
            actual_updated_at,
        ))
    }
}

fn version_conflict(
    entity: &'static str,
    id_field: &'static str,
    id: &str,
    expected_updated_at: &str,
    actual_updated_at: &str,
) -> AppError {
    let mut error = AppError::new(
        ErrorCode::Conflict,
        format!("{entity} was modified by another operation"),
    );
    error.details.insert(id_field.into(), id.into());
    error
        .details
        .insert("expectedUpdatedAt".into(), expected_updated_at.into());
    error
        .details
        .insert("actualUpdatedAt".into(), actual_updated_at.into());
    error
}

fn project_in_use(project_id: &str, has_profiles: bool, has_rules: bool) -> AppError {
    let mut error = AppError::new(
        ErrorCode::Conflict,
        "Project is still referenced and cannot be deleted",
    );
    error.details.insert("projectId".into(), project_id.into());
    error
        .details
        .insert("hasLaunchProfiles".into(), has_profiles.to_string());
    error
        .details
        .insert("hasClassificationRules".into(), has_rules.to_string());
    error
}

fn invalid_cursor(entity: &'static str, reason: &'static str) -> AppError {
    let mut error = AppError::new(ErrorCode::InvalidArgument, "List cursor is invalid");
    error.details.insert("entity".into(), entity.into());
    error.details.insert("field".into(), "cursor".into());
    error.details.insert("reason".into(), reason.into());
    error
}

fn invalid_server_project(field: &'static str, reason: &'static str) -> AppError {
    let mut error = AppError::new(ErrorCode::Internal, "Server-owned project is invalid");
    error.details.insert("field".into(), field.into());
    error.details.insert("reason".into(), reason.into());
    error
}

fn invalid_server_project_validation(source: AppError) -> AppError {
    invalid_server_contract("Server-owned project is invalid", source)
}

fn invalid_server_rule(field: &'static str, reason: &'static str) -> AppError {
    let mut error = AppError::new(
        ErrorCode::Internal,
        "Server-owned classification rule is invalid",
    );
    error.details.insert("field".into(), field.into());
    error.details.insert("reason".into(), reason.into());
    error
}

fn invalid_server_rule_validation(source: AppError) -> AppError {
    invalid_server_contract("Server-owned classification rule is invalid", source)
}

fn invalid_server_contract(message: &'static str, source: AppError) -> AppError {
    let mut error = AppError::new(ErrorCode::Internal, message);
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

fn corrupt_project_contract(source: AppError) -> AppError {
    corrupt_stored_contract("Stored project is invalid", source)
}

fn corrupt_rule_contract(source: AppError) -> AppError {
    corrupt_stored_contract("Stored classification rule is invalid", source)
}

fn corrupt_project_context(source: AppError) -> AppError {
    corrupt_stored_contract("Stored project and rule context is invalid", source)
}

fn corrupt_rule_field(field: &'static str, reason: &'static str) -> AppError {
    let mut error = AppError::new(
        ErrorCode::StorageError,
        "Stored classification rule is invalid",
    );
    error.details.insert("field".into(), field.into());
    error.details.insert("reason".into(), reason.into());
    error
}

fn corrupt_stored_contract(message: &'static str, source: AppError) -> AppError {
    let mut error = AppError::new(ErrorCode::StorageError, message);
    if let Some(field) = source.details.get("field") {
        error.details.insert("field".into(), field.clone());
    }
    error.details.insert("reason".into(), source.message);
    error
}
