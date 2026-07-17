import type {
  ClassificationRuleAction,
  ClassificationRuleInput,
  ClassificationRuleMatcherKind,
  ClassificationRuleSummary,
  DeleteClassificationRuleRequest,
  DeleteClassificationRuleResponse,
  DeleteProjectRequest,
  DeleteProjectResponse,
  ListClassificationRulesRequest,
  ListClassificationRulesResponse,
  ListProjectsRequest,
  ListProjectsResponse,
  ProjectInput,
  ProjectSummary,
  SaveClassificationRuleRequest,
  SaveProjectRequest,
} from '@dpm/generated-types';

import { forwardSupervisorRpc } from './supervisor';

export const CATALOG_PAGE_SIZE = 100;
export const MAX_CATALOG_ITEMS = 4_096;

const PROJECT_LIST_METHOD = 'project.list';
const PROJECT_SAVE_METHOD = 'project.save';
const PROJECT_DELETE_METHOD = 'project.delete';
const RULE_LIST_METHOD = 'rule.list';
const RULE_SAVE_METHOD = 'rule.save';
const RULE_DELETE_METHOD = 'rule.delete';

const CATALOG_READ_TIMEOUT_MS = 15_000;
const CATALOG_WRITE_TIMEOUT_MS = 30_000;
const MAX_CATALOG_PAGES = Math.ceil(MAX_CATALOG_ITEMS / CATALOG_PAGE_SIZE);
const MAX_PROJECT_ID_BYTES = 256;
const MAX_PROJECT_NAME_BYTES = 256;
const MAX_PROJECT_ROOT_BYTES = 32 * 1_024;
const MAX_TIMESTAMP_BYTES = 128;
const MAX_RULE_ID_BYTES = 256;
const MAX_RULE_PATTERN_BYTES = 4 * 1_024;
const MAX_RULE_PRIORITY = 1_000_000;
const MAX_CURSOR_BYTES = 4 * 1_024;
const MAX_PROJECT_REQUEST_WIRE_BYTES = 64 * 1_024;
const MAX_PROJECT_LIST_WIRE_BYTES = 4 * 1_024 * 1_024;
const MAX_RULE_REQUEST_WIRE_BYTES = 16 * 1_024;
const MAX_RULE_LIST_WIRE_BYTES = 1_024 * 1_024;

const PROJECT_INPUT_KEYS = ['name', 'rootDirectory'] as const;
const PROJECT_SUMMARY_KEYS = ['id', 'input', 'createdAt', 'updatedAt'] as const;
const PROJECT_LIST_RESPONSE_KEYS = ['projects', 'nextCursor'] as const;
const PROJECT_CREATE_REQUEST_KEYS = ['operation', 'input'] as const;
const PROJECT_UPDATE_REQUEST_KEYS = [
  'operation',
  'projectId',
  'expectedUpdatedAt',
  'input',
] as const;
const PROJECT_DELETE_REQUEST_KEYS = ['projectId', 'expectedUpdatedAt'] as const;
const PROJECT_DELETE_RESPONSE_KEYS = ['projectId'] as const;
const RULE_INPUT_KEYS = ['matcherKind', 'pattern', 'action', 'priority', 'enabled'] as const;
const RULE_SUMMARY_KEYS = ['id', 'input', 'createdAt', 'updatedAt'] as const;
const RULE_LIST_RESPONSE_KEYS = ['rules', 'nextCursor'] as const;
const RULE_CREATE_REQUEST_KEYS = ['operation', 'input'] as const;
const RULE_UPDATE_REQUEST_KEYS = ['operation', 'ruleId', 'expectedUpdatedAt', 'input'] as const;
const RULE_DELETE_REQUEST_KEYS = ['ruleId', 'expectedUpdatedAt'] as const;
const RULE_DELETE_RESPONSE_KEYS = ['ruleId'] as const;
const INCLUDE_ACTION_KEYS = ['kind'] as const;
const ASSIGN_PROJECT_ACTION_KEYS = ['kind', 'projectId'] as const;

const MATCHER_KINDS = new Set<unknown>([
  'executableNameExact',
  'executablePathExact',
  'commandLineContains',
  'workingDirectoryPrefix',
] satisfies ReadonlyArray<ClassificationRuleMatcherKind>);
const CANONICAL_UTC_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{9}Z$/;
const DISALLOWED_TEXT = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Cs}\p{Cn}]/u;
const utf8Encoder = new TextEncoder();

export async function listProjects(): Promise<ReadonlyArray<ProjectSummary>> {
  const projects: ProjectSummary[] = [];
  const projectIds = new Set<string>();
  const cursors = new Set<string>();
  let cursor: string | null = null;

  for (let page = 0; page < MAX_CATALOG_PAGES; page += 1) {
    const request: ListProjectsRequest = { cursor, limit: CATALOG_PAGE_SIZE };
    if (!isListProjectsRequest(request)) {
      throw new TypeError('invalid project list request');
    }
    const response = await forwardSupervisorRpc<unknown>({
      requestId: createRpcId('project-list-request'),
      operationId: null,
      timeoutMs: CATALOG_READ_TIMEOUT_MS,
      method: PROJECT_LIST_METHOD,
      params: request,
    });
    if (!isListProjectsResponse(response) || response.projects.length > request.limit) {
      throw new TypeError('invalid project list response');
    }
    if (projects.length + response.projects.length > MAX_CATALOG_ITEMS) {
      throw new TypeError('project list exceeds the supported item limit');
    }
    for (const project of response.projects) {
      if (projectIds.has(project.id)) {
        throw new TypeError('project list contains a duplicate project identity');
      }
      projectIds.add(project.id);
      projects.push(project);
    }
    if (response.nextCursor === null) {
      return projects;
    }
    if (
      response.projects.length === 0 ||
      response.nextCursor === cursor ||
      cursors.has(response.nextCursor)
    ) {
      throw new TypeError('project list contains a non-advancing cursor');
    }
    cursors.add(response.nextCursor);
    cursor = response.nextCursor;
  }

  throw new TypeError('project list exceeds the supported page limit');
}

export async function listClassificationRules(): Promise<ReadonlyArray<ClassificationRuleSummary>> {
  const rules: ClassificationRuleSummary[] = [];
  const ruleIds = new Set<string>();
  const cursors = new Set<string>();
  let cursor: string | null = null;

  for (let page = 0; page < MAX_CATALOG_PAGES; page += 1) {
    const request: ListClassificationRulesRequest = { cursor, limit: CATALOG_PAGE_SIZE };
    if (!isListClassificationRulesRequest(request)) {
      throw new TypeError('invalid classification rule list request');
    }
    const response = await forwardSupervisorRpc<unknown>({
      requestId: createRpcId('rule-list-request'),
      operationId: null,
      timeoutMs: CATALOG_READ_TIMEOUT_MS,
      method: RULE_LIST_METHOD,
      params: request,
    });
    if (!isListClassificationRulesResponse(response) || response.rules.length > request.limit) {
      throw new TypeError('invalid classification rule list response');
    }
    if (rules.length + response.rules.length > MAX_CATALOG_ITEMS) {
      throw new TypeError('classification rule list exceeds the supported item limit');
    }
    for (const rule of response.rules) {
      if (ruleIds.has(rule.id)) {
        throw new TypeError('classification rule list contains a duplicate rule identity');
      }
      ruleIds.add(rule.id);
      rules.push(rule);
    }
    if (response.nextCursor === null) {
      return rules;
    }
    if (
      response.rules.length === 0 ||
      response.nextCursor === cursor ||
      cursors.has(response.nextCursor)
    ) {
      throw new TypeError('classification rule list contains a non-advancing cursor');
    }
    cursors.add(response.nextCursor);
    cursor = response.nextCursor;
  }

  throw new TypeError('classification rule list exceeds the supported page limit');
}

/** Sends one mutation RPC. Callers decide whether the user should try again. */
export async function saveProject(request: SaveProjectRequest): Promise<ProjectSummary> {
  if (!isSaveProjectRequest(request)) {
    throw new TypeError('invalid project save request');
  }
  const response = await forwardSupervisorRpc<unknown>({
    requestId: createRpcId('project-save-request'),
    operationId: createRpcId('project-save-operation'),
    timeoutMs: CATALOG_WRITE_TIMEOUT_MS,
    method: PROJECT_SAVE_METHOD,
    params: request,
  });
  if (!isProjectSummary(response) || !projectSaveResponseMatchesRequest(response, request)) {
    throw new TypeError('invalid project save response');
  }
  return response;
}

/** Sends one mutation RPC and verifies that the acknowledged identity is exact. */
export async function deleteProject(request: DeleteProjectRequest): Promise<DeleteProjectResponse> {
  if (!isDeleteProjectRequest(request)) {
    throw new TypeError('invalid project delete request');
  }
  const response = await forwardSupervisorRpc<unknown>({
    requestId: createRpcId('project-delete-request'),
    operationId: createRpcId('project-delete-operation'),
    timeoutMs: CATALOG_WRITE_TIMEOUT_MS,
    method: PROJECT_DELETE_METHOD,
    params: request,
  });
  if (!isDeleteProjectResponse(response) || response.projectId !== request.projectId) {
    throw new TypeError('invalid project delete response');
  }
  return response;
}

/** Sends one mutation RPC. Callers decide whether the user should try again. */
export async function saveClassificationRule(
  request: SaveClassificationRuleRequest,
): Promise<ClassificationRuleSummary> {
  if (!isSaveClassificationRuleRequest(request)) {
    throw new TypeError('invalid classification rule save request');
  }
  const response = await forwardSupervisorRpc<unknown>({
    requestId: createRpcId('rule-save-request'),
    operationId: createRpcId('rule-save-operation'),
    timeoutMs: CATALOG_WRITE_TIMEOUT_MS,
    method: RULE_SAVE_METHOD,
    params: request,
  });
  if (
    !isClassificationRuleSummary(response) ||
    !ruleSaveResponseMatchesRequest(response, request)
  ) {
    throw new TypeError('invalid classification rule save response');
  }
  return response;
}

/** Sends one mutation RPC and verifies that the acknowledged identity is exact. */
export async function deleteClassificationRule(
  request: DeleteClassificationRuleRequest,
): Promise<DeleteClassificationRuleResponse> {
  if (!isDeleteClassificationRuleRequest(request)) {
    throw new TypeError('invalid classification rule delete request');
  }
  const response = await forwardSupervisorRpc<unknown>({
    requestId: createRpcId('rule-delete-request'),
    operationId: createRpcId('rule-delete-operation'),
    timeoutMs: CATALOG_WRITE_TIMEOUT_MS,
    method: RULE_DELETE_METHOD,
    params: request,
  });
  if (!isDeleteClassificationRuleResponse(response) || response.ruleId !== request.ruleId) {
    throw new TypeError('invalid classification rule delete response');
  }
  return response;
}

export function isProjectSummary(value: unknown): value is ProjectSummary {
  return (
    isObject(value) &&
    hasExactKeys(value, PROJECT_SUMMARY_KEYS) &&
    isRequiredText(value.id, MAX_PROJECT_ID_BYTES) &&
    isProjectInput(value.input) &&
    isTimestamp(value.createdAt) &&
    isTimestamp(value.updatedAt) &&
    value.updatedAt >= value.createdAt &&
    jsonFitsWireLimit(value, MAX_PROJECT_REQUEST_WIRE_BYTES)
  );
}

export function isClassificationRuleSummary(value: unknown): value is ClassificationRuleSummary {
  return (
    isObject(value) &&
    hasExactKeys(value, RULE_SUMMARY_KEYS) &&
    isRequiredText(value.id, MAX_RULE_ID_BYTES) &&
    isClassificationRuleInput(value.input) &&
    isTimestamp(value.createdAt) &&
    isTimestamp(value.updatedAt) &&
    value.updatedAt >= value.createdAt &&
    jsonFitsWireLimit(value, MAX_RULE_REQUEST_WIRE_BYTES)
  );
}

function isListProjectsRequest(value: unknown): value is ListProjectsRequest {
  return (
    isObject(value) &&
    hasExactKeys(value, ['cursor', 'limit']) &&
    isNullableRequiredText(value.cursor, MAX_CURSOR_BYTES) &&
    isPageSize(value.limit) &&
    jsonFitsWireLimit(value, MAX_PROJECT_REQUEST_WIRE_BYTES)
  );
}

function isListProjectsResponse(value: unknown): value is ListProjectsResponse {
  if (
    !isObject(value) ||
    !hasExactKeys(value, PROJECT_LIST_RESPONSE_KEYS) ||
    !Array.isArray(value.projects) ||
    value.projects.length > CATALOG_PAGE_SIZE ||
    !isNullableRequiredText(value.nextCursor, MAX_CURSOR_BYTES)
  ) {
    return false;
  }
  const ids = new Set<string>();
  for (const project of value.projects) {
    if (!isProjectSummary(project) || ids.has(project.id)) {
      return false;
    }
    ids.add(project.id);
  }
  return jsonFitsWireLimit(value, MAX_PROJECT_LIST_WIRE_BYTES);
}

function isListClassificationRulesRequest(value: unknown): value is ListClassificationRulesRequest {
  return (
    isObject(value) &&
    hasExactKeys(value, ['cursor', 'limit']) &&
    isNullableRequiredText(value.cursor, MAX_CURSOR_BYTES) &&
    isPageSize(value.limit) &&
    jsonFitsWireLimit(value, MAX_RULE_REQUEST_WIRE_BYTES)
  );
}

function isListClassificationRulesResponse(
  value: unknown,
): value is ListClassificationRulesResponse {
  if (
    !isObject(value) ||
    !hasExactKeys(value, RULE_LIST_RESPONSE_KEYS) ||
    !Array.isArray(value.rules) ||
    value.rules.length > CATALOG_PAGE_SIZE ||
    !isNullableRequiredText(value.nextCursor, MAX_CURSOR_BYTES)
  ) {
    return false;
  }
  const ids = new Set<string>();
  for (const rule of value.rules) {
    if (!isClassificationRuleSummary(rule) || ids.has(rule.id)) {
      return false;
    }
    ids.add(rule.id);
  }
  return jsonFitsWireLimit(value, MAX_RULE_LIST_WIRE_BYTES);
}

function isProjectInput(value: unknown): value is ProjectInput {
  return (
    isObject(value) &&
    hasExactKeys(value, PROJECT_INPUT_KEYS) &&
    isRequiredText(value.name, MAX_PROJECT_NAME_BYTES) &&
    isRequiredText(value.rootDirectory, MAX_PROJECT_ROOT_BYTES) &&
    isAbsolutePath(value.rootDirectory) &&
    jsonFitsWireLimit(value, MAX_PROJECT_REQUEST_WIRE_BYTES)
  );
}

function isClassificationRuleInput(value: unknown): value is ClassificationRuleInput {
  return (
    isObject(value) &&
    hasExactKeys(value, RULE_INPUT_KEYS) &&
    MATCHER_KINDS.has(value.matcherKind) &&
    isRequiredText(value.pattern, MAX_RULE_PATTERN_BYTES) &&
    isClassificationRuleAction(value.action) &&
    typeof value.priority === 'number' &&
    Number.isSafeInteger(value.priority) &&
    value.priority >= -MAX_RULE_PRIORITY &&
    value.priority <= MAX_RULE_PRIORITY &&
    typeof value.enabled === 'boolean' &&
    jsonFitsWireLimit(value, MAX_RULE_REQUEST_WIRE_BYTES)
  );
}

function isClassificationRuleAction(value: unknown): value is ClassificationRuleAction {
  if (!isObject(value)) {
    return false;
  }
  if (value.kind === 'include' || value.kind === 'exclude') {
    return hasExactKeys(value, INCLUDE_ACTION_KEYS);
  }
  return (
    value.kind === 'assignProject' &&
    hasExactKeys(value, ASSIGN_PROJECT_ACTION_KEYS) &&
    isRequiredText(value.projectId, MAX_PROJECT_ID_BYTES)
  );
}

function isSaveProjectRequest(value: unknown): value is SaveProjectRequest {
  if (!isObject(value)) {
    return false;
  }
  const valid =
    value.operation === 'create'
      ? hasExactKeys(value, PROJECT_CREATE_REQUEST_KEYS) && isProjectInput(value.input)
      : value.operation === 'update' &&
        hasExactKeys(value, PROJECT_UPDATE_REQUEST_KEYS) &&
        isRequiredText(value.projectId, MAX_PROJECT_ID_BYTES) &&
        isTimestamp(value.expectedUpdatedAt) &&
        isProjectInput(value.input);
  return valid && jsonFitsWireLimit(value, MAX_PROJECT_REQUEST_WIRE_BYTES);
}

function isSaveClassificationRuleRequest(value: unknown): value is SaveClassificationRuleRequest {
  if (!isObject(value)) {
    return false;
  }
  const valid =
    value.operation === 'create'
      ? hasExactKeys(value, RULE_CREATE_REQUEST_KEYS) && isClassificationRuleInput(value.input)
      : value.operation === 'update' &&
        hasExactKeys(value, RULE_UPDATE_REQUEST_KEYS) &&
        isRequiredText(value.ruleId, MAX_RULE_ID_BYTES) &&
        isTimestamp(value.expectedUpdatedAt) &&
        isClassificationRuleInput(value.input);
  return valid && jsonFitsWireLimit(value, MAX_RULE_REQUEST_WIRE_BYTES);
}

function isDeleteProjectRequest(value: unknown): value is DeleteProjectRequest {
  return (
    isObject(value) &&
    hasExactKeys(value, PROJECT_DELETE_REQUEST_KEYS) &&
    isRequiredText(value.projectId, MAX_PROJECT_ID_BYTES) &&
    isTimestamp(value.expectedUpdatedAt) &&
    jsonFitsWireLimit(value, MAX_PROJECT_REQUEST_WIRE_BYTES)
  );
}

function isDeleteProjectResponse(value: unknown): value is DeleteProjectResponse {
  return (
    isObject(value) &&
    hasExactKeys(value, PROJECT_DELETE_RESPONSE_KEYS) &&
    isRequiredText(value.projectId, MAX_PROJECT_ID_BYTES) &&
    jsonFitsWireLimit(value, MAX_PROJECT_REQUEST_WIRE_BYTES)
  );
}

function isDeleteClassificationRuleRequest(
  value: unknown,
): value is DeleteClassificationRuleRequest {
  return (
    isObject(value) &&
    hasExactKeys(value, RULE_DELETE_REQUEST_KEYS) &&
    isRequiredText(value.ruleId, MAX_RULE_ID_BYTES) &&
    isTimestamp(value.expectedUpdatedAt) &&
    jsonFitsWireLimit(value, MAX_RULE_REQUEST_WIRE_BYTES)
  );
}

function isDeleteClassificationRuleResponse(
  value: unknown,
): value is DeleteClassificationRuleResponse {
  return (
    isObject(value) &&
    hasExactKeys(value, RULE_DELETE_RESPONSE_KEYS) &&
    isRequiredText(value.ruleId, MAX_RULE_ID_BYTES) &&
    jsonFitsWireLimit(value, MAX_RULE_REQUEST_WIRE_BYTES)
  );
}

function projectSaveResponseMatchesRequest(response: ProjectSummary, request: SaveProjectRequest) {
  return (
    response.input.name === request.input.name &&
    (request.operation === 'create' || response.id === request.projectId)
  );
}

function ruleSaveResponseMatchesRequest(
  response: ClassificationRuleSummary,
  request: SaveClassificationRuleRequest,
) {
  return (
    classificationRuleInputsEqual(response.input, request.input) &&
    (request.operation === 'create' || response.id === request.ruleId)
  );
}

function classificationRuleInputsEqual(
  left: ClassificationRuleInput,
  right: ClassificationRuleInput,
) {
  return (
    left.matcherKind === right.matcherKind &&
    left.pattern === right.pattern &&
    left.priority === right.priority &&
    left.enabled === right.enabled &&
    classificationRuleActionsEqual(left.action, right.action)
  );
}

function classificationRuleActionsEqual(
  left: ClassificationRuleAction,
  right: ClassificationRuleAction,
) {
  return (
    left.kind === right.kind &&
    (left.kind !== 'assignProject' ||
      (right.kind === 'assignProject' && left.projectId === right.projectId))
  );
}

function isPageSize(value: unknown): value is number {
  return (
    typeof value === 'number' &&
    Number.isSafeInteger(value) &&
    value >= 1 &&
    value <= CATALOG_PAGE_SIZE
  );
}

function isTimestamp(value: unknown): value is string {
  if (
    !isRequiredText(value, MAX_TIMESTAMP_BYTES) ||
    !CANONICAL_UTC_TIMESTAMP.test(value) ||
    value.startsWith('0000-')
  ) {
    return false;
  }
  const parsed = new Date(value);
  return Number.isFinite(parsed.getTime()) && parsed.toISOString() === `${value.slice(0, 23)}Z`;
}

function isNullableRequiredText(value: unknown, maximumBytes: number): value is string | null {
  return value === null || isRequiredText(value, maximumBytes);
}

function isRequiredText(value: unknown, maximumBytes: number): value is string {
  return (
    typeof value === 'string' &&
    value.trim().length > 0 &&
    utf8ByteLength(value) <= maximumBytes &&
    !DISALLOWED_TEXT.test(value)
  );
}

function isAbsolutePath(value: string) {
  if (value.startsWith('/')) {
    return true;
  }
  const windowsPath = value.replaceAll('/', '\\');
  if (/^[A-Za-z]:\\/.test(windowsPath)) {
    return true;
  }
  if (!windowsPath.startsWith('\\\\')) {
    return false;
  }
  const [server, share] = windowsPath.slice(2).split('\\');
  return server !== undefined && share !== undefined && server !== '' && share !== '';
}

function jsonFitsWireLimit(value: unknown, maximumBytes: number) {
  try {
    const json = JSON.stringify(value);
    return typeof json === 'string' && utf8ByteLength(json) <= maximumBytes;
  } catch {
    return false;
  }
}

function utf8ByteLength(value: string) {
  return utf8Encoder.encode(value).length;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function hasExactKeys(value: Record<string, unknown>, expectedKeys: ReadonlyArray<string>) {
  const actualKeys = Object.keys(value);
  return (
    actualKeys.length === expectedKeys.length &&
    expectedKeys.every((key) => Object.hasOwn(value, key))
  );
}

function createRpcId(prefix: string) {
  return `${prefix}:${globalThis.crypto.randomUUID()}`;
}
