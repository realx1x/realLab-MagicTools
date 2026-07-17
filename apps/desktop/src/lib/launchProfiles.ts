import type {
  DeleteLaunchProfileRequest,
  DeleteLaunchProfileResponse,
  ExecutionPreviewRequest,
  FinalExecutionPreview,
  LaunchProfile,
  LaunchProfileInput,
  ListLaunchProfilesResponse,
  SaveLaunchProfileWithSecretsRequest,
} from '@dpm/generated-types';
import { forwardSupervisorRpc } from './supervisor';

const PROFILE_LIST_METHOD = 'profile.list';
const PROFILE_SAVE_METHOD = 'profile.save';
const PROFILE_DELETE_METHOD = 'profile.delete';
const PROFILE_PREVIEW_METHOD = 'profile.preview';

const PROFILE_READ_TIMEOUT_MS = 15_000;
const PROFILE_WRITE_TIMEOUT_MS = 30_000;
const MAX_PROFILE_LIST_PAGES = 256;
const MAX_PROFILE_LIST_ITEMS = 1_024;
const MAX_PROFILE_PAGE_SIZE = 4;

const MAX_PROFILE_ID_BYTES = 256;
const MAX_PROFILE_NAME_BYTES = 256;
const MAX_PROJECT_ID_BYTES = 256;
const MAX_EXECUTABLE_BYTES = 32 * 1_024;
const MAX_ARGUMENTS = 256;
const MAX_PREVIEW_ARGUMENTS = MAX_ARGUMENTS + 8;
const MAX_ARGUMENT_BYTES = 32 * 1_024;
const MAX_SHELL_ARGUMENT_BYTES = 64 * 1_024;
const MAX_ARGUMENT_TOTAL_BYTES = 64 * 1_024;
const MAX_PREVIEW_ARGUMENT_TOTAL_BYTES = 128 * 1_024;
const MAX_SHELL_COMMAND_BYTES = 64 * 1_024;
const MAX_WORKING_DIRECTORY_BYTES = 32 * 1_024;
const MAX_ENVIRONMENT_ENTRIES = 256;
const MAX_ENVIRONMENT_NAME_BYTES = 256;
const MAX_ENVIRONMENT_VALUE_BYTES = 32 * 1_024;
const MAX_ENVIRONMENT_TOTAL_BYTES = 64 * 1_024;
const MAX_MERGED_ENVIRONMENT_TOTAL_BYTES = 256 * 1_024;
const MAX_CREDENTIAL_REFERENCE_BYTES = 4 * 1_024;
const MAX_CREDENTIAL_SECRET_BYTES = 2_560;
const MAX_TIMESTAMP_BYTES = 128;
const MAX_PROFILE_CURSOR_BYTES = 1_024;
const MAX_STOP_TIMEOUT_MS = 300_000;
const MAX_PROFILE_INPUT_WIRE_BYTES = 192 * 1_024;
const MAX_SECRET_REQUEST_WIRE_BYTES = 256 * 1_024;
const MAX_PROFILE_LIST_WIRE_BYTES = 896 * 1_024;
const MAX_EXECUTION_PREVIEW_WIRE_BYTES = 896 * 1_024;
const MAX_PATH_EXTENSIONS = 64;
const MAX_PATH_EXTENSION_BYTES = 16;
const MAX_PATH_ENTRIES = 256;
const MAX_EXECUTABLE_CANDIDATES = 256;
const MAX_EXECUTABLE_CANDIDATE_TOTAL_BYTES = 256 * 1_024;

const PORTABLE_ENVIRONMENT_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;
const PATH_EXTENSION = /^\.[A-Z0-9]+$/;
const CREDENTIAL_REFERENCE = /^mtcred1:[0-9a-f]{64}:[0-9a-f]{64}$/;
const OPERATION_ID = /^[A-Za-z0-9_.:-]+$/;
const RFC3339_TIMESTAMP =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/;
const CONTROL_CHARACTER = /\p{Cc}/u;
const utf8Encoder = new TextEncoder();

const LAUNCH_PROFILE_KEYS = ['id', 'input', 'createdAt', 'updatedAt'] as const;
const LAUNCH_PROFILE_INPUT_KEYS = [
  'projectId',
  'name',
  'execution',
  'workingDirectory',
  'environment',
  'interactive',
  'stopTimeoutMs',
] as const;
const DIRECT_LAUNCH_KEYS = ['mode', 'executable', 'argv'] as const;
const SHELL_LAUNCH_KEYS = ['mode', 'shell', 'command'] as const;
const ENVIRONMENT_ENTRY_KEYS = ['name', 'value'] as const;
const PLAIN_ENVIRONMENT_VALUE_KEYS = ['kind', 'value'] as const;
const CREDENTIAL_ENVIRONMENT_VALUE_KEYS = ['kind', 'credentialReference'] as const;
const LIST_RESPONSE_KEYS = ['profiles', 'nextCursor'] as const;
const DELETE_REQUEST_KEYS = ['profileId', 'expectedUpdatedAt'] as const;
const DELETE_RESPONSE_KEYS = ['profileId'] as const;
const PREVIEW_REQUEST_KEYS = ['profile'] as const;
const SAVE_REQUEST_KEYS = ['request', 'secretEnvironment'] as const;
const CREATE_PROFILE_REQUEST_KEYS = ['operation', 'input'] as const;
const UPDATE_PROFILE_REQUEST_KEYS = [
  'operation',
  'profileId',
  'expectedUpdatedAt',
  'input',
] as const;
const SECRET_ENVIRONMENT_ENTRY_KEYS = ['name', 'secret'] as const;
const FINAL_PREVIEW_KEYS = [
  'platform',
  'workingDirectory',
  'interactive',
  'requiresCredentialResolution',
  'invocation',
  'environment',
  'path',
  'pathExtensions',
  'executableResolution',
] as const;
const DIRECT_PREVIEW_KEYS = ['mode', 'executable', 'argv'] as const;
const SHELL_PREVIEW_KEYS = ['mode', 'shell', 'executable', 'argv', 'command'] as const;
const ENVIRONMENT_PREVIEW_ENTRY_KEYS = ['name', 'value', 'source'] as const;
const PLAIN_ENVIRONMENT_PREVIEW_VALUE_KEYS = ['plain'] as const;
const KNOWN_PATH_KEYS = ['status', 'value', 'source'] as const;
const UNKNOWN_PATH_KEYS = ['status', 'reason', 'source'] as const;
const KNOWN_PATH_EXTENSION_KEYS = ['status', 'value', 'extensions', 'source'] as const;
const NOT_APPLICABLE_PATH_EXTENSION_KEYS = ['status'] as const;
const UNKNOWN_EXECUTABLE_KEYS = ['status', 'reason', 'candidates'] as const;
const NOT_FOUND_EXECUTABLE_KEYS = ['status', 'reason', 'candidates'] as const;
const NOT_SUPPORTED_EXECUTABLE_KEYS = ['status', 'reason'] as const;
const EXECUTABLE_CANDIDATE_KEYS = ['path', 'source'] as const;
const PATH_CANDIDATE_SOURCE_KEYS = ['path'] as const;
const PATH_CANDIDATE_SOURCE_DETAILS_KEYS = ['pathSource', 'pathIndex', 'entryKind'] as const;

/** Loads all profile pages. A bounded cursor walk prevents a faulty peer from looping forever. */
export async function listLaunchProfiles(): Promise<ReadonlyArray<LaunchProfile>> {
  const profiles: LaunchProfile[] = [];
  const profileIds = new Set<string>();
  const cursors = new Set<string>();
  let cursor: string | null = null;

  for (let page = 0; page < MAX_PROFILE_LIST_PAGES; page += 1) {
    const response: unknown = await forwardSupervisorRpc<unknown>({
      requestId: createRpcId('profile-list-request'),
      operationId: null,
      timeoutMs: PROFILE_READ_TIMEOUT_MS,
      method: PROFILE_LIST_METHOD,
      params: { cursor, limit: MAX_PROFILE_PAGE_SIZE },
    });
    if (!isListLaunchProfilesResponse(response)) {
      throw new TypeError('invalid launch profile list response');
    }
    if (profiles.length + response.profiles.length > MAX_PROFILE_LIST_ITEMS) {
      throw new TypeError('launch profile list exceeds the supported item limit');
    }
    for (const profile of response.profiles) {
      if (profileIds.has(profile.id)) {
        throw new TypeError('launch profile list contains a duplicate profile identity');
      }
      profileIds.add(profile.id);
      profiles.push(profile);
    }

    if (response.nextCursor === null) {
      return profiles;
    }
    if (response.nextCursor === cursor || cursors.has(response.nextCursor)) {
      throw new TypeError('launch profile list contains a repeated cursor');
    }
    cursors.add(response.nextCursor);
    cursor = response.nextCursor;
  }

  throw new TypeError('launch profile list exceeds the supported page limit');
}

/** Sends one caller-owned idempotent mutation attempt without automatic replay. */
export async function saveLaunchProfile(
  request: SaveLaunchProfileWithSecretsRequest,
  operationId: string,
): Promise<LaunchProfile> {
  if (!isSaveLaunchProfileRequest(request) || !isMutationOperationId(operationId)) {
    throw new TypeError('invalid launch profile save request');
  }

  const response = await forwardSupervisorRpc<unknown>({
    requestId: createRpcId('profile-save-request'),
    operationId,
    timeoutMs: PROFILE_WRITE_TIMEOUT_MS,
    method: PROFILE_SAVE_METHOD,
    params: request,
  });
  if (!isLaunchProfile(response)) {
    throw new TypeError('invalid launch profile save response');
  }
  if (!saveResponseMatchesRequest(response, request)) {
    throw new TypeError('launch profile save response does not match the request');
  }
  return response;
}

/** Sends exactly one idempotent delete operation and verifies the deleted identity. */
export async function deleteLaunchProfile(
  request: DeleteLaunchProfileRequest,
  operationId: string,
): Promise<DeleteLaunchProfileResponse> {
  if (!isDeleteLaunchProfileRequest(request) || !isMutationOperationId(operationId)) {
    throw new TypeError('invalid launch profile delete request');
  }

  const response = await forwardSupervisorRpc<unknown>({
    requestId: createRpcId('profile-delete-request'),
    operationId,
    timeoutMs: PROFILE_WRITE_TIMEOUT_MS,
    method: PROFILE_DELETE_METHOD,
    params: request,
  });
  if (!isDeleteLaunchProfileResponse(response) || response.profileId !== request.profileId) {
    throw new TypeError('invalid launch profile delete response');
  }
  return response;
}

export function createProfileMutationOperationId(kind: 'delete' | 'save'): string {
  return createRpcId(`profile-${kind}-operation`);
}

/** Returns a secret-safe identity for deciding whether a failed intent is an exact retry. */
export async function profileMutationRequestSha256(
  request: DeleteLaunchProfileRequest | SaveLaunchProfileWithSecretsRequest,
): Promise<string> {
  const subtle = globalThis.crypto?.subtle;
  if (subtle === undefined) {
    throw new TypeError('secure request hashing is unavailable');
  }
  const encoded = utf8Encoder.encode(JSON.stringify(request));
  try {
    const digest = new Uint8Array(await subtle.digest('SHA-256', encoded));
    return Array.from(digest, (byte) => byte.toString(16).padStart(2, '0')).join('');
  } finally {
    encoded.fill(0);
  }
}

export async function previewLaunchProfile(
  request: ExecutionPreviewRequest,
): Promise<FinalExecutionPreview> {
  if (!isExecutionPreviewRequest(request)) {
    throw new TypeError('invalid launch profile preview request');
  }

  const response = await forwardSupervisorRpc<unknown>({
    requestId: createRpcId('profile-preview-request'),
    operationId: null,
    timeoutMs: PROFILE_READ_TIMEOUT_MS,
    method: PROFILE_PREVIEW_METHOD,
    params: request,
  });
  if (!isFinalExecutionPreview(response) || !previewMatchesRequest(response, request)) {
    throw new TypeError('invalid final execution preview response');
  }
  return response;
}

export function isLaunchProfile(value: unknown): value is LaunchProfile {
  if (!isObject(value) || !hasExactKeys(value, LAUNCH_PROFILE_KEYS)) {
    return false;
  }
  if (
    !isRequiredText(value.id, MAX_PROFILE_ID_BYTES) ||
    !isLaunchProfileInput(value.input) ||
    !isTimestamp(value.createdAt) ||
    !isTimestamp(value.updatedAt)
  ) {
    return false;
  }
  return true;
}

export function isListLaunchProfilesResponse(value: unknown): value is ListLaunchProfilesResponse {
  if (!isObject(value) || !hasExactKeys(value, LIST_RESPONSE_KEYS)) {
    return false;
  }
  if (
    !Array.isArray(value.profiles) ||
    value.profiles.length > MAX_PROFILE_PAGE_SIZE ||
    !isNullableRequiredText(value.nextCursor, MAX_PROFILE_CURSOR_BYTES)
  ) {
    return false;
  }

  const ids = new Set<string>();
  for (const profile of value.profiles) {
    if (!isLaunchProfile(profile) || ids.has(profile.id)) {
      return false;
    }
    ids.add(profile.id);
  }
  return jsonFitsWireLimit(value, MAX_PROFILE_LIST_WIRE_BYTES);
}

export function isDeleteLaunchProfileResponse(
  value: unknown,
): value is DeleteLaunchProfileResponse {
  return (
    isObject(value) &&
    hasExactKeys(value, DELETE_RESPONSE_KEYS) &&
    isRequiredText(value.profileId, MAX_PROFILE_ID_BYTES)
  );
}

export function isFinalExecutionPreview(value: unknown): value is FinalExecutionPreview {
  if (!isObject(value) || !hasExactKeys(value, FINAL_PREVIEW_KEYS)) {
    return false;
  }
  if (
    !isExecutionPlatform(value.platform) ||
    !isRequiredText(value.workingDirectory, MAX_WORKING_DIRECTORY_BYTES) ||
    typeof value.interactive !== 'boolean' ||
    typeof value.requiresCredentialResolution !== 'boolean' ||
    !isExecutionInvocationPreview(value.invocation) ||
    !isEnvironmentPreview(value.environment, value.platform) ||
    !isPathResolution(value.path) ||
    !isPathExtensionResolution(value.pathExtensions) ||
    !isExecutableResolution(value.executableResolution, value.platform)
  ) {
    return false;
  }

  const requiresCredentialResolution = value.environment.some(
    (entry) => entry.value === 'credentialReferenceRedacted',
  );
  if (requiresCredentialResolution !== value.requiresCredentialResolution) {
    return false;
  }
  if (
    (value.platform === 'macOs') !== (value.pathExtensions.status === 'notApplicable') ||
    !invocationMatchesPlatform(value.invocation, value.platform, value.interactive) ||
    !resolutionsMatchEnvironment(
      value.platform,
      value.environment,
      value.path,
      value.pathExtensions,
    ) ||
    !executableResolutionMatchesInvocation(value.invocation, value.executableResolution)
  ) {
    return false;
  }
  return jsonFitsWireLimit(value, MAX_EXECUTION_PREVIEW_WIRE_BYTES);
}

function isLaunchProfileInput(value: unknown): value is LaunchProfileInput {
  if (!isObject(value) || !hasExactKeys(value, LAUNCH_PROFILE_INPUT_KEYS)) {
    return false;
  }
  if (
    !(value.projectId === null || isRequiredText(value.projectId, MAX_PROJECT_ID_BYTES)) ||
    !isRequiredText(value.name, MAX_PROFILE_NAME_BYTES) ||
    !isLaunchExecution(value.execution) ||
    !isRequiredText(value.workingDirectory, MAX_WORKING_DIRECTORY_BYTES) ||
    !isLaunchEnvironment(value.environment) ||
    typeof value.interactive !== 'boolean' ||
    !isNonNegativeSafeInteger(value.stopTimeoutMs) ||
    value.stopTimeoutMs > MAX_STOP_TIMEOUT_MS
  ) {
    return false;
  }
  return jsonFitsWireLimit(value, MAX_PROFILE_INPUT_WIRE_BYTES);
}

function isLaunchExecution(value: unknown): boolean {
  if (!isObject(value)) {
    return false;
  }
  if (value.mode === 'direct') {
    return (
      hasExactKeys(value, DIRECT_LAUNCH_KEYS) &&
      isRequiredText(value.executable, MAX_EXECUTABLE_BYTES) &&
      isStringArray(value.argv, MAX_ARGUMENTS, MAX_ARGUMENT_BYTES, MAX_ARGUMENT_TOTAL_BYTES)
    );
  }
  return (
    value.mode === 'shell' &&
    hasExactKeys(value, SHELL_LAUNCH_KEYS) &&
    isShellKind(value.shell) &&
    isRequiredText(value.command, MAX_SHELL_COMMAND_BYTES)
  );
}

function isLaunchEnvironment(value: unknown): boolean {
  if (!Array.isArray(value) || value.length > MAX_ENVIRONMENT_ENTRIES) {
    return false;
  }

  const names = new Set<string>();
  let totalBytes = 0;
  for (const entry of value) {
    if (
      !isObject(entry) ||
      !hasExactKeys(entry, ENVIRONMENT_ENTRY_KEYS) ||
      !isRequiredText(entry.name, MAX_ENVIRONMENT_NAME_BYTES) ||
      !PORTABLE_ENVIRONMENT_NAME.test(entry.name) ||
      names.has(entry.name) ||
      !isObject(entry.value)
    ) {
      return false;
    }
    names.add(entry.name);
    totalBytes += utf8ByteLength(entry.name);

    if (entry.value.kind === 'plain') {
      if (
        !hasExactKeys(entry.value, PLAIN_ENVIRONMENT_VALUE_KEYS) ||
        !isOptionalText(entry.value.value, MAX_ENVIRONMENT_VALUE_BYTES) ||
        isSensitiveFieldName(entry.name)
      ) {
        return false;
      }
      totalBytes += utf8ByteLength(entry.value.value);
    } else if (entry.value.kind === 'credentialReference') {
      if (
        !hasExactKeys(entry.value, CREDENTIAL_ENVIRONMENT_VALUE_KEYS) ||
        !isCredentialReference(entry.value.credentialReference)
      ) {
        return false;
      }
      totalBytes += utf8ByteLength(entry.value.credentialReference);
    } else {
      return false;
    }
    if (totalBytes > MAX_ENVIRONMENT_TOTAL_BYTES) {
      return false;
    }
  }
  return true;
}

function isSaveLaunchProfileRequest(value: unknown): value is SaveLaunchProfileWithSecretsRequest {
  if (!isObject(value) || !hasExactKeys(value, SAVE_REQUEST_KEYS) || !isObject(value.request)) {
    return false;
  }

  const profileInput =
    value.request.operation === 'create' &&
    hasExactKeys(value.request, CREATE_PROFILE_REQUEST_KEYS) &&
    isLaunchProfileInput(value.request.input)
      ? value.request.input
      : value.request.operation === 'update' &&
          hasExactKeys(value.request, UPDATE_PROFILE_REQUEST_KEYS) &&
          isRequiredText(value.request.profileId, MAX_PROFILE_ID_BYTES) &&
          isTimestamp(value.request.expectedUpdatedAt) &&
          isLaunchProfileInput(value.request.input)
        ? value.request.input
        : null;
  if (profileInput === null || !Array.isArray(value.secretEnvironment)) {
    return false;
  }
  if (
    value.request.operation === 'create' &&
    profileInput.environment.some((entry) => entry.value.kind === 'credentialReference')
  ) {
    return false;
  }
  if (value.secretEnvironment.length > MAX_ENVIRONMENT_ENTRIES) {
    return false;
  }

  const profileEnvironment = new Map(profileInput.environment.map((entry) => [entry.name, entry]));
  const secretNames = new Set<string>();
  const materializedNames = new Set(profileEnvironment.keys());
  let secretBytes = 0;
  for (const entry of value.secretEnvironment) {
    if (
      !isObject(entry) ||
      !hasExactKeys(entry, SECRET_ENVIRONMENT_ENTRY_KEYS) ||
      !isRequiredText(entry.name, MAX_ENVIRONMENT_NAME_BYTES) ||
      !PORTABLE_ENVIRONMENT_NAME.test(entry.name) ||
      !isOptionalText(entry.secret, MAX_CREDENTIAL_SECRET_BYTES) ||
      secretNames.has(entry.name)
    ) {
      return false;
    }
    const existing = profileEnvironment.get(entry.name);
    if (existing?.value.kind === 'plain') {
      return false;
    }
    secretNames.add(entry.name);
    materializedNames.add(entry.name);
    secretBytes += utf8ByteLength(entry.name) + utf8ByteLength(entry.secret);
  }

  return (
    materializedNames.size <= MAX_ENVIRONMENT_ENTRIES &&
    secretBytes <= MAX_ENVIRONMENT_TOTAL_BYTES &&
    jsonFitsWireLimit(value, MAX_SECRET_REQUEST_WIRE_BYTES)
  );
}

function isDeleteLaunchProfileRequest(value: unknown): value is DeleteLaunchProfileRequest {
  return (
    isObject(value) &&
    hasExactKeys(value, DELETE_REQUEST_KEYS) &&
    isRequiredText(value.profileId, MAX_PROFILE_ID_BYTES) &&
    isTimestamp(value.expectedUpdatedAt)
  );
}

function isExecutionPreviewRequest(value: unknown): value is ExecutionPreviewRequest {
  return (
    isObject(value) &&
    hasExactKeys(value, PREVIEW_REQUEST_KEYS) &&
    isLaunchProfileInput(value.profile)
  );
}

function isExecutionInvocationPreview(
  value: unknown,
): value is FinalExecutionPreview['invocation'] {
  if (!isObject(value)) {
    return false;
  }
  if (value.mode === 'direct') {
    return (
      hasExactKeys(value, DIRECT_PREVIEW_KEYS) &&
      isRequiredText(value.executable, MAX_EXECUTABLE_BYTES) &&
      isStringArray(value.argv, MAX_ARGUMENTS, MAX_ARGUMENT_BYTES, MAX_ARGUMENT_TOTAL_BYTES)
    );
  }
  return (
    value.mode === 'shell' &&
    hasExactKeys(value, SHELL_PREVIEW_KEYS) &&
    isShellKind(value.shell) &&
    (value.executable === null || isRequiredText(value.executable, MAX_EXECUTABLE_BYTES)) &&
    isStringArray(
      value.argv,
      MAX_PREVIEW_ARGUMENTS,
      MAX_SHELL_ARGUMENT_BYTES,
      MAX_PREVIEW_ARGUMENT_TOTAL_BYTES,
    ) &&
    isRequiredText(value.command, MAX_SHELL_COMMAND_BYTES)
  );
}

function isEnvironmentPreview(
  value: unknown,
  platform: 'windows' | 'macOs',
): value is FinalExecutionPreview['environment'] {
  if (!Array.isArray(value) || value.length > MAX_ENVIRONMENT_ENTRIES) {
    return false;
  }

  const names = new Set<string>();
  let totalBytes = 0;
  for (const entry of value) {
    if (
      !isObject(entry) ||
      !hasExactKeys(entry, ENVIRONMENT_PREVIEW_ENTRY_KEYS) ||
      !isRequiredText(entry.name, MAX_ENVIRONMENT_NAME_BYTES) ||
      !PORTABLE_ENVIRONMENT_NAME.test(entry.name) ||
      !isEnvironmentLayer(entry.source)
    ) {
      return false;
    }
    const nameKey = platform === 'windows' ? toAsciiUppercase(entry.name) : entry.name;
    if (names.has(nameKey)) {
      return false;
    }
    names.add(nameKey);
    totalBytes += utf8ByteLength(entry.name);

    if (isObject(entry.value)) {
      if (
        !hasExactKeys(entry.value, PLAIN_ENVIRONMENT_PREVIEW_VALUE_KEYS) ||
        !isOptionalText(entry.value.plain, MAX_ENVIRONMENT_VALUE_BYTES) ||
        entry.source === 'supervisorBase' ||
        isSensitiveFieldName(entry.name)
      ) {
        return false;
      }
      totalBytes += utf8ByteLength(entry.value.plain);
    } else if (entry.value === 'inheritedRedacted') {
      if (entry.source !== 'supervisorBase') {
        return false;
      }
    } else if (entry.value !== 'credentialReferenceRedacted') {
      return false;
    }
    if (totalBytes > MAX_MERGED_ENVIRONMENT_TOTAL_BYTES) {
      return false;
    }
  }
  return true;
}

function isPathResolution(value: unknown): value is FinalExecutionPreview['path'] {
  if (!isObject(value)) {
    return false;
  }
  if (value.status === 'known') {
    return (
      hasExactKeys(value, KNOWN_PATH_KEYS) &&
      isOptionalText(value.value, MAX_ENVIRONMENT_VALUE_BYTES) &&
      isEnvironmentLayer(value.source)
    );
  }
  return (
    value.status === 'unknown' &&
    hasExactKeys(value, UNKNOWN_PATH_KEYS) &&
    isPathUnknownReason(value.reason) &&
    isNullableEnvironmentLayer(value.source) &&
    ((value.reason === 'missing' && value.source === null) ||
      (value.reason !== 'missing' && value.source !== null))
  );
}

function isPathExtensionResolution(
  value: unknown,
): value is FinalExecutionPreview['pathExtensions'] {
  if (!isObject(value)) {
    return false;
  }
  if (value.status === 'known') {
    if (
      !hasExactKeys(value, KNOWN_PATH_EXTENSION_KEYS) ||
      !isOptionalText(value.value, MAX_ENVIRONMENT_VALUE_BYTES) ||
      !isEnvironmentLayer(value.source) ||
      !Array.isArray(value.extensions) ||
      value.extensions.length > MAX_PATH_EXTENSIONS
    ) {
      return false;
    }
    const extensions = new Set<string>();
    for (const extension of value.extensions) {
      if (
        !isRequiredText(extension, MAX_PATH_EXTENSION_BYTES) ||
        !PATH_EXTENSION.test(extension) ||
        extensions.has(extension)
      ) {
        return false;
      }
      extensions.add(extension);
    }
    return true;
  }
  if (value.status === 'notApplicable') {
    return hasExactKeys(value, NOT_APPLICABLE_PATH_EXTENSION_KEYS);
  }
  return (
    value.status === 'unknown' &&
    hasExactKeys(value, UNKNOWN_PATH_KEYS) &&
    isPathUnknownReason(value.reason) &&
    isNullableEnvironmentLayer(value.source) &&
    ((value.reason === 'missing' && value.source === null) ||
      (value.reason !== 'missing' && value.source !== null))
  );
}

function isExecutableResolution(
  value: unknown,
  platform: 'windows' | 'macOs',
): value is FinalExecutionPreview['executableResolution'] {
  if (!isObject(value)) {
    return false;
  }
  if (value.status === 'unknown') {
    return (
      hasExactKeys(value, UNKNOWN_EXECUTABLE_KEYS) &&
      isExecutableUnknownReason(value.reason) &&
      isExecutableCandidates(value.candidates, platform)
    );
  }
  if (value.status === 'notFound') {
    return (
      hasExactKeys(value, NOT_FOUND_EXECUTABLE_KEYS) &&
      value.reason === 'emptySearchPath' &&
      isExecutableCandidates(value.candidates, platform)
    );
  }
  return (
    value.status === 'notSupported' &&
    hasExactKeys(value, NOT_SUPPORTED_EXECUTABLE_KEYS) &&
    (value.reason === 'shellUnavailableOnPlatform' || value.reason === 'invalidExecutablePath')
  );
}

function isExecutableCandidates(value: unknown, platform: 'windows' | 'macOs'): boolean {
  if (!Array.isArray(value) || value.length > MAX_EXECUTABLE_CANDIDATES) {
    return false;
  }
  const paths = new Set<string>();
  let totalBytes = 0;
  for (const candidate of value) {
    if (
      !isObject(candidate) ||
      !hasExactKeys(candidate, EXECUTABLE_CANDIDATE_KEYS) ||
      !isRequiredText(candidate.path, MAX_WORKING_DIRECTORY_BYTES) ||
      !isExecutableCandidateSource(candidate.source)
    ) {
      return false;
    }
    const pathKey = platform === 'windows' ? toAsciiUppercase(candidate.path) : candidate.path;
    if (paths.has(pathKey)) {
      return false;
    }
    paths.add(pathKey);
    totalBytes += utf8ByteLength(candidate.path);
    if (totalBytes > MAX_EXECUTABLE_CANDIDATE_TOTAL_BYTES) {
      return false;
    }
  }
  return true;
}

function isExecutableCandidateSource(value: unknown): boolean {
  if (value === 'explicit' || value === 'workingDirectory') {
    return true;
  }
  if (!isObject(value) || !hasExactKeys(value, PATH_CANDIDATE_SOURCE_KEYS)) {
    return false;
  }
  const path = value.path;
  return (
    isObject(path) &&
    hasExactKeys(path, PATH_CANDIDATE_SOURCE_DETAILS_KEYS) &&
    isEnvironmentLayer(path.pathSource) &&
    isNonNegativeSafeInteger(path.pathIndex) &&
    path.pathIndex < MAX_PATH_ENTRIES &&
    (path.entryKind === 'absolute' ||
      path.entryKind === 'workingDirectoryEmpty' ||
      path.entryKind === 'workingDirectoryRelative')
  );
}

type ExpectedSavedEnvironmentEntry = {
  name: string;
  value:
    | { kind: 'plain'; value: string }
    | { kind: 'credentialReference'; credentialReference: string | null };
};

function saveResponseMatchesRequest(
  response: LaunchProfile,
  request: SaveLaunchProfileWithSecretsRequest,
): boolean {
  if (request.request.operation === 'update' && response.id !== request.request.profileId) {
    return false;
  }

  const requestedInput = request.request.input;
  if (
    response.input.projectId !== requestedInput.projectId ||
    response.input.name !== requestedInput.name ||
    response.input.workingDirectory !== requestedInput.workingDirectory ||
    response.input.interactive !== requestedInput.interactive ||
    response.input.stopTimeoutMs !== requestedInput.stopTimeoutMs ||
    !sameLaunchExecution(response.input.execution, requestedInput.execution)
  ) {
    return false;
  }

  return (
    savedEnvironmentMatchesRequest(response.input.environment, request, false) ||
    savedEnvironmentMatchesRequest(response.input.environment, request, true)
  );
}

function savedEnvironmentMatchesRequest(
  responseEnvironment: LaunchProfileInput['environment'],
  request: SaveLaunchProfileWithSecretsRequest,
  windowsCaseInsensitive: boolean,
): boolean {
  const expected: ExpectedSavedEnvironmentEntry[] = request.request.input.environment.map(
    (entry) => ({
      name: entry.name,
      value:
        entry.value.kind === 'plain'
          ? { kind: 'plain', value: entry.value.value }
          : {
              kind: 'credentialReference',
              credentialReference: entry.value.credentialReference,
            },
    }),
  );

  for (const secret of request.secretEnvironment) {
    const existingIndex = expected.findIndex((entry) =>
      environmentNamesEqual(entry.name, secret.name, windowsCaseInsensitive),
    );
    const replacement: ExpectedSavedEnvironmentEntry = {
      name: secret.name,
      value: { kind: 'credentialReference', credentialReference: null },
    };
    if (existingIndex === -1) {
      expected.push(replacement);
    } else {
      expected[existingIndex] = replacement;
    }
  }

  if (responseEnvironment.length !== expected.length) {
    return false;
  }
  const responseByName = new Map(responseEnvironment.map((entry) => [entry.name, entry]));
  if (responseByName.size !== responseEnvironment.length) {
    return false;
  }
  return expected.every((expectedEntry) => {
    const entry = responseByName.get(expectedEntry.name);
    if (entry === undefined) {
      return false;
    }
    if (expectedEntry.value.kind === 'plain') {
      return entry.value.kind === 'plain' && entry.value.value === expectedEntry.value.value;
    }
    return (
      entry.value.kind === 'credentialReference' &&
      (expectedEntry.value.credentialReference === null ||
        entry.value.credentialReference === expectedEntry.value.credentialReference)
    );
  });
}

function sameLaunchExecution(
  left: LaunchProfileInput['execution'],
  right: LaunchProfileInput['execution'],
): boolean {
  if (left.mode === 'direct' && right.mode === 'direct') {
    return left.executable === right.executable && sameStringArray(left.argv, right.argv);
  }
  return (
    left.mode === 'shell' &&
    right.mode === 'shell' &&
    left.shell === right.shell &&
    left.command === right.command
  );
}

function previewEnvironmentMatchesProfile(
  previewEnvironment: FinalExecutionPreview['environment'],
  profileEnvironment: LaunchProfileInput['environment'],
  platform: FinalExecutionPreview['platform'],
): boolean {
  const profileEntries = previewEnvironment.filter((entry) => entry.source === 'profile');
  if (profileEntries.length !== profileEnvironment.length) {
    return false;
  }

  return profileEnvironment.every((requestedEntry) => {
    const previewEntry = profileEntries.find((entry) =>
      environmentNamesEqual(entry.name, requestedEntry.name, platform === 'windows'),
    );
    if (previewEntry === undefined || previewEntry.name !== requestedEntry.name) {
      return false;
    }
    if (requestedEntry.value.kind === 'plain') {
      return (
        typeof previewEntry.value === 'object' &&
        previewEntry.value.plain === requestedEntry.value.value
      );
    }
    return previewEntry.value === 'credentialReferenceRedacted';
  });
}

function environmentNamesEqual(
  left: string,
  right: string,
  windowsCaseInsensitive: boolean,
): boolean {
  return windowsCaseInsensitive
    ? toAsciiUppercase(left) === toAsciiUppercase(right)
    : left === right;
}

function resolutionsMatchEnvironment(
  platform: FinalExecutionPreview['platform'],
  environment: FinalExecutionPreview['environment'],
  path: FinalExecutionPreview['path'],
  pathExtensions: FinalExecutionPreview['pathExtensions'],
): boolean {
  return (
    pathMatchesEnvironment(platform, environment, path) &&
    pathExtensionsMatchEnvironment(platform, environment, pathExtensions)
  );
}

function pathMatchesEnvironment(
  platform: FinalExecutionPreview['platform'],
  environment: FinalExecutionPreview['environment'],
  path: FinalExecutionPreview['path'],
): boolean {
  const entry = findEnvironmentPreviewEntry(environment, platform, 'PATH');
  if (entry === undefined) {
    return unknownPathMatches(path, 'missing', null);
  }
  if (entry.value === 'credentialReferenceRedacted') {
    return unknownPathMatches(path, 'credentialReference', entry.source);
  }
  if (entry.value === 'inheritedRedacted') {
    return (
      (path.status === 'known' && path.source === entry.source) ||
      unknownPathMatches(path, 'invalidValue', entry.source)
    );
  }

  const valid = isValidSearchPath(platform, entry.value.plain);
  return valid
    ? path.status === 'known' && path.value === entry.value.plain && path.source === entry.source
    : unknownPathMatches(path, 'invalidValue', entry.source);
}

function pathExtensionsMatchEnvironment(
  platform: FinalExecutionPreview['platform'],
  environment: FinalExecutionPreview['environment'],
  pathExtensions: FinalExecutionPreview['pathExtensions'],
): boolean {
  if (platform === 'macOs') {
    return pathExtensions.status === 'notApplicable';
  }

  const entry = findEnvironmentPreviewEntry(environment, platform, 'PATHEXT');
  if (entry === undefined) {
    return unknownPathMatches(pathExtensions, 'missing', null);
  }
  if (entry.value === 'credentialReferenceRedacted') {
    return unknownPathMatches(pathExtensions, 'credentialReference', entry.source);
  }
  if (entry.value === 'inheritedRedacted') {
    if (unknownPathMatches(pathExtensions, 'invalidValue', entry.source)) {
      return true;
    }
    return (
      pathExtensions.status === 'known' &&
      pathExtensions.source === entry.source &&
      knownPathExtensionsMatchValue(pathExtensions)
    );
  }

  const parsed = parsePathExtensions(entry.value.plain);
  if (parsed === null) {
    return unknownPathMatches(pathExtensions, 'invalidValue', entry.source);
  }
  if (parsed === undefined) {
    return false;
  }
  return (
    pathExtensions.status === 'known' &&
    pathExtensions.value === entry.value.plain &&
    pathExtensions.source === entry.source &&
    sameStringArray(pathExtensions.extensions, parsed)
  );
}

function findEnvironmentPreviewEntry(
  environment: FinalExecutionPreview['environment'],
  platform: FinalExecutionPreview['platform'],
  name: string,
): FinalExecutionPreview['environment'][number] | undefined {
  return environment.find((entry) =>
    environmentNamesEqual(entry.name, name, platform === 'windows'),
  );
}

function unknownPathMatches(
  resolution: FinalExecutionPreview['path'] | FinalExecutionPreview['pathExtensions'],
  reason: 'missing' | 'credentialReference' | 'invalidValue',
  source: FinalExecutionPreview['environment'][number]['source'] | null,
): boolean {
  return (
    resolution.status === 'unknown' && resolution.reason === reason && resolution.source === source
  );
}

function knownPathExtensionsMatchValue(
  resolution: Extract<FinalExecutionPreview['pathExtensions'], { status: 'known' }>,
): boolean {
  const parsed = parsePathExtensions(resolution.value);
  return Array.isArray(parsed) && sameStringArray(resolution.extensions, parsed);
}

function executableResolutionMatchesInvocation(
  invocation: FinalExecutionPreview['invocation'],
  executableResolution: FinalExecutionPreview['executableResolution'],
): boolean {
  const shellWithoutExecutable = invocation.mode === 'shell' && invocation.executable === null;
  const shellUnavailable =
    executableResolution.status === 'notSupported' &&
    executableResolution.reason === 'shellUnavailableOnPlatform';
  if (shellWithoutExecutable || shellUnavailable) {
    return shellWithoutExecutable && shellUnavailable;
  }
  return !(
    invocation.mode === 'shell' &&
    executableResolution.status === 'notSupported' &&
    executableResolution.reason === 'invalidExecutablePath'
  );
}

function previewMatchesRequest(
  preview: FinalExecutionPreview,
  request: ExecutionPreviewRequest,
): boolean {
  if (
    preview.workingDirectory !== request.profile.workingDirectory ||
    preview.interactive !== request.profile.interactive ||
    preview.invocation.mode !== request.profile.execution.mode ||
    !previewEnvironmentMatchesProfile(
      preview.environment,
      request.profile.environment,
      preview.platform,
    )
  ) {
    return false;
  }
  if (preview.invocation.mode === 'direct' && request.profile.execution.mode === 'direct') {
    return (
      preview.invocation.executable === request.profile.execution.executable &&
      sameStringArray(preview.invocation.argv, request.profile.execution.argv)
    );
  }
  return (
    preview.invocation.mode === 'shell' &&
    request.profile.execution.mode === 'shell' &&
    preview.invocation.shell === request.profile.execution.shell &&
    preview.invocation.command === request.profile.execution.command
  );
}

function invocationMatchesPlatform(
  invocation: FinalExecutionPreview['invocation'],
  platform: FinalExecutionPreview['platform'],
  interactive: boolean,
): boolean {
  if (invocation.mode === 'direct') {
    return true;
  }

  if (invocation.shell === 'powerShell') {
    const expectedArguments = ['-NoLogo', '-NoProfile'];
    if (!interactive) {
      expectedArguments.push('-NonInteractive');
    }
    expectedArguments.push('-Command', invocation.command);
    const executableMatches =
      platform === 'macOs'
        ? invocation.executable === 'pwsh'
        : invocation.executable === null ||
          isWindowsSystemShellExecutable(
            invocation.executable,
            'System32\\WindowsPowerShell\\v1.0\\powershell.exe',
          );
    return executableMatches && sameStringArray(invocation.argv, expectedArguments);
  }
  if (invocation.shell === 'cmd') {
    if (platform === 'macOs') {
      return invocation.executable === null && invocation.argv.length === 0;
    }
    return (
      (invocation.executable === null ||
        isWindowsSystemShellExecutable(invocation.executable, 'System32\\cmd.exe')) &&
      sameStringArray(invocation.argv, ['/D', '/S', '/C', invocation.command])
    );
  }
  return platform === 'windows'
    ? invocation.executable === null && invocation.argv.length === 0
    : invocation.executable === '/bin/zsh' &&
        sameStringArray(invocation.argv, ['-f', '-c', invocation.command]);
}

function isWindowsSystemShellExecutable(value: string, suffix: string): boolean {
  const normalized = value.replaceAll('/', '\\');
  if (
    hasInvalidWindowsNamespace(normalized) ||
    !toAsciiUppercase(normalized).endsWith(`\\${toAsciiUppercase(suffix)}`)
  ) {
    return false;
  }

  let components: string[];
  if (/^[A-Za-z]:\\/.test(normalized)) {
    components = normalized.slice(3).split('\\');
  } else if (normalized.startsWith('\\\\')) {
    const uncComponents = normalized.slice(2).split('\\');
    const server = uncComponents.shift();
    const share = uncComponents.shift();
    if (
      server === undefined ||
      share === undefined ||
      !isSafeWindowsPathComponent(server) ||
      !isSafeWindowsPathComponent(share) ||
      server === '.' ||
      server === '?' ||
      toAsciiUppercase(server) === 'GLOBALROOT'
    ) {
      return false;
    }
    components = uncComponents;
  } else {
    return false;
  }
  return components.every(isSafeWindowsPathComponent);
}

function isValidSearchPath(platform: FinalExecutionPreview['platform'], value: string): boolean {
  const separator = platform === 'windows' ? ';' : ':';
  const entries = value.split(separator);
  return (
    entries.length <= MAX_PATH_ENTRIES &&
    entries.every((entry) => isValidSearchPathEntry(platform, entry))
  );
}

function isValidSearchPathEntry(
  platform: FinalExecutionPreview['platform'],
  rawEntry: string,
): boolean {
  if (platform === 'macOs') {
    if (rawEntry.length === 0) {
      return true;
    }
    const tail = rawEntry.startsWith('/') ? rawEntry.slice(1) : rawEntry;
    return tail.length === 0 || tail.split('/').every(isNormalPathComponent);
  }

  const quotedEntry = normalizeQuotedWindowsPathEntry(rawEntry);
  if (quotedEntry === null || quotedEntry.length === 0) {
    return quotedEntry !== null;
  }
  const entry = quotedEntry.replaceAll('/', '\\');
  if (hasInvalidWindowsNamespace(entry)) {
    return false;
  }
  if (/^[A-Za-z]:/.test(entry)) {
    return (
      entry.length >= 3 &&
      entry[2] === '\\' &&
      (entry.length === 3 || entry.slice(3).split('\\').every(isSafeWindowsPathComponent))
    );
  }
  if (entry.startsWith('\\\\')) {
    const components = entry.slice(2).split('\\');
    const server = components.shift();
    const share = components.shift();
    return (
      server !== undefined &&
      share !== undefined &&
      !['.', '?', 'GLOBALROOT'].includes(toAsciiUppercase(server)) &&
      isSafeWindowsPathComponent(server) &&
      isSafeWindowsPathComponent(share) &&
      components.every(isSafeWindowsPathComponent)
    );
  }
  return (
    !entry.startsWith('\\') &&
    !entry.includes(':') &&
    entry.split('\\').every(isSafeWindowsPathComponent)
  );
}

function normalizeQuotedWindowsPathEntry(value: string): string | null {
  if (!value.includes('"')) {
    return value;
  }
  if (value.length <= 2 || !value.startsWith('"') || !value.endsWith('"')) {
    return null;
  }
  const inner = value.slice(1, -1);
  return inner.length > 0 && !inner.includes('"') ? inner : null;
}

function parsePathExtensions(value: string): string[] | null | undefined {
  const extensions: string[] = [];
  for (const rawExtension of value.split(';')) {
    const extension = rawExtension.replace(/^[\t\n\v\f\r ]+|[\t\n\v\f\r ]+$/g, '');
    if (extension.length === 0) {
      continue;
    }
    if (extensions.length >= MAX_PATH_EXTENSIONS) {
      return undefined;
    }
    const canonical = toAsciiUppercase(extension);
    if (utf8ByteLength(canonical) > MAX_PATH_EXTENSION_BYTES || !PATH_EXTENSION.test(canonical)) {
      return null;
    }
    if (!extensions.includes(canonical)) {
      extensions.push(canonical);
    }
  }
  return extensions;
}

function hasInvalidWindowsNamespace(value: string): boolean {
  const canonical = toAsciiUppercase(value);
  return (
    canonical.startsWith('\\\\?\\') ||
    canonical.startsWith('\\\\.\\') ||
    canonical.startsWith('\\??\\') ||
    canonical.startsWith('\\DEVICE\\')
  );
}

function isNormalPathComponent(value: string): boolean {
  return value.length > 0 && value !== '.' && value !== '..';
}

function isSafeWindowsPathComponent(value: string): boolean {
  return (
    value.length > 0 &&
    value !== '.' &&
    value !== '..' &&
    !value.endsWith(' ') &&
    !value.endsWith('.') &&
    !CONTROL_CHARACTER.test(value) &&
    ![...value].some((character) => '<>:"/\\|?*'.includes(character))
  );
}

function isExecutionPlatform(value: unknown): value is 'windows' | 'macOs' {
  return value === 'windows' || value === 'macOs';
}

function isShellKind(value: unknown): value is 'powerShell' | 'cmd' | 'zsh' {
  return value === 'powerShell' || value === 'cmd' || value === 'zsh';
}

function isEnvironmentLayer(value: unknown): boolean {
  return (
    value === 'supervisorBase' || value === 'user' || value === 'project' || value === 'profile'
  );
}

function isNullableEnvironmentLayer(value: unknown): boolean {
  return value === null || isEnvironmentLayer(value);
}

function isPathUnknownReason(value: unknown): boolean {
  return value === 'missing' || value === 'credentialReference' || value === 'invalidValue';
}

function isExecutableUnknownReason(value: unknown): boolean {
  return (
    value === 'filesystemNotInspected' ||
    value === 'pathMissing' ||
    value === 'pathInvalidValue' ||
    value === 'pathCredentialReference' ||
    value === 'pathExtensionMissing' ||
    value === 'pathExtensionCredentialReference'
  );
}

function isStringArray(
  value: unknown,
  maximumItems: number,
  maximumItemBytes: number,
  maximumTotalBytes: number,
): value is string[] {
  if (!Array.isArray(value) || value.length > maximumItems) {
    return false;
  }
  let totalBytes = 0;
  for (const item of value) {
    if (!isOptionalText(item, maximumItemBytes)) {
      return false;
    }
    totalBytes += utf8ByteLength(item);
    if (totalBytes > maximumTotalBytes) {
      return false;
    }
  }
  return true;
}

function sameStringArray(left: ReadonlyArray<string>, right: ReadonlyArray<string>): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function isTimestamp(value: unknown): value is string {
  return (
    isRequiredText(value, MAX_TIMESTAMP_BYTES) &&
    RFC3339_TIMESTAMP.test(value) &&
    Number.isFinite(Date.parse(value))
  );
}

function isCredentialReference(value: unknown): value is string {
  return isRequiredText(value, MAX_CREDENTIAL_REFERENCE_BYTES) && CREDENTIAL_REFERENCE.test(value);
}

function isNullableRequiredText(value: unknown, maximumBytes: number): value is string | null {
  return value === null || isRequiredText(value, maximumBytes);
}

function isRequiredText(value: unknown, maximumBytes: number): value is string {
  return isOptionalText(value, maximumBytes) && value.trim().length > 0;
}

function isOptionalText(value: unknown, maximumBytes: number): value is string {
  return (
    typeof value === 'string' && !value.includes('\0') && utf8ByteLength(value) <= maximumBytes
  );
}

function utf8ByteLength(value: string): number {
  return utf8Encoder.encode(value).length;
}

function jsonFitsWireLimit(value: unknown, maximumBytes: number): boolean {
  try {
    const json = JSON.stringify(value);
    return typeof json === 'string' && utf8ByteLength(json) <= maximumBytes;
  } catch {
    return false;
  }
}

function isNonNegativeSafeInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function hasExactKeys(
  value: Record<string, unknown>,
  expectedKeys: ReadonlyArray<string>,
): boolean {
  const actualKeys = Object.keys(value);
  return (
    actualKeys.length === expectedKeys.length &&
    expectedKeys.every((key) => Object.hasOwn(value, key))
  );
}

function createRpcId(prefix: string): string {
  const randomUuid = globalThis.crypto?.randomUUID?.();
  if (typeof randomUuid !== 'string' || randomUuid.length === 0) {
    throw new TypeError('secure random UUID generation is unavailable');
  }
  return `${prefix}:${randomUuid}`;
}

function isMutationOperationId(value: string): boolean {
  return value.length > 0 && value.length <= 128 && OPERATION_ID.test(value);
}

/** Mirrors platform_common::is_sensitive_field_name without exposing credential references. */
function isSensitiveFieldName(name: string): boolean {
  let canonical = '';
  let token = '';
  let previousLowerOrDigit = false;

  for (const character of name) {
    if (!isAsciiAlphaNumeric(character)) {
      if (isSensitiveToken(token)) {
        return true;
      }
      token = '';
      previousLowerOrDigit = false;
      continue;
    }
    if (isAsciiUppercase(character) && previousLowerOrDigit) {
      if (isSensitiveToken(token)) {
        return true;
      }
      token = '';
    }
    const lower = character.toLowerCase();
    canonical += lower;
    token += lower;
    previousLowerOrDigit = isAsciiLowercase(character) || isAsciiDigit(character);
  }

  return (
    isSensitiveToken(token) ||
    ['apikey', 'accesskey', 'privatekey', 'clientsecret', 'sessiontoken', 'authtoken'].some(
      (pattern) => canonical.includes(pattern),
    )
  );
}

function isSensitiveToken(value: string): boolean {
  return (
    value === 'password' ||
    value === 'passwd' ||
    value === 'pwd' ||
    value === 'secret' ||
    value === 'token' ||
    value === 'authorization' ||
    value === 'credential' ||
    value === 'cookie' ||
    value === 'session'
  );
}

function isAsciiAlphaNumeric(value: string): boolean {
  return isAsciiLowercase(value) || isAsciiUppercase(value) || isAsciiDigit(value);
}

function isAsciiLowercase(value: string): boolean {
  return value >= 'a' && value <= 'z';
}

function isAsciiUppercase(value: string): boolean {
  return value >= 'A' && value <= 'Z';
}

function isAsciiDigit(value: string): boolean {
  return value >= '0' && value <= '9';
}

function toAsciiUppercase(value: string): string {
  return value.replace(/[a-z]/g, (character) => String.fromCharCode(character.charCodeAt(0) - 32));
}
