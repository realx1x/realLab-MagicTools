import type {
  AccessLevel,
  AddressFamily,
  ClassificationCategory,
  ClassificationReason,
  ClassificationResult,
  PortBinding,
  PortOwnershipConfidence,
  PortProtocol,
  PortState,
  ProcessInstanceKey,
  ProcessOwnership,
  ProcessRecord,
  ProcessStatus,
  ProjectAssociationEvidence,
  ProjectFeatureEvidence,
  UserClassificationOverride,
} from '@dpm/generated-types';

const MAX_SNAPSHOT_ENTITY_BYTES = 512 * 1_024;
const MAX_PROCESS_BOOT_ID_BYTES = 256;
const MAX_PROCESS_NATIVE_START_TIME_BYTES = 128;
const MAX_MANAGED_RUN_ID_BYTES = 256;
const MAX_PROJECT_ID_BYTES = 256;
const MAX_PROJECT_PATH_BYTES = 32 * 1_024;
const MAX_PROJECT_FEATURES = 32;
const MAX_NESTED_PORT_BINDINGS = 4_096;
const MAX_ACCESS_REASON_BYTES = 4 * 1_024;
const MAX_OWNER_USER_BYTES = 4 * 1_024;
const MAX_EXECUTABLE_NAME_BYTES = 4 * 1_024;
const MAX_PROCESS_PATH_BYTES = MAX_SNAPSHOT_ENTITY_BYTES;
const MAX_COMMAND_LINE_BYTES = MAX_SNAPSHOT_ENTITY_BYTES;
const MAX_TIMESTAMP_BYTES = 128;
const MAX_LOCAL_ADDRESS_BYTES = 256;
const MAX_CLASSIFICATION_REASONS = 64;
const MAX_CLASSIFICATION_REASON_CODE_BYTES = 256;
const MAX_CLASSIFICATION_REASON_SUMMARY_BYTES = 4 * 1_024;
const MAX_PROJECT_MARKER_ID_BYTES = 256;
const MAX_CPU_PERCENT = 1_000_000;
const MAX_U32 = 0xffff_ffff;
const MAX_I32 = 0x7fff_ffff;
const MIN_I32 = -0x8000_0000;
const MAX_U64 = 0xffff_ffff_ffff_ffffn;
const DECIMAL_NATIVE_START_TIME = /^[1-9]\d*$/;
const UTF8_ENCODER = new TextEncoder();

const PROCESS_RECORD_KEYS = [
  'instanceKey',
  'parentInstanceKey',
  'ownerUser',
  'executableName',
  'executablePath',
  'commandLine',
  'workingDirectory',
  'cpuPercent',
  'memoryBytes',
  'startedAt',
  'status',
  'accessLevel',
  'ownership',
  'managedRunId',
  'projectAssociation',
  'projectFeatures',
  'projectId',
  'classification',
  'portBindings',
  'lastSeenRevision',
] as const;

const PORT_BINDING_KEYS = [
  'protocol',
  'addressFamily',
  'localAddress',
  'localPort',
  'state',
  'processInstanceKey',
  'confidence',
  'observedAt',
] as const;

const PROCESS_INSTANCE_KEY_KEYS = ['bootId', 'pid', 'nativeStartTime'] as const;
const CLASSIFICATION_RESULT_KEYS = [
  'score',
  'version',
  'category',
  'reasons',
  'userOverride',
  'isDevelopment',
] as const;
const CLASSIFICATION_REASON_KEYS = ['code', 'score', 'summary'] as const;
const PROJECT_ASSOCIATION_KEYS = ['projectId', 'registeredRoot'] as const;
const PROJECT_FEATURE_KEYS = ['markerId', 'markerPath', 'detectedRoot'] as const;

const ACCESS_LEVELS = new Set<unknown>([
  'full',
  'limited',
  'denied',
] satisfies ReadonlyArray<AccessLevel>);
const PROCESS_OWNERSHIPS = new Set<unknown>([
  'managed',
  'external',
] satisfies ReadonlyArray<ProcessOwnership>);
const PROCESS_STATUSES = new Set<unknown>([
  'running',
  'sleeping',
  'stopped',
  'zombie',
  'exited',
  'unknown',
] satisfies ReadonlyArray<ProcessStatus>);
const PORT_PROTOCOLS = new Set<unknown>(['tcp', 'udp'] satisfies ReadonlyArray<PortProtocol>);
const ADDRESS_FAMILIES = new Set<unknown>(['ipv4', 'ipv6'] satisfies ReadonlyArray<AddressFamily>);
const PORT_STATES = new Set<unknown>([
  'tcpListen',
  'tcpEstablished',
  'tcpOther',
  'udpBound',
  'unknown',
] satisfies ReadonlyArray<PortState>);
const PORT_OWNERSHIP_CONFIDENCES = new Set<unknown>([
  'exact',
  'shared',
  'inferred',
  'unknown',
] satisfies ReadonlyArray<PortOwnershipConfidence>);
const CLASSIFICATION_CATEGORIES = new Set<unknown>([
  'development',
  'runtime',
  'infrastructure',
  'database',
  'excluded',
  'unknown',
] satisfies ReadonlyArray<ClassificationCategory>);

const PROJECT_MARKER_IDS = [
  'node.packageJson',
  'rust.cargoToml',
  'go.module',
  'java.mavenPom',
  'java.gradleSettingsKts',
  'java.gradleSettings',
  'java.gradleBuildKts',
  'java.gradleBuild',
  'python.pyproject',
  'python.requirements',
  'python.pipfile',
  'ruby.gemfile',
  'php.composerJson',
  'dotnet.globalJson',
  'native.cmakeLists',
  'native.makefile',
] as const;
const PROJECT_MARKER_ORDER = new Map<string, number>(
  PROJECT_MARKER_IDS.map((markerId, index) => [markerId, index]),
);

type ValueValidator = (value: unknown) => boolean;

export function isStrictProcessRecord(value: unknown): value is ProcessRecord {
  try {
    return isProcessRecord(value);
  } catch {
    return false;
  }
}

export function isStrictPortBinding(value: unknown): value is PortBinding {
  try {
    return isPortBinding(value) && hasBoundedJsonSize(value);
  } catch {
    return false;
  }
}

function isProcessRecord(value: unknown): boolean {
  if (!isObject(value) || !hasExactKeys(value, PROCESS_RECORD_KEYS)) {
    return false;
  }

  const instanceKey = value.instanceKey;
  if (
    !isProcessInstanceKey(instanceKey) ||
    !isFieldValue(
      value.parentInstanceKey,
      (parent) => parent === null || isProcessInstanceKey(parent),
    ) ||
    !isFieldValue(value.ownerUser, (owner) => isBoundedText(owner, MAX_OWNER_USER_BYTES)) ||
    !isFieldValue(value.executableName, (name) => isBoundedText(name, MAX_EXECUTABLE_NAME_BYTES)) ||
    !isFieldValue(value.executablePath, (path) => isBoundedText(path, MAX_PROCESS_PATH_BYTES)) ||
    !isFieldValue(value.commandLine, (commandLine) =>
      isBoundedText(commandLine, MAX_COMMAND_LINE_BYTES),
    ) ||
    !isFieldValue(value.workingDirectory, (path) => isBoundedText(path, MAX_PROCESS_PATH_BYTES)) ||
    !isFieldValue(value.cpuPercent, isCpuPercent) ||
    !isFieldValue(value.memoryBytes, isNonNegativeSafeInteger) ||
    !isFieldValue(value.startedAt, isTimestamp) ||
    !isFieldValue(value.status, (status) => PROCESS_STATUSES.has(status)) ||
    !ACCESS_LEVELS.has(value.accessLevel) ||
    !PROCESS_OWNERSHIPS.has(value.ownership) ||
    !isManagedOwnership(value.ownership, value.managedRunId) ||
    !isProjectEvidence(value.projectAssociation, isProjectAssociationEvidence) ||
    !isProjectEvidence(value.projectFeatures, isProjectFeatureArray) ||
    !(value.projectId === null || isRequiredText(value.projectId, MAX_PROJECT_ID_BYTES)) ||
    !isClassificationResult(value.classification) ||
    !isFieldValue(value.portBindings, (bindings) =>
      isNestedPortBindingArray(bindings, instanceKey),
    ) ||
    !isNonNegativeSafeInteger(value.lastSeenRevision)
  ) {
    return false;
  }

  return (
    projectFieldsAreConsistent(value.projectAssociation, value.projectId, value.classification) &&
    hasBoundedJsonSize(value)
  );
}

function isPortBinding(value: unknown): value is PortBinding {
  return (
    isObject(value) &&
    hasExactKeys(value, PORT_BINDING_KEYS) &&
    PORT_PROTOCOLS.has(value.protocol) &&
    ADDRESS_FAMILIES.has(value.addressFamily) &&
    isRequiredText(value.localAddress, MAX_LOCAL_ADDRESS_BYTES) &&
    isUint16(value.localPort) &&
    isFieldValue(value.state, (state) => PORT_STATES.has(state)) &&
    (value.processInstanceKey === null || isProcessInstanceKey(value.processInstanceKey)) &&
    PORT_OWNERSHIP_CONFIDENCES.has(value.confidence) &&
    isTimestamp(value.observedAt)
  );
}

function isProcessInstanceKey(value: unknown): value is ProcessInstanceKey {
  if (
    !isObject(value) ||
    !hasExactKeys(value, PROCESS_INSTANCE_KEY_KEYS) ||
    !isRequiredText(value.bootId, MAX_PROCESS_BOOT_ID_BYTES) ||
    !isUint32(value.pid) ||
    value.pid === 0 ||
    !isRequiredText(value.nativeStartTime, MAX_PROCESS_NATIVE_START_TIME_BYTES) ||
    !DECIMAL_NATIVE_START_TIME.test(value.nativeStartTime)
  ) {
    return false;
  }

  return BigInt(value.nativeStartTime) <= MAX_U64;
}

function isFieldValue(value: unknown, isKnown: ValueValidator): boolean {
  if (value === 'unknown' || value === 'notSupported') {
    return true;
  }
  if (!isObject(value)) {
    return false;
  }
  if (hasExactKeys(value, ['known'])) {
    return isKnown(value.known);
  }
  return hasExactKeys(value, ['accessLimited']) && isAccessLimited(value.accessLimited);
}

function isProjectEvidence(value: unknown, isKnown: ValueValidator): boolean {
  if (value === 'missing' || value === 'unknown' || value === 'notSupported') {
    return true;
  }
  if (!isObject(value)) {
    return false;
  }
  if (hasExactKeys(value, ['known'])) {
    return isKnown(value.known);
  }
  return hasExactKeys(value, ['accessLimited']) && isAccessLimited(value.accessLimited);
}

function isAccessLimited(value: unknown): boolean {
  return (
    isObject(value) &&
    hasExactKeys(value, ['reason']) &&
    (value.reason === null || isBoundedText(value.reason, MAX_ACCESS_REASON_BYTES))
  );
}

function isProjectAssociationEvidence(value: unknown): value is ProjectAssociationEvidence {
  return (
    isObject(value) &&
    hasExactKeys(value, PROJECT_ASSOCIATION_KEYS) &&
    isRequiredText(value.projectId, MAX_PROJECT_ID_BYTES) &&
    isAbsolutePath(value.registeredRoot)
  );
}

function isProjectFeatureArray(value: unknown): boolean {
  if (!Array.isArray(value) || value.length > MAX_PROJECT_FEATURES) {
    return false;
  }

  let detectedRoot: string | null = null;
  let previousMarkerOrder = -1;
  for (const feature of value) {
    if (!isProjectFeatureEvidence(feature)) {
      return false;
    }
    const markerOrder = PROJECT_MARKER_ORDER.get(feature.markerId);
    if (markerOrder === undefined || markerOrder <= previousMarkerOrder) {
      return false;
    }
    if (detectedRoot !== null && feature.detectedRoot !== detectedRoot) {
      return false;
    }
    detectedRoot = feature.detectedRoot;
    previousMarkerOrder = markerOrder;
  }
  return true;
}

function isProjectFeatureEvidence(value: unknown): value is ProjectFeatureEvidence {
  return (
    isObject(value) &&
    hasExactKeys(value, PROJECT_FEATURE_KEYS) &&
    isRequiredText(value.markerId, MAX_PROJECT_MARKER_ID_BYTES) &&
    PROJECT_MARKER_ORDER.has(value.markerId) &&
    isAbsolutePath(value.markerPath) &&
    isAbsolutePath(value.detectedRoot)
  );
}

function isClassificationResult(value: unknown): value is ClassificationResult {
  return (
    isObject(value) &&
    hasExactKeys(value, CLASSIFICATION_RESULT_KEYS) &&
    isInt32(value.score) &&
    isUint32(value.version) &&
    value.version > 0 &&
    CLASSIFICATION_CATEGORIES.has(value.category) &&
    isClassificationReasonArray(value.reasons) &&
    (value.userOverride === null || isUserClassificationOverride(value.userOverride)) &&
    typeof value.isDevelopment === 'boolean'
  );
}

function isClassificationReasonArray(value: unknown): value is ClassificationReason[] {
  return (
    Array.isArray(value) &&
    value.length <= MAX_CLASSIFICATION_REASONS &&
    value.every(isClassificationReason)
  );
}

function isClassificationReason(value: unknown): value is ClassificationReason {
  return (
    isObject(value) &&
    hasExactKeys(value, CLASSIFICATION_REASON_KEYS) &&
    isRequiredText(value.code, MAX_CLASSIFICATION_REASON_CODE_BYTES) &&
    isInt32(value.score) &&
    isRequiredText(value.summary, MAX_CLASSIFICATION_REASON_SUMMARY_BYTES)
  );
}

function isUserClassificationOverride(value: unknown): value is UserClassificationOverride {
  if (value === 'include' || value === 'exclude') {
    return true;
  }
  return (
    isObject(value) &&
    hasExactKeys(value, ['assignProject']) &&
    isRequiredText(value.assignProject, MAX_PROJECT_ID_BYTES)
  );
}

function isNestedPortBindingArray(value: unknown, owner: ProcessInstanceKey): boolean {
  if (!Array.isArray(value) || value.length > MAX_NESTED_PORT_BINDINGS) {
    return false;
  }

  const identities = new Set<string>();
  for (const binding of value) {
    if (
      !isPortBinding(binding) ||
      binding.processInstanceKey === null ||
      !sameProcessInstance(binding.processInstanceKey, owner) ||
      !hasBoundedJsonSize(binding)
    ) {
      return false;
    }
    const identity = portBindingIdentity(binding);
    if (identities.has(identity)) {
      return false;
    }
    identities.add(identity);
  }
  return true;
}

function isManagedOwnership(ownership: unknown, managedRunId: unknown): boolean {
  return ownership === 'managed'
    ? isRequiredText(managedRunId, MAX_MANAGED_RUN_ID_BYTES)
    : ownership === 'external' && managedRunId === null;
}

function projectFieldsAreConsistent(
  association: unknown,
  projectId: unknown,
  classification: ClassificationResult,
): boolean {
  const assignedProject =
    isObject(classification.userOverride) &&
    hasExactKeys(classification.userOverride, ['assignProject'])
      ? classification.userOverride.assignProject
      : null;
  if (assignedProject !== null) {
    return projectId === assignedProject;
  }
  if (isObject(association) && hasExactKeys(association, ['known'])) {
    return (
      isProjectAssociationEvidence(association.known) && projectId === association.known.projectId
    );
  }
  return true;
}

function sameProcessInstance(left: ProcessInstanceKey, right: ProcessInstanceKey): boolean {
  return (
    left.bootId === right.bootId &&
    left.pid === right.pid &&
    left.nativeStartTime === right.nativeStartTime
  );
}

function portBindingIdentity(binding: PortBinding): string {
  return JSON.stringify([
    binding.protocol,
    binding.addressFamily,
    binding.localAddress,
    binding.localPort,
    binding.processInstanceKey?.bootId ?? null,
    binding.processInstanceKey?.pid ?? null,
    binding.processInstanceKey?.nativeStartTime ?? null,
  ]);
}

function isAbsolutePath(value: unknown): value is string {
  return (
    isRequiredText(value, MAX_PROJECT_PATH_BYTES) &&
    (value.startsWith('/') || /^[A-Za-z]:[\\/]/.test(value) || /^\\\\[^\\]+\\[^\\]+/.test(value))
  );
}

function isTimestamp(value: unknown): value is string {
  return isRequiredText(value, MAX_TIMESTAMP_BYTES);
}

function isCpuPercent(value: unknown): value is number {
  return (
    typeof value === 'number' && Number.isFinite(value) && value >= 0 && value <= MAX_CPU_PERCENT
  );
}

function isUint16(value: unknown): value is number {
  return isNonNegativeSafeInteger(value) && value <= 0xffff;
}

function isUint32(value: unknown): value is number {
  return isNonNegativeSafeInteger(value) && value <= MAX_U32;
}

function isInt32(value: unknown): value is number {
  return (
    typeof value === 'number' && Number.isSafeInteger(value) && value >= MIN_I32 && value <= MAX_I32
  );
}

function isNonNegativeSafeInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

function isRequiredText(value: unknown, maximumBytes: number): value is string {
  return isBoundedText(value, maximumBytes) && value.trim().length > 0;
}

function isBoundedText(value: unknown, maximumBytes: number): value is string {
  return (
    typeof value === 'string' &&
    !value.includes('\0') &&
    UTF8_ENCODER.encode(value).length <= maximumBytes
  );
}

function hasBoundedJsonSize(value: unknown): boolean {
  const encoded = JSON.stringify(value);
  return encoded !== undefined && UTF8_ENCODER.encode(encoded).length <= MAX_SNAPSHOT_ENTITY_BYTES;
}

function isObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
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
