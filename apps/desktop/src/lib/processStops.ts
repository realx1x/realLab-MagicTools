import type {
  ForceStopManagedRunRequest,
  GetProcessDetailsRequest,
  GetProcessDetailsResponse,
  ManagedRunSummary,
  ManagedStopOperationResult,
  ProcessInstanceKey,
  StopExternalProcessRequest,
  StopExternalProcessResult,
  StopManagedRunRequest,
} from '@dpm/generated-types';
import { forwardSupervisorRpc } from './supervisor';

const PROCESS_DETAILS_METHOD = 'process.get_details';
const GRACEFUL_STOP_METHOD = 'run.stop';
const FORCE_STOP_METHOD = 'run.force_stop';
const EXTERNAL_STOP_METHOD = 'process.stop_external';
const PROCESS_DETAILS_TIMEOUT_MS = 15_000;
const STOP_TIMEOUT_MS = 30_000;

const MAX_RUN_ID_BYTES = 256;
const MAX_PROFILE_ID_BYTES = 256;
const MAX_BOOT_ID_BYTES = 256;
const MAX_NATIVE_START_TIME_BYTES = 128;
const MAX_OPERATION_ID_BYTES = 128;
const MAX_TIMESTAMP_BYTES = 128;
const MAX_MANAGED_STOP_REQUEST_WIRE_BYTES = 1_024;
const MAX_MANAGED_RUN_RESULT_WIRE_BYTES = 4 * 1_024;
const MAX_MANAGED_STOP_RESULT_WIRE_BYTES = 8 * 1_024;
const MAX_EXTERNAL_STOP_REQUEST_WIRE_BYTES = 2 * 1_024;
const MAX_EXTERNAL_STOP_RESULT_WIRE_BYTES = 2 * 1_024;
const MAX_PROCESS_DETAILS_REQUEST_WIRE_BYTES = 2 * 1_024;
const MAX_PROCESS_DETAILS_RESPONSE_WIRE_BYTES = 16 * 1_024;
const MAX_PID = 4_294_967_295;
const MAX_MACOS_PROCESS_GROUP_ID = 2_147_483_647;
const MAX_U64 = 18_446_744_073_709_551_615n;

const MANAGED_STOP_REQUEST_KEYS = ['runId'] as const;
const FORCE_STOP_REQUEST_KEYS = ['runId', 'supersedeOperationId'] as const;
const PROCESS_DETAILS_REQUEST_KEYS = ['processInstanceKey'] as const;
const PROCESS_DETAILS_RESPONSE_KEYS = ['processInstanceKey', 'control'] as const;
const EXTERNAL_PROCESS_CONTROL_KEYS = ['kind'] as const;
const MANAGED_PROCESS_CONTROL_KEYS = ['kind', 'run', 'activeStop'] as const;
const EXTERNAL_STOP_REQUEST_KEYS = ['confirmation'] as const;
const EXTERNAL_STOP_CONFIRMATION_KEYS = ['processInstanceKey', 'scope'] as const;
const PROCESS_INSTANCE_KEY_KEYS = ['bootId', 'pid', 'nativeStartTime'] as const;
const MANAGED_STOP_RESULT_KEYS = [
  'operationId',
  'run',
  'kind',
  'status',
  'signalDisposition',
  'outcome',
  'createdAt',
  'updatedAt',
  'completedAt',
] as const;
const MANAGED_RUN_SUMMARY_KEYS = [
  'runId',
  'profileId',
  'profileUpdatedAt',
  'state',
  'processInstanceKey',
  'processGroupId',
  'startedAt',
  'updatedAt',
  'endedAt',
] as const;
const EXTERNAL_STOP_RESULT_KEYS = ['processInstanceKey', 'scope', 'outcome'] as const;

const OPERATION_ID = /^[A-Za-z0-9._:-]+$/;
const CANONICAL_UNSIGNED_DECIMAL = /^(?:0|[1-9][0-9]*)$/;
const RFC3339_TIMESTAMP =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|([+-])(\d{2}):(\d{2}))$/;
const utf8Encoder = new TextEncoder();

/** Reads control evidence for one exact process instance without retrying. */
export async function getProcessDetails(
  expectedKey: ProcessInstanceKey,
): Promise<GetProcessDetailsResponse> {
  if (!isProcessInstanceKey(expectedKey)) {
    throw new TypeError('invalid process details request');
  }
  const expectedIdentity = copyProcessInstanceKey(expectedKey);
  const request: GetProcessDetailsRequest = { processInstanceKey: expectedIdentity };
  if (!isGetProcessDetailsRequest(request)) {
    throw new TypeError('invalid process details request');
  }

  const response = await forwardSupervisorRpc<unknown>({
    requestId: createRpcId('process-details-request'),
    operationId: null,
    timeoutMs: PROCESS_DETAILS_TIMEOUT_MS,
    method: PROCESS_DETAILS_METHOD,
    params: request,
  });
  if (
    !isGetProcessDetailsResponse(response) ||
    !sameProcessInstanceKey(response.processInstanceKey, expectedIdentity)
  ) {
    throw new TypeError('invalid process details response');
  }
  return response;
}

/** Requests one graceful stop and binds the result to the selected run instance. */
export async function gracefullyStopManagedRun(
  runId: string,
  expectedKey: ProcessInstanceKey,
): Promise<ManagedStopOperationResult> {
  const request: StopManagedRunRequest = { runId };
  if (!isStopManagedRunRequest(request) || !isProcessInstanceKey(expectedKey)) {
    throw new TypeError('invalid graceful managed stop request');
  }
  const expectedIdentity = copyProcessInstanceKey(expectedKey);

  const operationId = createRpcId('run-stop-operation');
  const response = await forwardSupervisorRpc<unknown>({
    requestId: createRpcId('run-stop-request'),
    operationId,
    timeoutMs: STOP_TIMEOUT_MS,
    method: GRACEFUL_STOP_METHOD,
    params: request,
  });
  if (
    !isManagedStopOperationResult(response) ||
    !managedStopResponseMatchesRequest(
      response,
      operationId,
      request.runId,
      expectedIdentity,
      'graceful',
    )
  ) {
    throw new TypeError('invalid graceful managed stop response');
  }
  return response;
}

/**
 * Requests one force stop. Pass null explicitly for a direct force stop, or
 * the exact graceful operation ID when replacing that operation.
 */
export async function forceStopManagedRun(
  runId: string,
  expectedKey: ProcessInstanceKey,
  supersedeOperationId: string | null,
): Promise<ManagedStopOperationResult> {
  const request: ForceStopManagedRunRequest = { runId, supersedeOperationId };
  if (!isForceStopManagedRunRequest(request) || !isProcessInstanceKey(expectedKey)) {
    throw new TypeError('invalid force managed stop request');
  }
  const expectedIdentity = copyProcessInstanceKey(expectedKey);

  const operationId = createRpcId('run-force-stop-operation');
  const response = await forwardSupervisorRpc<unknown>({
    requestId: createRpcId('run-force-stop-request'),
    operationId,
    timeoutMs: STOP_TIMEOUT_MS,
    method: FORCE_STOP_METHOD,
    params: request,
  });
  if (
    !isManagedStopOperationResult(response) ||
    !managedStopResponseMatchesRequest(
      response,
      operationId,
      request.runId,
      expectedIdentity,
      'force',
    )
  ) {
    throw new TypeError('invalid force managed stop response');
  }
  return response;
}

/** Stops only the exact external process instance supplied by the caller. */
export async function stopExactExternalProcess(
  processInstanceKey: ProcessInstanceKey,
): Promise<StopExternalProcessResult> {
  if (!isProcessInstanceKey(processInstanceKey)) {
    throw new TypeError('invalid external process stop request');
  }
  const request: StopExternalProcessRequest = {
    confirmation: {
      processInstanceKey: copyProcessInstanceKey(processInstanceKey),
      scope: 'singleProcess',
    },
  };
  if (!isStopExternalProcessRequest(request)) {
    throw new TypeError('invalid external process stop request');
  }

  const response = await forwardSupervisorRpc<unknown>({
    requestId: createRpcId('process-stop-external-request'),
    operationId: createRpcId('process-stop-external-operation'),
    timeoutMs: STOP_TIMEOUT_MS,
    method: EXTERNAL_STOP_METHOD,
    params: request,
  });
  if (
    !isStopExternalProcessResult(response) ||
    response.scope !== request.confirmation.scope ||
    !sameProcessInstanceKey(response.processInstanceKey, request.confirmation.processInstanceKey)
  ) {
    throw new TypeError('invalid external process stop response');
  }
  return response;
}

export function isManagedStopOperationResult(value: unknown): value is ManagedStopOperationResult {
  if (!isObject(value) || !hasExactKeys(value, MANAGED_STOP_RESULT_KEYS)) {
    return false;
  }
  if (
    !isOperationId(value.operationId) ||
    !isManagedRunSummary(value.run) ||
    !isManagedStopKind(value.kind) ||
    !isManagedStopStatus(value.status) ||
    !isNullableManagedStopSignalDisposition(value.signalDisposition) ||
    !isNullableManagedStopOutcome(value.outcome) ||
    !isTimestamp(value.createdAt) ||
    !isTimestamp(value.updatedAt) ||
    !(value.completedAt === null || isTimestamp(value.completedAt))
  ) {
    return false;
  }

  const result: ManagedStopOperationResult = {
    operationId: value.operationId,
    run: value.run,
    kind: value.kind,
    status: value.status,
    signalDisposition: value.signalDisposition,
    outcome: value.outcome,
    createdAt: value.createdAt,
    updatedAt: value.updatedAt,
    completedAt: value.completedAt,
  };
  const terminal = result.status === 'completed' || result.status === 'superseded';
  if (terminal !== (result.completedAt !== null) || (!terminal && result.run.endedAt !== null)) {
    return false;
  }
  if (!managedStopStateIsConsistent(result)) {
    return false;
  }
  return jsonFitsWireLimit(value, MAX_MANAGED_STOP_RESULT_WIRE_BYTES);
}

export function isGetProcessDetailsResponse(value: unknown): value is GetProcessDetailsResponse {
  if (
    !isObject(value) ||
    !hasExactKeys(value, PROCESS_DETAILS_RESPONSE_KEYS) ||
    !isProcessInstanceKey(value.processInstanceKey) ||
    !isObject(value.control)
  ) {
    return false;
  }

  const control = value.control;
  if (control.kind === 'external') {
    return (
      hasExactKeys(control, EXTERNAL_PROCESS_CONTROL_KEYS) &&
      jsonFitsWireLimit(value, MAX_PROCESS_DETAILS_RESPONSE_WIRE_BYTES)
    );
  }
  if (
    control.kind !== 'managed' ||
    !hasExactKeys(control, MANAGED_PROCESS_CONTROL_KEYS) ||
    !isManagedRunSummary(control.run) ||
    control.run.processInstanceKey === null ||
    !sameProcessInstanceKey(control.run.processInstanceKey, value.processInstanceKey)
  ) {
    return false;
  }
  if (control.activeStop !== null) {
    if (
      !isManagedStopOperationResult(control.activeStop) ||
      control.activeStop.status === 'completed' ||
      control.activeStop.status === 'superseded' ||
      !sameManagedRunSummary(control.activeStop.run, control.run)
    ) {
      return false;
    }
  }
  return jsonFitsWireLimit(value, MAX_PROCESS_DETAILS_RESPONSE_WIRE_BYTES);
}

export function isStopExternalProcessResult(value: unknown): value is StopExternalProcessResult {
  return (
    isObject(value) &&
    hasExactKeys(value, EXTERNAL_STOP_RESULT_KEYS) &&
    isProcessInstanceKey(value.processInstanceKey) &&
    value.scope === 'singleProcess' &&
    value.outcome === 'signalDelivered' &&
    jsonFitsWireLimit(value, MAX_EXTERNAL_STOP_RESULT_WIRE_BYTES)
  );
}

function isStopManagedRunRequest(value: unknown): value is StopManagedRunRequest {
  return (
    isObject(value) &&
    hasExactKeys(value, MANAGED_STOP_REQUEST_KEYS) &&
    isRequiredText(value.runId, MAX_RUN_ID_BYTES) &&
    jsonFitsWireLimit(value, MAX_MANAGED_STOP_REQUEST_WIRE_BYTES)
  );
}

function isGetProcessDetailsRequest(value: unknown): value is GetProcessDetailsRequest {
  return (
    isObject(value) &&
    hasExactKeys(value, PROCESS_DETAILS_REQUEST_KEYS) &&
    isProcessInstanceKey(value.processInstanceKey) &&
    jsonFitsWireLimit(value, MAX_PROCESS_DETAILS_REQUEST_WIRE_BYTES)
  );
}

function isForceStopManagedRunRequest(value: unknown): value is ForceStopManagedRunRequest {
  return (
    isObject(value) &&
    hasExactKeys(value, FORCE_STOP_REQUEST_KEYS) &&
    isRequiredText(value.runId, MAX_RUN_ID_BYTES) &&
    (value.supersedeOperationId === null || isOperationId(value.supersedeOperationId)) &&
    jsonFitsWireLimit(value, MAX_MANAGED_STOP_REQUEST_WIRE_BYTES)
  );
}

function isStopExternalProcessRequest(value: unknown): value is StopExternalProcessRequest {
  if (!isObject(value) || !hasExactKeys(value, EXTERNAL_STOP_REQUEST_KEYS)) {
    return false;
  }
  const confirmation = value.confirmation;
  return (
    isObject(confirmation) &&
    hasExactKeys(confirmation, EXTERNAL_STOP_CONFIRMATION_KEYS) &&
    isProcessInstanceKey(confirmation.processInstanceKey) &&
    confirmation.scope === 'singleProcess' &&
    jsonFitsWireLimit(value, MAX_EXTERNAL_STOP_REQUEST_WIRE_BYTES)
  );
}

function isManagedRunSummary(value: unknown): value is ManagedRunSummary {
  if (!isObject(value) || !hasExactKeys(value, MANAGED_RUN_SUMMARY_KEYS)) {
    return false;
  }
  if (
    !isRequiredText(value.runId, MAX_RUN_ID_BYTES) ||
    !isRequiredText(value.profileId, MAX_PROFILE_ID_BYTES) ||
    !isTimestamp(value.profileUpdatedAt) ||
    !isRunState(value.state) ||
    !(value.processInstanceKey === null || isProcessInstanceKey(value.processInstanceKey)) ||
    !isNullableProcessGroupId(value.processGroupId) ||
    !isTimestamp(value.startedAt) ||
    !isTimestamp(value.updatedAt) ||
    !(value.endedAt === null || isTimestamp(value.endedAt))
  ) {
    return false;
  }
  if (
    value.processGroupId !== null &&
    (value.processInstanceKey === null || value.processGroupId !== value.processInstanceKey.pid)
  ) {
    return false;
  }
  return jsonFitsWireLimit(value, MAX_MANAGED_RUN_RESULT_WIRE_BYTES);
}

function isProcessInstanceKey(value: unknown): value is ProcessInstanceKey {
  if (!isObject(value) || !hasExactKeys(value, PROCESS_INSTANCE_KEY_KEYS)) {
    return false;
  }
  if (
    !isRequiredText(value.bootId, MAX_BOOT_ID_BYTES) ||
    !isPositivePid(value.pid) ||
    !isRequiredText(value.nativeStartTime, MAX_NATIVE_START_TIME_BYTES) ||
    !CANONICAL_UNSIGNED_DECIMAL.test(value.nativeStartTime) ||
    value.nativeStartTime === '0'
  ) {
    return false;
  }
  try {
    return BigInt(value.nativeStartTime) <= MAX_U64;
  } catch {
    return false;
  }
}

function managedStopStateIsConsistent(value: ManagedStopOperationResult): boolean {
  if (value.status === 'requested' || value.status === 'signalPending') {
    return (
      value.signalDisposition === null &&
      value.outcome === null &&
      (value.kind === 'graceful'
        ? value.run.state === 'stopRequested'
        : value.run.state === 'stopRequested' || value.run.state === 'gracefulStopping')
    );
  }
  if (value.status === 'inProgress') {
    return (
      value.signalDisposition !== null &&
      value.outcome === null &&
      value.run.state === (value.kind === 'graceful' ? 'gracefulStopping' : 'forceStopping')
    );
  }
  if (value.status === 'timedOut') {
    return (
      value.kind === 'graceful' &&
      value.signalDisposition !== null &&
      value.outcome === null &&
      value.run.state === 'gracefulStopping'
    );
  }
  if (value.status === 'superseded') {
    return value.kind === 'graceful' && value.outcome === null;
  }

  if (value.outcome === null) {
    return false;
  }
  if (value.outcome === 'signalUnavailable' && value.signalDisposition !== 'unavailable') {
    return false;
  }
  const expectedStates: Record<
    NonNullable<ManagedStopOperationResult['outcome']>,
    ReadonlySet<string>
  > = {
    exited: new Set(['exited']),
    alreadyExited: new Set(['exited', 'exitedWhileOffline']),
    identityMismatch: new Set(['identityMismatch']),
    orphaned: new Set(['orphaned']),
    signalUnavailable: new Set(['orphaned']),
    failed: new Set(['failed']),
  };
  if (!expectedStates[value.outcome].has(value.run.state)) {
    return false;
  }
  return !(
    (value.outcome === 'identityMismatch' ||
      value.outcome === 'orphaned' ||
      value.outcome === 'signalUnavailable') &&
    value.run.endedAt !== null
  );
}

function managedStopResponseMatchesRequest(
  response: ManagedStopOperationResult,
  operationId: string,
  runId: string,
  expectedKey: ProcessInstanceKey,
  expectedKind: ManagedStopOperationResult['kind'],
): boolean {
  return (
    response.operationId === operationId &&
    response.run.runId === runId &&
    response.kind === expectedKind &&
    response.run.processInstanceKey !== null &&
    sameProcessInstanceKey(response.run.processInstanceKey, expectedKey)
  );
}

function sameProcessInstanceKey(left: ProcessInstanceKey, right: ProcessInstanceKey): boolean {
  return (
    left.bootId === right.bootId &&
    left.pid === right.pid &&
    left.nativeStartTime === right.nativeStartTime
  );
}

function sameManagedRunSummary(left: ManagedRunSummary, right: ManagedRunSummary): boolean {
  return (
    left.runId === right.runId &&
    left.profileId === right.profileId &&
    left.profileUpdatedAt === right.profileUpdatedAt &&
    left.state === right.state &&
    ((left.processInstanceKey === null && right.processInstanceKey === null) ||
      (left.processInstanceKey !== null &&
        right.processInstanceKey !== null &&
        sameProcessInstanceKey(left.processInstanceKey, right.processInstanceKey))) &&
    left.processGroupId === right.processGroupId &&
    left.startedAt === right.startedAt &&
    left.updatedAt === right.updatedAt &&
    left.endedAt === right.endedAt
  );
}

function copyProcessInstanceKey(value: ProcessInstanceKey): ProcessInstanceKey {
  return {
    bootId: value.bootId,
    pid: value.pid,
    nativeStartTime: value.nativeStartTime,
  };
}

function isManagedStopKind(value: unknown): value is ManagedStopOperationResult['kind'] {
  return value === 'graceful' || value === 'force';
}

function isManagedStopStatus(value: unknown): value is ManagedStopOperationResult['status'] {
  return (
    value === 'requested' ||
    value === 'signalPending' ||
    value === 'inProgress' ||
    value === 'timedOut' ||
    value === 'completed' ||
    value === 'superseded'
  );
}

function isNullableManagedStopSignalDisposition(
  value: unknown,
): value is ManagedStopOperationResult['signalDisposition'] {
  return value === null || value === 'delivered' || value === 'unavailable';
}

function isNullableManagedStopOutcome(
  value: unknown,
): value is ManagedStopOperationResult['outcome'] {
  return (
    value === null ||
    value === 'exited' ||
    value === 'alreadyExited' ||
    value === 'identityMismatch' ||
    value === 'orphaned' ||
    value === 'signalUnavailable' ||
    value === 'failed'
  );
}

function isRunState(value: unknown): value is ManagedRunSummary['state'] {
  return (
    value === 'starting' ||
    value === 'running' ||
    value === 'stopRequested' ||
    value === 'gracefulStopping' ||
    value === 'forceStopping' ||
    value === 'exited' ||
    value === 'failed' ||
    value === 'recovered' ||
    value === 'exitedWhileOffline' ||
    value === 'identityMismatch' ||
    value === 'orphaned'
  );
}

function isTimestamp(value: unknown): value is string {
  if (!isRequiredText(value, MAX_TIMESTAMP_BYTES)) {
    return false;
  }
  const match = RFC3339_TIMESTAMP.exec(value);
  if (match === null) {
    return false;
  }
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const second = Number(match[6]);
  const offsetHour = match[8] === 'Z' ? 0 : Number(match[10]);
  const offsetMinute = match[8] === 'Z' ? 0 : Number(match[11]);
  return (
    year >= 1 &&
    month >= 1 &&
    month <= 12 &&
    day >= 1 &&
    day <= daysInMonth(year, month) &&
    hour <= 23 &&
    minute <= 59 &&
    second <= 59 &&
    offsetHour <= 23 &&
    offsetMinute <= 59
  );
}

function daysInMonth(year: number, month: number): number {
  if (month === 2) {
    return year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0) ? 29 : 28;
  }
  return month === 4 || month === 6 || month === 9 || month === 11 ? 30 : 31;
}

function isOperationId(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    utf8ByteLength(value) <= MAX_OPERATION_ID_BYTES &&
    OPERATION_ID.test(value)
  );
}

function isPositivePid(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 1 && value <= MAX_PID;
}

function isNullableProcessGroupId(value: unknown): value is number | null {
  return (
    value === null ||
    (typeof value === 'number' &&
      Number.isSafeInteger(value) &&
      value >= 1 &&
      value <= MAX_MACOS_PROCESS_GROUP_ID)
  );
}

function isRequiredText(value: unknown, maximumBytes: number): value is string {
  return (
    typeof value === 'string' &&
    !value.includes('\0') &&
    value.trim().length > 0 &&
    utf8ByteLength(value) <= maximumBytes
  );
}

function jsonFitsWireLimit(value: unknown, maximumBytes: number): boolean {
  try {
    const encoded = JSON.stringify(value);
    return typeof encoded === 'string' && utf8ByteLength(encoded) <= maximumBytes;
  } catch {
    return false;
  }
}

function utf8ByteLength(value: string): number {
  return utf8Encoder.encode(value).length;
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
  const result = `${prefix}:${randomUuid}`;
  if (!isOperationId(result)) {
    throw new TypeError('generated RPC identity is invalid');
  }
  return result;
}
