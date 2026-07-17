import type {
  ListRunHistoryRequest,
  ListRunHistoryResponse,
  ManagedStopKind,
  ProcessInstanceKey,
  RunHistoryItem,
  RunState,
} from '@dpm/generated-types';

import { forwardSupervisorRpc } from './supervisor';

export const RUN_HISTORY_PAGE_SIZE = 100;
export const MAX_RUN_HISTORY_ITEMS = 4_096;

const RUN_HISTORY_METHOD = 'run.get_history';
const RUN_HISTORY_TIMEOUT_MS = 15_000;
const MAX_RUN_ID_BYTES = 256;
const MAX_PROFILE_ID_BYTES = 256;
const MAX_PROFILE_NAME_BYTES = 256;
const MAX_BOOT_ID_BYTES = 256;
const MAX_NATIVE_START_TIME_BYTES = 128;
const MAX_TIMESTAMP_BYTES = 128;
const MAX_CURSOR_BYTES = 1_024;

const RUN_HISTORY_ITEM_KEYS = [
  'runId',
  'profileId',
  'profileName',
  'state',
  'processInstanceKey',
  'stopKind',
  'recoveryState',
  'startedAt',
  'updatedAt',
  'endedAt',
] as const;
const LIST_RESPONSE_KEYS = ['runs', 'nextCursor'] as const;
const PROCESS_INSTANCE_KEY_KEYS = ['bootId', 'pid', 'nativeStartTime'] as const;

const RUN_STATES = new Set<unknown>([
  'starting',
  'running',
  'stopRequested',
  'gracefulStopping',
  'forceStopping',
  'exited',
  'failed',
  'recovered',
  'exitedWhileOffline',
  'identityMismatch',
  'orphaned',
] satisfies ReadonlyArray<RunState>);
const RECOVERY_STATES = new Set<unknown>([
  'recovered',
  'exitedWhileOffline',
  'identityMismatch',
  'orphaned',
] satisfies ReadonlyArray<RunState>);
const STOP_KINDS = new Set<unknown>(['graceful', 'force'] satisfies ReadonlyArray<ManagedStopKind>);
const CANONICAL_UTC_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{9}Z$/;
const DECIMAL_NATIVE_START_TIME = /^(?:0|[1-9]\d*)$/;
const CONTROL_CHARACTER = /\p{Cc}/u;
const utf8Encoder = new TextEncoder();

export async function listRunHistoryPage(
  request: ListRunHistoryRequest,
): Promise<ListRunHistoryResponse> {
  if (!isListRunHistoryRequest(request)) {
    throw new TypeError('invalid run history request');
  }

  const response = await forwardSupervisorRpc<unknown>({
    requestId: `run-history:${globalThis.crypto.randomUUID()}`,
    operationId: null,
    timeoutMs: RUN_HISTORY_TIMEOUT_MS,
    method: RUN_HISTORY_METHOD,
    params: request,
  });
  if (!isListRunHistoryResponse(response) || response.runs.length > request.limit) {
    throw new TypeError('invalid run history response');
  }
  if (response.nextCursor !== null && response.nextCursor === request.cursor) {
    throw new TypeError('run history response repeats its request cursor');
  }
  return response;
}

export function isListRunHistoryResponse(value: unknown): value is ListRunHistoryResponse {
  if (!isObject(value) || !hasExactKeys(value, LIST_RESPONSE_KEYS)) {
    return false;
  }
  if (
    !Array.isArray(value.runs) ||
    value.runs.length > RUN_HISTORY_PAGE_SIZE ||
    !isNullableRequiredText(value.nextCursor, MAX_CURSOR_BYTES) ||
    (value.runs.length === 0 && value.nextCursor !== null)
  ) {
    return false;
  }

  const runIds = new Set<string>();
  for (const run of value.runs) {
    if (!isRunHistoryItem(run) || runIds.has(run.runId)) {
      return false;
    }
    runIds.add(run.runId);
  }
  return true;
}

export function isRunHistoryItem(value: unknown): value is RunHistoryItem {
  if (!isObject(value) || !hasExactKeys(value, RUN_HISTORY_ITEM_KEYS)) {
    return false;
  }
  if (
    !(
      isRequiredText(value.runId, MAX_RUN_ID_BYTES) &&
      isRequiredText(value.profileId, MAX_PROFILE_ID_BYTES) &&
      isRequiredText(value.profileName, MAX_PROFILE_NAME_BYTES) &&
      isRunState(value.state) &&
      (value.processInstanceKey === null || isProcessInstanceKey(value.processInstanceKey)) &&
      (value.stopKind === null || isStopKind(value.stopKind)) &&
      (value.recoveryState === null || isRecoveryState(value.recoveryState)) &&
      isTimestamp(value.startedAt) &&
      isTimestamp(value.updatedAt) &&
      (value.endedAt === null || isTimestamp(value.endedAt))
    )
  ) {
    return false;
  }
  if (
    value.updatedAt < value.startedAt ||
    (value.endedAt !== null && (value.endedAt < value.startedAt || value.endedAt > value.updatedAt))
  ) {
    return false;
  }
  const requiresEndedAt =
    value.state === 'exited' || value.state === 'failed' || value.state === 'exitedWhileOffline';
  if (requiresEndedAt !== (value.endedAt !== null)) {
    return false;
  }
  if (value.state === 'recovered' && value.recoveryState !== 'recovered') {
    return false;
  }
  if (value.state === 'exitedWhileOffline' && value.recoveryState !== 'exitedWhileOffline') {
    return false;
  }
  return recoveryStateMatches(value.state, value.recoveryState);
}

function recoveryStateMatches(state: RunState, recoveryState: RunState | null): boolean {
  switch (recoveryState) {
    case null:
      return state !== 'recovered' && state !== 'exitedWhileOffline';
    case 'recovered':
      return (
        state === 'recovered' ||
        state === 'stopRequested' ||
        state === 'gracefulStopping' ||
        state === 'forceStopping' ||
        state === 'exited' ||
        state === 'failed' ||
        state === 'identityMismatch' ||
        state === 'orphaned'
      );
    case 'exitedWhileOffline':
    case 'identityMismatch':
    case 'orphaned':
      return state === recoveryState;
    case 'starting':
    case 'running':
    case 'stopRequested':
    case 'gracefulStopping':
    case 'forceStopping':
    case 'exited':
    case 'failed':
      return false;
  }
}

function isListRunHistoryRequest(value: unknown): value is ListRunHistoryRequest {
  return (
    isObject(value) &&
    hasExactKeys(value, ['cursor', 'limit']) &&
    isNullableRequiredText(value.cursor, MAX_CURSOR_BYTES) &&
    typeof value.limit === 'number' &&
    Number.isSafeInteger(value.limit) &&
    value.limit >= 1 &&
    value.limit <= RUN_HISTORY_PAGE_SIZE
  );
}

function isProcessInstanceKey(value: unknown): value is ProcessInstanceKey {
  return (
    isObject(value) &&
    hasExactKeys(value, PROCESS_INSTANCE_KEY_KEYS) &&
    isRequiredText(value.bootId, MAX_BOOT_ID_BYTES) &&
    typeof value.pid === 'number' &&
    Number.isSafeInteger(value.pid) &&
    value.pid >= 1 &&
    value.pid <= 0xffff_ffff &&
    isRequiredText(value.nativeStartTime, MAX_NATIVE_START_TIME_BYTES) &&
    DECIMAL_NATIVE_START_TIME.test(value.nativeStartTime)
  );
}

function isRunState(value: unknown): value is RunState {
  return RUN_STATES.has(value);
}

function isRecoveryState(value: unknown): value is RunState {
  return RECOVERY_STATES.has(value);
}

function isStopKind(value: unknown): value is ManagedStopKind {
  return STOP_KINDS.has(value);
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
    value.length > 0 &&
    value.trim().length > 0 &&
    utf8Encoder.encode(value).length <= maximumBytes &&
    !CONTROL_CHARACTER.test(value)
  );
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
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
