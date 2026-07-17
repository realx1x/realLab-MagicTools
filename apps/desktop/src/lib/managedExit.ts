import type {
  ExitImpactSummary,
  ExitRunImpact,
  GetExitImpactRequest,
  StopAllForExitMemberAction,
  StopAllForExitMemberResult,
  StopAllForExitRequest,
  StopAllForExitResult,
} from '@dpm/generated-types';

import { forwardSupervisorRpc } from './supervisor';

const GET_EXIT_IMPACT_METHOD = 'system.get_exit_impact';
const STOP_ALL_FOR_EXIT_METHOD = 'run.stop_all_for_exit';
const GET_EXIT_IMPACT_TIMEOUT_MS = 15_000;
const STOP_ALL_FOR_EXIT_TIMEOUT_MS = 30_000;
const MAX_EXIT_IMPACT_RUNS = 16;
const MAX_RUN_ID_BYTES = 256;
const MAX_OPERATION_ID_BYTES = 128;
const MAX_EXIT_IMPACT_SUMMARY_WIRE_BYTES = 16 * 1_024;
const MAX_STOP_ALL_FOR_EXIT_RESULT_WIRE_BYTES = 24 * 1_024;
const ASSESSMENT_ID = /^[0-9a-f]{64}$/;
const PORTABLE_ID = /^[A-Za-z0-9._:-]+$/;
const utf8Encoder = new TextEncoder();

export async function getExitImpact(): Promise<ExitImpactSummary> {
  const request: GetExitImpactRequest = {};
  const response = await forwardSupervisorRpc<unknown>({
    requestId: createRpcId('exit-impact-request'),
    operationId: null,
    timeoutMs: GET_EXIT_IMPACT_TIMEOUT_MS,
    method: GET_EXIT_IMPACT_METHOD,
    params: request,
  });
  if (!isExitImpactSummary(response)) {
    throw new TypeError('invalid managed exit-impact response');
  }
  return response;
}

export async function stopAllForExit(
  expectedAssessmentId: string,
  operationId: string,
): Promise<StopAllForExitResult> {
  const request: StopAllForExitRequest = { expectedAssessmentId };
  if (!isAssessmentId(expectedAssessmentId) || !isOperationId(operationId)) {
    throw new TypeError('invalid stop-all-for-exit request');
  }
  const response = await forwardSupervisorRpc<unknown>({
    requestId: createRpcId('exit-stop-all-request'),
    operationId,
    timeoutMs: STOP_ALL_FOR_EXIT_TIMEOUT_MS,
    method: STOP_ALL_FOR_EXIT_METHOD,
    params: request,
  });
  if (!isStopAllForExitResult(response) || response.operationId !== operationId) {
    throw new TypeError('invalid stop-all-for-exit response');
  }
  return response;
}

export function createStopAllForExitOperationId(): string {
  return createRpcId('exit-stop-all-operation');
}

export function isStaleExitAssessmentError(
  value: unknown,
  operationId: string,
  expectedAssessmentId: string,
  currentAssessmentId: string,
): boolean {
  if (
    !hasKey(value, 'code') ||
    !hasKey(value, 'operationId') ||
    !hasKey(value, 'details') ||
    value.code !== 'CONFLICT' ||
    value.operationId !== operationId ||
    value.details === null ||
    typeof value.details !== 'object' ||
    Array.isArray(value.details)
  ) {
    return false;
  }
  const details = value.details as Record<string, unknown>;
  return (
    details.expectedAssessmentId === expectedAssessmentId &&
    details.currentAssessmentId === currentAssessmentId
  );
}

export function isExitImpactSummary(value: unknown): value is ExitImpactSummary {
  if (
    !hasExactKeys(value, ['assessmentId', 'runs']) ||
    !isAssessmentId(value.assessmentId) ||
    !Array.isArray(value.runs) ||
    value.runs.length > MAX_EXIT_IMPACT_RUNS ||
    utf8Length(value) > MAX_EXIT_IMPACT_SUMMARY_WIRE_BYTES
  ) {
    return false;
  }
  let previousRunId: string | null = null;
  for (const impact of value.runs) {
    if (!isExitRunImpact(impact)) {
      return false;
    }
    const runId = exitRunId(impact);
    if (previousRunId !== null && compareUtf8(previousRunId, runId) >= 0) {
      return false;
    }
    previousRunId = runId;
  }
  return true;
}

export function isStopAllForExitResult(value: unknown): value is StopAllForExitResult {
  if (
    !hasExactKeys(value, ['operationId', 'status', 'members']) ||
    !isOperationId(value.operationId) ||
    !Array.isArray(value.members) ||
    value.members.length > MAX_EXIT_IMPACT_RUNS ||
    utf8Length(value) > MAX_STOP_ALL_FOR_EXIT_RESULT_WIRE_BYTES
  ) {
    return false;
  }

  const operationIds = new Set<string>();
  let previousRunId: string | null = null;
  let hasCurrentImpact = false;
  let hasBlockingImpact = false;
  for (const member of value.members) {
    if (!isStopAllForExitMemberResult(member)) {
      return false;
    }
    if (previousRunId !== null && compareUtf8(previousRunId, member.runId) >= 0) {
      return false;
    }
    previousRunId = member.runId;
    const actionOperationId = stopActionOperationId(member.action);
    if (actionOperationId !== null) {
      if (operationIds.has(actionOperationId)) {
        return false;
      }
      operationIds.add(actionOperationId);
    }
    if (member.currentImpact !== null) {
      hasCurrentImpact = true;
      hasBlockingImpact ||= isBlockingExitImpact(member.currentImpact);
    }
  }

  const expectedStatus = !hasCurrentImpact
    ? 'completed'
    : hasBlockingImpact
      ? 'blocked'
      : 'draining';
  return value.status === expectedStatus;
}

export function exitRunId(impact: ExitRunImpact): string {
  return impact.runId;
}

export function isBlockingExitImpact(impact: ExitRunImpact): boolean {
  return (
    impact.kind === 'launching' ||
    impact.kind === 'running' ||
    impact.kind === 'gracefulTimedOut' ||
    impact.kind === 'retained'
  );
}

function isStopAllForExitMemberResult(value: unknown): value is StopAllForExitMemberResult {
  return (
    hasExactKeys(value, ['runId', 'action', 'currentImpact']) &&
    isRunId(value.runId) &&
    isStopAllForExitMemberAction(value.action) &&
    (value.currentImpact === null ||
      (isExitRunImpact(value.currentImpact) && exitRunId(value.currentImpact) === value.runId))
  );
}

function isStopAllForExitMemberAction(value: unknown): value is StopAllForExitMemberAction {
  if (!hasKey(value, 'kind')) {
    return false;
  }
  if (value.kind === 'none') {
    return hasExactKeys(value, ['kind']);
  }
  return (
    (value.kind === 'gracefulRequested' || value.kind === 'stopAdopted') &&
    hasExactKeys(value, ['kind', 'operationId']) &&
    isOperationId(value.operationId)
  );
}

function stopActionOperationId(action: StopAllForExitMemberAction): string | null {
  return action.kind === 'none' ? null : action.operationId;
}

function isExitRunImpact(value: unknown): value is ExitRunImpact {
  if (!hasKey(value, 'kind') || !hasKey(value, 'runId') || !isRunId(value.runId)) {
    return false;
  }
  switch (value.kind) {
    case 'launching':
    case 'running':
      return hasExactKeys(value, ['kind', 'runId']);
    case 'gracefulStopping':
    case 'gracefulTimedOut':
    case 'forceStopping':
      return (
        hasExactKeys(value, ['kind', 'runId', 'operationId']) && isOperationId(value.operationId)
      );
    case 'retained':
      return (
        hasExactKeys(value, ['kind', 'runId', 'reason']) &&
        (value.reason === 'quarantined' ||
          value.reason === 'cleanupPending' ||
          value.reason === 'durableOnly' ||
          value.reason === 'controlMismatch')
      );
    default:
      return false;
  }
}

function isAssessmentId(value: unknown): value is string {
  return typeof value === 'string' && ASSESSMENT_ID.test(value);
}

function isRunId(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.trim().length > 0 &&
    !value.includes('\0') &&
    utf8Encoder.encode(value).length <= MAX_RUN_ID_BYTES
  );
}

function isOperationId(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    PORTABLE_ID.test(value) &&
    utf8Encoder.encode(value).length <= MAX_OPERATION_ID_BYTES
  );
}

function compareUtf8(left: string, right: string): number {
  const leftBytes = utf8Encoder.encode(left);
  const rightBytes = utf8Encoder.encode(right);
  const common = Math.min(leftBytes.length, rightBytes.length);
  for (let index = 0; index < common; index += 1) {
    const leftByte = leftBytes[index];
    const rightByte = rightBytes[index];
    if (leftByte === undefined || rightByte === undefined) {
      break;
    }
    const difference = leftByte - rightByte;
    if (difference !== 0) {
      return difference;
    }
  }
  return leftBytes.length - rightBytes.length;
}

function utf8Length(value: unknown): number {
  try {
    return utf8Encoder.encode(JSON.stringify(value)).length;
  } catch {
    return Number.POSITIVE_INFINITY;
  }
}

function createRpcId(prefix: string): string {
  return `${prefix}:${globalThis.crypto.randomUUID()}`;
}

function hasKey<Key extends string>(value: unknown, key: Key): value is Record<Key, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value) && key in value;
}

function hasExactKeys<Key extends string>(
  value: unknown,
  keys: readonly Key[],
): value is Record<Key, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }
  const actual = Object.keys(value);
  return actual.length === keys.length && keys.every((key) => actual.includes(key));
}
