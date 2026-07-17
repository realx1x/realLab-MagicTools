import type {
  ProcessInstanceKey,
  RequestProcessEnrichmentRequest,
  RequestProcessEnrichmentResponse,
} from '@dpm/generated-types';

import { forwardSupervisorRpc } from './supervisor';

const PROCESS_ENRICHMENT_METHOD = 'process.request_enrichment';
const PROCESS_ENRICHMENT_TIMEOUT_MS = 15_000;
const MAX_VISIBLE_PROCESS_KEYS = 64;
const MAX_BOOT_ID_BYTES = 256;
const MAX_NATIVE_START_TIME_BYTES = 128;
const PROCESS_INSTANCE_KEY_KEYS = ['bootId', 'pid', 'nativeStartTime'] as const;
const REQUEST_KEYS = ['visibleProcessInstanceKeys', 'selectedProcessInstanceKey'] as const;
const RESPONSE_KEYS = ['visibleAccepted', 'selectedAccepted'] as const;
const DECIMAL_NATIVE_START_TIME = /^[1-9]\d*$/;
const CONTROL_CHARACTER = /\p{Cc}/u;
const MAX_U64 = 0xffff_ffff_ffff_ffffn;
const utf8Encoder = new TextEncoder();

export async function requestProcessEnrichment(
  request: RequestProcessEnrichmentRequest,
): Promise<RequestProcessEnrichmentResponse> {
  if (!isRequestProcessEnrichmentRequest(request)) {
    throw new TypeError('invalid process enrichment request');
  }

  const response = await forwardSupervisorRpc<unknown>({
    requestId: `process-enrichment:${createSecureUuid()}`,
    operationId: null,
    timeoutMs: PROCESS_ENRICHMENT_TIMEOUT_MS,
    method: PROCESS_ENRICHMENT_METHOD,
    params: request,
  });
  if (!isRequestProcessEnrichmentResponse(response, request)) {
    throw new TypeError('invalid process enrichment response');
  }
  return response;
}

function isRequestProcessEnrichmentRequest(
  value: unknown,
): value is RequestProcessEnrichmentRequest {
  if (
    !isObject(value) ||
    !hasExactKeys(value, REQUEST_KEYS) ||
    !Array.isArray(value.visibleProcessInstanceKeys) ||
    value.visibleProcessInstanceKeys.length > MAX_VISIBLE_PROCESS_KEYS ||
    !(
      value.selectedProcessInstanceKey === null ||
      isProcessInstanceKey(value.selectedProcessInstanceKey)
    )
  ) {
    return false;
  }

  const visibleIdentities = new Set<string>();
  for (const instanceKey of value.visibleProcessInstanceKeys) {
    if (!isProcessInstanceKey(instanceKey)) {
      return false;
    }
    const identity = processIdentity(instanceKey);
    if (visibleIdentities.has(identity)) {
      return false;
    }
    visibleIdentities.add(identity);
  }
  return true;
}

function isRequestProcessEnrichmentResponse(
  value: unknown,
  request: RequestProcessEnrichmentRequest,
): value is RequestProcessEnrichmentResponse {
  const selectedIdentity =
    request.selectedProcessInstanceKey === null
      ? null
      : processIdentity(request.selectedProcessInstanceKey);
  const maximumVisibleAccepted = request.visibleProcessInstanceKeys.filter(
    (key) => processIdentity(key) !== selectedIdentity,
  ).length;
  return (
    isObject(value) &&
    hasExactKeys(value, RESPONSE_KEYS) &&
    typeof value.visibleAccepted === 'number' &&
    Number.isSafeInteger(value.visibleAccepted) &&
    value.visibleAccepted >= 0 &&
    value.visibleAccepted <= maximumVisibleAccepted &&
    typeof value.selectedAccepted === 'boolean' &&
    (request.selectedProcessInstanceKey !== null || !value.selectedAccepted)
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
    DECIMAL_NATIVE_START_TIME.test(value.nativeStartTime) &&
    BigInt(value.nativeStartTime) <= MAX_U64
  );
}

function processIdentity(key: ProcessInstanceKey): string {
  return JSON.stringify([key.bootId, key.pid, key.nativeStartTime]);
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

function createSecureUuid(): string {
  const uuid = globalThis.crypto?.randomUUID?.();
  if (typeof uuid !== 'string' || uuid.length === 0) {
    throw new TypeError('secure random UUID generation is unavailable');
  }
  return uuid;
}
