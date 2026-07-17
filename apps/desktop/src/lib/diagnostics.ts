import type {
  DiagnosticContentKind,
  DiagnosticContentPrivacy,
  DiagnosticManifestItem,
  ExportDiagnosticsRequest,
  ExportDiagnosticsResult,
  GetDiagnosticsManifestRequest,
  GetDiagnosticsManifestResponse,
} from '@dpm/generated-types';

import { forwardSupervisorRpc } from './supervisor';

export type DiagnosticsExportRequest = ExportDiagnosticsRequest;

const DIAGNOSTICS_MANIFEST_METHOD = 'diagnostics.get_manifest';
const DIAGNOSTICS_EXPORT_METHOD = 'diagnostics.export';
const DIAGNOSTICS_MANIFEST_TIMEOUT_MS = 15_000;
const DIAGNOSTICS_EXPORT_TIMEOUT_MS = 120_000;
const DIAGNOSTICS_FORMAT_VERSION = 1;
const DIAGNOSTIC_BYTE_BUDGET = 64 * 1_024 * 1_024;
const MAX_DIAGNOSTIC_SUMMARY_BYTES = 64 * 1_024;
const MAX_DIAGNOSTIC_APPLICATION_LOG_BYTES = 32 * 1_024 * 1_024;
const MAX_DIAGNOSTIC_FILE_NAME_BYTES = 128;
const SHA_256_HEX = /^[0-9a-f]{64}$/;
const SAFE_DIAGNOSTIC_FILE_NAME = /^[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?$/;
const CONTROL_OR_FORMAT_CHARACTER = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Cs}\p{Cn}]/u;
const CONTENT_KINDS = new Set<unknown>([
  'systemSummary',
  'applicationLogs',
  'databaseSummary',
] satisfies ReadonlyArray<DiagnosticContentKind>);
const CONTENT_PRIVACY = new Set<unknown>([
  'metadataOnly',
  'structuredRedacted',
  'aggregateOnly',
] satisfies ReadonlyArray<DiagnosticContentPrivacy>);
const MANIFEST_KEYS = [
  'formatVersion',
  'items',
  'selectedEstimatedBytes',
  'selectedMaximumBytes',
  'byteBudget',
] as const;
const MANIFEST_ITEM_KEYS = [
  'kind',
  'included',
  'available',
  'estimatedBytes',
  'maximumBytes',
  'privacy',
  'truncated',
] as const;
const EXPORT_REQUEST_KEYS = ['includeApplicationLogs', 'includeDatabaseSummary'] as const;
const EXPORT_RESULT_KEYS = ['fileName', 'totalBytes', 'sha256', 'manifest'] as const;
const REQUIRED_PRIVACY: Readonly<Record<DiagnosticContentKind, DiagnosticContentPrivacy>> = {
  systemSummary: 'metadataOnly',
  applicationLogs: 'structuredRedacted',
  databaseSummary: 'aggregateOnly',
};
const MAXIMUM_BYTES_BY_KIND: Readonly<Record<DiagnosticContentKind, number>> = {
  systemSummary: MAX_DIAGNOSTIC_SUMMARY_BYTES,
  applicationLogs: MAX_DIAGNOSTIC_APPLICATION_LOG_BYTES,
  databaseSummary: MAX_DIAGNOSTIC_SUMMARY_BYTES,
};
const utf8Encoder = new TextEncoder();

export async function getDiagnosticsManifest(): Promise<GetDiagnosticsManifestResponse> {
  const request: GetDiagnosticsManifestRequest = {};
  const response = await forwardSupervisorRpc<unknown>({
    requestId: createRpcId('diagnostics-manifest-request'),
    operationId: null,
    timeoutMs: DIAGNOSTICS_MANIFEST_TIMEOUT_MS,
    method: DIAGNOSTICS_MANIFEST_METHOD,
    params: request,
  });
  if (
    !isGetDiagnosticsManifestResponse(response) ||
    !manifestSelectionMatches(response, false, false)
  ) {
    throw new TypeError('invalid diagnostics manifest response');
  }
  return response;
}

/** Sends one export mutation. Callers decide whether the user should try again. */
export async function exportDiagnostics(
  request: ExportDiagnosticsRequest,
): Promise<ExportDiagnosticsResult> {
  if (!isExportDiagnosticsRequest(request)) {
    throw new TypeError('invalid diagnostics export request');
  }

  const response = await forwardSupervisorRpc<unknown>({
    requestId: createRpcId('diagnostics-export-request'),
    operationId: createRpcId('diagnostics-export-operation'),
    timeoutMs: DIAGNOSTICS_EXPORT_TIMEOUT_MS,
    method: DIAGNOSTICS_EXPORT_METHOD,
    params: request,
  });
  if (!isExportDiagnosticsResult(response, request)) {
    throw new TypeError('invalid diagnostics export response');
  }
  return response;
}

export function isGetDiagnosticsManifestResponse(
  value: unknown,
): value is GetDiagnosticsManifestResponse {
  if (!isObject(value) || !hasExactKeys(value, MANIFEST_KEYS)) {
    return false;
  }
  if (
    value.formatVersion !== DIAGNOSTICS_FORMAT_VERSION ||
    !Array.isArray(value.items) ||
    value.items.length !== 3 ||
    !isBoundedByteCount(value.selectedEstimatedBytes, DIAGNOSTIC_BYTE_BUDGET) ||
    !isBoundedByteCount(value.selectedMaximumBytes, DIAGNOSTIC_BYTE_BUDGET) ||
    value.byteBudget !== DIAGNOSTIC_BYTE_BUDGET ||
    value.selectedEstimatedBytes > value.selectedMaximumBytes ||
    value.selectedMaximumBytes > value.byteBudget
  ) {
    return false;
  }

  const kinds = new Set<DiagnosticContentKind>();
  let selectedEstimatedBytes = 0;
  let selectedMaximumBytes = 0;
  for (const item of value.items) {
    if (!isDiagnosticManifestItem(item) || kinds.has(item.kind)) {
      return false;
    }
    kinds.add(item.kind);
    if (item.included) {
      selectedEstimatedBytes += item.estimatedBytes;
      selectedMaximumBytes += item.maximumBytes;
    }
  }

  const systemSummary = value.items.find(
    (item): item is DiagnosticManifestItem =>
      isObject(item) && item.kind === 'systemSummary' && isDiagnosticManifestItem(item),
  );
  return (
    CONTENT_KINDS.size === kinds.size &&
    [...CONTENT_KINDS].every((kind) => kinds.has(kind as DiagnosticContentKind)) &&
    systemSummary?.included === true &&
    systemSummary.available &&
    selectedEstimatedBytes === value.selectedEstimatedBytes &&
    selectedMaximumBytes === value.selectedMaximumBytes
  );
}

function isDiagnosticManifestItem(value: unknown): value is DiagnosticManifestItem {
  if (
    !isObject(value) ||
    !hasExactKeys(value, MANIFEST_ITEM_KEYS) ||
    !CONTENT_KINDS.has(value.kind) ||
    typeof value.included !== 'boolean' ||
    typeof value.available !== 'boolean' ||
    !CONTENT_PRIVACY.has(value.privacy) ||
    typeof value.truncated !== 'boolean'
  ) {
    return false;
  }

  const kind = value.kind as DiagnosticContentKind;
  return (
    isBoundedByteCount(value.estimatedBytes, MAXIMUM_BYTES_BY_KIND[kind]) &&
    isBoundedByteCount(value.maximumBytes, MAXIMUM_BYTES_BY_KIND[kind]) &&
    value.estimatedBytes <= value.maximumBytes &&
    REQUIRED_PRIVACY[kind] === value.privacy &&
    (!value.truncated || kind === 'applicationLogs') &&
    (value.available ||
      (!value.included && value.estimatedBytes === 0 && value.truncated === false)) &&
    (!value.included || value.available)
  );
}

function isExportDiagnosticsRequest(value: unknown): value is ExportDiagnosticsRequest {
  return (
    isObject(value) &&
    hasExactKeys(value, EXPORT_REQUEST_KEYS) &&
    typeof value.includeApplicationLogs === 'boolean' &&
    typeof value.includeDatabaseSummary === 'boolean'
  );
}

function isExportDiagnosticsResult(
  value: unknown,
  request: ExportDiagnosticsRequest,
): value is ExportDiagnosticsResult {
  if (
    !isObject(value) ||
    !hasExactKeys(value, EXPORT_RESULT_KEYS) ||
    !isSafeDiagnosticFileName(value.fileName) ||
    !isPositiveBoundedByteCount(value.totalBytes, DIAGNOSTIC_BYTE_BUDGET) ||
    typeof value.sha256 !== 'string' ||
    !SHA_256_HEX.test(value.sha256) ||
    !isGetDiagnosticsManifestResponse(value.manifest) ||
    value.totalBytes > value.manifest.byteBudget
  ) {
    return false;
  }

  return manifestSelectionMatches(
    value.manifest,
    request.includeApplicationLogs,
    request.includeDatabaseSummary,
  );
}

function manifestSelectionMatches(
  manifest: GetDiagnosticsManifestResponse,
  includeApplicationLogs: boolean,
  includeDatabaseSummary: boolean,
): boolean {
  const included = new Map(manifest.items.map((item) => [item.kind, item.included] as const));
  return (
    included.get('systemSummary') === true &&
    included.get('applicationLogs') === includeApplicationLogs &&
    included.get('databaseSummary') === includeDatabaseSummary
  );
}

function isSafeDiagnosticFileName(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    value === value.trim() &&
    value !== '.' &&
    value !== '..' &&
    value.startsWith('magictools-diagnostics-') &&
    value.toLowerCase().endsWith('.json') &&
    SAFE_DIAGNOSTIC_FILE_NAME.test(value) &&
    !value.includes('/') &&
    !value.includes('\\') &&
    !value.includes(':') &&
    !CONTROL_OR_FORMAT_CHARACTER.test(value) &&
    utf8Encoder.encode(value).length <= MAX_DIAGNOSTIC_FILE_NAME_BYTES
  );
}

function isBoundedByteCount(value: unknown, maximum: number): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && value <= maximum;
}

function isPositiveBoundedByteCount(value: unknown, maximum: number): value is number {
  return isBoundedByteCount(value, maximum) && value > 0;
}

function createRpcId(prefix: string): string {
  return `${prefix}:${globalThis.crypto.randomUUID()}`;
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
