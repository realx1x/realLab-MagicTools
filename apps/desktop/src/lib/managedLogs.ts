import type {
  GetManagedLogRangeRequest,
  GetManagedLogRangeResponse,
  ManagedLogBatch,
  ManagedLogChunk,
  ManagedLogEncoding,
  ManagedLogIoErrorKind,
  ManagedLogStream,
  ManagedLogTextStatus,
} from '@dpm/generated-types';

const MAX_MANAGED_RUN_ID_BYTES = 256;
const MAX_MANAGED_LOG_CHUNK_BYTES = 65_536;
const MAX_MANAGED_LOG_BATCH_CHUNKS = 2;
const MAX_MANAGED_LOG_BATCH_BYTES = 131_072;
const MIN_MANAGED_LOG_RANGE_BYTES = 4;
const MAX_MANAGED_LOG_RANGE_BYTES = 65_536;

const MANAGED_LOG_CHUNK_KEYS = [
  'runId',
  'stream',
  'sequence',
  'firstAvailableByteOffset',
  'firstByteOffset',
  'nextByteOffset',
  'streamEndByteOffset',
  'text',
  'hasMore',
  'caughtUp',
  'endOfFile',
  'ioStatusKnown',
  'diskError',
  'readError',
  'deliveryError',
  'textStatus',
] as const;

const MANAGED_LOG_BATCH_KEYS = ['chunks'] as const;

const MANAGED_LOG_RANGE_REQUEST_KEYS = [
  'runId',
  'stream',
  'startingByteOffset',
  'maximumBytes',
] as const;

const MANAGED_LOG_RANGE_RESPONSE_KEYS = [
  'runId',
  'stream',
  'observedSequence',
  'firstAvailableByteOffset',
  'firstByteOffset',
  'nextByteOffset',
  'streamEndByteOffset',
  'text',
  'hasMore',
  'complete',
  'endOfFile',
  'ioStatusKnown',
  'diskError',
  'readError',
  'textStatus',
] as const;

const MANAGED_LOG_KNOWN_TEXT_STATUS_KEYS = [
  'encoding',
  'replacementUsed',
  'controlsFiltered',
  'fallbackUnavailable',
] as const;

const MANAGED_LOG_WINDOWS_CODE_PAGE_KEYS = ['codePage'] as const;

const MANAGED_LOG_IO_ERROR_KINDS = new Set<unknown>([
  'invalidConfiguration',
  'invalidPath',
  'notFound',
  'permissionDenied',
  'alreadyExists',
  'resourceBusy',
  'storageFull',
  'interrupted',
  'unexpectedEof',
  'invalidData',
  'limitExceeded',
  'writeZero',
  'unavailable',
  'otherIo',
] satisfies ReadonlyArray<ManagedLogIoErrorKind>);

const CONTROL_CHARACTER_PATTERN = /\p{Cc}/u;
const NON_PRINTING_UNICODE_PATTERN = /[\p{Cc}\p{Cf}\p{Cn}\p{Cs}\p{Zl}\p{Zp}]/u;
const UTF8_ENCODER = new TextEncoder();

export function isManagedLogChunk(value: unknown): value is ManagedLogChunk {
  if (!isObject(value) || !hasExactKeys(value, MANAGED_LOG_CHUNK_KEYS)) {
    return false;
  }

  const {
    runId,
    stream,
    sequence,
    firstAvailableByteOffset,
    firstByteOffset,
    nextByteOffset,
    streamEndByteOffset,
    text,
    hasMore,
    caughtUp,
    endOfFile,
    ioStatusKnown,
    diskError,
    readError,
    deliveryError,
    textStatus,
  } = value;

  if (
    !isManagedLogRunId(runId) ||
    !isManagedLogStream(stream) ||
    !isPositiveSafeInteger(sequence) ||
    !isNonNegativeSafeInteger(firstAvailableByteOffset) ||
    !isNonNegativeSafeInteger(firstByteOffset) ||
    !isNonNegativeSafeInteger(nextByteOffset) ||
    !isNonNegativeSafeInteger(streamEndByteOffset) ||
    typeof hasMore !== 'boolean' ||
    typeof caughtUp !== 'boolean' ||
    typeof endOfFile !== 'boolean' ||
    typeof ioStatusKnown !== 'boolean' ||
    !isNullableManagedLogIoErrorKind(diskError) ||
    !isNullableManagedLogIoErrorKind(readError) ||
    !isNullableManagedLogIoErrorKind(deliveryError) ||
    !isManagedLogTextStatus(textStatus)
  ) {
    return false;
  }

  const textByteLength = managedLogUtf8ByteLength(text, MAX_MANAGED_LOG_CHUNK_BYTES);

  if (
    firstAvailableByteOffset > firstByteOffset ||
    firstByteOffset > nextByteOffset ||
    nextByteOffset > streamEndByteOffset ||
    textByteLength === null ||
    textByteLength !== nextByteOffset - firstByteOffset
  ) {
    return false;
  }

  return (
    hasMore === nextByteOffset < streamEndByteOffset &&
    !(caughtUp && hasMore) &&
    !(deliveryError !== null && caughtUp) &&
    !(!ioStatusKnown && (diskError !== null || readError !== null))
  );
}

export function isManagedLogBatch(value: unknown): value is ManagedLogBatch {
  if (!isObject(value) || !hasExactKeys(value, MANAGED_LOG_BATCH_KEYS)) {
    return false;
  }
  const { chunks } = value;
  if (
    !Array.isArray(chunks) ||
    chunks.length === 0 ||
    chunks.length > MAX_MANAGED_LOG_BATCH_CHUNKS
  ) {
    return false;
  }

  let runId: string | null = null;
  let totalBytes = 0;
  const streams = new Set<ManagedLogStream>();
  for (const chunk of chunks) {
    if (!isManagedLogChunk(chunk)) {
      return false;
    }
    if (runId !== null && chunk.runId !== runId) {
      return false;
    }
    if (streams.has(chunk.stream)) {
      return false;
    }
    runId = chunk.runId;
    streams.add(chunk.stream);
    totalBytes += UTF8_ENCODER.encode(chunk.text).length;
  }

  return totalBytes <= MAX_MANAGED_LOG_BATCH_BYTES;
}

export function isGetManagedLogRangeRequest(value: unknown): value is GetManagedLogRangeRequest {
  if (!isObject(value) || !hasExactKeys(value, MANAGED_LOG_RANGE_REQUEST_KEYS)) {
    return false;
  }
  return (
    isManagedLogRunId(value.runId) &&
    isManagedLogStream(value.stream) &&
    (value.startingByteOffset === null || isNonNegativeSafeInteger(value.startingByteOffset)) &&
    isPositiveSafeInteger(value.maximumBytes) &&
    value.maximumBytes >= MIN_MANAGED_LOG_RANGE_BYTES &&
    value.maximumBytes <= MAX_MANAGED_LOG_RANGE_BYTES
  );
}

export function isGetManagedLogRangeResponse(value: unknown): value is GetManagedLogRangeResponse {
  if (!isObject(value) || !hasExactKeys(value, MANAGED_LOG_RANGE_RESPONSE_KEYS)) {
    return false;
  }

  const {
    runId,
    stream,
    observedSequence,
    firstAvailableByteOffset,
    firstByteOffset,
    nextByteOffset,
    streamEndByteOffset,
    text,
    hasMore,
    complete,
    endOfFile,
    ioStatusKnown,
    diskError,
    readError,
    textStatus,
  } = value;

  if (
    !isManagedLogRunId(runId) ||
    !isManagedLogStream(stream) ||
    !isNonNegativeSafeInteger(observedSequence) ||
    !isNonNegativeSafeInteger(firstAvailableByteOffset) ||
    !isNonNegativeSafeInteger(firstByteOffset) ||
    !isNonNegativeSafeInteger(nextByteOffset) ||
    !isNonNegativeSafeInteger(streamEndByteOffset) ||
    typeof hasMore !== 'boolean' ||
    typeof complete !== 'boolean' ||
    typeof endOfFile !== 'boolean' ||
    typeof ioStatusKnown !== 'boolean' ||
    !isNullableManagedLogIoErrorKind(diskError) ||
    !isNullableManagedLogIoErrorKind(readError) ||
    !isManagedLogTextStatus(textStatus)
  ) {
    return false;
  }

  const textByteLength = managedLogUtf8ByteLength(text, MAX_MANAGED_LOG_RANGE_BYTES);

  if (
    firstAvailableByteOffset > firstByteOffset ||
    firstByteOffset > nextByteOffset ||
    nextByteOffset > streamEndByteOffset ||
    textByteLength === null ||
    textByteLength !== nextByteOffset - firstByteOffset
  ) {
    return false;
  }

  return (
    hasMore === nextByteOffset < streamEndByteOffset &&
    !(complete && hasMore) &&
    !(!ioStatusKnown && (diskError !== null || readError !== null))
  );
}

function isManagedLogRunId(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    UTF8_ENCODER.encode(value).length <= MAX_MANAGED_RUN_ID_BYTES &&
    !CONTROL_CHARACTER_PATTERN.test(value)
  );
}

function isManagedLogStream(value: unknown): value is ManagedLogStream {
  return value === 'stdout' || value === 'stderr';
}

function isNullableManagedLogIoErrorKind(value: unknown): value is ManagedLogIoErrorKind | null {
  return value === null || MANAGED_LOG_IO_ERROR_KINDS.has(value);
}

function isManagedLogTextStatus(value: unknown): value is ManagedLogTextStatus {
  if (value === 'unknown') {
    return true;
  }
  if (!isObject(value) || !hasExactKeys(value, ['known'])) {
    return false;
  }

  const known = value.known;
  if (!isObject(known) || !hasExactKeys(known, MANAGED_LOG_KNOWN_TEXT_STATUS_KEYS)) {
    return false;
  }
  const { encoding, replacementUsed, controlsFiltered, fallbackUnavailable } = known;
  return (
    isManagedLogEncoding(encoding) &&
    typeof replacementUsed === 'boolean' &&
    typeof controlsFiltered === 'boolean' &&
    typeof fallbackUnavailable === 'boolean' &&
    !(fallbackUnavailable && (encoding !== 'utf8' || !replacementUsed))
  );
}

function isManagedLogEncoding(value: unknown): value is ManagedLogEncoding {
  if (value === 'utf8' || value === 'utf16Le' || value === 'utf16Be') {
    return true;
  }
  if (!isObject(value) || !hasExactKeys(value, ['windowsCodePage'])) {
    return false;
  }

  const windowsCodePage = value.windowsCodePage;
  return (
    isObject(windowsCodePage) &&
    hasExactKeys(windowsCodePage, MANAGED_LOG_WINDOWS_CODE_PAGE_KEYS) &&
    isPositiveSafeInteger(windowsCodePage.codePage) &&
    windowsCodePage.codePage <= 65_535
  );
}

function managedLogUtf8ByteLength(value: unknown, maximumBytes: number): number | null {
  if (typeof value !== 'string') {
    return null;
  }
  for (const character of value) {
    if (character !== '\n' && character !== '\t' && NON_PRINTING_UNICODE_PATTERN.test(character)) {
      return null;
    }
  }

  const byteLength = UTF8_ENCODER.encode(value).length;
  return byteLength <= maximumBytes ? byteLength : null;
}

function isPositiveSafeInteger(value: unknown): value is number {
  return isNonNegativeSafeInteger(value) && value > 0;
}

function isNonNegativeSafeInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
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
