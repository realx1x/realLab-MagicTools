import type {
  GetManagedLogRangeResponse,
  ManagedLogChunk,
  ManagedLogIoErrorKind,
  ManagedLogStream,
  ManagedLogTextStatus,
} from '@dpm/generated-types';

export const MANAGED_LOG_STREAMS = [
  'stdout',
  'stderr',
] as const satisfies ReadonlyArray<ManagedLogStream>;
export const MANAGED_LOG_RANGE_BYTES = 65_536;
export const MANAGED_LOG_BUFFER_BYTES = 512 * 1_024;
export const MANAGED_LOG_FRAGMENT_LIMIT = 1_024;

interface ManagedLogFragment {
  readonly firstByteOffset: number;
  readonly nextByteOffset: number;
  readonly text: string;
}

export interface ManagedLogOmissionState {
  readonly backendRetentionOrRotation: boolean;
  readonly beforeByteOffset: number;
  readonly localClear: boolean;
  readonly localMemoryLimit: boolean;
}

export interface ManagedLogStreamSnapshot {
  readonly catchingUp: boolean;
  readonly complete: boolean;
  readonly deliveryError: ManagedLogIoErrorKind | null;
  readonly diskError: ManagedLogIoErrorKind | null;
  readonly endOfFile: boolean;
  readonly firstAvailableByteOffset: number;
  readonly firstByteOffset: number;
  readonly ioStatusKnown: boolean;
  readonly latestByteOffset: number;
  readonly loading: boolean;
  readonly nextByteOffset: number;
  readonly omission: ManagedLogOmissionState;
  readonly rangeError: boolean;
  readonly readError: ManagedLogIoErrorKind | null;
  readonly stream: ManagedLogStream;
  readonly textStatus: ManagedLogTextStatus;
  readonly visibleText: string;
}

export interface ManagedLogRangePlan {
  readonly reconciliationVersion: number;
  readonly startingByteOffset: number | null;
}

export interface ManagedLogApplyResult {
  readonly addedByteCount: number;
  readonly model: ManagedLogStreamModel;
}

export interface ManagedLogStreamModel {
  readonly backendOmission: boolean;
  readonly clearBeforeByteOffset: number;
  readonly deliveryError: ManagedLogIoErrorKind | null;
  readonly diskError: ManagedLogIoErrorKind | null;
  readonly endOfFile: boolean;
  readonly firstAvailableByteOffset: number;
  readonly fragments: ReadonlyArray<ManagedLogFragment>;
  readonly highestEventSequence: number | null;
  readonly highestObservedSequence: number;
  readonly initialRangeComplete: boolean;
  readonly ioStatusKnown: boolean;
  readonly localClear: boolean;
  readonly localMemoryLimit: boolean;
  readonly memoryBeforeByteOffset: number;
  readonly rangeBlocked: boolean;
  readonly rangeError: boolean;
  readonly rangeLoading: boolean;
  readonly readError: ManagedLogIoErrorKind | null;
  readonly reconciliationRequired: boolean;
  readonly reconciliationVersion: number;
  readonly stream: ManagedLogStream;
  readonly streamEndByteOffset: number;
  readonly textStatus: ManagedLogTextStatus;
}

const UTF8_ENCODER = new TextEncoder();
const UTF8_DECODER = new TextDecoder('utf-8', { fatal: true });

export function createManagedLogStreamModel(stream: ManagedLogStream): ManagedLogStreamModel {
  return {
    backendOmission: false,
    clearBeforeByteOffset: 0,
    deliveryError: null,
    diskError: null,
    endOfFile: false,
    firstAvailableByteOffset: 0,
    fragments: [],
    highestEventSequence: null,
    highestObservedSequence: 0,
    initialRangeComplete: false,
    ioStatusKnown: false,
    localClear: false,
    localMemoryLimit: false,
    memoryBeforeByteOffset: 0,
    rangeBlocked: false,
    rangeError: false,
    rangeLoading: false,
    readError: null,
    reconciliationRequired: false,
    reconciliationVersion: 0,
    stream,
    streamEndByteOffset: 0,
    textStatus: 'unknown',
  };
}

export function applyManagedLogChunk(
  current: ManagedLogStreamModel,
  chunk: ManagedLogChunk,
): ManagedLogApplyResult {
  if (chunk.stream !== current.stream) {
    return { addedByteCount: 0, model: current };
  }

  const previousSequence =
    current.highestEventSequence ??
    (current.initialRangeComplete ? current.highestObservedSequence : null);
  const sequenceAnomaly = previousSequence !== null && chunk.sequence !== previousSequence + 1;
  const deliveryAnomaly = chunk.deliveryError !== null || !chunk.caughtUp;
  const reconciliationRequired =
    current.reconciliationRequired || sequenceAnomaly || deliveryAnomaly;
  const reconciliationVersion =
    sequenceAnomaly || deliveryAnomaly
      ? current.reconciliationVersion + 1
      : current.reconciliationVersion;
  const prepared = prepareForObservedWindow(
    {
      ...current,
      deliveryError: chunk.deliveryError ?? current.deliveryError,
      diskError: chunk.diskError ?? current.diskError,
      endOfFile: current.endOfFile || chunk.endOfFile,
      highestEventSequence:
        current.highestEventSequence === null
          ? chunk.sequence
          : Math.max(current.highestEventSequence, chunk.sequence),
      highestObservedSequence: Math.max(current.highestObservedSequence, chunk.sequence),
      ioStatusKnown: current.ioStatusKnown || chunk.ioStatusKnown,
      readError: chunk.readError ?? current.readError,
      reconciliationRequired,
      reconciliationVersion,
      streamEndByteOffset: Math.max(current.streamEndByteOffset, chunk.streamEndByteOffset),
      textStatus: preferKnownTextStatus(current.textStatus, chunk.textStatus),
    },
    chunk.firstAvailableByteOffset,
  );
  return insertObservedText(prepared, chunk.firstByteOffset, chunk.nextByteOffset, chunk.text);
}

export function applyManagedLogRange(
  current: ManagedLogStreamModel,
  response: GetManagedLogRangeResponse,
  plan: ManagedLogRangePlan,
): ManagedLogApplyResult {
  if (response.stream !== current.stream) {
    return { addedByteCount: 0, model: current };
  }

  const skippedRequestedBytes =
    plan.startingByteOffset !== null && response.firstByteOffset > plan.startingByteOffset;
  const prepared = prepareForObservedWindow(
    {
      ...current,
      backendOmission: current.backendOmission || skippedRequestedBytes,
      diskError: response.diskError ?? current.diskError,
      endOfFile: current.endOfFile || response.endOfFile,
      highestObservedSequence: Math.max(current.highestObservedSequence, response.observedSequence),
      initialRangeComplete: current.initialRangeComplete || plan.startingByteOffset === null,
      ioStatusKnown: current.ioStatusKnown || response.ioStatusKnown,
      rangeBlocked: false,
      rangeError: false,
      rangeLoading: false,
      readError: response.readError ?? current.readError,
      reconciliationRequired:
        current.reconciliationVersion === plan.reconciliationVersion
          ? false
          : current.reconciliationRequired,
      streamEndByteOffset: Math.max(current.streamEndByteOffset, response.streamEndByteOffset),
      textStatus: preferKnownTextStatus(current.textStatus, response.textStatus),
    },
    response.firstAvailableByteOffset,
  );
  return insertObservedText(
    prepared,
    response.firstByteOffset,
    response.nextByteOffset,
    response.text,
  );
}

export function beginManagedLogRange(current: ManagedLogStreamModel): ManagedLogStreamModel {
  return {
    ...current,
    rangeBlocked: false,
    rangeError: false,
    rangeLoading: true,
  };
}

export function failManagedLogRange(current: ManagedLogStreamModel): ManagedLogStreamModel {
  return {
    ...current,
    rangeBlocked: true,
    rangeError: true,
    rangeLoading: false,
  };
}

export function retryManagedLogRange(current: ManagedLogStreamModel): ManagedLogStreamModel {
  return {
    ...current,
    rangeBlocked: false,
    rangeError: false,
  };
}

export function clearManagedLogStream(current: ManagedLogStreamModel): ManagedLogStreamModel {
  const cutoff = Math.max(
    current.clearBeforeByteOffset,
    current.streamEndByteOffset,
    contiguousEnd(current),
  );
  return {
    ...current,
    clearBeforeByteOffset: cutoff,
    fragments: clipFragments(current.fragments, cutoff),
    localClear: true,
  };
}

export function getManagedLogRangePlan(model: ManagedLogStreamModel): ManagedLogRangePlan | null {
  if (model.rangeLoading || model.rangeBlocked) {
    return null;
  }
  if (!model.initialRangeComplete) {
    return {
      reconciliationVersion: model.reconciliationVersion,
      startingByteOffset: null,
    };
  }

  const nextOffset = contiguousEnd(model);
  if (nextOffset < model.streamEndByteOffset || model.reconciliationRequired) {
    return {
      reconciliationVersion: model.reconciliationVersion,
      startingByteOffset: nextOffset,
    };
  }
  return null;
}

export function snapshotManagedLogStream(model: ManagedLogStreamModel): ManagedLogStreamSnapshot {
  const firstByteOffset = effectiveFloor(model);
  const visible = visibleContiguousText(model, firstByteOffset);
  const nextByteOffset = firstByteOffset + visible.byteLength;
  const needsCatchUp =
    model.initialRangeComplete &&
    (nextByteOffset < model.streamEndByteOffset || model.reconciliationRequired);
  return {
    catchingUp:
      !model.rangeError && (needsCatchUp || (model.initialRangeComplete && model.rangeLoading)),
    complete:
      model.initialRangeComplete && !model.rangeLoading && !model.rangeError && !needsCatchUp,
    deliveryError: model.deliveryError,
    diskError: model.diskError,
    endOfFile: model.endOfFile,
    firstAvailableByteOffset: model.firstAvailableByteOffset,
    firstByteOffset,
    ioStatusKnown: model.ioStatusKnown,
    latestByteOffset: model.streamEndByteOffset,
    loading: (!model.initialRangeComplete && !model.rangeError) || model.rangeLoading,
    nextByteOffset,
    omission: {
      backendRetentionOrRotation: model.backendOmission,
      beforeByteOffset: firstByteOffset,
      localClear: model.localClear,
      localMemoryLimit: model.localMemoryLimit,
    },
    rangeError: model.rangeError,
    readError: model.readError,
    stream: model.stream,
    textStatus: model.textStatus,
    visibleText: visible.text,
  };
}

function prepareForObservedWindow(
  current: ManagedLogStreamModel,
  observedFirstAvailableByteOffset: number,
): ManagedLogStreamModel {
  const firstAvailableByteOffset = Math.max(
    current.firstAvailableByteOffset,
    observedFirstAvailableByteOffset,
  );
  const backendOmission = current.backendOmission || firstAvailableByteOffset > 0;
  const floor = Math.max(
    firstAvailableByteOffset,
    current.clearBeforeByteOffset,
    current.memoryBeforeByteOffset,
  );
  return {
    ...current,
    backendOmission,
    firstAvailableByteOffset,
    fragments: clipFragments(current.fragments, floor),
  };
}

function insertObservedText(
  current: ManagedLogStreamModel,
  firstByteOffset: number,
  nextByteOffset: number,
  text: string,
): ManagedLogApplyResult {
  const floor = effectiveFloor(current);
  if (nextByteOffset <= floor || nextByteOffset <= firstByteOffset) {
    return { addedByteCount: 0, model: current };
  }

  const clippedStart = Math.max(firstByteOffset, floor);
  const clippedText = sliceUtf8(
    text,
    clippedStart - firstByteOffset,
    nextByteOffset - firstByteOffset,
  );
  const inserted = insertFragment(current.fragments, {
    firstByteOffset: clippedStart,
    nextByteOffset,
    text: clippedText,
  });
  const bounded = enforceMemoryLimit({ ...current, fragments: inserted.fragments });
  return { addedByteCount: inserted.addedByteCount, model: bounded };
}

function insertFragment(
  existing: ReadonlyArray<ManagedLogFragment>,
  incoming: ManagedLogFragment,
): { readonly addedByteCount: number; readonly fragments: ReadonlyArray<ManagedLogFragment> } {
  const additions: ManagedLogFragment[] = [];
  let cursor = incoming.firstByteOffset;
  for (const fragment of existing) {
    if (fragment.nextByteOffset <= cursor) {
      continue;
    }
    if (fragment.firstByteOffset >= incoming.nextByteOffset) {
      break;
    }
    if (fragment.firstByteOffset > cursor) {
      const additionEnd = Math.min(fragment.firstByteOffset, incoming.nextByteOffset);
      additions.push(sliceFragment(incoming, cursor, additionEnd));
    }
    cursor = Math.max(cursor, fragment.nextByteOffset);
    if (cursor >= incoming.nextByteOffset) {
      break;
    }
  }
  if (cursor < incoming.nextByteOffset) {
    additions.push(sliceFragment(incoming, cursor, incoming.nextByteOffset));
  }
  if (additions.length === 0) {
    return { addedByteCount: 0, fragments: existing };
  }

  const fragments = [...existing, ...additions].sort(
    (left, right) => left.firstByteOffset - right.firstByteOffset,
  );
  return {
    addedByteCount: additions.reduce(
      (total, fragment) => total + fragment.nextByteOffset - fragment.firstByteOffset,
      0,
    ),
    fragments: coalesceFragments(fragments),
  };
}

function coalesceFragments(
  fragments: ReadonlyArray<ManagedLogFragment>,
): ReadonlyArray<ManagedLogFragment> {
  const result: ManagedLogFragment[] = [];
  for (const fragment of fragments) {
    const previous = result.at(-1);
    if (previous && previous.nextByteOffset === fragment.firstByteOffset) {
      result[result.length - 1] = {
        firstByteOffset: previous.firstByteOffset,
        nextByteOffset: fragment.nextByteOffset,
        text: previous.text + fragment.text,
      };
    } else {
      result.push(fragment);
    }
  }
  return result;
}

function enforceMemoryLimit(current: ManagedLogStreamModel): ManagedLogStreamModel {
  let excessBytes = totalFragmentBytes(current.fragments) - MANAGED_LOG_BUFFER_BYTES;
  let excessFragments = current.fragments.length - MANAGED_LOG_FRAGMENT_LIMIT;
  if (excessBytes <= 0 && excessFragments <= 0) {
    return current;
  }

  const retained: ManagedLogFragment[] = [];
  let memoryBeforeByteOffset = current.memoryBeforeByteOffset;
  for (const fragment of current.fragments) {
    const byteLength = fragment.nextByteOffset - fragment.firstByteOffset;
    if (excessFragments > 0) {
      excessFragments -= 1;
      excessBytes = Math.max(0, excessBytes - byteLength);
      memoryBeforeByteOffset = fragment.nextByteOffset;
      continue;
    }
    if (excessBytes >= byteLength) {
      excessBytes -= byteLength;
      memoryBeforeByteOffset = fragment.nextByteOffset;
      continue;
    }
    if (excessBytes > 0) {
      const bytes = UTF8_ENCODER.encode(fragment.text);
      const boundary = utf8BoundaryAtOrAfter(bytes, excessBytes);
      const firstByteOffset = fragment.firstByteOffset + boundary;
      retained.push({
        firstByteOffset,
        nextByteOffset: fragment.nextByteOffset,
        text: UTF8_DECODER.decode(bytes.subarray(boundary)),
      });
      memoryBeforeByteOffset = firstByteOffset;
      excessBytes = 0;
    } else {
      retained.push(fragment);
    }
  }
  return {
    ...current,
    fragments: retained,
    localMemoryLimit: true,
    memoryBeforeByteOffset,
  };
}

function clipFragments(
  fragments: ReadonlyArray<ManagedLogFragment>,
  floor: number,
): ReadonlyArray<ManagedLogFragment> {
  const clipped: ManagedLogFragment[] = [];
  for (const fragment of fragments) {
    if (fragment.nextByteOffset <= floor) {
      continue;
    }
    clipped.push(
      fragment.firstByteOffset < floor
        ? sliceFragment(fragment, floor, fragment.nextByteOffset)
        : fragment,
    );
  }
  return clipped;
}

function visibleContiguousText(
  model: ManagedLogStreamModel,
  firstByteOffset: number,
): { readonly byteLength: number; readonly text: string } {
  if (!model.initialRangeComplete) {
    return { byteLength: 0, text: '' };
  }
  let cursor = firstByteOffset;
  let text = '';
  for (const fragment of model.fragments) {
    if (fragment.nextByteOffset <= cursor) {
      continue;
    }
    if (fragment.firstByteOffset !== cursor) {
      break;
    }
    text += fragment.text;
    cursor = fragment.nextByteOffset;
  }
  return { byteLength: cursor - firstByteOffset, text };
}

function contiguousEnd(model: ManagedLogStreamModel): number {
  const floor = effectiveFloor(model);
  if (!model.initialRangeComplete) {
    return floor;
  }
  let cursor = floor;
  for (const fragment of model.fragments) {
    if (fragment.nextByteOffset <= cursor) {
      continue;
    }
    if (fragment.firstByteOffset !== cursor) {
      break;
    }
    cursor = fragment.nextByteOffset;
  }
  return cursor;
}

function effectiveFloor(model: ManagedLogStreamModel): number {
  return Math.max(
    model.firstAvailableByteOffset,
    model.clearBeforeByteOffset,
    model.memoryBeforeByteOffset,
  );
}

function totalFragmentBytes(fragments: ReadonlyArray<ManagedLogFragment>): number {
  return fragments.reduce(
    (total, fragment) => total + fragment.nextByteOffset - fragment.firstByteOffset,
    0,
  );
}

function sliceFragment(
  fragment: ManagedLogFragment,
  firstByteOffset: number,
  nextByteOffset: number,
): ManagedLogFragment {
  return {
    firstByteOffset,
    nextByteOffset,
    text: sliceUtf8(
      fragment.text,
      firstByteOffset - fragment.firstByteOffset,
      nextByteOffset - fragment.firstByteOffset,
    ),
  };
}

function sliceUtf8(text: string, firstByte: number, nextByte: number): string {
  const bytes = UTF8_ENCODER.encode(text);
  return UTF8_DECODER.decode(bytes.subarray(firstByte, nextByte));
}

function utf8BoundaryAtOrAfter(bytes: Uint8Array, requestedByte: number): number {
  let boundary = Math.min(requestedByte, bytes.length);
  while (boundary < bytes.length && (bytes[boundary]! & 0xc0) === 0x80) {
    boundary += 1;
  }
  return boundary;
}

function preferKnownTextStatus(
  current: ManagedLogTextStatus,
  observed: ManagedLogTextStatus,
): ManagedLogTextStatus {
  return observed === 'unknown' ? current : observed;
}
