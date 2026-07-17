import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import type { UnlistenFn } from '@tauri-apps/api/event';
import type {
  GetManagedLogRangeRequest,
  GetManagedLogRangeResponse,
  GetSnapshotRequest,
  ManagedLogBatch,
  PortBinding,
  PortBindingKey,
  PortDelta,
  ProcessDelta,
  ProcessInstanceKey,
  ProcessRecord,
  SystemSnapshot,
} from '@dpm/generated-types';
import {
  isGetManagedLogRangeRequest,
  isGetManagedLogRangeResponse,
  isManagedLogBatch,
} from './managedLogs';
import { isStrictPortBinding, isStrictProcessRecord } from './processSnapshotValidation';

export {
  isGetManagedLogRangeRequest,
  isGetManagedLogRangeResponse,
  isManagedLogBatch,
  isManagedLogChunk,
} from './managedLogs';

export type { AppError } from '@dpm/generated-types';

export type DisconnectReason =
  | { kind: 'endpointUnavailable' }
  | { kind: 'pipeBusy' }
  | { kind: 'peerClosed' }
  | { kind: 'handshakeTimeout' }
  | { kind: 'authenticationFailed' }
  | { kind: 'protocolViolation' }
  | { kind: 'transport'; rawOsError: number | null };

export type SupervisorConnectionState =
  | { kind: 'disconnected'; reason: DisconnectReason | null }
  | { kind: 'connecting'; attempt: number }
  | { kind: 'authenticating' }
  | { kind: 'connected'; version: number; generation: number }
  | { kind: 'backoff'; attempt: number; retryAfterMs: number }
  | { kind: 'incompatibleVersion' }
  | { kind: 'accessDenied' }
  | { kind: 'shuttingDown' };

export interface SupervisorRpcRequest {
  requestId: string;
  operationId: string | null;
  timeoutMs: number;
  method: string;
  params: unknown;
}

export interface SupervisorCancelRequest {
  requestId: string;
  targetRequestId: string;
}

export type CancelDisposition = 'accepted' | 'notFound' | 'alreadyCompleted';

export interface CancelResult {
  targetRequestId: string;
  disposition: CancelDisposition;
}

export interface SupervisorEvent<T = unknown> {
  generation: number;
  revision: number;
  event: string;
  payload: T;
}

export type SupervisorLogChunkEvent = SupervisorEvent<ManagedLogBatch> & {
  event: 'log.chunk';
};

export interface SupervisorSnapshotState {
  connectionState: SupervisorConnectionState;
  generation: number | null;
  revision: number;
  synchronized: boolean;
  processes: ReadonlyArray<ProcessRecord>;
  portBindings: ReadonlyArray<PortBinding>;
}

export interface SupervisorSnapshotStore {
  subscribe(listener: () => void): () => void;
  getSnapshot(): SupervisorSnapshotState;
  dispose(): void;
}

export const SUPERVISOR_EVENT_BUFFER_CAPACITY = 1_024;
export const SUPERVISOR_EVENT_BUFFER_BYTES = 8 * 1_024 * 1_024;

const SNAPSHOT_METHOD = 'system.get_snapshot';
const SNAPSHOT_TIMEOUT_MS = 15_000;
const SNAPSHOT_RETRY_DELAY_MS = 500;
const SNAPSHOT_MAX_RETRY_DELAY_MS = 10_000;
const MAX_SNAPSHOT_CURSOR_BYTES = 128;
const MAX_SNAPSHOT_CHUNK_ENTITIES = 1_024;
const MAX_SNAPSHOT_CHUNK_PAYLOAD_BYTES = 768 * 1_024;
const MAX_SNAPSHOT_PROCESSES = 16_384;
const MAX_SNAPSHOT_PORT_BINDINGS = 65_536;
const MAX_SNAPSHOT_TOTAL_ENTITY_BYTES = 128 * 1_024 * 1_024;
const MAX_REVISION_DELTA_ENTITIES = 128;
const MAX_REVISION_DELTA_PAYLOAD_BYTES = 512 * 1_024;
const MANAGED_LOG_CHUNK_EVENT = 'log.chunk';
const MANAGED_LOG_RANGE_METHOD = 'run.get_log_range';
const MANAGED_LOG_RANGE_TIMEOUT_MS = 15_000;
const MAX_SAFE_REVISION = Number.MAX_SAFE_INTEGER;
const utf8Encoder = new TextEncoder();

export function getSupervisorConnectionState(): Promise<SupervisorConnectionState> {
  return invoke<SupervisorConnectionState>('supervisor_connection_state');
}

export function forwardSupervisorRpc<T = unknown>(request: SupervisorRpcRequest): Promise<T> {
  return invoke<T>('supervisor_forward_rpc', { request });
}

export function cancelSupervisorRequest(request: SupervisorCancelRequest): Promise<CancelResult> {
  return invoke<CancelResult>('supervisor_cancel_request', { request });
}

export function resetSupervisorConnection(): Promise<void> {
  return invoke<void>('supervisor_reset_connection');
}

export function onSupervisorConnectionState(
  handler: (state: SupervisorConnectionState) => void,
): Promise<UnlistenFn> {
  return listen<SupervisorConnectionState>('supervisor://connection-state', (event) => {
    handler(event.payload);
  });
}

export function onSupervisorEvent<T = unknown>(
  handler: (event: SupervisorEvent<T>) => void,
): Promise<UnlistenFn> {
  return listen<SupervisorEvent<T>>('supervisor://event', (event) => {
    handler(event.payload);
  });
}

export function isSupervisorLogChunkEvent(value: unknown): value is SupervisorLogChunkEvent {
  return (
    isObject(value) &&
    typeof value.generation === 'number' &&
    isEventRevision(value.generation) &&
    typeof value.revision === 'number' &&
    isEventRevision(value.revision) &&
    value.event === MANAGED_LOG_CHUNK_EVENT &&
    isManagedLogBatch(value.payload)
  );
}

export function onSupervisorLogChunk(
  handler: (event: SupervisorLogChunkEvent) => void,
): Promise<UnlistenFn> {
  return onSupervisorEvent((event) => {
    if (isSupervisorLogChunkEvent(event)) {
      handler(event);
    }
  });
}

export async function getManagedLogRange(
  request: GetManagedLogRangeRequest,
): Promise<GetManagedLogRangeResponse> {
  if (!isGetManagedLogRangeRequest(request)) {
    throw new TypeError('invalid managed log range request');
  }

  const response = await forwardSupervisorRpc<unknown>({
    requestId: `log-range:${globalThis.crypto.randomUUID()}`,
    operationId: null,
    timeoutMs: MANAGED_LOG_RANGE_TIMEOUT_MS,
    method: MANAGED_LOG_RANGE_METHOD,
    params: request,
  });
  if (
    !isGetManagedLogRangeResponse(response) ||
    response.runId !== request.runId ||
    response.stream !== request.stream ||
    utf8Encoder.encode(response.text).length > request.maximumBytes
  ) {
    throw new TypeError('invalid managed log range response');
  }
  return response;
}

export async function createSupervisorSnapshotStore(): Promise<SupervisorSnapshotStore> {
  const store = new SupervisorSnapshotStoreController();
  await store.initialize();
  return store;
}

type SyncPhase = 'waiting' | 'syncing' | 'live' | 'disposed';

interface SnapshotSyncRequest {
  epoch: number;
  generation: number;
  startingRevision: number;
}

interface CompletedSnapshot {
  revision: number;
  processes: Map<string, ProcessRecord>;
  processEntityBytes: Map<string, number>;
  portBindings: Map<string, PortBinding>;
  portEntityBytes: Map<string, number>;
  totalEntityBytes: number;
}

class SnapshotProtocolError extends Error {}

class SupervisorSnapshotStoreController implements SupervisorSnapshotStore {
  private readonly listeners = new Set<() => void>();
  private readonly processes = new Map<string, ProcessRecord>();
  private readonly processEntityBytes = new Map<string, number>();
  private readonly portBindings = new Map<string, PortBinding>();
  private readonly portEntityBytes = new Map<string, number>();
  private totalEntityBytes = 0;

  private connectionState: SupervisorConnectionState = {
    kind: 'disconnected',
    reason: null,
  };
  private state: SupervisorSnapshotState = Object.freeze({
    connectionState: this.connectionState,
    generation: null,
    revision: 0,
    synchronized: false,
    processes: Object.freeze([]) as ReadonlyArray<ProcessRecord>,
    portBindings: Object.freeze([]) as ReadonlyArray<PortBinding>,
  });
  private phase: SyncPhase = 'waiting';
  private generation: number | null = null;
  private trustedRevision = 0;
  private epoch = 0;
  private connectionEventSequence = 0;
  private readingInitialConnectionState = false;
  private initialConnectionReadStarted = false;
  private initialConnectionSequence = 0;
  private initialEvents: SupervisorEvent[] = [];
  private initialEventBytes = 0;
  private initialEventOverflow = false;
  private bufferedEvents: SupervisorEvent[] = [];
  private bufferedEventBytes = 0;
  private queuedSync: SnapshotSyncRequest | null = null;
  private syncInFlight = false;
  private syncRetryAttempt = 0;
  private snapshotProtocolResetAttempts = 0;
  private retryTimer: ReturnType<typeof setTimeout> | null = null;
  private connectionResetTimer: ReturnType<typeof setTimeout> | null = null;
  private connectionResetAttempt = 0;
  private unlistenEvent: UnlistenFn | null = null;
  private unlistenConnectionState: UnlistenFn | null = null;

  async initialize(): Promise<void> {
    try {
      this.readingInitialConnectionState = true;
      this.unlistenEvent = await onSupervisorEvent((event) => {
        this.handleEvent(event);
      });
      this.unlistenConnectionState = await onSupervisorConnectionState((state) => {
        this.connectionEventSequence += 1;
        if (!this.initialConnectionReadStarted) {
          return;
        }
        this.handleConnectionState(state);
      });

      this.initialConnectionSequence = this.connectionEventSequence;
      const statePromise = getSupervisorConnectionState();
      this.initialConnectionReadStarted = true;
      const state = await statePromise;
      this.readingInitialConnectionState = false;
      if (this.connectionEventSequence === this.initialConnectionSequence) {
        this.handleConnectionState(state);
      }
      this.initialEvents = [];
      this.initialEventBytes = 0;
      this.initialEventOverflow = false;
    } catch (error) {
      this.dispose();
      throw error;
    }
  }

  subscribe(listener: () => void): () => void {
    if (this.phase === 'disposed') {
      return () => undefined;
    }
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  getSnapshot(): SupervisorSnapshotState {
    return this.state;
  }

  dispose(): void {
    if (this.phase === 'disposed') {
      return;
    }
    this.phase = 'disposed';
    this.epoch += 1;
    this.clearRetryTimer();
    this.clearConnectionResetTimer();
    this.queuedSync = null;
    this.bufferedEvents = [];
    this.bufferedEventBytes = 0;
    this.initialEvents = [];
    this.initialEventBytes = 0;
    this.unlistenEvent?.();
    this.unlistenConnectionState?.();
    this.unlistenEvent = null;
    this.unlistenConnectionState = null;
    this.listeners.clear();
  }

  private handleConnectionState(state: SupervisorConnectionState): void {
    if (this.phase === 'disposed') {
      return;
    }
    this.clearConnectionResetTimer();
    this.connectionResetAttempt = 0;
    this.connectionState = state;

    if (state.kind !== 'connected') {
      this.invalidateWhileDisconnected();
      return;
    }

    if (this.generation === state.generation && this.phase !== 'waiting') {
      this.publishState();
      return;
    }

    const seedEvents = this.initialEventOverflow
      ? []
      : this.initialEvents.filter((event) => event.generation === state.generation);
    this.initialEvents = [];
    this.initialEventBytes = 0;
    this.initialEventOverflow = false;
    this.generation = state.generation;
    this.trustedRevision = 0;
    this.beginSync(0, seedEvents);
  }

  private handleEvent(event: SupervisorEvent): void {
    if (this.phase === 'disposed') {
      return;
    }

    if (this.readingInitialConnectionState && this.generation === null) {
      this.bufferInitialEvent(event);
      return;
    }

    if (this.generation === null || this.connectionState.kind !== 'connected') {
      return;
    }
    if (event.generation !== this.generation || !isEventRevision(event.revision)) {
      this.trustedRevision = 0;
      this.beginSync(0, []);
      return;
    }

    if (this.phase === 'syncing') {
      this.bufferEvent(event);
      return;
    }
    if (this.phase !== 'live') {
      return;
    }

    if (event.revision !== this.trustedRevision + 1) {
      this.beginSync(this.trustedRevision, [event]);
      return;
    }

    if (!this.applyLiveEvent(event)) {
      this.beginSync(this.trustedRevision, [event]);
      return;
    }
    this.trustedRevision = event.revision;
    this.publishState();
  }

  private bufferInitialEvent(event: SupervisorEvent): void {
    const eventBytes = encodedJsonBytes(event);
    if (
      eventBytes === null ||
      this.initialEvents.length >= SUPERVISOR_EVENT_BUFFER_CAPACITY ||
      this.initialEventBytes + eventBytes > SUPERVISOR_EVENT_BUFFER_BYTES
    ) {
      this.initialEvents = [];
      this.initialEventBytes = 0;
      this.initialEventOverflow = true;
      return;
    }
    if (!this.initialEventOverflow) {
      this.initialEvents.push(event);
      this.initialEventBytes += eventBytes;
    }
  }

  private bufferEvent(event: SupervisorEvent): void {
    const eventBytes = encodedJsonBytes(event);
    if (
      eventBytes === null ||
      this.bufferedEvents.length >= SUPERVISOR_EVENT_BUFFER_CAPACITY ||
      this.bufferedEventBytes + eventBytes > SUPERVISOR_EVENT_BUFFER_BYTES
    ) {
      this.trustedRevision = 0;
      this.beginSync(0, []);
      return;
    }
    this.bufferedEvents.push(event);
    this.bufferedEventBytes += eventBytes;
  }

  private invalidateWhileDisconnected(): void {
    this.epoch += 1;
    this.phase = 'waiting';
    this.generation = null;
    this.trustedRevision = 0;
    this.bufferedEvents = [];
    this.bufferedEventBytes = 0;
    this.initialEvents = [];
    this.initialEventBytes = 0;
    this.initialEventOverflow = false;
    this.queuedSync = null;
    this.clearRetryTimer();
    this.clearConnectionResetTimer();
    this.processes.clear();
    this.processEntityBytes.clear();
    this.portBindings.clear();
    this.portEntityBytes.clear();
    this.totalEntityBytes = 0;
    this.publishState();
  }

  private beginSync(startingRevision: number, seedEvents: ReadonlyArray<SupervisorEvent>): void {
    if (
      this.phase === 'disposed' ||
      this.connectionState.kind !== 'connected' ||
      this.generation === null
    ) {
      return;
    }

    const safeStartingRevision = isSnapshotRevision(startingRevision) ? startingRevision : 0;
    this.epoch += 1;
    this.phase = 'syncing';
    this.syncRetryAttempt = 0;
    this.bufferedEvents = [...seedEvents];
    const seedBytes = encodedJsonArrayItemsBytes(this.bufferedEvents);
    this.bufferedEventBytes = seedBytes ?? 0;
    if (
      seedBytes === null ||
      this.bufferedEvents.length > SUPERVISOR_EVENT_BUFFER_CAPACITY ||
      this.bufferedEventBytes > SUPERVISOR_EVENT_BUFFER_BYTES
    ) {
      this.bufferedEvents = [];
      this.bufferedEventBytes = 0;
    }
    this.queuedSync = {
      epoch: this.epoch,
      generation: this.generation,
      startingRevision: safeStartingRevision,
    };
    this.clearRetryTimer();
    this.processes.clear();
    this.processEntityBytes.clear();
    this.portBindings.clear();
    this.portEntityBytes.clear();
    this.totalEntityBytes = 0;
    this.publishState();
    this.pumpSync();
  }

  private pumpSync(): void {
    if (
      this.phase === 'disposed' ||
      this.syncInFlight ||
      this.retryTimer !== null ||
      this.queuedSync === null
    ) {
      return;
    }

    const request = this.queuedSync;
    this.queuedSync = null;
    if (!this.isCurrentSync(request)) {
      return;
    }

    this.syncInFlight = true;
    void this.fetchSnapshotChunks(request)
      .then(async (snapshot) => {
        const confirmedState = await getSupervisorConnectionState();
        if (!this.isCurrentSync(request)) {
          return;
        }
        if (
          confirmedState.kind !== 'connected' ||
          confirmedState.generation !== request.generation
        ) {
          this.handleConnectionState(confirmedState);
          return;
        }
        this.acceptSnapshot(request, snapshot);
      })
      .catch((error: unknown) => {
        if (error instanceof SnapshotProtocolError) {
          this.failSnapshotProtocol(request, true);
        } else if (isExplicitlyRetryableAppError(error)) {
          this.retrySync(request);
        } else {
          this.failSnapshotProtocol(request, false);
        }
      })
      .finally(() => {
        this.syncInFlight = false;
        this.pumpSync();
      });
  }

  private async fetchSnapshotChunks(request: SnapshotSyncRequest): Promise<CompletedSnapshot> {
    const processes = new Map<string, ProcessRecord>();
    const processEntityBytes = new Map<string, number>();
    const portBindings = new Map<string, PortBinding>();
    const portEntityBytes = new Map<string, number>();
    const seenCursors = new Set<string>();
    let cursor: string | null = null;
    let snapshotId: string | null = null;
    let snapshotRevision: number | null = null;
    let processCount: number | null = null;
    let portBindingCount: number | null = null;
    let declaredEntityBytes: number | null = null;
    let receivedEntityBytes = 0;
    let expectedChunkIndex = 0;

    while (this.isCurrentSync(request)) {
      const chunk = await this.requestSnapshotChunk(request, cursor);
      const confirmedState = await getSupervisorConnectionState();
      if (!this.isCurrentSync(request)) {
        throw new Error('snapshot synchronization is no longer current');
      }
      if (confirmedState.kind !== 'connected' || confirmedState.generation !== request.generation) {
        this.handleConnectionState(confirmedState);
        throw new Error('Supervisor generation changed during snapshot synchronization');
      }
      if (!isSystemSnapshotChunk(chunk) || chunk.chunkIndex !== expectedChunkIndex) {
        throw new SnapshotProtocolError('invalid Supervisor snapshot chunk');
      }
      if (expectedChunkIndex === 0) {
        if (chunk.revision < request.startingRevision) {
          throw new SnapshotProtocolError(
            'snapshot revision precedes the requested starting revision',
          );
        }
        snapshotId = chunk.snapshotId;
        snapshotRevision = chunk.revision;
        processCount = chunk.processCount;
        portBindingCount = chunk.portBindingCount;
        declaredEntityBytes = chunk.totalEntityBytes;
      } else if (
        chunk.snapshotId !== snapshotId ||
        chunk.revision !== snapshotRevision ||
        chunk.processCount !== processCount ||
        chunk.portBindingCount !== portBindingCount ||
        chunk.totalEntityBytes !== declaredEntityBytes
      ) {
        throw new SnapshotProtocolError('snapshot chunk does not belong to the frozen snapshot');
      }

      for (const process of chunk.processes) {
        const entityBytes = encodedJsonBytes(process);
        const key = processKey(process.instanceKey);
        if (
          entityBytes === null ||
          receivedEntityBytes + entityBytes > MAX_SNAPSHOT_TOTAL_ENTITY_BYTES ||
          process.lastSeenRevision > chunk.revision ||
          processes.has(key) ||
          processes.size >= chunk.processCount
        ) {
          throw new SnapshotProtocolError('snapshot contains an invalid or duplicate process');
        }
        receivedEntityBytes += entityBytes;
        processes.set(key, process);
        processEntityBytes.set(key, entityBytes);
      }
      for (const binding of chunk.portBindings) {
        const entityBytes = encodedJsonBytes(binding);
        const key = portKey(binding);
        if (
          entityBytes === null ||
          receivedEntityBytes + entityBytes > MAX_SNAPSHOT_TOTAL_ENTITY_BYTES ||
          portBindings.has(key) ||
          portBindings.size >= chunk.portBindingCount
        ) {
          throw new SnapshotProtocolError('snapshot contains an invalid or duplicate port binding');
        }
        receivedEntityBytes += entityBytes;
        portBindings.set(key, binding);
        portEntityBytes.set(key, entityBytes);
      }

      if (chunk.nextCursor === null) {
        if (
          snapshotRevision === null ||
          processCount === null ||
          portBindingCount === null ||
          declaredEntityBytes === null ||
          processes.size !== processCount ||
          portBindings.size !== portBindingCount
        ) {
          throw new SnapshotProtocolError(
            'snapshot completed before all declared entities arrived',
          );
        }
        return {
          revision: snapshotRevision,
          processes,
          processEntityBytes,
          portBindings,
          portEntityBytes,
          totalEntityBytes: receivedEntityBytes,
        };
      }
      if (seenCursors.has(chunk.nextCursor)) {
        throw new SnapshotProtocolError('snapshot continuation cursor repeated');
      }
      seenCursors.add(chunk.nextCursor);
      cursor = chunk.nextCursor;
      expectedChunkIndex += 1;
    }
    throw new Error('snapshot synchronization was superseded');
  }

  private async requestSnapshotChunk(
    request: SnapshotSyncRequest,
    cursor: string | null,
  ): Promise<unknown> {
    let retryAttempt = 0;
    while (this.isCurrentSync(request)) {
      const params: GetSnapshotRequest = {
        startingRevision: request.startingRevision,
        cursor,
      };
      try {
        return await forwardSupervisorRpc<unknown>({
          requestId: `snapshot:${globalThis.crypto.randomUUID()}`,
          operationId: null,
          timeoutMs: SNAPSHOT_TIMEOUT_MS,
          method: SNAPSHOT_METHOD,
          params,
        });
      } catch (error) {
        if (!isRetryableSnapshotTransportError(error)) {
          throw error;
        }
        await delay(snapshotRetryDelay(retryAttempt));
        retryAttempt += 1;
      }
    }
    throw new Error('snapshot synchronization was superseded');
  }

  private retrySync(request: SnapshotSyncRequest): void {
    if (!this.isCurrentSync(request)) {
      return;
    }
    this.queuedSync = request;
    const retryDelay = snapshotRetryDelay(this.syncRetryAttempt);
    this.syncRetryAttempt += 1;
    this.retryTimer = setTimeout(() => {
      this.retryTimer = null;
      this.pumpSync();
    }, retryDelay);
  }

  private failSnapshotProtocol(request: SnapshotSyncRequest, allowConnectionReset: boolean): void {
    if (!this.isCurrentSync(request)) {
      return;
    }
    this.connectionState = {
      kind: 'disconnected',
      reason: { kind: 'protocolViolation' },
    };
    this.invalidateWhileDisconnected();
    if (allowConnectionReset && this.snapshotProtocolResetAttempts === 0) {
      this.snapshotProtocolResetAttempts += 1;
      this.requestConnectionReset();
    }
  }

  private acceptSnapshot(request: SnapshotSyncRequest, snapshot: CompletedSnapshot): void {
    if (!this.isCurrentSync(request)) {
      return;
    }
    const processes = snapshot.processes;
    const processEntityBytes = snapshot.processEntityBytes;
    const portBindings = snapshot.portBindings;
    const portEntityBytes = snapshot.portEntityBytes;
    let totalEntityBytes = snapshot.totalEntityBytes;

    for (const event of this.bufferedEvents) {
      if (event.generation !== request.generation || !isEventRevision(event.revision)) {
        this.trustedRevision = 0;
        this.beginSync(0, []);
        return;
      }
    }

    let revision = snapshot.revision;
    const replayEvents = this.bufferedEvents.filter((event) => event.revision > snapshot.revision);
    for (const event of replayEvents) {
      const nextTotalEntityBytes =
        event.revision === revision + 1
          ? applyEvent(
              event,
              processes,
              processEntityBytes,
              portBindings,
              portEntityBytes,
              totalEntityBytes,
            )
          : null;
      if (nextTotalEntityBytes === null) {
        this.trustedRevision = snapshot.revision;
        this.beginSync(snapshot.revision, []);
        return;
      }
      totalEntityBytes = nextTotalEntityBytes;
      revision = event.revision;
    }

    if (!this.isCurrentSync(request)) {
      return;
    }
    this.processes.clear();
    this.processEntityBytes.clear();
    this.portBindings.clear();
    this.portEntityBytes.clear();
    for (const [key, process] of processes) {
      this.processes.set(key, process);
    }
    for (const [key, binding] of portBindings) {
      this.portBindings.set(key, binding);
    }
    for (const [key, encodedBytes] of processEntityBytes) {
      this.processEntityBytes.set(key, encodedBytes);
    }
    for (const [key, encodedBytes] of portEntityBytes) {
      this.portEntityBytes.set(key, encodedBytes);
    }
    this.totalEntityBytes = totalEntityBytes;
    this.bufferedEvents = [];
    this.bufferedEventBytes = 0;
    this.syncRetryAttempt = 0;
    this.snapshotProtocolResetAttempts = 0;
    this.trustedRevision = revision;
    this.phase = 'live';
    this.publishState();
  }

  private applyLiveEvent(event: SupervisorEvent): boolean {
    const processes = new Map(this.processes);
    const processEntityBytes = new Map(this.processEntityBytes);
    const portBindings = new Map(this.portBindings);
    const portEntityBytes = new Map(this.portEntityBytes);
    const totalEntityBytes = applyEvent(
      event,
      processes,
      processEntityBytes,
      portBindings,
      portEntityBytes,
      this.totalEntityBytes,
    );
    if (totalEntityBytes === null) {
      return false;
    }
    this.processes.clear();
    this.processEntityBytes.clear();
    this.portBindings.clear();
    this.portEntityBytes.clear();
    for (const [key, process] of processes) {
      this.processes.set(key, process);
    }
    for (const [key, binding] of portBindings) {
      this.portBindings.set(key, binding);
    }
    for (const [key, encodedBytes] of processEntityBytes) {
      this.processEntityBytes.set(key, encodedBytes);
    }
    for (const [key, encodedBytes] of portEntityBytes) {
      this.portEntityBytes.set(key, encodedBytes);
    }
    this.totalEntityBytes = totalEntityBytes;
    return true;
  }

  private isCurrentSync(request: SnapshotSyncRequest): boolean {
    return (
      this.phase === 'syncing' &&
      this.connectionState.kind === 'connected' &&
      this.epoch === request.epoch &&
      this.generation === request.generation &&
      this.connectionState.generation === request.generation
    );
  }

  private clearRetryTimer(): void {
    if (this.retryTimer !== null) {
      clearTimeout(this.retryTimer);
      this.retryTimer = null;
    }
  }

  private requestConnectionReset(): void {
    if (
      this.phase !== 'waiting' ||
      this.connectionState.kind !== 'disconnected' ||
      this.connectionState.reason?.kind !== 'protocolViolation'
    ) {
      return;
    }
    void resetSupervisorConnection().catch((error: unknown) => {
      if (
        !isExplicitlyRetryableAppError(error) ||
        this.phase !== 'waiting' ||
        this.connectionState.kind !== 'disconnected' ||
        this.connectionState.reason?.kind !== 'protocolViolation' ||
        this.connectionResetTimer !== null
      ) {
        return;
      }
      const retryDelay = snapshotRetryDelay(this.connectionResetAttempt);
      this.connectionResetAttempt += 1;
      this.connectionResetTimer = setTimeout(() => {
        this.connectionResetTimer = null;
        this.requestConnectionReset();
      }, retryDelay);
    });
  }

  private clearConnectionResetTimer(): void {
    if (this.connectionResetTimer !== null) {
      clearTimeout(this.connectionResetTimer);
      this.connectionResetTimer = null;
    }
  }

  private publishState(): void {
    if (this.phase === 'disposed') {
      return;
    }
    this.state = Object.freeze({
      connectionState: this.connectionState,
      generation: this.generation,
      revision: this.phase === 'live' ? this.trustedRevision : 0,
      synchronized: this.phase === 'live',
      processes: Object.freeze([...this.processes.values()]),
      portBindings: Object.freeze([...this.portBindings.values()]),
    });
    for (const listener of this.listeners) {
      listener();
    }
  }
}

function applyEvent(
  event: SupervisorEvent,
  processes: Map<string, ProcessRecord>,
  processEntityBytes: Map<string, number>,
  portBindings: Map<string, PortBinding>,
  portEntityBytes: Map<string, number>,
  totalEntityBytes: number,
): number | null {
  if (event.event === 'process.delta') {
    const delta = asProcessDelta(event.payload);
    if (
      delta === null ||
      delta.upserted.some((process) => process.lastSeenRevision !== event.revision)
    ) {
      return null;
    }
    for (const process of delta.upserted) {
      const key = processKey(process.instanceKey);
      const encodedBytes = encodedJsonBytes(process);
      const previousBytes = processEntityBytes.get(key);
      if (
        encodedBytes === null ||
        (processes.has(key) && previousBytes === undefined) ||
        totalEntityBytes < (previousBytes ?? 0)
      ) {
        return null;
      }
      totalEntityBytes = totalEntityBytes - (previousBytes ?? 0) + encodedBytes;
      processes.set(key, process);
      processEntityBytes.set(key, encodedBytes);
    }
    for (const key of delta.removed) {
      const identity = processKey(key);
      if (processes.has(identity)) {
        const previousBytes = processEntityBytes.get(identity);
        if (previousBytes === undefined || totalEntityBytes < previousBytes) {
          return null;
        }
        totalEntityBytes -= previousBytes;
        processes.delete(identity);
        processEntityBytes.delete(identity);
      }
    }
  } else if (event.event === 'port.delta') {
    const delta = asPortDelta(event.payload);
    if (delta === null) {
      return null;
    }
    for (const binding of delta.upserted) {
      const key = portKey(binding);
      const encodedBytes = encodedJsonBytes(binding);
      const previousBytes = portEntityBytes.get(key);
      if (
        encodedBytes === null ||
        (portBindings.has(key) && previousBytes === undefined) ||
        totalEntityBytes < (previousBytes ?? 0)
      ) {
        return null;
      }
      totalEntityBytes = totalEntityBytes - (previousBytes ?? 0) + encodedBytes;
      portBindings.set(key, binding);
      portEntityBytes.set(key, encodedBytes);
    }
    for (const key of delta.removed) {
      const identity = portKey(key);
      if (portBindings.has(identity)) {
        const previousBytes = portEntityBytes.get(identity);
        if (previousBytes === undefined || totalEntityBytes < previousBytes) {
          return null;
        }
        totalEntityBytes -= previousBytes;
        portBindings.delete(identity);
        portEntityBytes.delete(identity);
      }
    }
  } else if (event.event === MANAGED_LOG_CHUNK_EVENT) {
    if (!isManagedLogBatch(event.payload)) {
      return null;
    }
  } else {
    return null;
  }
  return isSnapshotCollectionStateValid(
    processes,
    processEntityBytes,
    portBindings,
    portEntityBytes,
    totalEntityBytes,
  )
    ? totalEntityBytes
    : null;
}

function asProcessDelta(payload: unknown): ProcessDelta | null {
  if (!isObject(payload) || !hasExactKeys(payload, ['upserted', 'removed'])) {
    return null;
  }
  const delta = payload as Partial<ProcessDelta>;
  if (!Array.isArray(delta.upserted) || !Array.isArray(delta.removed)) {
    return null;
  }
  if (!delta.upserted.every(isStrictProcessRecord) || !delta.removed.every(isProcessInstanceKey)) {
    return null;
  }
  const entityCount = delta.upserted.length + delta.removed.length;
  const encodedBytes = encodedJsonBytes(payload);
  if (
    entityCount > MAX_REVISION_DELTA_ENTITIES ||
    encodedBytes === null ||
    encodedBytes > MAX_REVISION_DELTA_PAYLOAD_BYTES ||
    !hasUniqueDisjointDeltaKeys(
      delta.upserted.map((process) => processKey(process.instanceKey)),
      delta.removed.map(processKey),
    )
  ) {
    return null;
  }
  return delta as ProcessDelta;
}

function asPortDelta(payload: unknown): PortDelta | null {
  if (!isObject(payload) || !hasExactKeys(payload, ['upserted', 'removed'])) {
    return null;
  }
  const delta = payload as Partial<PortDelta>;
  if (!Array.isArray(delta.upserted) || !Array.isArray(delta.removed)) {
    return null;
  }
  if (!delta.upserted.every(isStrictPortBinding) || !delta.removed.every(isPortBindingKey)) {
    return null;
  }
  const entityCount = delta.upserted.length + delta.removed.length;
  const encodedBytes = encodedJsonBytes(payload);
  if (
    entityCount > MAX_REVISION_DELTA_ENTITIES ||
    encodedBytes === null ||
    encodedBytes > MAX_REVISION_DELTA_PAYLOAD_BYTES ||
    !hasUniqueDisjointDeltaKeys(delta.upserted.map(portKey), delta.removed.map(portKey))
  ) {
    return null;
  }
  return delta as PortDelta;
}

function hasUniqueDisjointDeltaKeys(
  upsertedKeys: ReadonlyArray<string>,
  removedKeys: ReadonlyArray<string>,
): boolean {
  const seen = new Set<string>();
  for (const key of upsertedKeys) {
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
  }
  for (const key of removedKeys) {
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
  }
  return true;
}

function isSnapshotCollectionStateValid(
  processes: ReadonlyMap<string, ProcessRecord>,
  processEntityBytes: ReadonlyMap<string, number>,
  portBindings: ReadonlyMap<string, PortBinding>,
  portEntityBytes: ReadonlyMap<string, number>,
  totalEntityBytes: number,
): boolean {
  return (
    processes.size === processEntityBytes.size &&
    portBindings.size === portEntityBytes.size &&
    processes.size <= MAX_SNAPSHOT_PROCESSES &&
    portBindings.size <= MAX_SNAPSHOT_PORT_BINDINGS &&
    Number.isSafeInteger(totalEntityBytes) &&
    totalEntityBytes >= 0 &&
    totalEntityBytes <= MAX_SNAPSHOT_TOTAL_ENTITY_BYTES
  );
}

function isProcessInstanceKey(value: unknown): value is ProcessInstanceKey {
  if (
    !isObject(value) ||
    !hasExactKeys(value, ['bootId', 'pid', 'nativeStartTime']) ||
    !isBoundedWireText(value.bootId, 256) ||
    value.bootId.trim().length === 0 ||
    typeof value.pid !== 'number' ||
    !Number.isSafeInteger(value.pid) ||
    value.pid < 1 ||
    value.pid > 4_294_967_295 ||
    !isBoundedWireText(value.nativeStartTime, 128) ||
    !/^[1-9]\d*$/.test(value.nativeStartTime)
  ) {
    return false;
  }
  try {
    return BigInt(value.nativeStartTime) <= 0xffff_ffff_ffff_ffffn;
  } catch {
    return false;
  }
}

function isPortBindingKey(value: unknown): value is PortBindingKey {
  return (
    isObject(value) &&
    hasExactKeys(value, [
      'protocol',
      'addressFamily',
      'localAddress',
      'localPort',
      'processInstanceKey',
    ]) &&
    (value.protocol === 'tcp' || value.protocol === 'udp') &&
    (value.addressFamily === 'ipv4' || value.addressFamily === 'ipv6') &&
    isBoundedWireText(value.localAddress, 256) &&
    value.localAddress.length > 0 &&
    typeof value.localPort === 'number' &&
    Number.isSafeInteger(value.localPort) &&
    value.localPort >= 0 &&
    value.localPort <= 65_535 &&
    (value.processInstanceKey === null || isProcessInstanceKey(value.processInstanceKey))
  );
}

function isBoundedWireText(value: unknown, maximumBytes: number): value is string {
  return (
    typeof value === 'string' &&
    !value.includes('\0') &&
    utf8Encoder.encode(value).length <= maximumBytes
  );
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function isSystemSnapshotChunk(value: unknown): value is SystemSnapshot {
  if (
    !isObject(value) ||
    !hasExactKeys(value, [
      'snapshotId',
      'chunkIndex',
      'revision',
      'processCount',
      'portBindingCount',
      'totalEntityBytes',
      'processes',
      'portBindings',
      'nextCursor',
    ]) ||
    !isBoundedSnapshotToken(value.snapshotId) ||
    !isUint32(value.chunkIndex) ||
    !isSnapshotRevision(value.revision) ||
    !isBoundedCount(value.processCount, MAX_SNAPSHOT_PROCESSES) ||
    !isBoundedCount(value.portBindingCount, MAX_SNAPSHOT_PORT_BINDINGS) ||
    !isBoundedCount(value.totalEntityBytes, MAX_SNAPSHOT_TOTAL_ENTITY_BYTES) ||
    !Array.isArray(value.processes) ||
    !Array.isArray(value.portBindings) ||
    value.processes.length + value.portBindings.length > MAX_SNAPSHOT_CHUNK_ENTITIES
  ) {
    return false;
  }
  const revision = value.revision;
  if (
    !value.processes.every(
      (process) =>
        isStrictProcessRecord(process) &&
        isSnapshotRevision(process.lastSeenRevision) &&
        process.lastSeenRevision <= revision,
    ) ||
    !value.portBindings.every(isStrictPortBinding) ||
    (value.nextCursor !== null && !isBoundedSnapshotToken(value.nextCursor)) ||
    (value.nextCursor !== null && value.processes.length + value.portBindings.length === 0)
  ) {
    return false;
  }
  try {
    const encoded = JSON.stringify(value);
    return (
      encoded !== undefined &&
      utf8Encoder.encode(encoded).length <= MAX_SNAPSHOT_CHUNK_PAYLOAD_BYTES
    );
  } catch {
    return false;
  }
}

function hasExactKeys(value: Record<string, unknown>, expected: ReadonlyArray<string>): boolean {
  const actual = Object.keys(value);
  return actual.length === expected.length && expected.every((key) => actual.includes(key));
}

function isBoundedSnapshotToken(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    /^[\x21-\x7e]+$/.test(value) &&
    utf8Encoder.encode(value).length <= MAX_SNAPSHOT_CURSOR_BYTES
  );
}

function isUint32(value: unknown): value is number {
  return (
    typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && value <= 0xffffffff
  );
}

function isBoundedCount(value: unknown, maximum: number): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && value <= maximum;
}

function isRetryableSnapshotTransportError(error: unknown): boolean {
  return (
    isObject(error) &&
    error.retryable === true &&
    (error.code === 'TIMEOUT' || error.code === 'SUPERVISOR_UNAVAILABLE')
  );
}

function isExplicitlyRetryableAppError(error: unknown): boolean {
  return isObject(error) && error.retryable === true;
}

function delay(durationMs: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, durationMs);
  });
}

function snapshotRetryDelay(attempt: number): number {
  const exponent = Math.min(Math.max(attempt, 0), 8);
  return Math.min(SNAPSHOT_RETRY_DELAY_MS * 2 ** exponent, SNAPSHOT_MAX_RETRY_DELAY_MS);
}

function encodedJsonBytes(value: unknown): number | null {
  try {
    const encoded = JSON.stringify(value);
    return encoded === undefined ? null : utf8Encoder.encode(encoded).length;
  } catch {
    return null;
  }
}

function encodedJsonArrayItemsBytes(values: ReadonlyArray<unknown>): number | null {
  let total = 0;
  for (const value of values) {
    const encodedBytes = encodedJsonBytes(value);
    if (encodedBytes === null || total + encodedBytes > Number.MAX_SAFE_INTEGER) {
      return null;
    }
    total += encodedBytes;
  }
  return total;
}

function isSnapshotRevision(revision: unknown): revision is number {
  return (
    typeof revision === 'number' &&
    Number.isSafeInteger(revision) &&
    revision >= 0 &&
    revision <= MAX_SAFE_REVISION
  );
}

function isEventRevision(revision: number): boolean {
  return Number.isSafeInteger(revision) && revision >= 1 && revision <= MAX_SAFE_REVISION;
}

function processKey(key: ProcessInstanceKey): string {
  return tupleKey([key.bootId, key.pid, key.nativeStartTime]);
}

function portKey(key: PortBindingKey): string {
  return tupleKey([
    key.protocol,
    key.addressFamily,
    key.localAddress,
    key.localPort,
    key.processInstanceKey === null ? null : processKey(key.processInstanceKey),
  ]);
}

function tupleKey(parts: ReadonlyArray<unknown>): string {
  const serialized = JSON.stringify(parts);
  if (serialized === undefined) {
    throw new Error('failed to serialize a Supervisor snapshot key');
  }
  return serialized;
}
