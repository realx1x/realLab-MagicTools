import { useCallback, useEffect, useMemo, useRef, useState } from 'react';

import type { ManagedLogStream, ProcessRecord } from '@dpm/generated-types';

import {
  getManagedLogRange,
  onSupervisorLogChunk,
  type SupervisorLogChunkEvent,
} from '../../lib/supervisor';
import {
  applyManagedLogChunk,
  applyManagedLogRange,
  beginManagedLogRange,
  clearManagedLogStream,
  createManagedLogStreamModel,
  failManagedLogRange,
  getManagedLogRangePlan,
  MANAGED_LOG_RANGE_BYTES,
  MANAGED_LOG_STREAMS,
  retryManagedLogRange,
  snapshotManagedLogStream,
  type ManagedLogStreamModel,
  type ManagedLogStreamSnapshot,
} from './managedLogModel';

export type ManagedLogAvailability =
  | { readonly kind: 'available'; readonly runId: string }
  | { readonly kind: 'disconnected' }
  | { readonly kind: 'external' }
  | { readonly kind: 'managedRunUnavailable' }
  | { readonly kind: 'noProcess' };

export interface ManagedLogStreamView extends ManagedLogStreamSnapshot {
  readonly pendingByteCount: number;
  readonly pendingUpdateCount: number;
}

export interface UseManagedLogControllerOptions {
  readonly connectionGeneration: number | null;
  readonly process: ProcessRecord | null;
}

export interface UseManagedLogControllerResult {
  readonly autoFollow: boolean;
  readonly availability: ManagedLogAvailability;
  readonly clearAllStreams: () => void;
  readonly clearSelectedStream: () => void;
  readonly expanded: boolean;
  readonly paused: boolean;
  readonly pendingByteCount: number;
  readonly pendingUpdateCount: number;
  readonly retrySelectedStream: () => void;
  readonly searchQuery: string;
  readonly selectedStream: ManagedLogStream;
  readonly setAutoFollow: (enabled: boolean) => void;
  readonly setExpanded: (expanded: boolean) => void;
  readonly setPaused: (paused: boolean) => void;
  readonly setSearchQuery: (query: string) => void;
  readonly setSelectedStream: (stream: ManagedLogStream) => void;
  readonly streams: Readonly<Record<ManagedLogStream, ManagedLogStreamView>>;
  readonly subscriptionError: boolean;
  readonly targetRunId: string | null;
  readonly toggleExpanded: () => void;
  readonly togglePaused: () => void;
}

interface PendingState {
  readonly byteCount: number;
  readonly updateCount: number;
}

interface ManagedLogViewState {
  readonly paused: boolean;
  readonly pending: Readonly<Record<ManagedLogStream, PendingState>>;
  readonly scopeKey: string;
  readonly snapshots: Readonly<Record<ManagedLogStream, ManagedLogStreamSnapshot>>;
  readonly subscriptionError: boolean;
}

interface ManagedLogSession {
  readonly epoch: number;
  readonly generation: number;
  readonly runId: string;
  readonly scopeKey: string;
  active: boolean;
  listenerReady: boolean;
  models: Record<ManagedLogStream, ManagedLogStreamModel>;
  publish: (additions?: PendingAdditions) => void;
  rangeEnabled: boolean;
  scheduleRange: (stream: ManagedLogStream) => void;
  unlisten: (() => void) | null;
}

type PendingAdditions = Partial<Record<ManagedLogStream, PendingState>>;

const EMPTY_PENDING: Readonly<Record<ManagedLogStream, PendingState>> = Object.freeze({
  stderr: Object.freeze({ byteCount: 0, updateCount: 0 }),
  stdout: Object.freeze({ byteCount: 0, updateCount: 0 }),
});

const MAX_SEARCH_QUERY_LENGTH = 256;

export function useManagedLogController({
  connectionGeneration,
  process,
}: UseManagedLogControllerOptions): UseManagedLogControllerResult {
  const hasProcess = process !== null;
  const ownership = process?.ownership ?? null;
  const managedRunId = process?.managedRunId ?? null;
  const availability = useMemo(
    () => managedLogAvailability(connectionGeneration, hasProcess, ownership, managedRunId),
    [connectionGeneration, hasProcess, managedRunId, ownership],
  );
  const selectionKey = process === null ? 'none' : processIdentity(process);
  const scopeKey = managedLogScopeKey(connectionGeneration, availability, selectionKey);
  const initialView = useMemo(() => createEmptyView(scopeKey), [scopeKey]);
  const [view, setView] = useState<ManagedLogViewState>(initialView);
  const [selectedStream, setSelectedStream] = useState<ManagedLogStream>('stdout');
  const [searchQuery, setSearchQueryState] = useState('');
  const [autoFollow, setAutoFollow] = useState(true);
  const [expanded, setExpanded] = useState(false);
  const expandedRef = useRef(false);
  const activeSession = useRef<ManagedLogSession | null>(null);
  const epoch = useRef(0);

  useEffect(() => {
    epoch.current += 1;
    const currentEpoch = epoch.current;
    setView(createEmptyView(scopeKey));

    if (availability.kind !== 'available' || connectionGeneration === null) {
      activeSession.current = null;
      return;
    }

    const session: ManagedLogSession = {
      active: true,
      epoch: currentEpoch,
      generation: connectionGeneration,
      listenerReady: false,
      models: createStreamModels(),
      publish: () => undefined,
      rangeEnabled: expandedRef.current,
      runId: availability.runId,
      scheduleRange: () => undefined,
      scopeKey,
      unlisten: null,
    };
    activeSession.current = session;

    const sessionIsCurrent = () =>
      session.active && activeSession.current === session && epoch.current === session.epoch;

    const publish = (additions: PendingAdditions = {}) => {
      if (!sessionIsCurrent()) {
        return;
      }
      const snapshots = snapshotModels(session.models);
      setView((previous) => {
        if (previous.scopeKey !== session.scopeKey) {
          return previous;
        }
        if (!session.rangeEnabled && !previous.paused) {
          return previous;
        }
        if (!previous.paused) {
          return {
            ...previous,
            pending: EMPTY_PENDING,
            snapshots,
          };
        }
        return {
          ...previous,
          pending: addPending(previous.pending, additions),
        };
      });
    };

    const scheduleRange = (stream: ManagedLogStream) => {
      if (!sessionIsCurrent() || !session.listenerReady || !session.rangeEnabled) {
        return;
      }
      const plan = getManagedLogRangePlan(session.models[stream]);
      if (plan === null) {
        return;
      }
      session.models[stream] = beginManagedLogRange(session.models[stream]);
      publish();

      void getManagedLogRange({
        maximumBytes: MANAGED_LOG_RANGE_BYTES,
        runId: session.runId,
        startingByteOffset: plan.startingByteOffset,
        stream,
      }).then(
        (response) => {
          if (!sessionIsCurrent()) {
            return;
          }
          const applied = applyManagedLogRange(session.models[stream], response, plan);
          session.models[stream] = applied.model;

          if (
            plan.startingByteOffset !== null &&
            response.nextByteOffset <= plan.startingByteOffset &&
            response.streamEndByteOffset > plan.startingByteOffset
          ) {
            session.models[stream] = failManagedLogRange(session.models[stream]);
          }
          publish(
            applied.addedByteCount === 0
              ? {}
              : {
                  [stream]: {
                    byteCount: applied.addedByteCount,
                    updateCount: 1,
                  },
                },
          );
          scheduleRange(stream);
        },
        () => {
          if (!sessionIsCurrent()) {
            return;
          }
          session.models[stream] = failManagedLogRange(session.models[stream]);
          publish();
        },
      );
    };
    session.publish = publish;
    session.scheduleRange = scheduleRange;

    const handleLogEvent = (event: SupervisorLogChunkEvent) => {
      if (!sessionIsCurrent() || event.generation !== session.generation) {
        return;
      }
      const additions: PendingAdditions = {};
      const touched = new Set<ManagedLogStream>();
      for (const chunk of event.payload.chunks) {
        if (chunk.runId !== session.runId) {
          continue;
        }
        const applied = applyManagedLogChunk(session.models[chunk.stream], chunk);
        session.models[chunk.stream] = applied.model;
        touched.add(chunk.stream);
        if (applied.addedByteCount > 0) {
          additions[chunk.stream] = {
            byteCount: applied.addedByteCount,
            updateCount: 1,
          };
        }
      }
      if (touched.size === 0) {
        return;
      }
      publish(additions);
      for (const stream of touched) {
        scheduleRange(stream);
      }
    };

    void onSupervisorLogChunk(handleLogEvent).then(
      (unlisten) => {
        if (!sessionIsCurrent()) {
          unlisten();
          return;
        }
        session.unlisten = unlisten;
        session.listenerReady = true;
        scheduleRange('stdout');
        scheduleRange('stderr');
      },
      () => {
        if (!sessionIsCurrent()) {
          return;
        }
        setView((previous) =>
          previous.scopeKey === session.scopeKey
            ? { ...previous, subscriptionError: true }
            : previous,
        );
      },
    );

    return () => {
      session.active = false;
      if (activeSession.current === session) {
        activeSession.current = null;
      }
      session.unlisten?.();
      session.unlisten = null;
    };
  }, [scopeKey]);

  const renderedView = view.scopeKey === scopeKey ? view : initialView;

  const changePaused = useCallback(
    (paused: boolean) => {
      const session = activeSession.current;
      setView((previous) => {
        if (previous.scopeKey !== scopeKey || previous.paused === paused) {
          return previous;
        }
        if (paused) {
          return { ...previous, paused: true, pending: EMPTY_PENDING };
        }
        const snapshots =
          session?.scopeKey === scopeKey ? snapshotModels(session.models) : previous.snapshots;
        return {
          ...previous,
          paused: false,
          pending: EMPTY_PENDING,
          snapshots,
        };
      });
    },
    [scopeKey],
  );

  const clearStreams = useCallback(
    (streams: ReadonlyArray<ManagedLogStream>) => {
      const session = activeSession.current;
      if (session?.scopeKey !== scopeKey) {
        return;
      }
      for (const stream of streams) {
        session.models[stream] = clearManagedLogStream(session.models[stream]);
      }
      const liveSnapshots = snapshotModels(session.models);
      setView((previous) => {
        if (previous.scopeKey !== scopeKey) {
          return previous;
        }
        const snapshots = { ...previous.snapshots };
        const pending = { ...previous.pending };
        for (const stream of streams) {
          snapshots[stream] = liveSnapshots[stream];
          pending[stream] = EMPTY_PENDING[stream];
        }
        return { ...previous, pending, snapshots };
      });
    },
    [scopeKey],
  );

  const clearSelectedStream = useCallback(() => {
    clearStreams([selectedStream]);
  }, [clearStreams, selectedStream]);

  const clearAllStreams = useCallback(() => {
    clearStreams(MANAGED_LOG_STREAMS);
  }, [clearStreams]);

  const retrySelectedStream = useCallback(() => {
    const session = activeSession.current;
    if (session?.scopeKey !== scopeKey || !session.listenerReady) {
      return;
    }
    session.models[selectedStream] = retryManagedLogRange(session.models[selectedStream]);
    session.publish();
    session.scheduleRange(selectedStream);
  }, [scopeKey, selectedStream]);

  const setSearchQuery = useCallback((query: string) => {
    setSearchQueryState(query.slice(0, MAX_SEARCH_QUERY_LENGTH));
  }, []);
  const changeExpanded = useCallback(
    (nextExpanded: boolean) => {
      expandedRef.current = nextExpanded;
      setExpanded(nextExpanded);
      const session = activeSession.current;
      if (session?.scopeKey !== scopeKey) {
        return;
      }
      session.rangeEnabled = nextExpanded;
      if (nextExpanded) {
        session.publish();
        session.scheduleRange('stdout');
        session.scheduleRange('stderr');
      }
    },
    [scopeKey],
  );
  const togglePaused = useCallback(() => {
    changePaused(!renderedView.paused);
  }, [changePaused, renderedView.paused]);
  const toggleExpanded = useCallback(() => {
    changeExpanded(!expandedRef.current);
  }, [changeExpanded]);
  const streamViews = addPendingToSnapshots(renderedView.snapshots, renderedView.pending);
  const pendingByteCount = sumPending(renderedView.pending, 'byteCount');
  const pendingUpdateCount = sumPending(renderedView.pending, 'updateCount');

  return {
    autoFollow,
    availability,
    clearAllStreams,
    clearSelectedStream,
    expanded,
    paused: renderedView.paused,
    pendingByteCount,
    pendingUpdateCount,
    retrySelectedStream,
    searchQuery,
    selectedStream,
    setAutoFollow,
    setExpanded: changeExpanded,
    setPaused: changePaused,
    setSearchQuery,
    setSelectedStream,
    streams: streamViews,
    subscriptionError: renderedView.subscriptionError,
    targetRunId: availability.kind === 'available' ? availability.runId : null,
    toggleExpanded,
    togglePaused,
  };
}

function managedLogAvailability(
  connectionGeneration: number | null,
  hasProcess: boolean,
  ownership: ProcessRecord['ownership'] | null,
  managedRunId: string | null,
): ManagedLogAvailability {
  if (connectionGeneration === null) {
    return { kind: 'disconnected' };
  }
  if (!hasProcess) {
    return { kind: 'noProcess' };
  }
  if (ownership === 'external') {
    return { kind: 'external' };
  }
  return typeof managedRunId === 'string' && managedRunId.length > 0
    ? { kind: 'available', runId: managedRunId }
    : { kind: 'managedRunUnavailable' };
}

function managedLogScopeKey(
  connectionGeneration: number | null,
  availability: ManagedLogAvailability,
  selectionKey: string,
): string {
  return JSON.stringify([
    connectionGeneration,
    availability.kind,
    availability.kind === 'available' ? availability.runId : null,
    selectionKey,
  ]);
}

function processIdentity(process: ProcessRecord): string {
  const { bootId, nativeStartTime, pid } = process.instanceKey;
  return JSON.stringify([bootId, pid, nativeStartTime]);
}

function createStreamModels(): Record<ManagedLogStream, ManagedLogStreamModel> {
  return {
    stderr: createManagedLogStreamModel('stderr'),
    stdout: createManagedLogStreamModel('stdout'),
  };
}

function snapshotModels(
  models: Readonly<Record<ManagedLogStream, ManagedLogStreamModel>>,
): Readonly<Record<ManagedLogStream, ManagedLogStreamSnapshot>> {
  return {
    stderr: snapshotManagedLogStream(models.stderr),
    stdout: snapshotManagedLogStream(models.stdout),
  };
}

function createEmptyView(scopeKey: string): ManagedLogViewState {
  return {
    paused: false,
    pending: EMPTY_PENDING,
    scopeKey,
    snapshots: snapshotModels(createStreamModels()),
    subscriptionError: false,
  };
}

function addPending(
  current: Readonly<Record<ManagedLogStream, PendingState>>,
  additions: PendingAdditions,
): Readonly<Record<ManagedLogStream, PendingState>> {
  return {
    stderr: addStreamPending(current.stderr, additions.stderr),
    stdout: addStreamPending(current.stdout, additions.stdout),
  };
}

function addStreamPending(current: PendingState, addition: PendingState | undefined): PendingState {
  if (addition === undefined) {
    return current;
  }
  return {
    byteCount: safeAdd(current.byteCount, addition.byteCount),
    updateCount: safeAdd(current.updateCount, addition.updateCount),
  };
}

function addPendingToSnapshots(
  snapshots: Readonly<Record<ManagedLogStream, ManagedLogStreamSnapshot>>,
  pending: Readonly<Record<ManagedLogStream, PendingState>>,
): Readonly<Record<ManagedLogStream, ManagedLogStreamView>> {
  return {
    stderr: {
      ...snapshots.stderr,
      pendingByteCount: pending.stderr.byteCount,
      pendingUpdateCount: pending.stderr.updateCount,
    },
    stdout: {
      ...snapshots.stdout,
      pendingByteCount: pending.stdout.byteCount,
      pendingUpdateCount: pending.stdout.updateCount,
    },
  };
}

function sumPending(
  pending: Readonly<Record<ManagedLogStream, PendingState>>,
  field: keyof PendingState,
): number {
  return safeAdd(pending.stdout[field], pending.stderr[field]);
}

function safeAdd(left: number, right: number): number {
  return Math.min(Number.MAX_SAFE_INTEGER, left + right);
}
