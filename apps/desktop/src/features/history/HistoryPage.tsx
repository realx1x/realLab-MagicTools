import { useEffect, useRef, useState, type ComponentType } from 'react';
import { CircleOff, History, LoaderCircle, RefreshCw, TriangleAlert } from 'lucide-react';

import type { RunHistoryItem, RunState } from '@dpm/generated-types';
import { Button, IconButton } from '@dpm/ui';

import { useSupervisorSnapshot } from '../../app/SupervisorProvider';
import type { SupervisorConnectionState } from '../../lib/supervisor';
import {
  listRunHistoryPage,
  MAX_RUN_HISTORY_ITEMS,
  RUN_HISTORY_PAGE_SIZE,
} from '../../lib/runHistory';
import './history.css';

interface HistoryLoadState {
  readonly error: 'initial' | 'more' | null;
  readonly initialLoading: boolean;
  readonly limitReached: boolean;
  readonly loadingMore: boolean;
  readonly nextCursor: string | null;
  readonly runs: ReadonlyArray<RunHistoryItem>;
}

interface HistoryAvailability {
  readonly busy: boolean;
  readonly detail: string;
  readonly Icon: ComponentType<{
    'aria-hidden': true;
    className?: string;
    size: number;
    strokeWidth: number;
  }>;
  readonly title: string;
}

const EMPTY_HISTORY: HistoryLoadState = {
  error: null,
  initialLoading: false,
  limitReached: false,
  loadingMore: false,
  nextCursor: null,
  runs: [],
};

const timestampFormatter = new Intl.DateTimeFormat(undefined, {
  dateStyle: 'medium',
  timeStyle: 'medium',
});

export function HistoryPage() {
  const snapshot = useSupervisorSnapshot();
  const ready =
    snapshot.connectionState.kind === 'connected' &&
    snapshot.synchronized &&
    snapshot.generation !== null;
  const generation = ready ? snapshot.generation : null;
  const [reloadToken, setReloadToken] = useState(0);
  const [history, setHistory] = useState<HistoryLoadState>(EMPTY_HISTORY);
  const requestSequence = useRef(0);
  const scope = useRef({ generation, ready });
  const seenCursors = useRef(new Set<string>());
  const seenRunIds = useRef(new Set<string>());
  scope.current = { generation, ready };

  useEffect(() => {
    requestSequence.current += 1;
    const sequence = requestSequence.current;
    seenCursors.current = new Set();
    seenRunIds.current = new Set();

    if (!ready || generation === null) {
      setHistory(EMPTY_HISTORY);
      return;
    }

    setHistory({ ...EMPTY_HISTORY, initialLoading: true });
    void listRunHistoryPage({ cursor: null, limit: RUN_HISTORY_PAGE_SIZE }).then(
      (response) => {
        if (!requestIsCurrent(scope.current, requestSequence.current, generation, sequence)) {
          return;
        }
        try {
          const accepted = acceptHistoryPage(
            response.runs,
            response.nextCursor,
            0,
            seenRunIds.current,
            seenCursors.current,
          );
          setHistory({
            error: null,
            initialLoading: false,
            limitReached: accepted.limitReached,
            loadingMore: false,
            nextCursor: accepted.nextCursor,
            runs: response.runs,
          });
        } catch {
          setHistory({ ...EMPTY_HISTORY, error: 'initial' });
        }
      },
      () => {
        if (requestIsCurrent(scope.current, requestSequence.current, generation, sequence)) {
          setHistory({ ...EMPTY_HISTORY, error: 'initial' });
        }
      },
    );

    return () => {
      requestSequence.current += 1;
    };
  }, [generation, ready, reloadToken]);

  const refresh = () => {
    requestSequence.current += 1;
    setReloadToken((current) => current + 1);
  };

  const loadMore = () => {
    if (
      !ready ||
      generation === null ||
      history.initialLoading ||
      history.loadingMore ||
      history.nextCursor === null ||
      history.limitReached
    ) {
      return;
    }

    const cursor = history.nextCursor;
    const remaining = MAX_RUN_HISTORY_ITEMS - history.runs.length;
    if (remaining <= 0) {
      setHistory((current) => ({ ...current, limitReached: true, nextCursor: null }));
      return;
    }
    const sequence = requestSequence.current + 1;
    requestSequence.current = sequence;
    setHistory((current) => ({ ...current, error: null, loadingMore: true }));

    void listRunHistoryPage({
      cursor,
      limit: Math.min(RUN_HISTORY_PAGE_SIZE, remaining),
    }).then(
      (response) => {
        if (!requestIsCurrent(scope.current, requestSequence.current, generation, sequence)) {
          return;
        }
        try {
          const accepted = acceptHistoryPage(
            response.runs,
            response.nextCursor,
            history.runs.length,
            seenRunIds.current,
            seenCursors.current,
          );
          setHistory((current) => {
            if (current.nextCursor !== cursor) {
              return current;
            }
            return {
              error: null,
              initialLoading: false,
              limitReached: accepted.limitReached,
              loadingMore: false,
              nextCursor: accepted.nextCursor,
              runs: [...current.runs, ...response.runs],
            };
          });
        } catch {
          setHistory((current) => ({ ...current, error: 'more', loadingMore: false }));
        }
      },
      () => {
        if (requestIsCurrent(scope.current, requestSequence.current, generation, sequence)) {
          setHistory((current) => ({ ...current, error: 'more', loadingMore: false }));
        }
      },
    );
  };

  const availability = ready ? null : presentAvailability(snapshot.connectionState);
  const busy = history.initialLoading || history.loadingMore;

  return (
    <main className="history-page" id="main-content" tabIndex={-1}>
      <header className="page-header history-page-header">
        <div className="page-title">
          <History aria-hidden="true" size={18} strokeWidth={1.8} />
          <div>
            <h1>History</h1>
            <p>Managed run lifecycle</p>
          </div>
        </div>
        <IconButton
          disabled={!ready || busy}
          icon={
            <RefreshCw
              aria-hidden="true"
              className={history.initialLoading ? 'history-status-icon--busy' : undefined}
              size={16}
              strokeWidth={1.8}
            />
          }
          label="Refresh run history"
          onClick={refresh}
          variant="ghost"
        />
      </header>

      {availability ? (
        <HistoryState availability={availability} />
      ) : history.initialLoading ? (
        <HistoryState
          availability={{
            busy: true,
            detail: 'Reading durable managed run records.',
            Icon: LoaderCircle,
            title: 'Loading run history',
          }}
        />
      ) : history.error === 'initial' ? (
        <div aria-live="polite" className="history-message" role="alert">
          <TriangleAlert aria-hidden="true" size={20} strokeWidth={1.8} />
          <strong>Run history unavailable</strong>
          <span>The Supervisor could not read durable run records.</span>
          <Button
            leadingIcon={<RefreshCw aria-hidden="true" size={14} strokeWidth={1.8} />}
            onClick={refresh}
            size="compact"
          >
            Retry
          </Button>
        </div>
      ) : history.runs.length === 0 ? (
        <div aria-live="polite" className="history-message" role="status">
          <History aria-hidden="true" size={20} strokeWidth={1.8} />
          <strong>No managed run history</strong>
          <span>Runs started by this tool will appear here.</span>
        </div>
      ) : (
        <HistoryTable
          error={history.error}
          limitReached={history.limitReached}
          loadingMore={history.loadingMore}
          onLoadMore={loadMore}
          runs={history.runs}
          showLoadMore={history.nextCursor !== null}
        />
      )}
    </main>
  );
}

function HistoryTable({
  error,
  limitReached,
  loadingMore,
  onLoadMore,
  runs,
  showLoadMore,
}: {
  error: HistoryLoadState['error'];
  limitReached: boolean;
  loadingMore: boolean;
  onLoadMore: () => void;
  runs: ReadonlyArray<RunHistoryItem>;
  showLoadMore: boolean;
}) {
  return (
    <section aria-labelledby="history-table-heading" className="history-table-region">
      <div className="history-table-summary">
        <h2 id="history-table-heading">Managed runs</h2>
        <span>{runs.length.toLocaleString()} loaded</span>
      </div>
      <div
        aria-label="Managed run history table"
        className="history-table-scroll"
        role="region"
        tabIndex={0}
      >
        <table className="history-table">
          <caption>Managed run history ordered by start time, newest first</caption>
          <thead>
            <tr>
              <th scope="col">Started</th>
              <th scope="col">Profile</th>
              <th scope="col">State</th>
              <th scope="col">Stop</th>
              <th scope="col">Recovery</th>
              <th scope="col">Ended</th>
            </tr>
          </thead>
          <tbody>
            {runs.map((run) => (
              <tr key={run.runId}>
                <td>
                  <HistoryTime value={run.startedAt} />
                </td>
                <td>
                  <span className="history-profile-name" title={run.profileName}>
                    {run.profileName}
                  </span>
                  <small className="history-mono" title={run.profileId}>
                    {run.profileId}
                  </small>
                </td>
                <td>
                  <span className="history-state" data-state={run.state}>
                    {presentRunState(run.state)}
                  </span>
                </td>
                <td>{run.stopKind === null ? 'Not requested' : presentStopKind(run.stopKind)}</td>
                <td>
                  {run.recoveryState === null
                    ? 'Not applicable'
                    : presentRunState(run.recoveryState)}
                </td>
                <td>
                  {run.endedAt === null ? (
                    <span className="history-muted">
                      {run.state === 'identityMismatch' || run.state === 'orphaned'
                        ? 'Not confirmed'
                        : 'Active'}
                    </span>
                  ) : (
                    <HistoryTime value={run.endedAt} />
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <footer className="history-table-footer">
        <div aria-live="polite" role="status">
          {limitReached
            ? `Display limit reached at ${MAX_RUN_HISTORY_ITEMS.toLocaleString()} runs.`
            : null}
          {error === 'more' ? 'Additional history could not be loaded.' : null}
        </div>
        {showLoadMore || error === 'more' ? (
          <Button
            disabled={loadingMore}
            leadingIcon={
              <RefreshCw
                aria-hidden="true"
                className={loadingMore ? 'history-status-icon--busy' : undefined}
                size={14}
                strokeWidth={1.8}
              />
            }
            onClick={onLoadMore}
            size="compact"
            variant="secondary"
          >
            {loadingMore ? 'Loading' : error === 'more' ? 'Retry' : 'Load more'}
          </Button>
        ) : null}
      </footer>
    </section>
  );
}

function HistoryTime({ value }: { value: string }) {
  return (
    <time className="history-time" dateTime={value} title={value}>
      {timestampFormatter.format(new Date(value))}
    </time>
  );
}

function HistoryState({ availability }: { availability: HistoryAvailability }) {
  const { busy, detail, Icon, title } = availability;
  return (
    <div aria-live="polite" className="history-message" role="status">
      <Icon
        aria-hidden={true}
        {...(busy ? { className: 'history-status-icon--busy' } : {})}
        size={20}
        strokeWidth={1.8}
      />
      <strong>{title}</strong>
      <span>{detail}</span>
    </div>
  );
}

function acceptHistoryPage(
  runs: ReadonlyArray<RunHistoryItem>,
  nextCursor: string | null,
  currentCount: number,
  runIds: Set<string>,
  cursors: Set<string>,
): { readonly limitReached: boolean; readonly nextCursor: string | null } {
  if (currentCount + runs.length > MAX_RUN_HISTORY_ITEMS) {
    throw new TypeError('run history exceeds the supported item limit');
  }
  for (const run of runs) {
    if (runIds.has(run.runId)) {
      throw new TypeError('run history contains a duplicate run identity');
    }
  }
  if (nextCursor !== null && cursors.has(nextCursor)) {
    throw new TypeError('run history contains a repeated cursor');
  }
  for (const run of runs) {
    runIds.add(run.runId);
  }
  if (nextCursor !== null) {
    cursors.add(nextCursor);
  }
  const atDisplayCapacity = currentCount + runs.length >= MAX_RUN_HISTORY_ITEMS;
  const limitReached = atDisplayCapacity && nextCursor !== null;
  return { limitReached, nextCursor: atDisplayCapacity ? null : nextCursor };
}

function requestIsCurrent(
  currentScope: { readonly generation: number | null; readonly ready: boolean },
  currentSequence: number,
  expectedGeneration: number,
  expectedSequence: number,
): boolean {
  return (
    currentScope.ready &&
    currentScope.generation === expectedGeneration &&
    currentSequence === expectedSequence
  );
}

function presentAvailability(state: SupervisorConnectionState): HistoryAvailability {
  switch (state.kind) {
    case 'connected':
      return {
        busy: true,
        detail: 'Waiting for a consistent Supervisor snapshot.',
        Icon: LoaderCircle,
        title: 'Synchronizing history',
      };
    case 'connecting':
    case 'authenticating':
    case 'backoff':
      return {
        busy: true,
        detail: 'History will load after the local Supervisor reconnects.',
        Icon: LoaderCircle,
        title: 'Connecting to Supervisor',
      };
    case 'incompatibleVersion':
      return {
        busy: false,
        detail: 'The desktop app and Supervisor require compatible versions.',
        Icon: TriangleAlert,
        title: 'Supervisor update required',
      };
    case 'accessDenied':
      return {
        busy: false,
        detail: 'The current user cannot authenticate this Supervisor session.',
        Icon: TriangleAlert,
        title: 'Supervisor access denied',
      };
    case 'shuttingDown':
    case 'disconnected':
      return {
        busy: false,
        detail: 'Reconnect to the local Supervisor to read durable run records.',
        Icon: CircleOff,
        title: 'Run history unavailable',
      };
  }
}

function presentRunState(state: RunState): string {
  switch (state) {
    case 'starting':
      return 'Starting';
    case 'running':
      return 'Running';
    case 'stopRequested':
      return 'Stop requested';
    case 'gracefulStopping':
      return 'Stopping';
    case 'forceStopping':
      return 'Force stopping';
    case 'exited':
      return 'Exited';
    case 'failed':
      return 'Failed';
    case 'recovered':
      return 'Recovered';
    case 'exitedWhileOffline':
      return 'Exited while offline';
    case 'identityMismatch':
      return 'Identity mismatch';
    case 'orphaned':
      return 'Orphaned';
  }
}

function presentStopKind(kind: 'graceful' | 'force'): string {
  return kind === 'graceful' ? 'Graceful' : 'Force';
}
