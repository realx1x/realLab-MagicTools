import {
  forwardRef,
  useEffect,
  useId,
  useImperativeHandle,
  useMemo,
  useRef,
  type ReactNode,
} from 'react';
import {
  ArrowDownToLine,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  CircleOff,
  CirclePause,
  CircleStop,
  FileWarning,
  LoaderCircle,
  Pause,
  Play,
  RefreshCw,
  Search,
  Trash2,
  TriangleAlert,
  X,
  type LucideIcon,
} from 'lucide-react';

import type {
  ManagedLogEncoding,
  ManagedLogIoErrorKind,
  ManagedLogStream,
  ManagedLogTextStatus,
} from '@dpm/generated-types';
import { Button, IconButton, SegmentedControl, TextInput } from '@dpm/ui';

import type {
  ManagedLogAvailability,
  ManagedLogStreamView,
  UseManagedLogControllerResult,
} from './useManagedLogController';

const MAX_HIGHLIGHT_MATCHES = 1_000;

const STREAM_ITEMS = [
  { label: 'stdout', value: 'stdout' },
  { label: 'stderr', value: 'stderr' },
] as const;

export interface ProcessLogPanelProps {
  readonly controller: UseManagedLogControllerResult;
}

export interface ProcessLogPanelHandle {
  readonly focusSearch: () => void;
  readonly scrollToEnd: () => void;
}

interface HighlightedLog {
  readonly capped: boolean;
  readonly matchCount: number;
  readonly nodes: ReactNode;
}

interface DiagnosticNotice {
  readonly detail: string;
  readonly icon: LucideIcon;
  readonly id: string;
  readonly title: string;
  readonly tone: 'busy' | 'danger' | 'neutral' | 'warning';
}

export const ProcessLogPanel = forwardRef<ProcessLogPanelHandle, ProcessLogPanelProps>(
  function ProcessLogPanel({ controller }, ref) {
    const {
      autoFollow,
      availability,
      clearSelectedStream,
      expanded,
      paused,
      retrySelectedStream,
      searchQuery,
      selectedStream,
      setAutoFollow,
      setSearchQuery,
      setSelectedStream,
      streams,
      subscriptionError,
      toggleExpanded,
      togglePaused,
    } = controller;
    const contentId = useId();
    const headingId = useId();
    const searchStatusId = useId();
    const searchInputRef = useRef<HTMLInputElement>(null);
    const viewportRef = useRef<HTMLDivElement>(null);
    const stream = streams[selectedStream];
    const highlighted = useMemo(
      () => highlightLogText(stream.visibleText, searchQuery),
      [searchQuery, stream.visibleText],
    );

    const scrollToEnd = () => {
      const viewport = viewportRef.current;
      if (viewport !== null) {
        viewport.scrollTop = viewport.scrollHeight;
      }
    };

    useImperativeHandle(
      ref,
      () => ({
        focusSearch: () => searchInputRef.current?.focus({ preventScroll: true }),
        scrollToEnd,
      }),
      [],
    );

    useEffect(() => {
      if (!expanded || availability.kind !== 'available' || !autoFollow || paused) {
        return;
      }
      const frame = globalThis.requestAnimationFrame(scrollToEnd);
      return () => globalThis.cancelAnimationFrame(frame);
    }, [
      autoFollow,
      availability.kind,
      expanded,
      paused,
      selectedStream,
      stream.catchingUp,
      stream.loading,
      stream.visibleText,
    ]);

    const pendingLabel = formatPending(stream.pendingUpdateCount, stream.pendingByteCount);
    const availabilityLabel = presentAvailabilityLabel(availability);

    return (
      <section
        aria-labelledby={headingId}
        className="process-log-tool"
        data-expanded={expanded || undefined}
      >
        <header className="process-log-header">
          <div className="process-log-heading">
            <IconButton
              aria-controls={contentId}
              aria-expanded={expanded}
              icon={
                expanded ? (
                  <ChevronDown aria-hidden="true" size={16} strokeWidth={1.8} />
                ) : (
                  <ChevronRight aria-hidden="true" size={16} strokeWidth={1.8} />
                )
              }
              label={expanded ? 'Collapse logs' : 'Expand logs'}
              onClick={toggleExpanded}
              variant="ghost"
            />
            <span className="process-log-heading-copy">
              <strong id={headingId}>Logs</strong>
              <small>{availabilityLabel}</small>
            </span>
          </div>
          {paused ? (
            <span aria-atomic="true" aria-live="polite" className="process-log-pending">
              <CirclePause aria-hidden="true" size={14} strokeWidth={1.8} />
              <span className="visually-hidden">Log display paused.</span>
              <span aria-hidden="true">
                {stream.pendingUpdateCount > 0 ? pendingLabel : 'Paused'}
              </span>
            </span>
          ) : null}
        </header>

        {expanded ? (
          <div className="process-log-content" id={contentId}>
            {availability.kind === 'available' ? (
              <>
                <div aria-label="Log controls" className="process-log-toolbar" role="toolbar">
                  <SegmentedControl
                    ariaLabel="Log stream"
                    items={STREAM_ITEMS}
                    onValueChange={(value) => {
                      if (isManagedLogStream(value)) {
                        setSelectedStream(value);
                      }
                    }}
                    value={selectedStream}
                  />
                  <div className="process-log-search">
                    <Search aria-hidden="true" size={14} strokeWidth={1.8} />
                    <TextInput
                      aria-describedby={searchQuery.length > 0 ? searchStatusId : undefined}
                      aria-label={`Search ${selectedStream} logs`}
                      maxLength={256}
                      onChange={(event) => setSearchQuery(event.currentTarget.value)}
                      placeholder="Search logs"
                      ref={searchInputRef}
                      type="search"
                      value={searchQuery}
                    />
                    {searchQuery.length > 0 ? (
                      <IconButton
                        icon={<X aria-hidden="true" size={14} strokeWidth={1.8} />}
                        label="Clear log search"
                        onClick={() => {
                          setSearchQuery('');
                          searchInputRef.current?.focus({ preventScroll: true });
                        }}
                        variant="ghost"
                      />
                    ) : null}
                  </div>
                  <IconButton
                    aria-pressed={paused}
                    icon={
                      paused ? (
                        <Play aria-hidden="true" size={14} strokeWidth={1.8} />
                      ) : (
                        <Pause aria-hidden="true" size={14} strokeWidth={1.8} />
                      )
                    }
                    label={paused ? 'Resume log display' : 'Pause log display'}
                    onClick={togglePaused}
                    variant="ghost"
                  />
                  <IconButton
                    disabled={stream.loading && stream.visibleText.length === 0}
                    icon={<Trash2 aria-hidden="true" size={14} strokeWidth={1.8} />}
                    label={`Clear ${selectedStream} display`}
                    onClick={clearSelectedStream}
                    variant="ghost"
                  />
                  <label className="process-log-auto-follow">
                    <input
                      checked={autoFollow}
                      onChange={(event) => setAutoFollow(event.currentTarget.checked)}
                      type="checkbox"
                    />
                    <ArrowDownToLine aria-hidden="true" size={14} strokeWidth={1.8} />
                    <span>Auto-scroll</span>
                  </label>
                </div>

                <SearchStatus
                  capped={highlighted.capped}
                  id={searchStatusId}
                  matchCount={highlighted.matchCount}
                  query={searchQuery}
                />
                <StreamStatus stream={stream} subscriptionError={subscriptionError} />
                <div
                  aria-busy={stream.loading || stream.catchingUp || undefined}
                  aria-label={`${selectedStream} log output`}
                  className="process-log-viewport"
                  onScroll={(event) => {
                    if (
                      autoFollow &&
                      event.currentTarget.scrollHeight -
                        event.currentTarget.scrollTop -
                        event.currentTarget.clientHeight >
                        16
                    ) {
                      setAutoFollow(false);
                    }
                  }}
                  ref={viewportRef}
                  role="region"
                  tabIndex={0}
                >
                  <OmissionStatus stream={stream} />
                  {stream.visibleText.length > 0 ? (
                    <pre className="process-log-text">
                      <code>{highlighted.nodes}</code>
                    </pre>
                  ) : (
                    <EmptyLogState stream={stream} subscriptionError={subscriptionError} />
                  )}
                  {stream.endOfFile ? (
                    <div className="process-log-eof" role="status">
                      <CircleStop aria-hidden="true" size={14} strokeWidth={1.8} />
                      End of {selectedStream} stream
                    </div>
                  ) : null}
                </div>
                {stream.rangeError ? (
                  <div className="process-log-retry">
                    <span>Historical log read failed.</span>
                    <Button
                      leadingIcon={<RefreshCw aria-hidden="true" size={14} strokeWidth={1.8} />}
                      onClick={retrySelectedStream}
                      size="compact"
                      variant="secondary"
                    >
                      Retry
                    </Button>
                  </div>
                ) : null}
              </>
            ) : (
              <UnavailableLogState availability={availability} />
            )}
          </div>
        ) : null}
      </section>
    );
  },
);

function SearchStatus({
  capped,
  id,
  matchCount,
  query,
}: {
  capped: boolean;
  id: string;
  matchCount: number;
  query: string;
}) {
  if (query.length === 0) {
    return null;
  }
  return (
    <div aria-atomic="true" aria-live="polite" className="process-log-search-status" id={id}>
      <Search aria-hidden="true" size={13} strokeWidth={1.8} />
      {capped
        ? `At least ${matchCount.toLocaleString()} matches; highlighting is capped.`
        : `${matchCount.toLocaleString()} ${matchCount === 1 ? 'match' : 'matches'}`}
    </div>
  );
}

function StreamStatus({
  stream,
  subscriptionError,
}: {
  stream: ManagedLogStreamView;
  subscriptionError: boolean;
}) {
  const notices = buildDiagnosticNotices(stream, subscriptionError);
  const textStatus = presentTextStatus(stream.textStatus);
  const hasDangerNotice = notices.some((notice) => notice.tone === 'danger');
  return (
    <div className="process-log-state-area">
      <div aria-label="Log text status" className="process-log-text-status">
        <span>{textStatus.encoding}</span>
        <span>{textStatus.filtering}</span>
        {textStatus.warning ? (
          <span data-tone="warning">
            <TriangleAlert aria-hidden="true" size={13} strokeWidth={1.8} />
            {textStatus.warning}
          </span>
        ) : null}
      </div>
      {notices.length > 0 ? (
        <ul
          aria-atomic="true"
          aria-label="Log diagnostics"
          aria-live={hasDangerNotice ? 'assertive' : 'polite'}
          className="process-log-diagnostics"
          role={hasDangerNotice ? 'alert' : 'status'}
        >
          {notices.map(({ detail, icon: Icon, id, title, tone }) => (
            <li data-tone={tone} key={id}>
              <Icon
                aria-hidden="true"
                className={tone === 'busy' ? 'process-log-status-icon--busy' : undefined}
                size={14}
                strokeWidth={1.8}
              />
              <span>
                <strong>{title}</strong>
                <small>{detail}</small>
              </span>
            </li>
          ))}
        </ul>
      ) : null}
    </div>
  );
}

function OmissionStatus({ stream }: { stream: ManagedLogStreamView }) {
  const notices: string[] = [];
  if (stream.omission.backendRetentionOrRotation) {
    notices.push('Earlier output is no longer available after log rotation or retention.');
  }
  if (stream.omission.localMemoryLimit) {
    notices.push('Earlier output was omitted from this bounded display buffer.');
  }
  if (stream.omission.localClear) {
    notices.push('Earlier output was hidden by Clear display.');
  }
  if (notices.length === 0) {
    return null;
  }
  return (
    <div className="process-log-omission" role="status">
      <FileWarning aria-hidden="true" size={14} strokeWidth={1.8} />
      <span>
        {notices.map((notice) => (
          <span key={notice}>{notice}</span>
        ))}
        <small>
          Visible output starts at byte {stream.omission.beforeByteOffset.toLocaleString()}.
        </small>
      </span>
    </div>
  );
}

function EmptyLogState({
  stream,
  subscriptionError,
}: {
  stream: ManagedLogStreamView;
  subscriptionError: boolean;
}) {
  if (subscriptionError) {
    return (
      <LogViewportState
        Icon={TriangleAlert}
        detail="No history was loaded because a live subscription could not be established."
        title="Log connection unavailable"
      />
    );
  }
  if (stream.rangeError) {
    return (
      <LogViewportState
        Icon={TriangleAlert}
        detail="Retry the historical range read."
        title="Log history unavailable"
      />
    );
  }
  if (stream.loading || stream.catchingUp) {
    return (
      <LogViewportState
        Icon={LoaderCircle}
        busy
        detail={stream.catchingUp ? 'Reading missing output ranges.' : 'Reading retained output.'}
        title={stream.catchingUp ? 'Catching up' : 'Loading logs'}
      />
    );
  }
  return (
    <LogViewportState
      Icon={stream.endOfFile ? CircleStop : CheckCircle2}
      detail={stream.endOfFile ? 'The stream ended without visible output.' : 'Waiting for output.'}
      title={`No ${stream.stream} output`}
    />
  );
}

function LogViewportState({
  busy = false,
  detail,
  Icon,
  title,
}: {
  busy?: boolean;
  detail: string;
  Icon: LucideIcon;
  title: string;
}) {
  return (
    <div aria-live="polite" className="process-log-empty" role="status">
      <Icon
        aria-hidden="true"
        className={busy ? 'process-log-status-icon--busy' : undefined}
        size={18}
        strokeWidth={1.8}
      />
      <strong>{title}</strong>
      <span>{detail}</span>
    </div>
  );
}

function UnavailableLogState({ availability }: { availability: ManagedLogAvailability }) {
  switch (availability.kind) {
    case 'disconnected':
      return (
        <UnavailableCopy
          Icon={CircleOff}
          detail="Reconnect to the local Supervisor to read managed output."
          title="Logs unavailable"
        />
      );
    case 'external':
      return (
        <UnavailableCopy
          Icon={CircleOff}
          detail="stdout and stderr cannot be captured after an external process has started."
          title="External process logs unavailable"
        />
      );
    case 'managedRunUnavailable':
      return (
        <UnavailableCopy
          Icon={TriangleAlert}
          detail="The selected managed process has no authoritative run association."
          title="Managed log source unavailable"
        />
      );
    case 'noProcess':
      return (
        <UnavailableCopy
          Icon={CircleOff}
          detail="Choose a process to view its managed output."
          title="No process selected"
        />
      );
    case 'available':
      return null;
  }
}

function UnavailableCopy({
  detail,
  Icon,
  title,
}: {
  detail: string;
  Icon: LucideIcon;
  title: string;
}) {
  return (
    <div aria-live="polite" className="process-log-unavailable" role="status">
      <Icon aria-hidden="true" size={18} strokeWidth={1.8} />
      <strong>{title}</strong>
      <span>{detail}</span>
    </div>
  );
}

function buildDiagnosticNotices(
  stream: ManagedLogStreamView,
  subscriptionError: boolean,
): ReadonlyArray<DiagnosticNotice> {
  const notices: DiagnosticNotice[] = [];
  if (subscriptionError) {
    notices.push({
      detail: 'The live subscription failed, so retained history was not loaded.',
      icon: TriangleAlert,
      id: 'subscription',
      title: 'Live log updates unavailable',
      tone: 'danger',
    });
  }
  if (stream.rangeError) {
    notices.push({
      detail: 'The requested historical range could not be read.',
      icon: TriangleAlert,
      id: 'range',
      title: 'Historical log read failed',
      tone: 'danger',
    });
  } else if (!subscriptionError && stream.loading) {
    notices.push({
      detail: 'Reading retained output for this stream.',
      icon: LoaderCircle,
      id: 'loading',
      title: 'Loading log history',
      tone: 'busy',
    });
  } else if (!subscriptionError && stream.catchingUp) {
    notices.push({
      detail: 'Reading a missing range before showing the latest contiguous output.',
      icon: LoaderCircle,
      id: 'catching-up',
      title: 'Catching up',
      tone: 'busy',
    });
  }
  if (!subscriptionError && !stream.ioStatusKnown) {
    notices.push({
      detail: 'Capture and storage status have not been reported yet.',
      icon: LoaderCircle,
      id: 'io-pending',
      title: 'Log I/O status pending',
      tone: 'busy',
    });
  }
  if (stream.diskError !== null) {
    notices.push(ioNotice('disk', 'Log capture or storage issue', stream.diskError));
  }
  if (stream.readError !== null) {
    notices.push(ioNotice('read', 'Historical log read issue', stream.readError));
  }
  if (stream.deliveryError !== null) {
    notices.push(ioNotice('delivery', 'Live log delivery issue', stream.deliveryError));
  }
  if (stream.complete && !stream.endOfFile) {
    notices.push({
      detail: 'Displayed output is caught up with the latest known byte offset.',
      icon: CheckCircle2,
      id: 'complete',
      title: 'Live output current',
      tone: 'neutral',
    });
  }
  if (stream.endOfFile) {
    notices.push({
      detail: 'No more output is expected from this stream.',
      icon: CircleStop,
      id: 'eof',
      title: 'End of stream',
      tone: 'neutral',
    });
  }
  return notices;
}

function ioNotice(
  id: 'delivery' | 'disk' | 'read',
  title: string,
  error: ManagedLogIoErrorKind,
): DiagnosticNotice {
  return {
    detail: presentIoError(error),
    icon: TriangleAlert,
    id,
    title,
    tone: 'danger',
  };
}

function presentIoError(error: ManagedLogIoErrorKind): string {
  switch (error) {
    case 'invalidConfiguration':
      return 'The log source configuration is invalid.';
    case 'invalidPath':
      return 'The managed log storage location is invalid.';
    case 'notFound':
      return 'The requested log data is no longer available.';
    case 'permissionDenied':
      return 'Access to managed log storage was denied.';
    case 'alreadyExists':
      return 'Log storage conflicted with an existing entry.';
    case 'resourceBusy':
      return 'The log resource is currently busy.';
    case 'storageFull':
      return 'Managed log storage has no remaining capacity.';
    case 'interrupted':
      return 'The log operation was interrupted.';
    case 'unexpectedEof':
      return 'The stored log ended before the requested range completed.';
    case 'invalidData':
      return 'The stored log data could not be decoded safely.';
    case 'limitExceeded':
      return 'A managed log safety limit was reached.';
    case 'writeZero':
      return 'The log collector could not write additional output.';
    case 'unavailable':
      return 'This log operation is unavailable on the current platform.';
    case 'otherIo':
      return 'The managed log I/O operation failed.';
  }
}

function presentTextStatus(status: ManagedLogTextStatus): {
  readonly encoding: string;
  readonly filtering: string;
  readonly warning: string | null;
} {
  if (status === 'unknown') {
    return {
      encoding: 'Encoding: pending',
      filtering: 'Control filtering: pending',
      warning: null,
    };
  }
  const warnings: string[] = [];
  if (status.known.replacementUsed) {
    warnings.push('Invalid source bytes were replaced.');
  }
  if (status.known.fallbackUnavailable) {
    warnings.push('The requested encoding fallback was unavailable.');
  }
  return {
    encoding: `Encoding: ${presentEncoding(status.known.encoding)}`,
    filtering: status.known.controlsFiltered
      ? 'Control filtering: unsafe sequences removed'
      : 'Control filtering: no unsafe sequences found',
    warning: warnings.length === 0 ? null : warnings.join(' '),
  };
}

function presentEncoding(encoding: ManagedLogEncoding): string {
  if (encoding === 'utf8') {
    return 'UTF-8';
  }
  if (encoding === 'utf16Le') {
    return 'UTF-16 LE';
  }
  if (encoding === 'utf16Be') {
    return 'UTF-16 BE';
  }
  return `Windows code page ${encoding.windowsCodePage.codePage.toLocaleString()}`;
}

function highlightLogText(text: string, query: string): HighlightedLog {
  if (text.length === 0 || query.length === 0) {
    return { capped: false, matchCount: 0, nodes: text };
  }

  const expression = new RegExp(escapeRegularExpression(query), 'giu');
  const nodes: ReactNode[] = [];
  let cursor = 0;
  let matchCount = 0;
  let match: RegExpExecArray | null;
  while (matchCount < MAX_HIGHLIGHT_MATCHES && (match = expression.exec(text)) !== null) {
    if (match.index > cursor) {
      nodes.push(text.slice(cursor, match.index));
    }
    nodes.push(<mark key={`${match.index}:${matchCount}`}>{match[0]}</mark>);
    cursor = match.index + match[0].length;
    matchCount += 1;
  }
  const capped = matchCount === MAX_HIGHLIGHT_MATCHES && expression.exec(text) !== null;
  if (cursor < text.length) {
    nodes.push(text.slice(cursor));
  }
  return { capped, matchCount, nodes };
}

function escapeRegularExpression(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function presentAvailabilityLabel(availability: ManagedLogAvailability): string {
  switch (availability.kind) {
    case 'available':
      return 'Managed output';
    case 'disconnected':
      return 'Supervisor disconnected';
    case 'external':
      return 'External process';
    case 'managedRunUnavailable':
      return 'Run association unavailable';
    case 'noProcess':
      return 'No process selected';
  }
}

function formatPending(updateCount: number, byteCount: number): string {
  const updates = `${updateCount.toLocaleString()} ${updateCount === 1 ? 'update' : 'updates'}`;
  return `${updates} / ${formatBytes(byteCount)}`;
}

function formatBytes(bytes: number): string {
  if (bytes < 1_024) {
    return `${bytes.toLocaleString()} B`;
  }
  if (bytes < 1_048_576) {
    return `${(bytes / 1_024).toFixed(bytes < 10_240 ? 1 : 0)} KiB`;
  }
  return `${(bytes / 1_048_576).toFixed(bytes < 10_485_760 ? 1 : 0)} MiB`;
}

function isManagedLogStream(value: string): value is ManagedLogStream {
  return value === 'stdout' || value === 'stderr';
}
