import { useEffect, useRef, useState, type ReactNode, type RefObject } from 'react';
import { useNavigate } from 'react-router-dom';
import { AlertTriangle, LoaderCircle, LogOut, Square, X } from 'lucide-react';

import type { ExitImpactSummary, ExitRunImpact, StopAllForExitResult } from '@dpm/generated-types';
import {
  Button,
  DialogContent,
  DialogDescription,
  DialogOverlay,
  DialogPortal,
  DialogRoot,
  DialogTitle,
} from '@dpm/ui';

import {
  acknowledgeDesktopNavigation,
  cancelDesktopExit,
  completeDesktopExit,
  connectDesktopLifecycle,
  type DesktopExitRequest,
  type DesktopNavigationRequest,
} from '../lib/appLifecycle';
import {
  createStopAllForExitOperationId,
  exitRunId,
  getExitImpact,
  isStaleExitAssessmentError,
  stopAllForExit,
} from '../lib/managedExit';

type ExitPhase = 'checking' | 'decision' | 'stopping' | 'blocked' | 'error' | 'completing';

type BlockedReason = 'newTasks' | 'retained' | 'timedOut' | 'inconsistent';
type ErrorPhase = 'assessment' | 'stopping' | 'completion';

interface ExitFlowState {
  blockedReason: BlockedReason | null;
  errorPhase: ErrorPhase | null;
  expectedAssessmentId: string | null;
  impact: ExitImpactSummary | null;
  initialRunIds: readonly string[];
  operationId: string | null;
  phase: ExitPhase;
  request: DesktopExitRequest;
  result: StopAllForExitResult | null;
}

const STOP_PROGRESS_INTERVAL_MS = 750;
const LIFECYCLE_RETRY_BASE_MS = 250;
const LIFECYCLE_RETRY_MAX_MS = 8_000;

export function DesktopLifecycleController({ children }: { children: ReactNode }) {
  const navigate = useNavigate();
  const [flow, setFlow] = useState<ExitFlowState | null>(null);
  const flowRef = useRef<ExitFlowState | null>(null);
  const mountedRef = useRef(true);
  const navigateRef = useRef(navigate);
  const epochRef = useRef(0);
  const appliedNavigationSequenceRef = useRef(0);
  const navigationNonceRef = useRef<string | null>(null);
  const navigationSequenceRef = useRef(0);
  const progressTimerRef = useRef<ReturnType<typeof globalThis.setTimeout> | null>(null);
  const cancelButtonRef = useRef<HTMLButtonElement | null>(null);
  const acceptExitRequestRef = useRef<(request: DesktopExitRequest) => void>(() => undefined);
  const acceptNavigationRequestRef = useRef<(request: DesktopNavigationRequest) => void>(
    () => undefined,
  );
  navigateRef.current = navigate;

  function publishFlow(next: ExitFlowState | null) {
    flowRef.current = next;
    if (mountedRef.current) {
      setFlow(next);
    }
  }

  function clearProgressTimer() {
    if (progressTimerRef.current !== null) {
      globalThis.clearTimeout(progressTimerRef.current);
      progressTimerRef.current = null;
    }
  }

  function isCurrent(epoch: number, nonce: string): boolean {
    return (
      mountedRef.current && epochRef.current === epoch && flowRef.current?.request.nonce === nonce
    );
  }

  function finishExit(state: ExitFlowState) {
    clearProgressTimer();
    const epoch = epochRef.current + 1;
    epochRef.current = epoch;
    const completing = { ...state, errorPhase: null, phase: 'completing' as const };
    publishFlow(completing);
    void completeDesktopExit(state.request.nonce).then(
      (accepted) => {
        if (accepted || !isCurrent(epoch, state.request.nonce)) {
          return;
        }
        publishFlow({ ...completing, errorPhase: 'completion', phase: 'error' });
      },
      () => {
        if (isCurrent(epoch, state.request.nonce)) {
          publishFlow({ ...completing, errorPhase: 'completion', phase: 'error' });
        }
      },
    );
  }

  async function assessExit(request: DesktopExitRequest, epoch: number) {
    try {
      const impact = await getExitImpact();
      if (!isCurrent(epoch, request.nonce)) {
        return;
      }
      const next: ExitFlowState = {
        blockedReason: null,
        errorPhase: null,
        expectedAssessmentId: null,
        impact,
        initialRunIds: impact.runs.map(exitRunId),
        operationId: null,
        phase: impact.runs.length === 0 ? 'completing' : 'decision',
        request,
        result: null,
      };
      if (impact.runs.length === 0) {
        finishExit(next);
      } else {
        publishFlow(next);
      }
    } catch {
      if (isCurrent(epoch, request.nonce)) {
        publishFlow({
          blockedReason: null,
          errorPhase: 'assessment',
          expectedAssessmentId: null,
          impact: null,
          initialRunIds: [],
          operationId: null,
          phase: 'error',
          request,
          result: null,
        });
      }
    }
  }

  function acceptExitRequest(request: DesktopExitRequest) {
    if (flowRef.current?.request.nonce === request.nonce) {
      return;
    }
    clearProgressTimer();
    const epoch = epochRef.current + 1;
    epochRef.current = epoch;
    publishFlow({
      blockedReason: null,
      errorPhase: null,
      expectedAssessmentId: null,
      impact: null,
      initialRunIds: [],
      operationId: null,
      phase: 'checking',
      request,
      result: null,
    });
    void assessExit(request, epoch);
  }
  acceptExitRequestRef.current = acceptExitRequest;

  function acceptNavigationRequest(request: DesktopNavigationRequest) {
    if (navigationNonceRef.current === request.nonce) {
      return;
    }
    navigationNonceRef.current = request.nonce;
    const sequence = navigationSequenceRef.current + 1;
    navigationSequenceRef.current = sequence;
    void acknowledgeDesktopNavigation(request.nonce).then(
      (accepted) => {
        if (accepted && mountedRef.current && sequence > appliedNavigationSequenceRef.current) {
          appliedNavigationSequenceRef.current = sequence;
          navigateRef.current(
            request.route === 'launch-profiles' ? '/launch-profiles' : '/settings',
          );
        }
      },
      () => {
        if (navigationNonceRef.current === request.nonce) {
          navigationNonceRef.current = null;
        }
      },
    );
  }
  acceptNavigationRequestRef.current = acceptNavigationRequest;

  useEffect(() => {
    mountedRef.current = true;
    let disposed = false;
    let disposeConnection: (() => void) | null = null;
    let retryAttempt = 0;
    let retryTimer: ReturnType<typeof globalThis.setTimeout> | null = null;

    const connect = () => {
      void connectDesktopLifecycle({
        onExitRequest: (request) => acceptExitRequestRef.current(request),
        onNavigationRequest: (request) => acceptNavigationRequestRef.current(request),
      }).then(
        (connection) => {
          if (disposed) {
            connection.dispose();
            return;
          }
          disposeConnection = () => connection.dispose();
          if (connection.snapshot.pendingNavigation !== null) {
            acceptNavigationRequestRef.current(connection.snapshot.pendingNavigation);
          }
          if (connection.snapshot.pendingExit !== null) {
            acceptExitRequestRef.current(connection.snapshot.pendingExit);
          }
        },
        () => {
          if (disposed) {
            return;
          }
          const delay = Math.min(
            LIFECYCLE_RETRY_BASE_MS * 2 ** Math.min(retryAttempt, 5),
            LIFECYCLE_RETRY_MAX_MS,
          );
          retryAttempt += 1;
          retryTimer = globalThis.setTimeout(() => {
            retryTimer = null;
            connect();
          }, delay);
        },
      );
    };
    connect();
    return () => {
      disposed = true;
      mountedRef.current = false;
      epochRef.current += 1;
      clearProgressTimer();
      if (retryTimer !== null) {
        globalThis.clearTimeout(retryTimer);
      }
      disposeConnection?.();
    };
  }, []);

  function cancelExitFlow() {
    const current = flowRef.current;
    if (current === null || current.phase === 'completing') {
      return;
    }
    epochRef.current += 1;
    clearProgressTimer();
    publishFlow(null);
    void cancelDesktopExit(current.request.nonce);
  }

  async function advanceStopFlow(state: ExitFlowState, epoch: number) {
    const operationId = state.operationId;
    const expectedAssessmentId = state.expectedAssessmentId;
    if (operationId === null || expectedAssessmentId === null) {
      return;
    }
    try {
      const result = await stopAllForExit(expectedAssessmentId, operationId);
      if (!isCurrent(epoch, state.request.nonce)) {
        return;
      }
      if (
        !sameRunIds(
          result.members.map((member) => member.runId),
          state.initialRunIds,
        )
      ) {
        publishFlow({
          ...state,
          blockedReason: 'inconsistent',
          phase: 'blocked',
          result,
        });
        return;
      }
      const currentImpact = await getExitImpact();
      if (!isCurrent(epoch, state.request.nonce)) {
        return;
      }
      const updated = { ...state, impact: currentImpact, result };
      if (currentImpact.runs.length === 0) {
        finishExit(updated);
        return;
      }
      const blockedReason = blockReasonForImpact(currentImpact, state.initialRunIds);
      if (blockedReason !== null) {
        publishFlow({ ...updated, blockedReason, phase: 'blocked' });
        return;
      }
      publishFlow({ ...updated, blockedReason: null, phase: 'stopping' });
      progressTimerRef.current = globalThis.setTimeout(() => {
        progressTimerRef.current = null;
        if (isCurrent(epoch, state.request.nonce)) {
          void advanceStopFlow({ ...updated, phase: 'stopping' }, epoch);
        }
      }, STOP_PROGRESS_INTERVAL_MS);
    } catch (error) {
      try {
        const currentImpact = await getExitImpact();
        if (!isCurrent(epoch, state.request.nonce)) {
          return;
        }
        if (
          isStaleExitAssessmentError(
            error,
            operationId,
            expectedAssessmentId,
            currentImpact.assessmentId,
          )
        ) {
          const decision: ExitFlowState = {
            ...state,
            blockedReason: null,
            errorPhase: null,
            expectedAssessmentId: null,
            impact: currentImpact,
            initialRunIds: currentImpact.runs.map(exitRunId),
            operationId: null,
            phase: currentImpact.runs.length === 0 ? 'completing' : 'decision',
            result: null,
          };
          if (currentImpact.runs.length === 0) {
            finishExit(decision);
          } else {
            publishFlow(decision);
          }
          return;
        }
        const blockedReason = blockReasonForImpact(currentImpact, state.initialRunIds);
        if (blockedReason !== null) {
          publishFlow({ ...state, blockedReason, impact: currentImpact, phase: 'blocked' });
          return;
        }
        publishFlow({ ...state, errorPhase: 'stopping', impact: currentImpact, phase: 'error' });
      } catch {
        if (isCurrent(epoch, state.request.nonce)) {
          publishFlow({ ...state, errorPhase: 'stopping', phase: 'error' });
        }
      }
    }
  }

  function requestStopAll() {
    const current = flowRef.current;
    if (current === null || current.impact === null || current.phase !== 'decision') {
      return;
    }
    const epoch = epochRef.current + 1;
    epochRef.current = epoch;
    const stopping: ExitFlowState = {
      ...current,
      errorPhase: null,
      expectedAssessmentId: current.impact.assessmentId,
      initialRunIds: current.impact.runs.map(exitRunId),
      operationId: createStopAllForExitOperationId(),
      phase: 'stopping',
      result: null,
    };
    publishFlow(stopping);
    void advanceStopFlow(stopping, epoch);
  }

  function retryExitFlow() {
    const current = flowRef.current;
    if (current === null || current.phase !== 'error') {
      return;
    }
    clearProgressTimer();
    const epoch = epochRef.current + 1;
    epochRef.current = epoch;
    if (current.errorPhase === 'stopping' && current.operationId !== null) {
      const stopping = { ...current, errorPhase: null, phase: 'stopping' as const };
      publishFlow(stopping);
      void advanceStopFlow(stopping, epoch);
      return;
    }
    const checking: ExitFlowState = {
      ...current,
      blockedReason: null,
      errorPhase: null,
      expectedAssessmentId: null,
      impact: null,
      initialRunIds: [],
      operationId: null,
      phase: 'checking',
      result: null,
    };
    publishFlow(checking);
    void assessExit(current.request, epoch);
  }

  function reassessBlockedFlow() {
    const current = flowRef.current;
    if (current === null || current.phase !== 'blocked') {
      return;
    }
    clearProgressTimer();
    const epoch = epochRef.current + 1;
    epochRef.current = epoch;
    const checking: ExitFlowState = {
      ...current,
      blockedReason: null,
      errorPhase: null,
      expectedAssessmentId: null,
      impact: null,
      initialRunIds: [],
      operationId: null,
      phase: 'checking',
      result: null,
    };
    publishFlow(checking);
    void assessExit(current.request, epoch);
  }

  return (
    <>
      {children}
      {flow !== null ? (
        <ExitDecisionDialog
          cancelButtonRef={cancelButtonRef}
          flow={flow}
          onCancel={cancelExitFlow}
          onKeepRunning={() => finishExit(flow)}
          onReassess={reassessBlockedFlow}
          onRetry={retryExitFlow}
          onStopAll={requestStopAll}
        />
      ) : null}
    </>
  );
}

interface ExitDecisionDialogProps {
  cancelButtonRef: RefObject<HTMLButtonElement | null>;
  flow: ExitFlowState;
  onCancel(): void;
  onKeepRunning(): void;
  onReassess(): void;
  onRetry(): void;
  onStopAll(): void;
}

function ExitDecisionDialog({
  cancelButtonRef,
  flow,
  onCancel,
  onKeepRunning,
  onReassess,
  onRetry,
  onStopAll,
}: ExitDecisionDialogProps) {
  const busy =
    flow.phase === 'checking' || flow.phase === 'stopping' || flow.phase === 'completing';
  const canDismiss = flow.phase !== 'completing';
  const impactCounts = flow.impact === null ? [] : summarizeImpacts(flow.impact.runs);
  const hasStopAttempt = flow.operationId !== null;

  return (
    <DialogRoot
      onOpenChange={(open) => {
        if (!open && canDismiss) {
          onCancel();
        }
      }}
      open={true}
    >
      <DialogPortal>
        <DialogOverlay className="exit-dialog-overlay" />
        <DialogContent
          aria-busy={busy}
          className="exit-dialog"
          onEscapeKeyDown={(event) => {
            if (!canDismiss) {
              event.preventDefault();
            }
          }}
          onOpenAutoFocus={(event) => {
            event.preventDefault();
            globalThis.requestAnimationFrame(() => cancelButtonRef.current?.focus());
          }}
        >
          <div className="exit-dialog-heading">
            {flow.phase === 'error' || flow.phase === 'blocked' ? (
              <AlertTriangle aria-hidden="true" size={18} strokeWidth={1.8} />
            ) : busy ? (
              <LoaderCircle
                aria-hidden="true"
                className="status-icon--busy"
                size={18}
                strokeWidth={1.8}
              />
            ) : (
              <LogOut aria-hidden="true" size={18} strokeWidth={1.8} />
            )}
            <DialogTitle>Quit MagicTools?</DialogTitle>
          </div>
          <DialogDescription aria-atomic="true" aria-live="polite">
            {exitDescription(flow)}
          </DialogDescription>
          {impactCounts.length > 0 ? (
            <ul className="exit-impact-summary" aria-label="Managed task impact">
              {impactCounts.map(({ count, label }) => (
                <li key={label}>
                  <span>{label}</span>
                  <strong>{count}</strong>
                </li>
              ))}
            </ul>
          ) : null}
          <div className="exit-dialog-actions">
            {canDismiss ? (
              <Button
                leadingIcon={<X aria-hidden="true" size={15} strokeWidth={1.8} />}
                onClick={onCancel}
                ref={cancelButtonRef}
                variant="ghost"
              >
                Cancel
              </Button>
            ) : null}
            {flow.phase === 'decision' ? (
              <Button
                leadingIcon={<Square aria-hidden="true" size={15} strokeWidth={1.8} />}
                onClick={onStopAll}
                variant="danger"
              >
                Stop all tasks
              </Button>
            ) : null}
            {flow.phase === 'error' ? <Button onClick={onRetry}>Retry</Button> : null}
            {flow.phase === 'blocked' ? <Button onClick={onReassess}>Recheck</Button> : null}
            {canDismiss && flow.phase !== 'checking' ? (
              <Button
                leadingIcon={<LogOut aria-hidden="true" size={15} strokeWidth={1.8} />}
                onClick={onKeepRunning}
                variant={flow.phase === 'decision' ? 'secondary' : 'primary'}
              >
                {hasStopAttempt ? 'Quit with remaining tasks' : 'Keep tasks running and quit'}
              </Button>
            ) : null}
          </div>
        </DialogContent>
      </DialogPortal>
    </DialogRoot>
  );
}

function exitDescription(flow: ExitFlowState): string {
  switch (flow.phase) {
    case 'checking':
      return 'Checking the authoritative managed-task state with the Supervisor.';
    case 'decision':
      return 'Quitting only closes the MagicTools interface. The independent Supervisor, managed tasks, and log capture continue unless you request a graceful stop.';
    case 'stopping':
      return 'Graceful stop requests are in progress. MagicTools stays open until the Supervisor confirms that no managed work remains.';
    case 'blocked':
      switch (flow.blockedReason) {
        case 'newTasks':
          return 'A task started after this stop-all decision. It was not stopped silently. Recheck the current task set or quit and leave the remaining work with the Supervisor.';
        case 'timedOut':
          return 'At least one graceful stop timed out. MagicTools does not force-stop it automatically; return to the process workspace for an explicit force-stop decision, or quit with it still managed.';
        case 'retained':
          return 'The Supervisor still owns work that cannot be stopped safely from this batch. It will remain managed if you quit.';
        case 'inconsistent':
        default:
          return 'The Supervisor returned a different fixed member set. MagicTools will not treat this batch as complete.';
      }
    case 'error':
      if (flow.errorPhase === 'completion') {
        return 'The native exit authorization expired or could not be completed. Recheck before trying again.';
      }
      if (flow.errorPhase === 'stopping') {
        return 'MagicTools could not confirm the stop-all progress. Retrying uses the same operation and fixed member set.';
      }
      return 'The Supervisor could not verify which managed tasks are active. Stop all is unavailable until an authoritative assessment succeeds.';
    case 'completing':
      return 'Closing the MagicTools interface.';
  }
}

function summarizeImpacts(
  impacts: readonly ExitRunImpact[],
): Array<{ count: number; label: string }> {
  const counts = new Map<string, number>();
  for (const impact of impacts) {
    const label = impactLabel(impact);
    counts.set(label, (counts.get(label) ?? 0) + 1);
  }
  return [...counts].map(([label, count]) => ({ count, label }));
}

function impactLabel(impact: ExitRunImpact): string {
  switch (impact.kind) {
    case 'launching':
      return 'Launching';
    case 'running':
      return 'Running';
    case 'gracefulStopping':
      return 'Graceful stop in progress';
    case 'gracefulTimedOut':
      return 'Graceful stop timed out';
    case 'forceStopping':
      return 'Force stop in progress';
    case 'retained':
      switch (impact.reason) {
        case 'quarantined':
          return 'Quarantined control';
        case 'cleanupPending':
          return 'Cleanup pending';
        case 'durableOnly':
          return 'Durable record without live control';
        case 'controlMismatch':
          return 'Control mismatch';
      }
  }
}

function sameRunIds(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((runId, index) => runId === right[index]);
}

function blockReasonForImpact(
  impact: ExitImpactSummary,
  initialRunIds: readonly string[],
): BlockedReason | null {
  const initial = new Set(initialRunIds);
  if (impact.runs.some((run) => !initial.has(exitRunId(run)))) {
    return 'newTasks';
  }
  if (impact.runs.some((run) => run.kind === 'gracefulTimedOut')) {
    return 'timedOut';
  }
  if (impact.runs.some((run) => run.kind === 'retained')) {
    return 'retained';
  }
  return null;
}
