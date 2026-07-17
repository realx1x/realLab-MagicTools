import { useEffect, useRef, useState } from 'react';

import type {
  ManagedStopOperationResult,
  ProcessInstanceKey,
  ProcessRecord,
  StopExternalProcessResult,
} from '@dpm/generated-types';

import {
  forceStopManagedRun,
  getProcessDetails,
  gracefullyStopManagedRun,
  stopExactExternalProcess,
} from '../../lib/processStops';
import {
  canRequestGracefulStop,
  presentExternalStopOutcome,
  presentManagedStopOperation,
  processInstanceKeysEqual,
  processStopConfirmationMatches,
  shouldShortPollProcessControl,
  type AuthoritativeProcessControlDetails,
  type ExternalStopConfirmationToken,
  type ForceStopConfirmationToken,
  type ProcessStopConfirmationToken,
  type ProcessStopStatusPresentation,
} from './processStopModel';

const PROCESS_CONTROL_POLL_INTERVAL_MS = 1_000;

const CONTROL_CHANGED_FEEDBACK: ProcessStopStatusPresentation = Object.freeze({
  detail: 'Review the current process controls before trying again.',
  icon: 'shieldAlert',
  title: 'Process control changed',
  tone: 'warning',
});

const STOP_REQUEST_FAILED_FEEDBACK: ProcessStopStatusPresentation = Object.freeze({
  detail: 'The Supervisor could not accept the stop request.',
  icon: 'triangleAlert',
  title: 'Stop request failed',
  tone: 'danger',
});

interface SelectionScope {
  readonly key: string | null;
  readonly version: number;
}

interface DetailsQueryState {
  readonly details: AuthoritativeProcessControlDetails | null;
  readonly error: boolean;
  readonly loading: boolean;
  readonly scopeVersion: number;
}

interface ScopedExternalResult {
  readonly result: StopExternalProcessResult | null;
  readonly scopeVersion: number;
}

interface DetailsQueryTask {
  readonly execute: () => Promise<void>;
  readonly scopeVersion: number;
}

interface ManagedStopSubmission {
  readonly processInstanceKey: ProcessInstanceKey;
  readonly scopeVersion: number;
}

interface ExternalStopSubmission extends ManagedStopSubmission {
  readonly token: ExternalStopConfirmationToken;
}

export interface UseProcessStopControllerOptions {
  readonly connected: boolean;
  readonly process: ProcessRecord | null;
}

export interface UseProcessStopControllerResult {
  readonly cancelConfirmation: () => void;
  readonly clearFeedback: () => void;
  readonly confirmation: ProcessStopConfirmationToken | null;
  readonly confirmStop: (token: ProcessStopConfirmationToken) => void;
  readonly details: AuthoritativeProcessControlDetails | null;
  readonly detailsError: boolean;
  readonly detailsLoading: boolean;
  readonly externalResult: StopExternalProcessResult | null;
  readonly feedback: ProcessStopStatusPresentation | null;
  readonly requestExternalConfirmation: (token: ExternalStopConfirmationToken) => void;
  readonly requestForceConfirmation: (token: ForceStopConfirmationToken) => void;
  readonly requestGracefulStop: () => void;
  readonly submitting: boolean;
}

export function useProcessStopController({
  connected,
  process,
}: UseProcessStopControllerOptions): UseProcessStopControllerResult {
  const nextScopeKey = connected && process !== null ? processIdentity(process.instanceKey) : null;
  const selectionScopeRef = useRef<SelectionScope>({ key: nextScopeKey, version: 0 });
  if (selectionScopeRef.current.key !== nextScopeKey) {
    selectionScopeRef.current = {
      key: nextScopeKey,
      version: selectionScopeRef.current.version + 1,
    };
  }
  const scopeVersion = selectionScopeRef.current.version;
  const hasQueryTarget = connected && process !== null;

  const connectedRef = useRef(connected);
  const processRef = useRef<ProcessRecord | null>(process);
  connectedRef.current = connected;
  processRef.current = process;

  const initialDetailsState: DetailsQueryState = {
    details: null,
    error: false,
    loading: hasQueryTarget,
    scopeVersion,
  };
  const [detailsState, setDetailsState] = useState<DetailsQueryState>(initialDetailsState);
  const detailsRef = useRef<DetailsQueryState>(initialDetailsState);
  const [externalResultState, setExternalResultState] = useState<ScopedExternalResult>({
    result: null,
    scopeVersion,
  });
  const externalResultRef = useRef<ScopedExternalResult>({
    result: null,
    scopeVersion,
  });
  const [confirmationState, setConfirmationState] = useState<ProcessStopConfirmationToken | null>(
    null,
  );
  const confirmationRef = useRef<ProcessStopConfirmationToken | null>(null);
  const [feedback, setFeedback] = useState<ProcessStopStatusPresentation | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const submittingRef = useRef(false);

  const mountedRef = useRef(true);
  const detailsSequenceRef = useRef(0);
  const detailsQueryTaskRef = useRef<DetailsQueryTask | null>(null);
  const detailsQueryInFlightRef = useRef(false);
  const detailsQueryPendingRef = useRef(false);
  const detailsPollTimerRef = useRef<ReturnType<typeof globalThis.setTimeout> | null>(null);
  const mutationSequenceRef = useRef(0);
  const requestDetailsRef = useRef<() => void>(() => undefined);

  function clearDetailsPollTimer() {
    if (detailsPollTimerRef.current !== null) {
      globalThis.clearTimeout(detailsPollTimerRef.current);
      detailsPollTimerRef.current = null;
    }
  }

  function readCurrentDetails(): AuthoritativeProcessControlDetails | null {
    const current = detailsRef.current;
    return current.scopeVersion === selectionScopeRef.current.version ? current.details : null;
  }

  function shouldPollCurrentDetails(): boolean {
    if (!mountedRef.current || !connectedRef.current || submittingRef.current) {
      return false;
    }
    const currentProcess = processRef.current;
    const currentDetails = readCurrentDetails();
    return (
      currentProcess !== null &&
      currentDetails !== null &&
      processInstanceKeysEqual(currentProcess.instanceKey, currentDetails.processInstanceKey) &&
      shouldShortPollProcessControl(currentProcess, currentDetails)
    );
  }

  function scheduleDetailsPoll() {
    clearDetailsPollTimer();
    if (
      detailsQueryInFlightRef.current ||
      detailsQueryPendingRef.current ||
      !shouldPollCurrentDetails()
    ) {
      return;
    }
    detailsPollTimerRef.current = globalThis.setTimeout(() => {
      detailsPollTimerRef.current = null;
      if (shouldPollCurrentDetails()) {
        requestDetailsRef.current();
      }
    }, PROCESS_CONTROL_POLL_INTERVAL_MS);
  }

  function runQueuedDetailsQuery() {
    if (!mountedRef.current || detailsQueryInFlightRef.current || !detailsQueryPendingRef.current) {
      return;
    }
    const task = detailsQueryTaskRef.current;
    detailsQueryPendingRef.current = false;
    if (task === null || task.scopeVersion !== selectionScopeRef.current.version) {
      return;
    }

    detailsQueryInFlightRef.current = true;
    const finish = () => {
      detailsQueryInFlightRef.current = false;
      if (!mountedRef.current) {
        return;
      }
      if (detailsQueryPendingRef.current) {
        runQueuedDetailsQuery();
      } else {
        scheduleDetailsPoll();
      }
    };
    void task.execute().then(finish, finish);
  }

  function requestDetails() {
    clearDetailsPollTimer();
    const task = detailsQueryTaskRef.current;
    if (
      !mountedRef.current ||
      task === null ||
      task.scopeVersion !== selectionScopeRef.current.version
    ) {
      return;
    }
    detailsQueryPendingRef.current = true;
    runQueuedDetailsQuery();
  }
  requestDetailsRef.current = requestDetails;

  function publishConfirmation(next: ProcessStopConfirmationToken | null) {
    confirmationRef.current = next;
    if (mountedRef.current) {
      setConfirmationState(next);
    }
  }

  function publishExternalResult(scope: number, result: StopExternalProcessResult | null) {
    const next: ScopedExternalResult = { result, scopeVersion: scope };
    externalResultRef.current = next;
    if (mountedRef.current) {
      setExternalResultState(next);
    }
  }

  function revalidateUnsubmittedConfirmation() {
    const token = confirmationRef.current;
    if (token === null || submittingRef.current) {
      return;
    }
    const currentProcess = processRef.current;
    const currentDetails = readCurrentDetails();
    if (
      !connectedRef.current ||
      currentProcess === null ||
      currentDetails === null ||
      !processStopConfirmationMatches(token, currentProcess, currentDetails)
    ) {
      publishConfirmation(null);
    }
  }

  function revalidateExternalResult() {
    const scopedResult = externalResultRef.current;
    if (
      scopedResult.result === null ||
      scopedResult.scopeVersion !== selectionScopeRef.current.version
    ) {
      return;
    }
    const currentProcess = processRef.current;
    const currentDetails = readCurrentDetails();
    if (
      !connectedRef.current ||
      currentProcess === null ||
      currentDetails === null ||
      currentDetails.control.kind !== 'external' ||
      !processInstanceKeysEqual(currentProcess.instanceKey, scopedResult.result.processInstanceKey)
    ) {
      publishExternalResult(selectionScopeRef.current.version, null);
    }
  }

  function publishDetails(next: DetailsQueryState) {
    detailsRef.current = next;
    if (mountedRef.current) {
      setDetailsState(next);
    }
    revalidateUnsubmittedConfirmation();
    revalidateExternalResult();
  }

  function invalidateOutstandingDetailsQuery() {
    detailsSequenceRef.current += 1;
    detailsQueryPendingRef.current = false;
    clearDetailsPollTimer();
  }

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      detailsSequenceRef.current += 1;
      detailsQueryTaskRef.current = null;
      detailsQueryPendingRef.current = false;
      clearDetailsPollTimer();
    };
  }, []);

  useEffect(() => {
    const effectScopeVersion = scopeVersion;
    const targetProcess = connected && process !== null ? process : null;
    const targetKey =
      targetProcess === null ? null : copyProcessInstanceKey(targetProcess.instanceKey);
    let active = true;

    invalidateOutstandingDetailsQuery();
    const resetDetails: DetailsQueryState = {
      details: null,
      error: false,
      loading: targetKey !== null,
      scopeVersion: effectScopeVersion,
    };
    detailsRef.current = resetDetails;
    setDetailsState(resetDetails);
    publishExternalResult(effectScopeVersion, null);
    if (!submittingRef.current) {
      publishConfirmation(null);
    }

    if (targetKey === null) {
      detailsQueryTaskRef.current = null;
      return () => {
        active = false;
      };
    }

    const task: DetailsQueryTask = {
      execute: async () => {
        const sequence = detailsSequenceRef.current + 1;
        detailsSequenceRef.current = sequence;
        try {
          const response = await getProcessDetails(targetKey);
          if (
            !active ||
            !mountedRef.current ||
            detailsSequenceRef.current !== sequence ||
            selectionScopeRef.current.version !== effectScopeVersion ||
            !processInstanceKeysEqual(response.processInstanceKey, targetKey)
          ) {
            return;
          }
          publishDetails({
            details: response,
            error: false,
            loading: false,
            scopeVersion: effectScopeVersion,
          });
        } catch {
          if (
            !active ||
            !mountedRef.current ||
            detailsSequenceRef.current !== sequence ||
            selectionScopeRef.current.version !== effectScopeVersion
          ) {
            return;
          }
          publishDetails({
            details: null,
            error: true,
            loading: false,
            scopeVersion: effectScopeVersion,
          });
        }
      },
      scopeVersion: effectScopeVersion,
    };
    detailsQueryTaskRef.current = task;
    requestDetailsRef.current();

    return () => {
      active = false;
      detailsSequenceRef.current += 1;
      detailsQueryPendingRef.current = false;
      clearDetailsPollTimer();
      if (detailsQueryTaskRef.current === task) {
        detailsQueryTaskRef.current = null;
      }
    };
  }, [process?.managedRunId, process?.ownership, scopeVersion]);

  useEffect(() => {
    revalidateUnsubmittedConfirmation();
    revalidateExternalResult();
  }, [connected, process?.managedRunId, process?.ownership, scopeVersion]);

  function rejectStaleControl() {
    if (!submittingRef.current) {
      publishConfirmation(null);
    }
    if (mountedRef.current) {
      setFeedback(CONTROL_CHANGED_FEEDBACK);
    }
  }

  function beginMutation(): number | null {
    if (!mountedRef.current || submittingRef.current) {
      return null;
    }
    const mutationSequence = mutationSequenceRef.current + 1;
    mutationSequenceRef.current = mutationSequence;
    submittingRef.current = true;
    invalidateOutstandingDetailsQuery();
    setSubmitting(true);
    setFeedback(null);
    return mutationSequence;
  }

  function finishMutation(mutationSequence: number) {
    if (!mountedRef.current || mutationSequenceRef.current !== mutationSequence) {
      return;
    }
    submittingRef.current = false;
    setSubmitting(false);
    publishConfirmation(null);
    scheduleDetailsPoll();
  }

  function mutationFailed(mutationSequence: number) {
    if (!mountedRef.current || mutationSequenceRef.current !== mutationSequence) {
      return;
    }
    setFeedback(STOP_REQUEST_FAILED_FEEDBACK);
    finishMutation(mutationSequence);
  }

  function selectionStillMatches(submission: ManagedStopSubmission): boolean {
    const currentProcess = processRef.current;
    return (
      connectedRef.current &&
      selectionScopeRef.current.version === submission.scopeVersion &&
      currentProcess !== null &&
      processInstanceKeysEqual(currentProcess.instanceKey, submission.processInstanceKey)
    );
  }

  function applyManagedResult(
    mutationSequence: number,
    submission: ManagedStopSubmission,
    result: ManagedStopOperationResult,
  ) {
    if (!mountedRef.current || mutationSequenceRef.current !== mutationSequence) {
      return;
    }
    setFeedback(presentManagedStopOperation(result));
    if (!selectionStillMatches(submission)) {
      return;
    }

    const terminal = result.status === 'completed' || result.status === 'superseded';
    invalidateOutstandingDetailsQuery();
    publishExternalResult(submission.scopeVersion, null);
    publishDetails({
      details: {
        control: {
          activeStop: terminal ? null : result,
          kind: 'managed',
          run: result.run,
        },
        processInstanceKey: copyProcessInstanceKey(submission.processInstanceKey),
      },
      error: false,
      loading: false,
      scopeVersion: submission.scopeVersion,
    });
    if (!terminal) {
      requestDetailsRef.current();
    }
  }

  function applyExternalResult(
    mutationSequence: number,
    submission: ExternalStopSubmission,
    result: StopExternalProcessResult,
  ) {
    if (!mountedRef.current || mutationSequenceRef.current !== mutationSequence) {
      return;
    }
    setFeedback(presentExternalStopOutcome(result.outcome));
    const currentProcess = processRef.current;
    const currentDetails = readCurrentDetails();
    if (
      !selectionStillMatches(submission) ||
      currentProcess === null ||
      currentDetails === null ||
      !processStopConfirmationMatches(submission.token, currentProcess, currentDetails)
    ) {
      return;
    }
    publishExternalResult(submission.scopeVersion, result);
  }

  function requestGracefulStop() {
    if (submittingRef.current || confirmationRef.current !== null) {
      return;
    }
    const currentProcess = processRef.current;
    const currentDetails = readCurrentDetails();
    if (
      !connectedRef.current ||
      currentProcess === null ||
      currentDetails === null ||
      !canRequestGracefulStop(currentProcess, currentDetails) ||
      currentDetails.control.kind !== 'managed'
    ) {
      rejectStaleControl();
      return;
    }

    const mutationSequence = beginMutation();
    if (mutationSequence === null) {
      return;
    }
    const submission: ManagedStopSubmission = {
      processInstanceKey: copyProcessInstanceKey(currentProcess.instanceKey),
      scopeVersion: selectionScopeRef.current.version,
    };
    void gracefullyStopManagedRun(
      currentDetails.control.run.runId,
      submission.processInstanceKey,
    ).then(
      (result) => {
        applyManagedResult(mutationSequence, submission, result);
        finishMutation(mutationSequence);
      },
      () => {
        mutationFailed(mutationSequence);
      },
    );
  }

  function requestExternalConfirmation(token: ExternalStopConfirmationToken) {
    if (submittingRef.current) {
      return;
    }
    const currentProcess = processRef.current;
    const currentDetails = readCurrentDetails();
    const currentExternalResult = externalResultRef.current;
    if (
      !connectedRef.current ||
      currentProcess === null ||
      currentDetails === null ||
      (currentExternalResult.scopeVersion === selectionScopeRef.current.version &&
        currentExternalResult.result !== null) ||
      !processStopConfirmationMatches(token, currentProcess, currentDetails)
    ) {
      rejectStaleControl();
      return;
    }
    setFeedback(null);
    publishConfirmation(token);
  }

  function requestForceConfirmation(token: ForceStopConfirmationToken) {
    if (submittingRef.current) {
      return;
    }
    const currentProcess = processRef.current;
    const currentDetails = readCurrentDetails();
    if (
      !connectedRef.current ||
      currentProcess === null ||
      currentDetails === null ||
      !processStopConfirmationMatches(token, currentProcess, currentDetails)
    ) {
      rejectStaleControl();
      return;
    }
    setFeedback(null);
    publishConfirmation(token);
  }

  function cancelConfirmation() {
    if (!submittingRef.current) {
      publishConfirmation(null);
    }
  }

  function confirmStop(token: ProcessStopConfirmationToken) {
    if (submittingRef.current) {
      return;
    }
    const currentConfirmation = confirmationRef.current;
    const currentProcess = processRef.current;
    const currentDetails = readCurrentDetails();
    if (
      !connectedRef.current ||
      currentConfirmation === null ||
      currentProcess === null ||
      currentDetails === null ||
      !confirmationTokensEqual(currentConfirmation, token) ||
      !processStopConfirmationMatches(token, currentProcess, currentDetails)
    ) {
      rejectStaleControl();
      return;
    }

    const mutationSequence = beginMutation();
    if (mutationSequence === null) {
      return;
    }
    const processInstanceKey = copyProcessInstanceKey(token.processInstanceKey);
    if (token.kind === 'force') {
      const submission: ManagedStopSubmission = {
        processInstanceKey,
        scopeVersion: selectionScopeRef.current.version,
      };
      void forceStopManagedRun(token.runId, processInstanceKey, token.gracefulOperationId).then(
        (result) => {
          applyManagedResult(mutationSequence, submission, result);
          finishMutation(mutationSequence);
        },
        () => {
          mutationFailed(mutationSequence);
        },
      );
      return;
    }

    const submission: ExternalStopSubmission = {
      processInstanceKey,
      scopeVersion: selectionScopeRef.current.version,
      token,
    };
    void stopExactExternalProcess(processInstanceKey).then(
      (result) => {
        applyExternalResult(mutationSequence, submission, result);
        finishMutation(mutationSequence);
      },
      () => {
        mutationFailed(mutationSequence);
      },
    );
  }

  function clearFeedback() {
    setFeedback(null);
  }

  const detailsStateIsCurrent = detailsState.scopeVersion === scopeVersion;
  const details = hasQueryTarget && detailsStateIsCurrent ? detailsState.details : null;
  const externalResult =
    hasQueryTarget && externalResultState.scopeVersion === scopeVersion
      ? externalResultState.result
      : null;
  const visibleConfirmation =
    submitting ||
    (confirmationState !== null &&
      process !== null &&
      details !== null &&
      processStopConfirmationMatches(confirmationState, process, details))
      ? confirmationState
      : null;

  return {
    cancelConfirmation,
    clearFeedback,
    confirmation: visibleConfirmation,
    confirmStop,
    details,
    detailsError: hasQueryTarget && detailsStateIsCurrent ? detailsState.error : false,
    detailsLoading: hasQueryTarget && (!detailsStateIsCurrent || detailsState.loading),
    externalResult,
    feedback,
    requestExternalConfirmation,
    requestForceConfirmation,
    requestGracefulStop,
    submitting,
  };
}

function processIdentity(key: ProcessInstanceKey): string {
  return JSON.stringify([key.bootId, key.pid, key.nativeStartTime]);
}

function copyProcessInstanceKey(key: Readonly<ProcessInstanceKey>): ProcessInstanceKey {
  return {
    bootId: key.bootId,
    nativeStartTime: key.nativeStartTime,
    pid: key.pid,
  };
}

function confirmationTokensEqual(
  left: ProcessStopConfirmationToken,
  right: ProcessStopConfirmationToken,
): boolean {
  if (
    left.kind !== right.kind ||
    !processInstanceKeysEqual(left.processInstanceKey, right.processInstanceKey)
  ) {
    return false;
  }
  if (left.kind === 'external' && right.kind === 'external') {
    return left.scope === right.scope;
  }
  return (
    left.kind === 'force' &&
    right.kind === 'force' &&
    left.runId === right.runId &&
    left.gracefulOperationId === right.gracefulOperationId
  );
}
