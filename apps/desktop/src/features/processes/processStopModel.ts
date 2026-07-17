import type {
  ExternalProcessStopOutcome,
  ManagedRunSummary,
  ManagedStopOperationResult,
  ProcessInstanceKey,
  ProcessRecord,
  RunState,
} from '@dpm/generated-types';

export type ProcessRecordWithManagedRunId = ProcessRecord & {
  readonly managedRunId?: string | null;
};

export type AuthoritativeProcessControl =
  | {
      readonly kind: 'external';
    }
  | {
      readonly activeStop: ManagedStopOperationResult | null;
      readonly kind: 'managed';
      readonly run: ManagedRunSummary;
    };

export interface AuthoritativeProcessControlDetails {
  readonly control: AuthoritativeProcessControl;
  readonly processInstanceKey: ProcessInstanceKey;
}

export type ProcessControlConsistencyFailure =
  | 'activeStopIdentityMismatch'
  | 'activeStopRunMismatch'
  | 'detailsIdentityMismatch'
  | 'invalidManagedRunId'
  | 'managedRunIdMismatch'
  | 'managedRunIdentityMismatch'
  | 'missingManagedRunId'
  | 'ownershipMismatch';

export type ProcessControlConsistency =
  | {
      readonly control: AuthoritativeProcessControl;
      readonly kind: 'consistent';
      readonly managedRunId: string | null;
    }
  | {
      readonly kind: 'inconsistent';
      readonly reason: ProcessControlConsistencyFailure;
    };

export type ProcessStopStatusIcon =
  | 'checkCircle'
  | 'clock'
  | 'loader'
  | 'pauseCircle'
  | 'shieldAlert'
  | 'stopCircle'
  | 'triangleAlert';

export type ProcessStopStatusTone = 'busy' | 'danger' | 'neutral' | 'success' | 'warning';

export interface ProcessStopStatusPresentation {
  readonly detail: string;
  readonly icon: ProcessStopStatusIcon;
  readonly title: string;
  readonly tone: ProcessStopStatusTone;
}

export interface ExternalStopConfirmationToken {
  readonly kind: 'external';
  readonly processInstanceKey: Readonly<ProcessInstanceKey>;
  readonly scope: 'singleProcess';
}

export interface ForceStopConfirmationToken {
  readonly gracefulOperationId: string;
  readonly kind: 'force';
  readonly processInstanceKey: Readonly<ProcessInstanceKey>;
  readonly runId: string;
}

export type ProcessStopConfirmationToken =
  | ExternalStopConfirmationToken
  | ForceStopConfirmationToken;

type ManagedRunIdRead =
  | {
      readonly kind: 'known';
      readonly value: string | null;
    }
  | {
      readonly kind: 'invalid';
    }
  | {
      readonly kind: 'missing';
    };

export function processInstanceKeysEqual(
  left: ProcessInstanceKey | Readonly<ProcessInstanceKey> | null,
  right: ProcessInstanceKey | Readonly<ProcessInstanceKey> | null,
): boolean {
  return (
    left !== null &&
    right !== null &&
    left.bootId === right.bootId &&
    left.pid === right.pid &&
    left.nativeStartTime === right.nativeStartTime
  );
}

export function checkProcessControlConsistency(
  snapshot: ProcessRecordWithManagedRunId,
  details: AuthoritativeProcessControlDetails,
): ProcessControlConsistency {
  if (!processInstanceKeysEqual(snapshot.instanceKey, details.processInstanceKey)) {
    return inconsistent('detailsIdentityMismatch');
  }

  const managedRunId = readManagedRunId(snapshot);
  if (managedRunId.kind === 'missing') {
    return inconsistent('missingManagedRunId');
  }
  if (managedRunId.kind === 'invalid') {
    return inconsistent('invalidManagedRunId');
  }

  if (details.control.kind === 'external') {
    if (snapshot.ownership !== 'external') {
      return inconsistent('ownershipMismatch');
    }
    if (managedRunId.value !== null) {
      return inconsistent('managedRunIdMismatch');
    }
    return consistent(details.control, null);
  }

  const { activeStop, run } = details.control;
  if (snapshot.ownership !== 'managed') {
    return inconsistent('ownershipMismatch');
  }
  if (managedRunId.value !== run.runId || run.runId.length === 0) {
    return inconsistent('managedRunIdMismatch');
  }
  if (!processInstanceKeysEqual(snapshot.instanceKey, run.processInstanceKey)) {
    return inconsistent('managedRunIdentityMismatch');
  }
  if (activeStop !== null) {
    if (activeStop.run.runId !== run.runId || activeStop.operationId.length === 0) {
      return inconsistent('activeStopRunMismatch');
    }
    if (!processInstanceKeysEqual(snapshot.instanceKey, activeStop.run.processInstanceKey)) {
      return inconsistent('activeStopIdentityMismatch');
    }
  }
  return consistent(details.control, run.runId);
}

export function canRequestGracefulStop(
  snapshot: ProcessRecordWithManagedRunId,
  details: AuthoritativeProcessControlDetails,
): boolean {
  const consistency = checkProcessControlConsistency(snapshot, details);
  return (
    consistency.kind === 'consistent' &&
    consistency.control.kind === 'managed' &&
    consistency.control.activeStop === null &&
    isGracefullyStoppableRunState(consistency.control.run.state)
  );
}

export function canRequestForceStop(
  snapshot: ProcessRecordWithManagedRunId,
  details: AuthoritativeProcessControlDetails,
): boolean {
  return forceStopSupersessionOperationId(snapshot, details) !== null;
}

export function forceStopSupersessionOperationId(
  snapshot: ProcessRecordWithManagedRunId,
  details: AuthoritativeProcessControlDetails,
): string | null {
  const consistency = checkProcessControlConsistency(snapshot, details);
  if (consistency.kind !== 'consistent' || consistency.control.kind !== 'managed') {
    return null;
  }
  const { activeStop, run } = consistency.control;
  if (
    run.state !== 'gracefulStopping' ||
    activeStop === null ||
    activeStop.kind !== 'graceful' ||
    activeStop.status !== 'timedOut'
  ) {
    return null;
  }
  return activeStop.operationId;
}

export function shouldShortPollProcessControl(
  snapshot: ProcessRecordWithManagedRunId,
  details: AuthoritativeProcessControlDetails,
): boolean {
  const consistency = checkProcessControlConsistency(snapshot, details);
  if (consistency.kind !== 'consistent' || consistency.control.kind !== 'managed') {
    return false;
  }
  const { activeStop, run } = consistency.control;
  if (activeStop !== null && !isTerminalStopStatus(activeStop.status)) {
    return true;
  }
  return isTransitionalRunState(run.state);
}

export function presentAuthoritativeProcessControlStatus(
  control: AuthoritativeProcessControl,
): ProcessStopStatusPresentation {
  if (control.kind === 'external') {
    return {
      detail: 'This process is not controlled as a managed run.',
      icon: 'stopCircle',
      title: 'External process',
      tone: 'neutral',
    };
  }
  return control.activeStop === null
    ? presentManagedRunState(control.run.state)
    : presentManagedStopOperation(control.activeStop);
}

export function presentManagedRunState(state: RunState): ProcessStopStatusPresentation {
  switch (state) {
    case 'starting':
      return {
        detail: 'Supervisor is establishing managed process control.',
        icon: 'loader',
        title: 'Starting managed run',
        tone: 'busy',
      };
    case 'running':
      return {
        detail: 'Supervisor owns the running process control.',
        icon: 'checkCircle',
        title: 'Managed run is running',
        tone: 'success',
      };
    case 'stopRequested':
      return {
        detail: 'The request is waiting for the stop signal stage.',
        icon: 'clock',
        title: 'Stop requested',
        tone: 'busy',
      };
    case 'gracefulStopping':
      return {
        detail: 'Supervisor is waiting for the managed process to exit.',
        icon: 'loader',
        title: 'Stopping gracefully',
        tone: 'busy',
      };
    case 'forceStopping':
      return {
        detail: 'Supervisor is waiting for the managed control boundary to exit.',
        icon: 'loader',
        title: 'Force stopping',
        tone: 'warning',
      };
    case 'exited':
      return {
        detail: 'Managed process exit was confirmed.',
        icon: 'checkCircle',
        title: 'Managed run stopped',
        tone: 'success',
      };
    case 'failed':
      return {
        detail: 'The managed run ended in a failed state.',
        icon: 'triangleAlert',
        title: 'Managed run failed',
        tone: 'danger',
      };
    case 'recovered':
      return {
        detail: 'Supervisor restored control during startup reconciliation.',
        icon: 'shieldAlert',
        title: 'Managed run recovered',
        tone: 'neutral',
      };
    case 'exitedWhileOffline':
      return {
        detail: 'Exit was recorded during Supervisor startup reconciliation.',
        icon: 'checkCircle',
        title: 'Run exited while Supervisor was offline',
        tone: 'success',
      };
    case 'identityMismatch':
      return {
        detail: 'Supervisor did not continue control against a different process instance.',
        icon: 'shieldAlert',
        title: 'Process identity changed',
        tone: 'warning',
      };
    case 'orphaned':
      return {
        detail: 'Process exit could not be confirmed through the managed control boundary.',
        icon: 'triangleAlert',
        title: 'Managed process control lost',
        tone: 'warning',
      };
  }
}

export function presentManagedStopOperation(
  operation: ManagedStopOperationResult,
): ProcessStopStatusPresentation {
  switch (operation.status) {
    case 'requested':
      return {
        detail: 'Supervisor accepted the managed stop request.',
        icon: 'clock',
        title: 'Stop requested',
        tone: 'busy',
      };
    case 'signalPending':
      return {
        detail: 'Supervisor is revalidating process identity before signaling.',
        icon: 'loader',
        title: 'Preparing stop signal',
        tone: 'busy',
      };
    case 'inProgress':
      return presentInProgressStop(operation);
    case 'timedOut':
      return {
        detail: 'The process is still running under the managed control boundary.',
        icon: 'clock',
        title: 'Graceful stop timed out',
        tone: 'warning',
      };
    case 'completed':
      return presentManagedStopOutcome(operation.outcome);
    case 'superseded':
      return {
        detail: 'A confirmed force-stop operation replaced this graceful operation.',
        icon: 'pauseCircle',
        title: 'Graceful stop replaced',
        tone: 'warning',
      };
  }
}

export function presentManagedStopOutcome(
  outcome: ManagedStopOperationResult['outcome'],
): ProcessStopStatusPresentation {
  switch (outcome) {
    case 'exited':
      return {
        detail: 'Managed process exit was confirmed.',
        icon: 'checkCircle',
        title: 'Managed run stopped',
        tone: 'success',
      };
    case 'alreadyExited':
      return {
        detail: 'No additional stop signal was required.',
        icon: 'checkCircle',
        title: 'Managed run already exited',
        tone: 'success',
      };
    case 'identityMismatch':
      return {
        detail: 'Supervisor did not continue the stop against a different process instance.',
        icon: 'shieldAlert',
        title: 'Process identity changed',
        tone: 'warning',
      };
    case 'orphaned':
      return {
        detail: 'Process exit could not be confirmed through the managed control boundary.',
        icon: 'triangleAlert',
        title: 'Managed process control lost',
        tone: 'warning',
      };
    case 'signalUnavailable':
      return {
        detail: 'The platform could not deliver the requested stop signal.',
        icon: 'triangleAlert',
        title: 'Stop signal unavailable',
        tone: 'danger',
      };
    case 'failed':
      return {
        detail: 'Supervisor could not complete the managed stop operation.',
        icon: 'triangleAlert',
        title: 'Managed stop failed',
        tone: 'danger',
      };
    case null:
      return {
        detail: 'The completed operation did not include a terminal outcome.',
        icon: 'triangleAlert',
        title: 'Stop result unavailable',
        tone: 'danger',
      };
  }
}

export function presentExternalStopOutcome(
  outcome: ExternalProcessStopOutcome,
): ProcessStopStatusPresentation {
  switch (outcome) {
    case 'signalDelivered':
      return {
        detail: 'Delivery does not confirm that the process exited.',
        icon: 'checkCircle',
        title: 'Stop signal delivered',
        tone: 'success',
      };
  }
}

export function createExternalStopConfirmationToken(
  snapshot: ProcessRecordWithManagedRunId,
  details: AuthoritativeProcessControlDetails,
): ExternalStopConfirmationToken | null {
  const consistency = checkProcessControlConsistency(snapshot, details);
  if (consistency.kind !== 'consistent' || consistency.control.kind !== 'external') {
    return null;
  }
  return Object.freeze({
    kind: 'external',
    processInstanceKey: freezeProcessInstanceKey(snapshot.instanceKey),
    scope: 'singleProcess',
  });
}

export function createForceStopConfirmationToken(
  snapshot: ProcessRecordWithManagedRunId,
  details: AuthoritativeProcessControlDetails,
): ForceStopConfirmationToken | null {
  const operationId = forceStopSupersessionOperationId(snapshot, details);
  if (operationId === null || details.control.kind !== 'managed') {
    return null;
  }
  return Object.freeze({
    gracefulOperationId: operationId,
    kind: 'force',
    processInstanceKey: freezeProcessInstanceKey(snapshot.instanceKey),
    runId: details.control.run.runId,
  });
}

export function processStopConfirmationMatches(
  token: ProcessStopConfirmationToken,
  snapshot: ProcessRecordWithManagedRunId,
  details: AuthoritativeProcessControlDetails,
): boolean {
  if (!processInstanceKeysEqual(token.processInstanceKey, snapshot.instanceKey)) {
    return false;
  }
  const consistency = checkProcessControlConsistency(snapshot, details);
  if (consistency.kind !== 'consistent') {
    return false;
  }
  if (token.kind === 'external') {
    return token.scope === 'singleProcess' && consistency.control.kind === 'external';
  }
  if (consistency.control.kind !== 'managed') {
    return false;
  }
  return (
    consistency.control.run.runId === token.runId &&
    forceStopSupersessionOperationId(snapshot, details) === token.gracefulOperationId
  );
}

function readManagedRunId(snapshot: ProcessRecordWithManagedRunId): ManagedRunIdRead {
  if (!Object.prototype.hasOwnProperty.call(snapshot, 'managedRunId')) {
    return { kind: 'missing' };
  }
  const value: unknown = snapshot.managedRunId;
  if (value === null) {
    return { kind: 'known', value };
  }
  if (typeof value !== 'string' || value.length === 0) {
    return { kind: 'invalid' };
  }
  return { kind: 'known', value };
}

function isGracefullyStoppableRunState(state: RunState): boolean {
  return state === 'running' || state === 'recovered';
}

function isTransitionalRunState(state: RunState): boolean {
  return (
    state === 'starting' ||
    state === 'stopRequested' ||
    state === 'gracefulStopping' ||
    state === 'forceStopping'
  );
}

function isTerminalStopStatus(status: ManagedStopOperationResult['status']): boolean {
  return status === 'completed' || status === 'superseded';
}

function presentInProgressStop(
  operation: ManagedStopOperationResult,
): ProcessStopStatusPresentation {
  if (operation.signalDisposition === 'unavailable') {
    return {
      detail: 'The platform signal was unavailable while Supervisor finalizes the result.',
      icon: 'triangleAlert',
      title: 'Stop signal unavailable',
      tone: 'warning',
    };
  }
  if (operation.kind === 'force') {
    return {
      detail: 'Supervisor is waiting for the managed control boundary to exit.',
      icon: 'loader',
      title: 'Force stopping',
      tone: 'warning',
    };
  }
  return {
    detail: 'Supervisor is waiting for the managed process to exit.',
    icon: 'loader',
    title: 'Stopping gracefully',
    tone: 'busy',
  };
}

function freezeProcessInstanceKey(key: ProcessInstanceKey): Readonly<ProcessInstanceKey> {
  return Object.freeze({
    bootId: key.bootId,
    nativeStartTime: key.nativeStartTime,
    pid: key.pid,
  });
}

function consistent(
  control: AuthoritativeProcessControl,
  managedRunId: string | null,
): ProcessControlConsistency {
  return { control, kind: 'consistent', managedRunId };
}

function inconsistent(reason: ProcessControlConsistencyFailure): ProcessControlConsistency {
  return { kind: 'inconsistent', reason };
}
