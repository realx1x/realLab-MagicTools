import { useRef } from 'react';
import {
  CircleCheck,
  CirclePause,
  CircleStop,
  Clock3,
  Ellipsis,
  LoaderCircle,
  OctagonX,
  ShieldAlert,
  Square,
  TriangleAlert,
  X,
  type LucideIcon,
} from 'lucide-react';

import type { ProcessRecord, StopExternalProcessResult } from '@dpm/generated-types';
import {
  Button,
  DialogContent,
  DialogDescription,
  DialogOverlay,
  DialogPortal,
  DialogRoot,
  DialogTitle,
  IconButton,
  Menu,
} from '@dpm/ui';

import {
  canRequestForceStop,
  canRequestGracefulStop,
  checkProcessControlConsistency,
  createExternalStopConfirmationToken,
  createForceStopConfirmationToken,
  presentAuthoritativeProcessControlStatus,
  presentExternalStopOutcome,
  processInstanceKeysEqual,
  type AuthoritativeProcessControlDetails,
  type ExternalStopConfirmationToken,
  type ForceStopConfirmationToken,
  type ProcessStopConfirmationToken,
  type ProcessStopStatusIcon,
  type ProcessStopStatusPresentation,
} from './processStopModel';

export interface ProcessStopControlsProps {
  readonly details: AuthoritativeProcessControlDetails | null;
  readonly detailsError: boolean;
  readonly detailsLoading: boolean;
  readonly externalResult: StopExternalProcessResult | null;
  readonly onGracefulStop: () => void;
  readonly onRequestExternalConfirmation: (token: ExternalStopConfirmationToken) => void;
  readonly onRequestForceConfirmation: (token: ForceStopConfirmationToken) => void;
  readonly process: ProcessRecord;
  readonly submitting: boolean;
}

export interface ProcessStopConfirmationDialogProps {
  readonly onCancel: () => void;
  readonly onConfirm: (token: ProcessStopConfirmationToken) => void;
  readonly processName: string;
  readonly submitting: boolean;
  readonly token: ProcessStopConfirmationToken | null;
}

export interface ProcessStopFeedbackProps {
  readonly onDismiss: () => void;
  readonly presentation: ProcessStopStatusPresentation;
}

const SUBMITTING_PRESENTATION: ProcessStopStatusPresentation = {
  detail: 'Waiting for the Supervisor to accept the stop request.',
  icon: 'loader',
  title: 'Submitting stop request',
  tone: 'busy',
};

const STATUS_ICONS: Readonly<Record<ProcessStopStatusIcon, LucideIcon>> = {
  checkCircle: CircleCheck,
  clock: Clock3,
  loader: LoaderCircle,
  pauseCircle: CirclePause,
  shieldAlert: ShieldAlert,
  stopCircle: CircleStop,
  triangleAlert: TriangleAlert,
};

export function ProcessStopControls({
  details,
  detailsError,
  detailsLoading,
  externalResult,
  onGracefulStop,
  onRequestExternalConfirmation,
  onRequestForceConfirmation,
  process,
  submitting,
}: ProcessStopControlsProps) {
  if (detailsLoading || detailsError || details === null) {
    return <UnavailableControls />;
  }

  const consistency = checkProcessControlConsistency(process, details);
  if (consistency.kind !== 'consistent') {
    return <UnavailableControls />;
  }
  if (externalResult !== null && !externalResultMatches(process, details, externalResult)) {
    return <UnavailableControls />;
  }

  const presentation = submitting
    ? SUBMITTING_PRESENTATION
    : externalResult === null
      ? presentAuthoritativeProcessControlStatus(consistency.control)
      : presentExternalStopOutcome(externalResult.outcome);
  const gracefulAvailable = canRequestGracefulStop(process, details);
  const forceAvailable = canRequestForceStop(process, details);
  const externalAvailable = consistency.control.kind === 'external' && externalResult === null;

  const requestExternalConfirmation = () => {
    const token = createExternalStopConfirmationToken(process, details);
    if (token !== null) {
      onRequestExternalConfirmation(token);
    }
  };
  const requestForceConfirmation = () => {
    const token = createForceStopConfirmationToken(process, details);
    if (token !== null) {
      onRequestForceConfirmation(token);
    }
  };

  return (
    <section aria-label="Process controls" className="process-stop-controls">
      <StopStatus presentation={presentation} />
      {gracefulAvailable || forceAvailable || externalAvailable ? (
        <div className="process-stop-actions">
          {gracefulAvailable ? (
            <Button
              disabled={submitting}
              leadingIcon={<Square aria-hidden="true" size={14} strokeWidth={1.8} />}
              onClick={onGracefulStop}
              size="compact"
              variant="danger"
            >
              Stop
            </Button>
          ) : null}
          {externalAvailable ? (
            <Button
              disabled={submitting}
              leadingIcon={<Square aria-hidden="true" size={14} strokeWidth={1.8} />}
              onClick={requestExternalConfirmation}
              size="compact"
              variant="danger"
            >
              Stop process...
            </Button>
          ) : null}
          {forceAvailable ? (
            <Menu
              items={[
                {
                  danger: true,
                  disabled: submitting,
                  icon: <OctagonX aria-hidden="true" size={15} strokeWidth={1.8} />,
                  id: 'force-stop',
                  label: 'Force stop...',
                  onSelect: requestForceConfirmation,
                },
              ]}
              label="More stop actions"
              trigger={
                <IconButton
                  disabled={submitting}
                  icon={<Ellipsis aria-hidden="true" size={16} strokeWidth={1.8} />}
                  label="More stop actions"
                  variant="ghost"
                />
              }
            />
          ) : null}
        </div>
      ) : null}
    </section>
  );
}

export function ProcessStopConfirmationDialog({
  onCancel,
  onConfirm,
  processName,
  submitting,
  token,
}: ProcessStopConfirmationDialogProps) {
  const cancelButton = useRef<HTMLButtonElement>(null);
  const open = token !== null;

  return (
    <DialogRoot
      onOpenChange={(nextOpen) => {
        if (!nextOpen && !submitting) {
          onCancel();
        }
      }}
      open={open}
    >
      {token ? (
        <DialogPortal>
          <DialogOverlay className="process-stop-dialog-overlay" />
          <DialogContent
            aria-busy={submitting}
            className="process-stop-dialog"
            onEscapeKeyDown={(event) => {
              if (submitting) {
                event.preventDefault();
              }
            }}
            onOpenAutoFocus={(event) => {
              event.preventDefault();
              cancelButton.current?.focus({ preventScroll: true });
            }}
            onPointerDownOutside={(event) => {
              if (submitting) {
                event.preventDefault();
              }
            }}
          >
            <ConfirmationCopy processName={processName} token={token} />
            <div className="process-stop-dialog-actions">
              <Button disabled={submitting} onClick={onCancel} ref={cancelButton}>
                Cancel
              </Button>
              <Button
                disabled={submitting}
                leadingIcon={
                  submitting ? (
                    <LoaderCircle
                      aria-hidden="true"
                      className="process-stop-status-icon--busy"
                      size={15}
                      strokeWidth={1.8}
                    />
                  ) : token.kind === 'force' ? (
                    <OctagonX aria-hidden="true" size={15} strokeWidth={1.8} />
                  ) : (
                    <Square aria-hidden="true" size={14} strokeWidth={1.8} />
                  )
                }
                onClick={() => onConfirm(token)}
                variant="danger"
              >
                {submitting
                  ? 'Submitting...'
                  : token.kind === 'force'
                    ? 'Force stop'
                    : 'Stop process'}
              </Button>
            </div>
          </DialogContent>
        </DialogPortal>
      ) : null}
    </DialogRoot>
  );
}

export function ProcessStopFeedback({ onDismiss, presentation }: ProcessStopFeedbackProps) {
  const Icon = STATUS_ICONS[presentation.icon];
  return (
    <section className="process-stop-feedback" data-tone={presentation.tone}>
      <div
        aria-atomic="true"
        aria-live="polite"
        className="process-stop-feedback-message"
        role="status"
      >
        <Icon aria-hidden="true" size={16} strokeWidth={1.8} />
        <span>
          <strong>{presentation.title}</strong>
          <small>{presentation.detail}</small>
        </span>
      </div>
      <IconButton
        className="process-stop-feedback-dismiss"
        icon={<X aria-hidden="true" size={14} strokeWidth={1.8} />}
        label="Dismiss stop status"
        onClick={onDismiss}
        variant="ghost"
      />
    </section>
  );
}

function ConfirmationCopy({
  processName,
  token,
}: {
  processName: string;
  token: ProcessStopConfirmationToken;
}) {
  const force = token.kind === 'force';
  return (
    <>
      <header className="process-stop-dialog-header">
        <DialogTitle>{force ? 'Force stop managed run?' : 'Stop external process?'}</DialogTitle>
        <DialogDescription asChild>
          <p>
            {force
              ? 'Force stop this Supervisor-owned managed run. Unsaved work in processes under its control may be lost.'
              : 'Send a stop signal to this exact process instance only. Signal delivery does not confirm that the process exited.'}
          </p>
        </DialogDescription>
      </header>
      <dl className="process-stop-dialog-identity">
        <div>
          <dt>Process</dt>
          <dd>{processName}</dd>
        </div>
        <div>
          <dt>PID</dt>
          <dd>{token.processInstanceKey.pid.toLocaleString()}</dd>
        </div>
        <div>
          <dt>Boot identity</dt>
          <dd>{token.processInstanceKey.bootId}</dd>
        </div>
        <div>
          <dt>Native start time</dt>
          <dd>{token.processInstanceKey.nativeStartTime}</dd>
        </div>
        {force ? (
          <div>
            <dt>Managed run</dt>
            <dd>{token.runId}</dd>
          </div>
        ) : (
          <div>
            <dt>Scope</dt>
            <dd>Single process</dd>
          </div>
        )}
      </dl>
    </>
  );
}

function StopStatus({ presentation }: { presentation: ProcessStopStatusPresentation }) {
  const Icon = STATUS_ICONS[presentation.icon];
  return (
    <div
      aria-atomic="true"
      aria-live="polite"
      className="process-stop-status"
      data-tone={presentation.tone}
      role="status"
    >
      <Icon
        aria-hidden="true"
        className={presentation.icon === 'loader' ? 'process-stop-status-icon--busy' : undefined}
        size={16}
        strokeWidth={1.8}
      />
      <span>
        <strong>{presentation.title}</strong>
        <small>{presentation.detail}</small>
      </span>
    </div>
  );
}

function UnavailableControls() {
  return (
    <section aria-label="Process controls" className="process-stop-controls">
      <div aria-live="polite" className="process-stop-unavailable" role="status">
        Controls unavailable
      </div>
    </section>
  );
}

function externalResultMatches(
  process: ProcessRecord,
  details: AuthoritativeProcessControlDetails,
  result: StopExternalProcessResult,
): boolean {
  return (
    details.control.kind === 'external' &&
    result.scope === 'singleProcess' &&
    processInstanceKeysEqual(process.instanceKey, result.processInstanceKey)
  );
}
