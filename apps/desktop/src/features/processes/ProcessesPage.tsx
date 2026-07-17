import { useEffect, useRef, useState } from 'react';
import {
  CircleOff,
  LoaderCircle,
  Radio,
  RefreshCw,
  ShieldAlert,
  TriangleAlert,
  type LucideIcon,
} from 'lucide-react';

import type {
  ProcessInstanceKey,
  ProcessRecord,
  RequestProcessEnrichmentRequest,
} from '@dpm/generated-types';

import { requestProcessEnrichment } from '../../lib/processEnrichment';
import type { SupervisorConnectionState } from '../../lib/supervisor';
import { useSupervisorSnapshot } from '../../app/SupervisorProvider';
import { ProcessInspector } from './ProcessInspector';
import { ProcessLogPanel } from './ProcessLogPanel';
import {
  ProcessStopConfirmationDialog,
  ProcessStopControls,
  ProcessStopFeedback,
} from './ProcessStopControls';
import { processInstanceKey } from './processTableModel';
import { ProcessTable, type ProcessTableHandle } from './ProcessTable';
import { useManagedLogController } from './useManagedLogController';
import { useProcessStopController } from './useProcessStopController';

interface WorkbenchAvailability {
  busy: boolean;
  detail: string;
  Icon: LucideIcon;
  title: string;
}

interface ProcessEnrichmentInput {
  request: RequestProcessEnrichmentRequest;
  selectedSignature: string | null;
  signature: string;
}

interface ProcessEnrichmentWork extends ProcessEnrichmentInput {
  generation: number;
  scope: number;
}

const PROCESS_ENRICHMENT_DEBOUNCE_MS = 100;
const PROCESS_ENRICHMENT_REFRESH_MS = 10_000;
const MAX_VISIBLE_PROCESS_KEYS = 64;

export function ProcessesPage() {
  const snapshot = useSupervisorSnapshot();
  const [selectedKey, setSelectedKey] = useState<string | null>(null);
  const [visibleProcessKeys, setVisibleProcessKeys] = useState<ReadonlyArray<ProcessInstanceKey>>(
    [],
  );
  const table = useRef<ProcessTableHandle>(null);
  const ready = snapshot.connectionState.kind === 'connected' && snapshot.synchronized;
  const availability = ready ? null : presentAvailability(snapshot.connectionState);
  const selectedProcess =
    selectedKey === null
      ? null
      : (snapshot.processes.find(
          (process) => processInstanceKey(process.instanceKey) === selectedKey,
        ) ?? null);
  const stopController = useProcessStopController({ connected: ready, process: selectedProcess });
  const logController = useManagedLogController({
    connectionGeneration: ready ? snapshot.generation : null,
    process: selectedProcess,
  });
  useProcessEnrichmentHints(
    ready && snapshot.generation !== null ? snapshot.generation : null,
    visibleProcessKeys,
    selectedProcess?.instanceKey ?? null,
  );
  const confirmationProcessName = useRef('Selected process');

  const restoreFocus = (key: string) => {
    requestAnimationFrame(() => {
      if (table.current) {
        table.current.focusProcess(key);
      } else {
        document.getElementById('main-content')?.focus({ preventScroll: true });
      }
    });
  };

  useEffect(() => {
    if (selectedKey !== null && (!ready || selectedProcess === null)) {
      const staleKey = selectedKey;
      setSelectedKey(null);
      restoreFocus(staleKey);
    }
  }, [ready, selectedKey, selectedProcess]);

  const closeInspector = () => {
    const key = selectedKey;
    setSelectedKey(null);
    if (key) {
      restoreFocus(key);
    }
  };

  return (
    <>
      <main className="process-workbench" id="main-content" tabIndex={-1}>
        <header className="page-header process-page-header">
          <div className="process-page-title">
            <h1>Processes</h1>
            <p>Current user session</p>
          </div>
          <div className="process-page-header-meta">
            {stopController.feedback ? (
              <ProcessStopFeedback
                onDismiss={stopController.clearFeedback}
                presentation={stopController.feedback}
              />
            ) : null}
            {ready ? (
              <span aria-live="polite" className="workbench-summary" role="status">
                <Radio aria-hidden="true" size={14} strokeWidth={1.8} />
                {formatProcessCount(snapshot.processes.length)}
              </span>
            ) : null}
          </div>
        </header>
        {ready ? (
          <div
            className="process-workspace"
            data-inspector-open={selectedProcess ? true : undefined}
            onKeyDownCapture={(event) => {
              if (event.key === 'Escape' && selectedProcess) {
                event.preventDefault();
                event.stopPropagation();
                closeInspector();
              }
            }}
          >
            <ProcessTable
              onSelectionChange={setSelectedKey}
              onVisibleProcessKeysChange={setVisibleProcessKeys}
              processes={snapshot.processes}
              ref={table}
              selectedKey={selectedKey}
            />
            {selectedProcess ? (
              <ProcessInspector
                onClose={closeInspector}
                process={selectedProcess}
                processes={snapshot.processes}
                stopControls={
                  <ProcessStopControls
                    details={stopController.details}
                    detailsError={stopController.detailsError}
                    detailsLoading={stopController.detailsLoading}
                    externalResult={stopController.externalResult}
                    onGracefulStop={stopController.requestGracefulStop}
                    onRequestExternalConfirmation={(token) => {
                      confirmationProcessName.current = readProcessName(selectedProcess);
                      stopController.requestExternalConfirmation(token);
                    }}
                    onRequestForceConfirmation={(token) => {
                      confirmationProcessName.current = readProcessName(selectedProcess);
                      stopController.requestForceConfirmation(token);
                    }}
                    process={selectedProcess}
                    submitting={stopController.submitting}
                  />
                }
              />
            ) : null}
          </div>
        ) : availability ? (
          <UnavailableState availability={availability} />
        ) : null}
        <ProcessLogPanel controller={logController} />
      </main>
      <ProcessStopConfirmationDialog
        onCancel={stopController.cancelConfirmation}
        onConfirm={stopController.confirmStop}
        processName={confirmationProcessName.current}
        submitting={stopController.submitting}
        token={stopController.confirmation}
      />
    </>
  );
}

function useProcessEnrichmentHints(
  generation: number | null,
  visibleProcessKeys: ReadonlyArray<ProcessInstanceKey>,
  selectedProcessKey: ProcessInstanceKey | null,
) {
  const mounted = useRef(false);
  const currentGeneration = useRef<number | null>(generation);
  const activeGeneration = useRef<number | null>(null);
  const scope = useRef(0);
  const inFlight = useRef<ProcessEnrichmentWork | null>(null);
  const pending = useRef<ProcessEnrichmentWork | null>(null);
  const debounceTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const refreshTimer = useRef<ReturnType<typeof setInterval> | null>(null);
  const lastDesiredSignature = useRef<string | null>(null);
  const previousSelectedSignature = useRef<string | null | undefined>(undefined);
  const input = buildProcessEnrichmentInput(visibleProcessKeys, selectedProcessKey);

  currentGeneration.current = generation;

  const clearDebounceTimer = () => {
    if (debounceTimer.current !== null) {
      clearTimeout(debounceTimer.current);
      debounceTimer.current = null;
    }
  };

  const clearRefreshTimer = () => {
    if (refreshTimer.current !== null) {
      clearInterval(refreshTimer.current);
      refreshTimer.current = null;
    }
  };

  const finishWork = (work: ProcessEnrichmentWork) => {
    if (inFlight.current !== work) {
      return;
    }
    inFlight.current = null;
    const next = pending.current;
    pending.current = null;
    if (next !== null) {
      startWork(next);
    }
  };

  const startWork = (work: ProcessEnrichmentWork) => {
    if (
      !mounted.current ||
      currentGeneration.current !== work.generation ||
      activeGeneration.current !== work.generation ||
      scope.current !== work.scope
    ) {
      return;
    }
    inFlight.current = work;
    void requestProcessEnrichment(work.request).then(
      () => finishWork(work),
      () => finishWork(work),
    );
  };

  const queueWork = (work: ProcessEnrichmentWork) => {
    const activeWork = inFlight.current;
    if (activeWork === null) {
      startWork(work);
      return;
    }
    pending.current = work;
  };

  const scheduleRefresh = (work: ProcessEnrichmentWork) => {
    clearRefreshTimer();
    refreshTimer.current = setInterval(() => {
      if (
        !mounted.current ||
        currentGeneration.current !== work.generation ||
        activeGeneration.current !== work.generation ||
        scope.current !== work.scope
      ) {
        return;
      }
      queueWork(work);
    }, PROCESS_ENRICHMENT_REFRESH_MS);
  };

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      currentGeneration.current = null;
      activeGeneration.current = null;
      scope.current += 1;
      pending.current = null;
      lastDesiredSignature.current = null;
      previousSelectedSignature.current = undefined;
      clearDebounceTimer();
      clearRefreshTimer();
    };
  }, []);

  useEffect(() => {
    currentGeneration.current = generation;
    if (generation === null) {
      if (activeGeneration.current !== null) {
        scope.current += 1;
      }
      activeGeneration.current = null;
      pending.current = null;
      lastDesiredSignature.current = null;
      previousSelectedSignature.current = undefined;
      clearDebounceTimer();
      clearRefreshTimer();
      return;
    }

    const generationChanged = activeGeneration.current !== generation;
    if (generationChanged) {
      scope.current += 1;
      activeGeneration.current = generation;
      pending.current = null;
      lastDesiredSignature.current = null;
      clearDebounceTimer();
      clearRefreshTimer();
    }

    const selectedChanged = generationChanged
      ? input.selectedSignature !== null
      : previousSelectedSignature.current !== input.selectedSignature;
    previousSelectedSignature.current = input.selectedSignature;
    if (lastDesiredSignature.current === input.signature) {
      return;
    }
    lastDesiredSignature.current = input.signature;

    const work: ProcessEnrichmentWork = {
      ...input,
      generation,
      scope: scope.current,
    };
    clearDebounceTimer();
    scheduleRefresh(work);
    if (selectedChanged) {
      queueWork(work);
      return;
    }
    debounceTimer.current = setTimeout(() => {
      debounceTimer.current = null;
      queueWork(work);
    }, PROCESS_ENRICHMENT_DEBOUNCE_MS);
  }, [generation, input.selectedSignature, input.signature]);
}

function buildProcessEnrichmentInput(
  visibleProcessKeys: ReadonlyArray<ProcessInstanceKey>,
  selectedProcessKey: ProcessInstanceKey | null,
): ProcessEnrichmentInput {
  const selectedSignature =
    selectedProcessKey === null ? null : processIdentity(selectedProcessKey);
  const selected = selectedProcessKey === null ? null : copyProcessInstanceKey(selectedProcessKey);
  const visible: ProcessInstanceKey[] = [];
  const seen = new Set<string>();

  for (const processKey of visibleProcessKeys) {
    if (visible.length >= MAX_VISIBLE_PROCESS_KEYS) {
      break;
    }
    const identity = processIdentity(processKey);
    if (identity === selectedSignature || seen.has(identity)) {
      continue;
    }
    seen.add(identity);
    visible.push(copyProcessInstanceKey(processKey));
  }

  const request: RequestProcessEnrichmentRequest = {
    visibleProcessInstanceKeys: visible,
    selectedProcessInstanceKey: selected,
  };
  return {
    request,
    selectedSignature,
    signature: JSON.stringify([
      visible.map(processKeyTuple),
      selected === null ? null : processKeyTuple(selected),
    ]),
  };
}

function processIdentity(key: ProcessInstanceKey): string {
  return JSON.stringify(processKeyTuple(key));
}

function processKeyTuple(key: ProcessInstanceKey): [string, number, string] {
  return [key.bootId, key.pid, key.nativeStartTime];
}

function copyProcessInstanceKey(key: ProcessInstanceKey): ProcessInstanceKey {
  return {
    bootId: key.bootId,
    nativeStartTime: key.nativeStartTime,
    pid: key.pid,
  };
}

function UnavailableState({ availability }: { availability: WorkbenchAvailability }) {
  const { busy, detail, Icon, title } = availability;
  return (
    <div aria-atomic="true" aria-live="polite" className="empty-state" role="status">
      <Icon
        aria-hidden="true"
        className={busy ? 'empty-state-icon status-icon--busy' : 'empty-state-icon'}
        size={20}
        strokeWidth={1.8}
      />
      <strong>{title}</strong>
      <span>{detail}</span>
    </div>
  );
}

function presentAvailability(state: SupervisorConnectionState): WorkbenchAvailability {
  switch (state.kind) {
    case 'connected':
      return {
        busy: true,
        detail: 'Waiting for a consistent process snapshot.',
        Icon: LoaderCircle,
        title: 'Loading processes',
      };
    case 'connecting':
      return {
        busy: true,
        detail: 'Opening the local Supervisor connection.',
        Icon: LoaderCircle,
        title: 'Connecting to Supervisor',
      };
    case 'authenticating':
      return {
        busy: true,
        detail: 'Verifying the local Supervisor session.',
        Icon: LoaderCircle,
        title: 'Authenticating Supervisor',
      };
    case 'backoff':
      return {
        busy: true,
        detail: 'The local connection will retry automatically.',
        Icon: RefreshCw,
        title: 'Reconnecting to Supervisor',
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
        Icon: ShieldAlert,
        title: 'Supervisor access denied',
      };
    case 'shuttingDown':
      return {
        busy: false,
        detail: 'Process discovery is unavailable while the Supervisor exits.',
        Icon: CircleOff,
        title: 'Supervisor shutting down',
      };
    case 'disconnected':
      return {
        busy: false,
        detail: 'Waiting for the local Supervisor connection.',
        Icon: CircleOff,
        title: 'Supervisor unavailable',
      };
  }
}

function formatProcessCount(count: number) {
  return `${count.toLocaleString()} ${count === 1 ? 'process' : 'processes'}`;
}

function readProcessName(process: ProcessRecord): string {
  const name = process.executableName;
  return typeof name === 'object' && 'known' in name && name.known.trim().length > 0
    ? name.known
    : `PID ${process.instanceKey.pid.toLocaleString()}`;
}
