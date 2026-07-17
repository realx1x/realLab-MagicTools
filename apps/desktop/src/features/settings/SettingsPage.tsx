import { useEffect, useRef, useState, type ComponentType } from 'react';
import {
  Check,
  CheckCircle2,
  CircleOff,
  FileOutput,
  LoaderCircle,
  RefreshCw,
  Settings,
  ShieldCheck,
  TriangleAlert,
} from 'lucide-react';

import type {
  DiagnosticContentKind,
  DiagnosticContentPrivacy,
  DiagnosticManifestItem,
  ExportDiagnosticsResult,
  GetDiagnosticsManifestResponse,
} from '@dpm/generated-types';
import { Button, SegmentedControl } from '@dpm/ui';

import { useSupervisorSnapshot } from '../../app/SupervisorProvider';
import { useTheme } from '../../app/ThemeProvider';
import {
  exportDiagnostics,
  getDiagnosticsManifest,
  type DiagnosticsExportRequest,
} from '../../lib/diagnostics';
import type { SupervisorConnectionState } from '../../lib/supervisor';
import './settings.css';
import { THEME_OPTIONS } from './themeOptions';

interface ManifestState {
  readonly generation: number | null;
  readonly status: 'idle' | 'loading' | 'ready' | 'error';
  readonly value: GetDiagnosticsManifestResponse | null;
}

type ExportFailure =
  | 'accessDenied'
  | 'conflict'
  | 'storage'
  | 'platform'
  | 'timeout'
  | 'unavailable';

type ExportState =
  | { readonly status: 'idle' }
  | { readonly generation: number; readonly status: 'exporting' }
  | {
      readonly generation: number;
      readonly status: 'succeeded';
      readonly result: ExportDiagnosticsResult;
    }
  | { readonly generation: number; readonly status: 'failed'; readonly reason: ExportFailure };

interface AvailabilityPresentation {
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

interface ContentPresentation {
  readonly description: string;
  readonly label: string;
}

const EMPTY_MANIFEST: ManifestState = { generation: null, status: 'idle', value: null };
const IDLE_EXPORT: ExportState = { status: 'idle' };
const CONTENT_ORDER: ReadonlyArray<DiagnosticContentKind> = [
  'systemSummary',
  'applicationLogs',
  'databaseSummary',
];

export function SettingsPage() {
  const { preference, setPreference } = useTheme();
  const snapshot = useSupervisorSnapshot();
  const ready = snapshot.connectionState.kind === 'connected' && snapshot.generation !== null;
  const generation = ready ? snapshot.generation : null;
  const [manifest, setManifest] = useState<ManifestState>(EMPTY_MANIFEST);
  const [includeApplicationLogs, setIncludeApplicationLogs] = useState(false);
  const [includeDatabaseSummary, setIncludeDatabaseSummary] = useState(false);
  const [exportState, setExportState] = useState<ExportState>(IDLE_EXPORT);
  const [reloadToken, setReloadToken] = useState(0);
  const manifestSequence = useRef(0);
  const exportSequence = useRef(0);
  const exportInFlight = useRef(false);
  const scope = useRef({ generation, ready });
  scope.current = { generation, ready };

  useEffect(() => {
    manifestSequence.current += 1;
    exportSequence.current += 1;
    exportInFlight.current = false;
    const sequence = manifestSequence.current;
    setIncludeApplicationLogs(false);
    setIncludeDatabaseSummary(false);
    setExportState(IDLE_EXPORT);

    if (!ready || generation === null) {
      setManifest(EMPTY_MANIFEST);
      return;
    }

    setManifest({ generation, status: 'loading', value: null });
    void getDiagnosticsManifest().then(
      (response) => {
        if (requestIsCurrent(scope.current, manifestSequence.current, generation, sequence)) {
          setIncludeApplicationLogs(manifestItemIncluded(response, 'applicationLogs'));
          setIncludeDatabaseSummary(manifestItemIncluded(response, 'databaseSummary'));
          setManifest({ generation, status: 'ready', value: response });
        }
      },
      () => {
        if (requestIsCurrent(scope.current, manifestSequence.current, generation, sequence)) {
          setManifest({ generation, status: 'error', value: null });
        }
      },
    );

    return () => {
      manifestSequence.current += 1;
      exportSequence.current += 1;
    };
  }, [generation, ready, reloadToken]);

  const retryManifest = () => {
    manifestSequence.current += 1;
    setReloadToken((current) => current + 1);
  };

  const startExport = () => {
    if (
      !ready ||
      generation === null ||
      manifest.generation !== generation ||
      manifest.status !== 'ready' ||
      manifest.value === null ||
      exportState.status === 'exporting' ||
      exportInFlight.current
    ) {
      return;
    }

    const applicationLogsAvailable = manifestItemAvailable(manifest.value, 'applicationLogs');
    const databaseSummaryAvailable = manifestItemAvailable(manifest.value, 'databaseSummary');
    const request: DiagnosticsExportRequest = {
      includeApplicationLogs: includeApplicationLogs && applicationLogsAvailable,
      includeDatabaseSummary: includeDatabaseSummary && databaseSummaryAvailable,
    };
    const sequence = exportSequence.current + 1;
    exportSequence.current = sequence;
    exportInFlight.current = true;
    setExportState({ generation, status: 'exporting' });

    void exportDiagnostics(request).then(
      (result) => {
        if (requestIsCurrent(scope.current, exportSequence.current, generation, sequence)) {
          exportInFlight.current = false;
          setIncludeApplicationLogs(manifestItemIncluded(result.manifest, 'applicationLogs'));
          setIncludeDatabaseSummary(manifestItemIncluded(result.manifest, 'databaseSummary'));
          setManifest({ generation, status: 'ready', value: result.manifest });
          setExportState({ generation, status: 'succeeded', result });
        }
      },
      (error: unknown) => {
        if (requestIsCurrent(scope.current, exportSequence.current, generation, sequence)) {
          exportInFlight.current = false;
          setExportState({ generation, status: 'failed', reason: classifyExportFailure(error) });
        }
      },
    );
  };

  const availability = ready ? null : presentAvailability(snapshot.connectionState);
  const manifestIsCurrent = ready && manifest.generation === generation;
  const orderedItems =
    manifestIsCurrent && manifest.value ? orderManifestItems(manifest.value.items) : [];
  const visibleExportState =
    exportState.status === 'idle' || exportState.generation === generation
      ? exportState
      : IDLE_EXPORT;

  return (
    <main className="route-page" id="main-content" tabIndex={-1}>
      <header className="page-header">
        <div className="page-title">
          <Settings aria-hidden="true" size={18} strokeWidth={1.8} />
          <h1>Settings</h1>
        </div>
      </header>
      <section aria-labelledby="appearance-heading" className="settings-section">
        <div>
          <h2 id="appearance-heading">Appearance</h2>
          <p>Theme</p>
        </div>
        <SegmentedControl
          ariaLabel="Theme preference"
          items={THEME_OPTIONS}
          onValueChange={(value) => {
            if (value === 'system' || value === 'light' || value === 'dark') {
              setPreference(value);
            }
          }}
          value={preference}
        />
      </section>

      <section aria-labelledby="diagnostics-heading" className="settings-diagnostics">
        <header className="settings-diagnostics-header">
          <div>
            <div className="settings-diagnostics-title">
              <ShieldCheck aria-hidden="true" size={17} strokeWidth={1.8} />
              <h2 id="diagnostics-heading">Diagnostics</h2>
            </div>
            <p>Create a local, redacted file in the private diagnostics directory.</p>
          </div>
        </header>

        {availability ? (
          <DiagnosticsAvailability presentation={availability} />
        ) : !manifestIsCurrent || manifest.status === 'loading' ? (
          <DiagnosticsAvailability
            presentation={{
              busy: true,
              detail: 'Reading the bounded diagnostic contents from the Supervisor.',
              Icon: LoaderCircle,
              title: 'Loading diagnostic contents',
            }}
          />
        ) : manifest.status === 'error' ? (
          <div className="settings-diagnostics-message" data-tone="danger" role="alert">
            <TriangleAlert aria-hidden="true" size={20} strokeWidth={1.8} />
            <div>
              <strong>Diagnostic contents unavailable</strong>
              <span>The Supervisor did not return a valid content manifest.</span>
            </div>
            <Button
              leadingIcon={<RefreshCw aria-hidden="true" size={14} strokeWidth={1.8} />}
              onClick={retryManifest}
              size="compact"
            >
              Retry
            </Button>
          </div>
        ) : manifest.status === 'ready' && manifest.value ? (
          <>
            <fieldset
              aria-busy={visibleExportState.status === 'exporting'}
              className="settings-diagnostics-contents"
              disabled={visibleExportState.status === 'exporting'}
            >
              <legend className="visually-hidden">Diagnostic export contents</legend>
              <ul>
                {orderedItems.map((item) => (
                  <DiagnosticContentItem
                    checked={
                      item.kind === 'applicationLogs'
                        ? includeApplicationLogs
                        : item.kind === 'databaseSummary'
                          ? includeDatabaseSummary
                          : item.included
                    }
                    item={item}
                    key={item.kind}
                    onCheckedChange={
                      item.kind === 'applicationLogs'
                        ? setIncludeApplicationLogs
                        : item.kind === 'databaseSummary'
                          ? setIncludeDatabaseSummary
                          : undefined
                    }
                  />
                ))}
              </ul>
            </fieldset>

            <div className="settings-diagnostics-actions">
              <div>
                <strong>Private export location</strong>
                <span>The Supervisor selects the directory and returns only a safe file name.</span>
              </div>
              <Button
                disabled={visibleExportState.status === 'exporting'}
                leadingIcon={
                  visibleExportState.status === 'exporting' ? (
                    <LoaderCircle
                      aria-hidden="true"
                      className="settings-diagnostics-spin"
                      size={14}
                      strokeWidth={1.8}
                    />
                  ) : (
                    <FileOutput aria-hidden="true" size={14} strokeWidth={1.8} />
                  )
                }
                onClick={startExport}
                variant="primary"
              >
                {visibleExportState.status === 'exporting' ? 'Exporting' : 'Export diagnostics'}
              </Button>
            </div>

            <DiagnosticsExportFeedback state={visibleExportState} />
          </>
        ) : null}
      </section>
    </main>
  );
}

function DiagnosticContentItem({
  checked,
  item,
  onCheckedChange,
}: {
  checked: boolean;
  item: DiagnosticManifestItem;
  onCheckedChange: ((checked: boolean) => void) | undefined;
}) {
  const presentation = presentContent(item.kind);
  const metadata = `${item.kind === 'systemSummary' ? 'Always included · ' : ''}${presentPrivacy(item.privacy)} · ${formatBytes(item.estimatedBytes)} estimated · ${formatBytes(item.maximumBytes)} limit${item.truncated ? ' · truncated' : ''}`;

  return (
    <li data-available={item.available ? 'true' : 'false'}>
      {onCheckedChange ? (
        <label className="settings-diagnostics-option">
          <input
            checked={checked}
            disabled={!item.available}
            onChange={(event) => onCheckedChange(event.currentTarget.checked)}
            type="checkbox"
          />
          <span>
            <strong>{presentation.label}</strong>
            <small>{presentation.description}</small>
          </span>
        </label>
      ) : (
        <div className="settings-diagnostics-option settings-diagnostics-option--required">
          <span aria-hidden="true" className="settings-diagnostics-required-icon">
            <Check size={14} strokeWidth={2} />
          </span>
          <span>
            <strong>{presentation.label}</strong>
            <small>{presentation.description}</small>
          </span>
        </div>
      )}
      <span className="settings-diagnostics-metadata">
        {item.available ? metadata : 'Unavailable from this Supervisor'}
      </span>
    </li>
  );
}

function DiagnosticsExportFeedback({ state }: { state: ExportState }) {
  if (state.status === 'idle' || state.status === 'exporting') {
    return state.status === 'exporting' ? (
      <div className="settings-diagnostics-feedback" role="status">
        <LoaderCircle
          aria-hidden="true"
          className="settings-diagnostics-spin"
          size={18}
          strokeWidth={1.8}
        />
        <div>
          <strong>Exporting diagnostics</strong>
          <span>The bounded diagnostic file is being assembled and published.</span>
        </div>
      </div>
    ) : null;
  }

  if (state.status === 'failed') {
    return (
      <div className="settings-diagnostics-feedback" data-tone="danger" role="alert">
        <TriangleAlert aria-hidden="true" size={18} strokeWidth={1.8} />
        <div>
          <strong>Diagnostic export failed</strong>
          <span>{presentExportFailure(state.reason)}</span>
        </div>
      </div>
    );
  }

  return (
    <div className="settings-diagnostics-feedback" data-tone="success" role="status">
      <CheckCircle2 aria-hidden="true" size={18} strokeWidth={1.8} />
      <div>
        <strong>Diagnostics exported</strong>
        <span>
          <span className="settings-diagnostics-file-name">{state.result.fileName}</span>
          {' · '}
          {formatBytes(state.result.totalBytes)}
        </span>
        <code>SHA-256 {state.result.sha256}</code>
      </div>
    </div>
  );
}

function DiagnosticsAvailability({ presentation }: { presentation: AvailabilityPresentation }) {
  const { busy, detail, Icon, title } = presentation;
  return (
    <div className="settings-diagnostics-message" role="status">
      <Icon
        aria-hidden={true}
        {...(busy ? { className: 'settings-diagnostics-spin' } : {})}
        size={20}
        strokeWidth={1.8}
      />
      <div>
        <strong>{title}</strong>
        <span>{detail}</span>
      </div>
    </div>
  );
}

function orderManifestItems(
  items: ReadonlyArray<DiagnosticManifestItem>,
): ReadonlyArray<DiagnosticManifestItem> {
  const byKind = new Map(items.map((item) => [item.kind, item]));
  return CONTENT_ORDER.flatMap((kind) => {
    const item = byKind.get(kind);
    return item ? [item] : [];
  });
}

function manifestItemAvailable(
  manifest: GetDiagnosticsManifestResponse,
  kind: DiagnosticContentKind,
): boolean {
  return manifest.items.some((item) => item.kind === kind && item.available);
}

function manifestItemIncluded(
  manifest: GetDiagnosticsManifestResponse,
  kind: DiagnosticContentKind,
): boolean {
  return manifest.items.some((item) => item.kind === kind && item.included);
}

function presentContent(kind: DiagnosticContentKind): ContentPresentation {
  switch (kind) {
    case 'systemSummary':
      return {
        description: 'Build, platform, and bounded Supervisor health metadata.',
        label: 'System summary',
      };
    case 'applicationLogs':
      return {
        description:
          'Bounded structured application events with sensitive values redacted; managed process output is excluded.',
        label: 'Application logs',
      };
    case 'databaseSummary':
      return {
        description: 'Aggregate schema and record counts without database rows.',
        label: 'Database summary',
      };
  }
}

function presentPrivacy(privacy: DiagnosticContentPrivacy): string {
  switch (privacy) {
    case 'metadataOnly':
      return 'Metadata only';
    case 'structuredRedacted':
      return 'Structured and redacted';
    case 'aggregateOnly':
      return 'Aggregate only';
  }
}

function presentAvailability(state: SupervisorConnectionState): AvailabilityPresentation {
  switch (state.kind) {
    case 'connected':
      return {
        busy: true,
        detail: 'Waiting for the authenticated Supervisor generation.',
        Icon: LoaderCircle,
        title: 'Preparing diagnostics',
      };
    case 'connecting':
    case 'authenticating':
    case 'backoff':
      return {
        busy: true,
        detail: 'Diagnostic contents will load after the local Supervisor reconnects.',
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
        detail: 'Reconnect to create a private diagnostic export.',
        Icon: CircleOff,
        title: 'Diagnostics unavailable',
      };
  }
}

function classifyExportFailure(error: unknown): ExportFailure {
  if (!isObject(error) || typeof error.code !== 'string') {
    return 'unavailable';
  }
  switch (error.code) {
    case 'ACCESS_DENIED':
      return 'accessDenied';
    case 'CONFLICT':
      return 'conflict';
    case 'STORAGE_ERROR':
      return 'storage';
    case 'PLATFORM_ERROR':
      return 'platform';
    case 'TIMEOUT':
      return 'timeout';
    default:
      return 'unavailable';
  }
}

function presentExportFailure(reason: ExportFailure): string {
  switch (reason) {
    case 'accessDenied':
      return 'The private diagnostics directory is not accessible to the current user.';
    case 'conflict':
      return 'Another export is in progress or the destination changed. Try again.';
    case 'storage':
      return 'The Supervisor could not read the bounded diagnostic source data.';
    case 'platform':
      return 'The Supervisor could not publish the diagnostic file to its private directory.';
    case 'timeout':
      return 'The request timed out and its result is unknown. Wait before trying again.';
    case 'unavailable':
      return 'The Supervisor did not return a valid export result.';
  }
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

function formatBytes(value: number): string {
  if (value < 1_024) {
    return `${value.toLocaleString()} B`;
  }
  if (value < 1_024 * 1_024) {
    return `${(value / 1_024).toFixed(1)} KiB`;
  }
  return `${(value / (1_024 * 1_024)).toFixed(1)} MiB`;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}
