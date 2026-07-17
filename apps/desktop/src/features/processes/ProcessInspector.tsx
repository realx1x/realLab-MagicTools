import { useEffect, useId, useMemo, useState, type ReactNode } from 'react';
import {
  Binary,
  Box,
  CircleCheck,
  CircleHelp,
  CircleMinus,
  CircleOff,
  CirclePause,
  CircleStop,
  ExternalLink,
  GitBranch,
  ListTree,
  Moon,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  TriangleAlert,
  X,
  type LucideIcon,
} from 'lucide-react';

import type { ProcessRecord, ProcessStatus } from '@dpm/generated-types';
import {
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogOverlay,
  DialogPortal,
  DialogRoot,
  DialogTitle,
  IconButton,
  TabsContent,
  TabsList,
  TabsRoot,
  TabsTrigger,
} from '@dpm/ui';

import {
  buildProcessInspectorProjection,
  type AncestryTermination,
  type AvailabilityKind,
  type FieldPresentation,
  type ProcessInspectorProjection,
  type ProcessTreeNode,
} from './processInspectorModel';

const COMPACT_INSPECTOR_QUERY = '(max-width: 719px)';
const MAX_INSPECTOR_ITEMS = 64;

type InspectorTab = 'overview' | 'tree' | 'command' | 'reasons';
type InlineValueKind = AvailabilityKind | 'unavailable';

interface ProcessInspectorProps {
  onClose: () => void;
  process: ProcessRecord;
  processes: ReadonlyArray<ProcessRecord>;
  stopControls: ReactNode;
}

interface InspectorSurfaceProps {
  compact: boolean;
  onClose: () => void;
  projection: ProcessInspectorProjection;
  stopControls: ReactNode;
  titleId: string;
}

export function ProcessInspector({
  onClose,
  process,
  processes,
  stopControls,
}: ProcessInspectorProps) {
  const compact = useCompactInspector();
  const titleId = useId();
  const projection = useMemo(
    () => buildProcessInspectorProjection(processes, process.instanceKey),
    [process.instanceKey, processes],
  );

  if (!projection) {
    return null;
  }

  if (compact) {
    return (
      <DialogRoot
        onOpenChange={(open) => {
          if (!open) {
            onClose();
          }
        }}
        open
      >
        <DialogPortal>
          <DialogOverlay className="process-inspector-overlay" />
          <DialogContent
            className="process-inspector process-inspector--dialog"
            onCloseAutoFocus={(event) => event.preventDefault()}
          >
            <InspectorSurface
              compact
              onClose={onClose}
              projection={projection}
              stopControls={stopControls}
              titleId={titleId}
            />
          </DialogContent>
        </DialogPortal>
      </DialogRoot>
    );
  }

  return (
    <aside
      aria-labelledby={titleId}
      className="process-inspector process-inspector--aside"
      onKeyDown={(event) => {
        if (event.key === 'Escape') {
          event.preventDefault();
          onClose();
        }
      }}
    >
      <InspectorSurface
        compact={false}
        onClose={onClose}
        projection={projection}
        stopControls={stopControls}
        titleId={titleId}
      />
    </aside>
  );
}

function InspectorSurface({
  compact,
  onClose,
  projection,
  stopControls,
  titleId,
}: InspectorSurfaceProps) {
  const [tab, setTab] = useState<InspectorTab>('overview');

  useEffect(() => {
    setTab('overview');
  }, [projection.key]);

  const header = (
    <>
      <div className="process-inspector-heading">
        <div className="process-inspector-title-row">
          {compact ? (
            <DialogTitle asChild>
              <h2>{projection.name.text}</h2>
            </DialogTitle>
          ) : (
            <h2 id={titleId}>{projection.name.text}</h2>
          )}
          {compact ? (
            <DialogClose asChild>
              <IconButton
                icon={<X aria-hidden="true" size={16} strokeWidth={1.8} />}
                label="Close process details"
                variant="ghost"
              />
            </DialogClose>
          ) : (
            <IconButton
              icon={<X aria-hidden="true" size={16} strokeWidth={1.8} />}
              label="Close process details"
              onClick={onClose}
              variant="ghost"
            />
          )}
        </div>
        {compact ? (
          <DialogDescription asChild>
            <p className="process-inspector-subtitle">
              PID {projection.pid.toLocaleString()} / {projection.status.text}
            </p>
          </DialogDescription>
        ) : (
          <p className="process-inspector-subtitle">
            PID {projection.pid.toLocaleString()} / {projection.status.text}
          </p>
        )}
      </div>
    </>
  );

  return (
    <>
      <header className="process-inspector-header">{header}</header>
      <TabsRoot
        className="process-inspector-tabs"
        onValueChange={(value) => {
          if (isInspectorTab(value)) {
            setTab(value);
          }
        }}
        orientation="horizontal"
        value={tab}
      >
        <TabsList aria-label="Process detail views" className="process-inspector-tab-list">
          <TabsTrigger value="overview">
            <Box aria-hidden="true" size={14} strokeWidth={1.8} />
            <span>Overview</span>
          </TabsTrigger>
          <TabsTrigger value="tree">
            <ListTree aria-hidden="true" size={14} strokeWidth={1.8} />
            <span>Tree</span>
          </TabsTrigger>
          <TabsTrigger value="command">
            <Terminal aria-hidden="true" size={14} strokeWidth={1.8} />
            <span>Command</span>
          </TabsTrigger>
          <TabsTrigger value="reasons">
            <Binary aria-hidden="true" size={14} strokeWidth={1.8} />
            <span>Reasons</span>
          </TabsTrigger>
        </TabsList>
        <TabsContent className="process-inspector-panel" value="overview">
          <OverviewPanel projection={projection} />
        </TabsContent>
        <TabsContent className="process-inspector-panel" value="tree">
          <TreePanel projection={projection} />
        </TabsContent>
        <TabsContent className="process-inspector-panel" value="command">
          <CommandPanel projection={projection} />
        </TabsContent>
        <TabsContent className="process-inspector-panel" value="reasons">
          <ReasonsPanel projection={projection} />
        </TabsContent>
      </TabsRoot>
      {stopControls}
    </>
  );
}

function OverviewPanel({ projection }: { projection: ProcessInspectorProjection }) {
  const StatusIcon =
    projection.status.kind === 'known'
      ? statusIcon(projection.status.value)
      : availabilityPresentation(projection.status.kind).Icon;
  const AccessIcon = projection.accessLevel === 'full' ? ShieldCheck : ShieldAlert;
  const OwnershipIcon = projection.ownership === 'managed' ? Box : ExternalLink;
  const ports = projection.ports.kind === 'known' ? projection.ports.value : [];
  const visiblePorts = ports.slice(0, MAX_INSPECTOR_ITEMS);

  return (
    <div className="process-inspector-sections">
      <InspectorSection title="Overview">
        <dl className="process-inspector-fields">
          <InspectorData label="Status">
            <InlineValue
              Icon={StatusIcon}
              kind={projection.status.kind}
              text={projection.status.text}
            />
          </InspectorData>
          <InspectorData label="Ownership">
            <InlineValue Icon={OwnershipIcon} kind="known" text={projection.ownershipLabel} />
          </InspectorData>
          <InspectorData label="Access">
            <InlineValue
              Icon={AccessIcon}
              kind={projection.accessLevel === 'full' ? 'known' : 'accessLimited'}
              text={projection.accessLevelLabel}
            />
          </InspectorData>
          <InspectorData label="Owner">
            <AvailabilityValue value={projection.owner} />
          </InspectorData>
          <InspectorData label="CPU">
            <AvailabilityValue mono value={projection.cpu} />
          </InspectorData>
          <InspectorData label="Memory">
            <AvailabilityValue mono value={projection.memory} />
          </InspectorData>
          <InspectorData label="Started">
            <AvailabilityValue value={projection.startedAt} />
          </InspectorData>
          <InspectorData label="Project">
            <AvailabilityValue value={projection.projectAssociation} />
          </InspectorData>
        </dl>
      </InspectorSection>

      <InspectorSection title="Ports">
        <AvailabilityValue value={projection.ports} />
        {visiblePorts.length > 0 ? (
          <ul className="process-inspector-list process-port-list">
            {visiblePorts.map((port) => (
              <li key={port.key}>
                <div>
                  <span className="process-mono">{port.endpoint}</span>
                  <small>
                    {port.protocolLabel} / {port.confidenceLabel}
                  </small>
                </div>
                <AvailabilityValue compact value={port.state} />
              </li>
            ))}
          </ul>
        ) : null}
        {ports.length > visiblePorts.length ? (
          <p className="process-inspector-overflow">
            {ports.length - visiblePorts.length} additional bindings
          </p>
        ) : null}
      </InspectorSection>

      <InspectorSection title="Process identity">
        <dl className="process-inspector-fields process-inspector-fields--stacked">
          <InspectorData label="PID">
            <span className="process-mono">{projection.pid.toLocaleString()}</span>
          </InspectorData>
          <InspectorData label="Boot identity">
            <span className="process-breakable process-mono">{projection.instanceKey.bootId}</span>
          </InspectorData>
          <InspectorData label="Native start time">
            <span className="process-breakable process-mono">
              {projection.instanceKey.nativeStartTime}
            </span>
          </InspectorData>
          <InspectorData label="Snapshot revision">
            <span className="process-mono">{projection.lastSeenRevision.toLocaleString()}</span>
          </InspectorData>
        </dl>
      </InspectorSection>
    </div>
  );
}

function TreePanel({ projection }: { projection: ProcessInspectorProjection }) {
  const ancestors = [...projection.tree.ancestorsClosestFirst].reverse();
  const children = projection.tree.directChildren.slice(0, MAX_INSPECTOR_ITEMS);
  return (
    <div className="process-inspector-sections">
      <InspectorSection title="Observed relationships">
        <TreeTermination termination={projection.tree.termination} />
        <ul className="process-tree-list">
          {ancestors.map((node, index) => (
            <li className="process-tree-node process-tree-node--ancestor" key={node.key}>
              <TreeNodeValue node={node} />
              <span aria-hidden="true" className="process-tree-connector">
                {index < ancestors.length - 1 || projection.tree.selected ? '|' : ''}
              </span>
            </li>
          ))}
          <li className="process-tree-node process-tree-node--selected">
            <TreeNodeValue node={projection.tree.selected} selected />
          </li>
        </ul>
      </InspectorSection>

      <InspectorSection title="Direct children">
        {children.length > 0 ? (
          <ul className="process-inspector-list">
            {children.map((child) => (
              <li key={child.key}>
                <TreeNodeValue node={child} />
              </li>
            ))}
          </ul>
        ) : (
          <p className="process-inspector-empty">No observed child processes</p>
        )}
        {projection.tree.directChildren.length > children.length ? (
          <p className="process-inspector-overflow">
            {projection.tree.directChildren.length - children.length} additional children
          </p>
        ) : null}
      </InspectorSection>
    </div>
  );
}

function CommandPanel({ projection }: { projection: ProcessInspectorProjection }) {
  return (
    <div className="process-inspector-sections">
      <InspectorSection title="Executable">
        <CodeValue value={projection.executablePath} />
      </InspectorSection>
      <InspectorSection title="Command line">
        <CodeValue value={projection.command} />
      </InspectorSection>
      <InspectorSection title="Working directory">
        <CodeValue value={projection.workingDirectory} />
      </InspectorSection>
      <InspectorSection title="Environment">
        <InlineValue
          Icon={CircleOff}
          detail="Environment details are not exposed by the current process snapshot."
          kind="unavailable"
          text="Not available"
        />
      </InspectorSection>
    </div>
  );
}

function ReasonsPanel({ projection }: { projection: ProcessInspectorProjection }) {
  const reasons = projection.classification.reasons.slice(0, MAX_INSPECTOR_ITEMS);
  const features =
    projection.projectFeatures.kind === 'known'
      ? projection.projectFeatures.value.slice(0, MAX_INSPECTOR_ITEMS)
      : [];

  return (
    <div className="process-inspector-sections">
      <InspectorSection title="Classification">
        <dl className="process-inspector-fields">
          <InspectorData label="Category">{projection.classification.categoryLabel}</InspectorData>
          <InspectorData label="Decision">
            {projection.classification.isDevelopment ? 'Development process' : 'Not development'}
          </InspectorData>
          <InspectorData label="Score">
            <span className="process-mono">{projection.classification.score}</span>
          </InspectorData>
          <InspectorData label="Rule set">
            <span className="process-mono">v{projection.classification.version}</span>
          </InspectorData>
          <InspectorData label="Override">{projection.classification.override.label}</InspectorData>
          <InspectorData label="Project ID">
            {projection.projectId ?? <span className="process-muted">None</span>}
          </InspectorData>
        </dl>
      </InspectorSection>

      <InspectorSection title="Reasons">
        {reasons.length > 0 ? (
          <ul className="process-inspector-list process-reason-list">
            {reasons.map((reason) => (
              <li key={reason.key}>
                <div>
                  <span>{reason.summary}</span>
                  <small className="process-mono">{reason.code}</small>
                </div>
                <strong className="process-mono">
                  {reason.score > 0 ? '+' : ''}
                  {reason.score}
                </strong>
              </li>
            ))}
          </ul>
        ) : (
          <p className="process-inspector-empty">No classification reasons reported</p>
        )}
        {projection.classification.reasons.length > reasons.length ? (
          <p className="process-inspector-overflow">
            {projection.classification.reasons.length - reasons.length} additional reasons
          </p>
        ) : null}
      </InspectorSection>

      <InspectorSection title="Project evidence">
        <AvailabilityValue value={projection.projectFeatures} />
        {features.length > 0 ? (
          <ul className="process-inspector-list process-feature-list">
            {features.map((feature) => (
              <li key={`${feature.markerId}:${feature.markerPath}`}>
                <div>
                  <span>{feature.markerId}</span>
                  <small className="process-breakable process-mono">{feature.markerPath}</small>
                </div>
              </li>
            ))}
          </ul>
        ) : null}
        {projection.projectFeatures.kind === 'known' &&
        projection.projectFeatures.value.length > features.length ? (
          <p className="process-inspector-overflow">
            {projection.projectFeatures.value.length - features.length} additional markers
          </p>
        ) : null}
      </InspectorSection>
    </div>
  );
}

function InspectorSection({ children, title }: { children: ReactNode; title: string }) {
  const headingId = useId();
  return (
    <section aria-labelledby={headingId} className="process-inspector-section">
      <h3 id={headingId}>{title}</h3>
      {children}
    </section>
  );
}

function InspectorData({ children, label }: { children: ReactNode; label: string }) {
  return (
    <div>
      <dt>{label}</dt>
      <dd>{children}</dd>
    </div>
  );
}

function AvailabilityValue<T>({
  compact = false,
  mono = false,
  value,
}: {
  compact?: boolean;
  mono?: boolean;
  value: FieldPresentation<T>;
}) {
  if (value.kind === 'known') {
    return <span className={mono ? 'process-mono' : undefined}>{value.text}</span>;
  }
  const { Icon, tone } = availabilityPresentation(value.kind);
  return (
    <InlineValue
      Icon={Icon}
      compact={compact}
      detail={value.reason ?? undefined}
      kind={value.kind}
      text={value.text}
      tone={tone}
    />
  );
}

function InlineValue({
  Icon,
  compact = false,
  detail,
  kind,
  text,
  tone,
}: {
  Icon: LucideIcon;
  compact?: boolean;
  detail?: string | undefined;
  kind: InlineValueKind;
  text: string;
  tone?: 'muted' | 'warning' | undefined;
}) {
  return (
    <span
      className={
        compact ? 'process-inline-value process-inline-value--compact' : 'process-inline-value'
      }
      data-field-kind={kind}
      data-tone={tone}
    >
      <Icon aria-hidden="true" size={14} strokeWidth={1.8} />
      <span>
        <span>{text}</span>
        {detail ? <small>{detail}</small> : null}
      </span>
    </span>
  );
}

function CodeValue({ value }: { value: FieldPresentation<string> }) {
  if (value.kind !== 'known') {
    return <AvailabilityValue value={value} />;
  }
  return <pre className="process-code-value">{value.value}</pre>;
}

function TreeNodeValue({ node, selected = false }: { node: ProcessTreeNode; selected?: boolean }) {
  return (
    <span className="process-tree-value" data-selected={selected || undefined}>
      <GitBranch aria-hidden="true" size={14} strokeWidth={1.8} />
      <span>
        {node.name.kind === 'known' ? (
          <span>{node.name.text}</span>
        ) : (
          <AvailabilityValue compact value={node.name} />
        )}
        <small className="process-mono">PID {node.pid.toLocaleString()}</small>
      </span>
    </span>
  );
}

function TreeTermination({ termination }: { termination: AncestryTermination }) {
  const kind = terminationKind(termination.kind);
  const { Icon, tone } =
    termination.kind === 'cycle' || termination.kind === 'depthLimited'
      ? { Icon: TriangleAlert, tone: 'warning' as const }
      : availabilityPresentation(kind);
  return (
    <div className="process-tree-termination">
      <InlineValue
        Icon={Icon}
        detail={termination.reason ?? undefined}
        kind={kind}
        text={termination.text}
        tone={tone}
      />
    </div>
  );
}

function availabilityPresentation(kind: AvailabilityKind): {
  Icon: LucideIcon;
  tone: 'muted' | 'warning';
} {
  switch (kind) {
    case 'accessLimited':
      return { Icon: ShieldAlert, tone: 'warning' };
    case 'missing':
      return { Icon: CircleMinus, tone: 'muted' };
    case 'notSupported':
      return { Icon: CircleOff, tone: 'muted' };
    case 'unknown':
      return { Icon: CircleHelp, tone: 'muted' };
    case 'known':
      return { Icon: CircleCheck, tone: 'muted' };
  }
}

function statusIcon(status: ProcessStatus | null): LucideIcon {
  switch (status) {
    case 'running':
      return CircleCheck;
    case 'sleeping':
      return Moon;
    case 'stopped':
      return CirclePause;
    case 'zombie':
      return TriangleAlert;
    case 'exited':
      return CircleStop;
    case 'unknown':
    case null:
      return CircleHelp;
  }
}

function terminationKind(kind: AncestryTermination['kind']): AvailabilityKind {
  switch (kind) {
    case 'root':
      return 'known';
    case 'accessLimited':
      return 'accessLimited';
    case 'notSupported':
      return 'notSupported';
    case 'outsideSnapshot':
      return 'missing';
    case 'cycle':
    case 'depthLimited':
    case 'unknown':
      return 'unknown';
  }
}

function isInspectorTab(value: string): value is InspectorTab {
  return value === 'overview' || value === 'tree' || value === 'command' || value === 'reasons';
}

function useCompactInspector() {
  const [compact, setCompact] = useState(() => mediaQueryMatches(COMPACT_INSPECTOR_QUERY));

  useEffect(() => {
    if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') {
      return;
    }
    const query = window.matchMedia(COMPACT_INSPECTOR_QUERY);
    const update = () => setCompact(query.matches);
    update();
    query.addEventListener('change', update);
    return () => query.removeEventListener('change', update);
  }, []);

  return compact;
}

function mediaQueryMatches(query: string) {
  return (
    typeof window !== 'undefined' &&
    typeof window.matchMedia === 'function' &&
    window.matchMedia(query).matches
  );
}
