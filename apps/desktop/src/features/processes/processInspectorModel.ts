import type {
  AccessLevel,
  AddressFamily,
  ClassificationCategory,
  ClassificationReason,
  FieldValue,
  PortBinding,
  PortOwnershipConfidence,
  PortProtocol,
  PortState,
  ProcessInstanceKey,
  ProcessOwnership,
  ProcessRecord,
  ProcessStatus,
  ProjectAssociationEvidence,
  ProjectEvidence,
  ProjectFeatureEvidence,
  UserClassificationOverride,
} from '@dpm/generated-types';

import { processInstanceKey } from './processTableModel';

export { processInstanceKey };

export const DEFAULT_ANCESTRY_DEPTH = 32;
export const MAX_ANCESTRY_DEPTH = 64;

export type AvailabilityKind = 'known' | 'missing' | 'unknown' | 'accessLimited' | 'notSupported';

export type FieldPresentation<T> =
  | {
      readonly kind: 'known';
      readonly reason: null;
      readonly text: string;
      readonly value: T;
    }
  | {
      readonly kind: Exclude<AvailabilityKind, 'known'>;
      readonly reason: string | null;
      readonly text: string;
      readonly value: null;
    };

export interface AvailabilityLabels {
  readonly accessLimited?: string;
  readonly missing?: string;
  readonly notSupported?: string;
  readonly unknown?: string;
}

export type ClassificationOverrideKind = 'automatic' | 'include' | 'exclude' | 'assignProject';

export interface ClassificationOverridePresentation {
  readonly kind: ClassificationOverrideKind;
  readonly label: string;
  readonly projectId: string | null;
  readonly value: UserClassificationOverride | null;
}

export interface ClassificationReasonPresentation {
  readonly code: string;
  readonly key: string;
  readonly score: number;
  readonly summary: string;
}

export interface ProcessClassificationProjection {
  readonly category: ClassificationCategory;
  readonly categoryLabel: string;
  readonly isDevelopment: boolean;
  readonly override: ClassificationOverridePresentation;
  readonly reasons: readonly ClassificationReasonPresentation[];
  readonly score: number;
  readonly version: number;
}

export interface PortPresentation {
  readonly addressFamily: AddressFamily;
  readonly binding: PortBinding;
  readonly confidence: PortOwnershipConfidence;
  readonly confidenceLabel: string;
  readonly endpoint: string;
  readonly key: string;
  readonly localAddress: string;
  readonly localPort: number;
  readonly observedAt: string;
  readonly observedAtText: string;
  readonly protocol: PortProtocol;
  readonly protocolLabel: string;
  readonly state: FieldPresentation<PortState>;
}

export interface ProcessTreeNode {
  readonly instanceKey: ProcessInstanceKey;
  readonly key: string;
  readonly name: FieldPresentation<string>;
  readonly pid: number;
  readonly process: ProcessRecord;
}

export interface ProcessReference {
  readonly instanceKey: ProcessInstanceKey;
  readonly key: string;
  readonly name: FieldPresentation<string>;
  readonly pid: number;
  readonly process: ProcessRecord | null;
}

export type ProcessParentKind = 'root' | 'known' | 'unknown' | 'accessLimited' | 'notSupported';

export interface ProcessParentPresentation {
  readonly kind: ProcessParentKind;
  readonly reason: string | null;
  readonly reference: ProcessReference | null;
  readonly text: string;
}

export type AncestryTerminationKind =
  | 'root'
  | 'unknown'
  | 'accessLimited'
  | 'notSupported'
  | 'outsideSnapshot'
  | 'cycle'
  | 'depthLimited';

export interface AncestryTermination {
  readonly kind: AncestryTerminationKind;
  readonly reason: string | null;
  readonly reference: ProcessReference | null;
  readonly text: string;
}

export interface ProcessTreeContext {
  readonly ancestorsClosestFirst: readonly ProcessTreeNode[];
  readonly depthLimit: number;
  readonly directChildren: readonly ProcessTreeNode[];
  readonly parent: ProcessParentPresentation;
  readonly selected: ProcessTreeNode;
  readonly termination: AncestryTermination;
}

export interface BuildProcessTreeOptions {
  readonly maxAncestryDepth?: number;
}

export interface ProcessInspectorProjection {
  readonly accessLevel: AccessLevel;
  readonly accessLevelLabel: string;
  readonly classification: ProcessClassificationProjection;
  readonly command: FieldPresentation<string>;
  readonly cpu: FieldPresentation<number>;
  readonly executablePath: FieldPresentation<string>;
  readonly instanceKey: ProcessInstanceKey;
  readonly key: string;
  readonly lastSeenRevision: number;
  readonly memory: FieldPresentation<number>;
  readonly name: FieldPresentation<string>;
  readonly owner: FieldPresentation<string>;
  readonly ownership: ProcessOwnership;
  readonly ownershipLabel: string;
  readonly pid: number;
  readonly ports: FieldPresentation<readonly PortPresentation[]>;
  readonly projectAssociation: FieldPresentation<ProjectAssociationEvidence>;
  readonly projectFeatures: FieldPresentation<readonly ProjectFeatureEvidence[]>;
  readonly projectId: string | null;
  readonly startedAt: FieldPresentation<string>;
  readonly status: FieldPresentation<ProcessStatus>;
  readonly tree: ProcessTreeContext;
  readonly workingDirectory: FieldPresentation<string>;
}

export const processStatusLabels: Readonly<Record<ProcessStatus, string>> = {
  running: 'Running',
  sleeping: 'Sleeping',
  stopped: 'Stopped',
  zombie: 'Zombie',
  exited: 'Exited',
  unknown: 'Status unknown',
};

export const classificationCategoryLabels: Readonly<Record<ClassificationCategory, string>> = {
  development: 'Development',
  runtime: 'Runtime',
  infrastructure: 'Infrastructure',
  database: 'Database',
  excluded: 'Excluded',
  unknown: 'Unclassified',
};

export const classificationOverrideLabels: Readonly<Record<ClassificationOverrideKind, string>> = {
  automatic: 'Automatic',
  include: 'Included by rule',
  exclude: 'Excluded by rule',
  assignProject: 'Assigned project',
};

export const processOwnershipLabels: Readonly<Record<ProcessOwnership, string>> = {
  managed: 'Managed process',
  external: 'External process',
};

export const accessLevelLabels: Readonly<Record<AccessLevel, string>> = {
  full: 'Full access',
  limited: 'Limited access',
  denied: 'Access denied',
};

export const portStateLabels: Readonly<Record<PortState, string>> = {
  tcpListen: 'Listening',
  tcpEstablished: 'Established',
  tcpOther: 'Other TCP state',
  udpBound: 'Bound',
  unknown: 'State unknown',
};

export const portConfidenceLabels: Readonly<Record<PortOwnershipConfidence, string>> = {
  exact: 'Exact owner',
  shared: 'Shared owner',
  inferred: 'Inferred owner',
  unknown: 'Owner unknown',
};

export const addressFamilyLabels: Readonly<Record<AddressFamily, string>> = {
  ipv4: 'IPv4',
  ipv6: 'IPv6',
};

const DEFAULT_AVAILABILITY_LABELS: Required<AvailabilityLabels> = {
  accessLimited: 'Access limited',
  missing: 'Not found',
  notSupported: 'Not supported',
  unknown: 'Unknown',
};

const DATE_TIME_FORMATTER = new Intl.DateTimeFormat('en-US', {
  dateStyle: 'medium',
  timeStyle: 'medium',
});

export function presentFieldValue<T>(
  field: FieldValue<T>,
  formatKnown: (value: T) => string,
  labels: AvailabilityLabels = {},
): FieldPresentation<T> {
  if (typeof field === 'object' && 'known' in field) {
    return { kind: 'known', reason: null, text: formatKnown(field.known), value: field.known };
  }
  if (typeof field === 'object') {
    return {
      kind: 'accessLimited',
      reason: field.accessLimited.reason,
      text: labels.accessLimited ?? DEFAULT_AVAILABILITY_LABELS.accessLimited,
      value: null,
    };
  }
  if (field === 'notSupported') {
    return {
      kind: 'notSupported',
      reason: null,
      text: labels.notSupported ?? DEFAULT_AVAILABILITY_LABELS.notSupported,
      value: null,
    };
  }
  return {
    kind: 'unknown',
    reason: null,
    text: labels.unknown ?? DEFAULT_AVAILABILITY_LABELS.unknown,
    value: null,
  };
}

export function presentProjectEvidence<T>(
  evidence: ProjectEvidence<T>,
  formatKnown: (value: T) => string,
  labels: AvailabilityLabels = {},
): FieldPresentation<T> {
  if (typeof evidence === 'object' && 'known' in evidence) {
    return {
      kind: 'known',
      reason: null,
      text: formatKnown(evidence.known),
      value: evidence.known,
    };
  }
  if (evidence === 'missing') {
    return {
      kind: 'missing',
      reason: null,
      text: labels.missing ?? DEFAULT_AVAILABILITY_LABELS.missing,
      value: null,
    };
  }
  if (typeof evidence === 'object') {
    return {
      kind: 'accessLimited',
      reason: evidence.accessLimited.reason,
      text: labels.accessLimited ?? DEFAULT_AVAILABILITY_LABELS.accessLimited,
      value: null,
    };
  }
  if (evidence === 'notSupported') {
    return {
      kind: 'notSupported',
      reason: null,
      text: labels.notSupported ?? DEFAULT_AVAILABILITY_LABELS.notSupported,
      value: null,
    };
  }
  return {
    kind: 'unknown',
    reason: null,
    text: labels.unknown ?? DEFAULT_AVAILABILITY_LABELS.unknown,
    value: null,
  };
}

export function presentClassificationOverride(
  value: UserClassificationOverride | null,
): ClassificationOverridePresentation {
  if (value === null) {
    return {
      kind: 'automatic',
      label: classificationOverrideLabels.automatic,
      projectId: null,
      value,
    };
  }
  if (typeof value === 'object') {
    return {
      kind: 'assignProject',
      label: `${classificationOverrideLabels.assignProject}: ${value.assignProject}`,
      projectId: value.assignProject,
      value,
    };
  }
  return {
    kind: value,
    label: classificationOverrideLabels[value],
    projectId: null,
    value,
  };
}

export function presentClassificationReasons(
  reasons: readonly ClassificationReason[],
): ClassificationReasonPresentation[] {
  const sorted = reasons
    .map((reason, sourceIndex) => ({ reason, sourceIndex }))
    .sort((left, right) => {
      return (
        compareNumber(right.reason.score, left.reason.score) ||
        compareText(left.reason.code, right.reason.code) ||
        compareText(left.reason.summary, right.reason.summary) ||
        compareNumber(left.sourceIndex, right.sourceIndex)
      );
    });
  const occurrences = new Map<string, number>();

  return sorted.map(({ reason }) => {
    const baseKey = JSON.stringify([reason.code, reason.score, reason.summary]);
    const occurrence = occurrences.get(baseKey) ?? 0;
    occurrences.set(baseKey, occurrence + 1);
    return {
      code: reason.code,
      key: `${baseKey}:${occurrence}`,
      score: reason.score,
      summary: reason.summary,
    };
  });
}

export function buildProcessTreeContext(
  processes: readonly ProcessRecord[],
  selectedKey: string | ProcessInstanceKey | null,
  options: BuildProcessTreeOptions = {},
): ProcessTreeContext | null {
  if (selectedKey === null) {
    return null;
  }

  const index = buildProcessIndex(processes);
  const normalizedSelectedKey =
    typeof selectedKey === 'string' ? selectedKey : processInstanceKey(selectedKey);
  const selectedProcess = index.get(normalizedSelectedKey);
  if (selectedProcess === undefined) {
    return null;
  }

  const selected = buildTreeNode(selectedProcess);
  const parent = presentParent(selectedProcess.parentInstanceKey, index);
  const directChildren = processes
    .filter(
      (process) =>
        processInstanceKey(process.instanceKey) !== normalizedSelectedKey &&
        knownParentKey(process.parentInstanceKey) === normalizedSelectedKey,
    )
    .map(buildTreeNode)
    .sort(compareTreeNodes);
  const depthLimit = normalizeDepthLimit(options.maxAncestryDepth);
  const ancestry = buildAncestry(selected, parent, index, depthLimit);

  return {
    ancestorsClosestFirst: ancestry.ancestors,
    depthLimit,
    directChildren,
    parent,
    selected,
    termination: ancestry.termination,
  };
}

export function buildProcessInspectorProjection(
  processes: readonly ProcessRecord[],
  selectedKey: string | ProcessInstanceKey | null,
  options: BuildProcessTreeOptions = {},
): ProcessInspectorProjection | null {
  const tree = buildProcessTreeContext(processes, selectedKey, options);
  if (tree === null) {
    return null;
  }

  const process = tree.selected.process;
  return {
    accessLevel: process.accessLevel,
    accessLevelLabel: accessLevelLabels[process.accessLevel],
    classification: {
      category: process.classification.category,
      categoryLabel: classificationCategoryLabels[process.classification.category],
      isDevelopment: process.classification.isDevelopment,
      override: presentClassificationOverride(process.classification.userOverride),
      reasons: presentClassificationReasons(process.classification.reasons),
      score: process.classification.score,
      version: process.classification.version,
    },
    command: presentFieldValue(process.commandLine, presentTextValue, {
      unknown: 'Command unknown',
    }),
    cpu: presentFieldValue(process.cpuPercent, formatCpuPercent),
    executablePath: presentFieldValue(process.executablePath, presentTextValue, {
      unknown: 'Path unknown',
    }),
    instanceKey: process.instanceKey,
    key: tree.selected.key,
    lastSeenRevision: process.lastSeenRevision,
    memory: presentFieldValue(process.memoryBytes, formatBytes),
    name: tree.selected.name,
    owner: presentFieldValue(process.ownerUser, presentTextValue, {
      unknown: 'Owner unknown',
    }),
    ownership: process.ownership,
    ownershipLabel: processOwnershipLabels[process.ownership],
    pid: process.instanceKey.pid,
    ports: presentPorts(process.portBindings),
    projectAssociation: presentProjectEvidence(
      process.projectAssociation,
      (association) => association.projectId,
      { missing: 'No associated project' },
    ),
    projectFeatures: presentProjectEvidence(
      process.projectFeatures,
      (features) => formatFeatureCount(features.length),
      { missing: 'No project features detected' },
    ),
    projectId: process.projectId,
    startedAt: presentFieldValue(process.startedAt, formatStartedAt, {
      unknown: 'Start time unknown',
    }),
    status: presentFieldValue(process.status, (status) => processStatusLabels[status]),
    tree,
    workingDirectory: presentFieldValue(process.workingDirectory, presentTextValue, {
      unknown: 'Working directory unknown',
    }),
  };
}

export function formatCpuPercent(value: number): string {
  return `${value.toFixed(value >= 100 ? 0 : 1)}%`;
}

export function formatBytes(value: number): string {
  const units = ['B', 'KB', 'MB', 'GB', 'TB'] as const;
  let amount = Math.max(0, value);
  let unitIndex = 0;
  while (amount >= 1024 && unitIndex < units.length - 1) {
    amount /= 1024;
    unitIndex += 1;
  }
  return `${amount.toFixed(unitIndex === 0 || amount >= 100 ? 0 : 1)} ${units[unitIndex]}`;
}

export function formatStartedAt(value: string): string {
  const timestamp = Date.parse(value);
  return Number.isFinite(timestamp) ? DATE_TIME_FORMATTER.format(timestamp) : value;
}

export function formatProcessIdentity(key: ProcessInstanceKey): string {
  return `PID ${key.pid} / boot ${key.bootId} / started ${key.nativeStartTime}`;
}

function presentPorts(
  field: FieldValue<PortBinding[]>,
): FieldPresentation<readonly PortPresentation[]> {
  const source = presentFieldValue(field, (bindings) => formatPortCount(bindings.length));
  if (source.kind !== 'known') {
    return source;
  }
  const items = presentPortBindings(source.value);
  return {
    kind: 'known',
    reason: null,
    text: formatPortCount(items.length),
    value: items,
  };
}

function presentPortBindings(bindings: readonly PortBinding[]): PortPresentation[] {
  const sorted = bindings
    .map((binding, sourceIndex) => ({ binding, sourceIndex }))
    .sort((left, right) => {
      return (
        compareNumber(left.binding.localPort, right.binding.localPort) ||
        compareText(left.binding.protocol, right.binding.protocol) ||
        compareText(left.binding.addressFamily, right.binding.addressFamily) ||
        compareText(left.binding.localAddress, right.binding.localAddress) ||
        compareNumber(left.sourceIndex, right.sourceIndex)
      );
    });
  const occurrences = new Map<string, number>();

  return sorted.map(({ binding }) => {
    const ownerKey =
      binding.processInstanceKey === null ? null : processInstanceKey(binding.processInstanceKey);
    const baseKey = JSON.stringify([
      binding.protocol,
      binding.addressFamily,
      binding.localAddress,
      binding.localPort,
      ownerKey,
    ]);
    const occurrence = occurrences.get(baseKey) ?? 0;
    occurrences.set(baseKey, occurrence + 1);
    return {
      addressFamily: binding.addressFamily,
      binding,
      confidence: binding.confidence,
      confidenceLabel: portConfidenceLabels[binding.confidence],
      endpoint: formatEndpoint(binding.addressFamily, binding.localAddress, binding.localPort),
      key: `${baseKey}:${occurrence}`,
      localAddress: binding.localAddress,
      localPort: binding.localPort,
      observedAt: binding.observedAt,
      observedAtText: formatStartedAt(binding.observedAt),
      protocol: binding.protocol,
      protocolLabel: binding.protocol.toUpperCase(),
      state: presentFieldValue(binding.state, (state) => portStateLabels[state]),
    };
  });
}

function buildProcessIndex(processes: readonly ProcessRecord[]): Map<string, ProcessRecord> {
  const index = new Map<string, ProcessRecord>();
  for (const process of processes) {
    index.set(processInstanceKey(process.instanceKey), process);
  }
  return index;
}

function buildTreeNode(process: ProcessRecord): ProcessTreeNode {
  return {
    instanceKey: process.instanceKey,
    key: processInstanceKey(process.instanceKey),
    name: presentFieldValue(process.executableName, presentTextValue, {
      unknown: 'Name unknown',
    }),
    pid: process.instanceKey.pid,
    process,
  };
}

function buildProcessReference(
  instanceKey: ProcessInstanceKey,
  process: ProcessRecord | null,
): ProcessReference {
  return {
    instanceKey,
    key: processInstanceKey(instanceKey),
    name:
      process === null
        ? { kind: 'missing', reason: null, text: 'Outside current snapshot', value: null }
        : presentFieldValue(process.executableName, presentTextValue, { unknown: 'Name unknown' }),
    pid: instanceKey.pid,
    process,
  };
}

function presentParent(
  field: FieldValue<ProcessInstanceKey | null>,
  index: ReadonlyMap<string, ProcessRecord>,
): ProcessParentPresentation {
  if (typeof field === 'object' && 'known' in field) {
    if (field.known === null) {
      return { kind: 'root', reason: null, reference: null, text: 'No parent process' };
    }
    const key = processInstanceKey(field.known);
    const reference = buildProcessReference(field.known, index.get(key) ?? null);
    return {
      kind: 'known',
      reason: null,
      reference,
      text:
        reference.process === null
          ? `PID ${reference.pid} (outside snapshot)`
          : reference.name.text,
    };
  }
  if (typeof field === 'object') {
    return {
      kind: 'accessLimited',
      reason: field.accessLimited.reason,
      reference: null,
      text: 'Parent process access limited',
    };
  }
  if (field === 'notSupported') {
    return {
      kind: 'notSupported',
      reason: null,
      reference: null,
      text: 'Parent information not supported',
    };
  }
  return { kind: 'unknown', reason: null, reference: null, text: 'Parent process unknown' };
}

function buildAncestry(
  selected: ProcessTreeNode,
  initialParent: ProcessParentPresentation,
  index: ReadonlyMap<string, ProcessRecord>,
  depthLimit: number,
): { ancestors: ProcessTreeNode[]; termination: AncestryTermination } {
  const ancestors: ProcessTreeNode[] = [];
  const visited = new Set<string>([selected.key]);
  let parent = initialParent;

  while (parent.kind === 'known') {
    const reference = parent.reference;
    if (reference === null) {
      return { ancestors, termination: terminationForParent(parent) };
    }
    if (visited.has(reference.key)) {
      return {
        ancestors,
        termination: {
          kind: 'cycle',
          reason: null,
          reference,
          text: `Parent cycle detected at PID ${reference.pid}`,
        },
      };
    }
    if (reference.process === null) {
      return {
        ancestors,
        termination: {
          kind: 'outsideSnapshot',
          reason: null,
          reference,
          text: `Parent PID ${reference.pid} is outside the current snapshot`,
        },
      };
    }
    if (ancestors.length >= depthLimit) {
      return {
        ancestors,
        termination: {
          kind: 'depthLimited',
          reason: null,
          reference,
          text: `Only the nearest ${depthLimit} parent levels are shown`,
        },
      };
    }

    const node = buildTreeNode(reference.process);
    ancestors.push(node);
    visited.add(node.key);
    parent = presentParent(reference.process.parentInstanceKey, index);
  }

  return { ancestors, termination: terminationForParent(parent) };
}

function terminationForParent(parent: ProcessParentPresentation): AncestryTermination {
  switch (parent.kind) {
    case 'root':
      return { kind: 'root', reason: null, reference: null, text: 'Reached the process tree root' };
    case 'unknown':
      return { kind: 'unknown', reason: null, reference: null, text: 'Higher parent unknown' };
    case 'accessLimited':
      return {
        kind: 'accessLimited',
        reason: parent.reason,
        reference: null,
        text: 'Higher parent access limited',
      };
    case 'notSupported':
      return {
        kind: 'notSupported',
        reason: null,
        reference: null,
        text: 'Higher parent information is not supported',
      };
    case 'known':
      return {
        kind: 'outsideSnapshot',
        reason: null,
        reference: parent.reference,
        text: parent.text,
      };
  }
}

function knownParentKey(field: FieldValue<ProcessInstanceKey | null>): string | null {
  return typeof field === 'object' && 'known' in field && field.known !== null
    ? processInstanceKey(field.known)
    : null;
}

function normalizeDepthLimit(requested: number | undefined): number {
  if (requested === undefined || !Number.isFinite(requested)) {
    return DEFAULT_ANCESTRY_DEPTH;
  }
  return Math.min(MAX_ANCESTRY_DEPTH, Math.max(1, Math.trunc(requested)));
}

function compareTreeNodes(left: ProcessTreeNode, right: ProcessTreeNode): number {
  return (
    compareText(left.name.text, right.name.text) ||
    compareNumber(left.pid, right.pid) ||
    compareText(left.key, right.key)
  );
}

function compareNumber(left: number, right: number): number {
  return left === right ? 0 : left < right ? -1 : 1;
}

function compareText(left: string, right: string): number {
  const normalizedLeft = left.toLowerCase();
  const normalizedRight = right.toLowerCase();
  if (normalizedLeft !== normalizedRight) {
    return normalizedLeft < normalizedRight ? -1 : 1;
  }
  return left === right ? 0 : left < right ? -1 : 1;
}

function presentTextValue(value: string): string {
  return value.length === 0 ? '(empty)' : value;
}

function formatPortCount(count: number): string {
  return count === 0 ? 'No ports' : `${count} ${count === 1 ? 'port' : 'ports'}`;
}

function formatFeatureCount(count: number): string {
  return count === 0
    ? 'No project features detected'
    : `${count} project ${count === 1 ? 'feature' : 'features'}`;
}

function formatEndpoint(family: AddressFamily, address: string, port: number): string {
  return family === 'ipv6' ? `[${address}]:${port}` : `${address}:${port}`;
}
