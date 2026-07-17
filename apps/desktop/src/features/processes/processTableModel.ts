import type {
  FieldValue,
  PortBinding,
  ProcessInstanceKey,
  ProcessRecord,
  ProcessStatus,
  ProjectAssociationEvidence,
  ProjectEvidence,
} from '@dpm/generated-types';

export type ProcessFilter = 'all' | 'managed' | 'recognized' | 'listening' | 'limited';

export type ProcessSortKey =
  | 'name'
  | 'status'
  | 'project'
  | 'ports'
  | 'cpu'
  | 'memory'
  | 'uptime'
  | 'pid';

export type SortDirection = 'asc' | 'desc';

export type FieldPresentationKind =
  | 'known'
  | 'missing'
  | 'unknown'
  | 'accessLimited'
  | 'notSupported';

export interface FieldPresentation<T> {
  readonly kind: FieldPresentationKind;
  readonly reason: string | null;
  readonly text: string;
  readonly value: T | null;
}

export interface ProcessSort {
  readonly direction: SortDirection;
  readonly key: ProcessSortKey;
}

export interface BuildProcessTableRowsOptions {
  readonly filter?: ProcessFilter;
  readonly search?: string;
  readonly sort?: ProcessSort;
}

export interface ProcessTableRow {
  readonly cpu: FieldPresentation<number>;
  readonly cpuPercent: number | null;
  readonly key: string;
  readonly limited: boolean;
  readonly listening: boolean;
  readonly memory: FieldPresentation<number>;
  readonly memoryBytes: number | null;
  readonly name: FieldPresentation<string>;
  readonly pid: number;
  readonly portCount: number | null;
  readonly ports: FieldPresentation<readonly PortBinding[]>;
  readonly portSummary: string;
  readonly process: ProcessRecord;
  readonly project: FieldPresentation<string>;
  readonly recognized: boolean;
  readonly startedAt: FieldPresentation<number>;
  readonly startedAtMs: number | null;
  readonly status: FieldPresentation<ProcessStatus>;
}

export const processFilterItems: ReadonlyArray<{
  readonly label: string;
  readonly value: ProcessFilter;
}> = [
  { value: 'all', label: 'All' },
  { value: 'managed', label: 'Managed' },
  { value: 'recognized', label: 'Recognized' },
  { value: 'listening', label: 'Listening' },
  { value: 'limited', label: 'Limited' },
];

export const defaultProcessSort: ProcessSort = { key: 'name', direction: 'asc' };

const STATUS_TEXT: Readonly<Record<ProcessStatus, string>> = {
  running: '运行中',
  sleeping: '休眠',
  stopped: '已停止',
  zombie: '僵尸进程',
  exited: '已退出',
  unknown: '状态未知',
};

const STATUS_ORDER: Readonly<Record<ProcessStatus, number>> = {
  running: 0,
  sleeping: 1,
  stopped: 2,
  zombie: 3,
  exited: 4,
  unknown: 5,
};

const PRESENTATION_ORDER: Readonly<Record<FieldPresentationKind, number>> = {
  known: 0,
  missing: 1,
  unknown: 2,
  accessLimited: 3,
  notSupported: 4,
};

export function processInstanceKey(key: ProcessInstanceKey): string {
  return JSON.stringify([key.bootId, key.pid, key.nativeStartTime]);
}

export function buildProcessTableRows(
  processes: readonly ProcessRecord[],
  options: BuildProcessTableRowsOptions = {},
): ProcessTableRow[] {
  const filter = options.filter ?? 'all';
  const searchTokens = normalizeSearch(options.search ?? '');
  const sort = options.sort ?? defaultProcessSort;

  return processes
    .map(buildProcessTableRow)
    .filter((row) => matchesFilter(row, filter) && matchesSearch(row, searchTokens))
    .sort((left, right) => compareRows(left, right, sort));
}

export function summarizePorts(bindings: readonly PortBinding[], limit = 3): string {
  const ports = uniqueSortedPorts(bindings);
  if (ports.length === 0) {
    return '无端口';
  }

  const visibleLimit = Math.max(1, Math.trunc(limit));
  const visible = ports.slice(0, visibleLimit).map(({ localPort, protocol }) => {
    return `${protocol.toUpperCase()} ${localPort}`;
  });
  const hiddenCount = ports.length - visible.length;
  return hiddenCount > 0 ? `${visible.join(' · ')} +${hiddenCount}` : visible.join(' · ');
}

function buildProcessTableRow(process: ProcessRecord): ProcessTableRow {
  const name = presentField(process.executableName, (value) => value || '未命名');
  const status = presentField(process.status, (value) => STATUS_TEXT[value]);
  const cpu = presentField(process.cpuPercent, formatCpuPercent);
  const memory = presentField(process.memoryBytes, formatBytes);
  const startedAt = presentStartedAt(process.startedAt);
  const ports = presentField(process.portBindings, summarizePorts);
  const project = presentProject(process.projectAssociation, process.projectId);
  const portCount =
    ports.kind === 'known' && ports.value !== null ? uniqueSortedPorts(ports.value).length : null;
  const listening = hasListeningPort(process.portBindings);
  const limited = isAccessLimited(process);

  return {
    cpu,
    cpuPercent: cpu.value,
    key: processInstanceKey(process.instanceKey),
    limited,
    listening,
    memory,
    memoryBytes: memory.value,
    name,
    pid: process.instanceKey.pid,
    portCount,
    ports,
    portSummary: ports.text,
    process,
    project,
    recognized: process.classification.isDevelopment,
    startedAt,
    startedAtMs: startedAt.value,
    status,
  };
}

function presentField<T>(
  field: FieldValue<T>,
  formatKnown: (value: T) => string,
): FieldPresentation<T> {
  if (typeof field === 'object' && 'known' in field) {
    return { kind: 'known', reason: null, text: formatKnown(field.known), value: field.known };
  }
  if (typeof field === 'object') {
    return {
      kind: 'accessLimited',
      reason: field.accessLimited.reason,
      text: '访问受限',
      value: null,
    };
  }
  if (field === 'notSupported') {
    return { kind: 'notSupported', reason: null, text: '不支持', value: null };
  }
  return { kind: 'unknown', reason: null, text: '未知', value: null };
}

function presentStartedAt(field: FieldValue<string>): FieldPresentation<number> {
  const presentation = presentField(field, (value) => value);
  if (presentation.kind !== 'known' || presentation.value === null) {
    return { ...presentation, value: null };
  }

  const timestamp = Date.parse(presentation.value);
  if (!Number.isFinite(timestamp)) {
    return { kind: 'unknown', reason: null, text: '未知', value: null };
  }
  return { ...presentation, value: timestamp };
}

function presentProject(
  evidence: ProjectEvidence<ProjectAssociationEvidence>,
  compatibilityProjectId: string | null,
): FieldPresentation<string> {
  if (typeof evidence === 'object' && 'known' in evidence) {
    return {
      kind: 'known',
      reason: null,
      text: evidence.known.projectId,
      value: evidence.known.projectId,
    };
  }
  if (compatibilityProjectId !== null) {
    return {
      kind: 'known',
      reason: null,
      text: compatibilityProjectId,
      value: compatibilityProjectId,
    };
  }
  if (evidence === 'missing') {
    return { kind: 'missing', reason: null, text: '未关联', value: null };
  }
  if (typeof evidence === 'object') {
    return {
      kind: 'accessLimited',
      reason: evidence.accessLimited.reason,
      text: '访问受限',
      value: null,
    };
  }
  if (evidence === 'notSupported') {
    return { kind: 'notSupported', reason: null, text: '不支持', value: null };
  }
  return { kind: 'unknown', reason: null, text: '未知', value: null };
}

function matchesFilter(row: ProcessTableRow, filter: ProcessFilter): boolean {
  switch (filter) {
    case 'all':
      return true;
    case 'managed':
      return row.process.ownership === 'managed';
    case 'recognized':
      return row.recognized;
    case 'listening':
      return row.listening;
    case 'limited':
      return row.limited;
  }
}

function matchesSearch(row: ProcessTableRow, tokens: readonly string[]): boolean {
  if (tokens.length === 0) {
    return true;
  }

  const process = row.process;
  const values = [
    String(row.pid),
    row.name.text,
    row.status.text,
    row.project.text,
    row.portSummary,
    knownValue(process.ownerUser),
    knownValue(process.executablePath),
    knownValue(process.commandLine),
    knownValue(process.workingDirectory),
    knownProjectRoot(process.projectAssociation),
    ...knownPorts(process.portBindings).flatMap((binding) => [
      binding.protocol,
      binding.localAddress,
      String(binding.localPort),
    ]),
  ];
  const haystack = values.join('\n').toLowerCase();
  return tokens.every((token) => haystack.includes(token));
}

function normalizeSearch(search: string): string[] {
  return search.trim().toLowerCase().split(/\s+/u).filter(Boolean);
}

function knownValue(field: FieldValue<string>): string {
  return typeof field === 'object' && 'known' in field ? field.known : '';
}

function knownProjectRoot(evidence: ProjectEvidence<ProjectAssociationEvidence>): string {
  return typeof evidence === 'object' && 'known' in evidence ? evidence.known.registeredRoot : '';
}

function knownPorts(field: FieldValue<Array<PortBinding>>): readonly PortBinding[] {
  return typeof field === 'object' && 'known' in field ? field.known : [];
}

function hasListeningPort(field: FieldValue<Array<PortBinding>>): boolean {
  return knownPorts(field).some((binding) => {
    if (typeof binding.state !== 'object' || !('known' in binding.state)) {
      return false;
    }
    return binding.state.known === 'tcpListen' || binding.state.known === 'udpBound';
  });
}

function isAccessLimited(process: ProcessRecord): boolean {
  return (
    process.accessLevel !== 'full' ||
    [
      process.parentInstanceKey,
      process.ownerUser,
      process.executableName,
      process.executablePath,
      process.commandLine,
      process.workingDirectory,
      process.cpuPercent,
      process.memoryBytes,
      process.startedAt,
      process.status,
      process.portBindings,
      process.projectAssociation,
      process.projectFeatures,
    ].some(isAccessLimitedValue)
  );
}

function isAccessLimitedValue(value: unknown): boolean {
  return typeof value === 'object' && value !== null && 'accessLimited' in value;
}

function compareRows(left: ProcessTableRow, right: ProcessTableRow, sort: ProcessSort): number {
  const direction = sort.direction === 'asc' ? 1 : -1;
  let result: number;

  switch (sort.key) {
    case 'name':
      result = comparePresentation(left.name, right.name, compareText, direction);
      break;
    case 'status':
      result = comparePresentation(
        left.status,
        right.status,
        (a, b) => STATUS_ORDER[a] - STATUS_ORDER[b],
        direction,
      );
      break;
    case 'project':
      result = comparePresentation(left.project, right.project, compareText, direction);
      break;
    case 'ports':
      result = compareNullableNumber(
        left.portCount,
        left.ports,
        right.portCount,
        right.ports,
        direction,
      );
      break;
    case 'cpu':
      result = comparePresentation(left.cpu, right.cpu, compareNumber, direction);
      break;
    case 'memory':
      result = comparePresentation(left.memory, right.memory, compareNumber, direction);
      break;
    case 'uptime':
      result = comparePresentation(left.startedAt, right.startedAt, compareNumber, -direction);
      break;
    case 'pid':
      result = compareNumber(left.pid, right.pid) * direction;
      break;
  }

  if (result !== 0) {
    return result;
  }
  return compareText(left.key, right.key);
}

function comparePresentation<T>(
  left: FieldPresentation<T>,
  right: FieldPresentation<T>,
  compareKnown: (a: T, b: T) => number,
  direction: number,
): number {
  const availability = PRESENTATION_ORDER[left.kind] - PRESENTATION_ORDER[right.kind];
  if (availability !== 0) {
    return availability;
  }
  if (
    left.kind !== 'known' ||
    right.kind !== 'known' ||
    left.value === null ||
    right.value === null
  ) {
    return compareText(left.reason ?? '', right.reason ?? '');
  }
  return compareKnown(left.value, right.value) * direction;
}

function compareNullableNumber(
  left: number | null,
  leftPresentation: FieldPresentation<unknown>,
  right: number | null,
  rightPresentation: FieldPresentation<unknown>,
  direction: number,
): number {
  const availability =
    PRESENTATION_ORDER[leftPresentation.kind] - PRESENTATION_ORDER[rightPresentation.kind];
  if (availability !== 0) {
    return availability;
  }
  if (left === null || right === null) {
    return compareText(leftPresentation.reason ?? '', rightPresentation.reason ?? '');
  }
  return compareNumber(left, right) * direction;
}

function compareNumber(left: number, right: number): number {
  return left === right ? 0 : left < right ? -1 : 1;
}

function compareText(left: string, right: string): number {
  const normalizedLeft = left.toLowerCase();
  const normalizedRight = right.toLowerCase();
  return normalizedLeft === normalizedRight ? 0 : normalizedLeft < normalizedRight ? -1 : 1;
}

function uniqueSortedPorts(bindings: readonly PortBinding[]): PortBinding[] {
  const seen = new Set<string>();
  return [...bindings]
    .sort((left, right) => {
      return (
        compareNumber(left.localPort, right.localPort) ||
        compareText(left.protocol, right.protocol) ||
        compareText(left.localAddress, right.localAddress)
      );
    })
    .filter((binding) => {
      const key = `${binding.protocol}:${binding.localPort}`;
      if (seen.has(key)) {
        return false;
      }
      seen.add(key);
      return true;
    });
}

function formatCpuPercent(value: number): string {
  return `${value.toFixed(value >= 100 ? 0 : 1)}%`;
}

function formatBytes(value: number): string {
  const units = ['B', 'KB', 'MB', 'GB', 'TB'] as const;
  let amount = Math.max(0, value);
  let unitIndex = 0;
  while (amount >= 1024 && unitIndex < units.length - 1) {
    amount /= 1024;
    unitIndex += 1;
  }
  return `${amount.toFixed(unitIndex === 0 || amount >= 100 ? 0 : 1)} ${units[unitIndex]}`;
}
