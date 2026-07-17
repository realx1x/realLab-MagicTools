import type {
  AccessLevel,
  AddressFamily,
  ClassificationCategory,
  FieldValue,
  PortBinding,
  PortOwnershipConfidence,
  PortProtocol,
  PortState,
  ProcessInstanceKey,
  ProcessRecord,
  ProcessStatus,
  ProjectAssociationEvidence,
  ProjectEvidence,
  ProjectFeatureEvidence,
  UserClassificationOverride,
} from '@dpm/generated-types';

const MAX_STRESS_ROWS = 100_000;
const MOCK_BOOT_ID = 'mock-boot-p6-table-stress';
const MOCK_NOW_MS = Date.UTC(2026, 0, 15, 12, 0, 0);

const PROCESS_NAMES = [
  'node',
  'vite',
  'java',
  'python',
  'go',
  'postgres',
  'redis-server',
  'dotnet',
  '开发服务',
  '资源编译器',
] as const;

const PROCESS_STATUSES: readonly ProcessStatus[] = [
  'running',
  'sleeping',
  'stopped',
  'zombie',
  'exited',
  'unknown',
];

const CLASSIFICATION_CATEGORIES: readonly ClassificationCategory[] = [
  'development',
  'runtime',
  'infrastructure',
  'database',
  'excluded',
  'unknown',
];

/**
 * Explicit stress-data factory for UI development. Production code never enables it automatically.
 */
export function createProcessTableStressRows(count = 1_000): ProcessRecord[] {
  if (!Number.isInteger(count) || count < 0 || count > MAX_STRESS_ROWS) {
    throw new RangeError(`count must be an integer between 0 and ${MAX_STRESS_ROWS}`);
  }
  return Array.from({ length: count }, (_, index) => createProcessRecord(index));
}

function createProcessRecord(index: number): ProcessRecord {
  const instanceKey = createInstanceKey(index);
  const ownership = index % 4 === 0 ? 'managed' : 'external';
  const projectAssociation = createProjectAssociation(index);
  const projectId = knownProjectId(projectAssociation);
  const userOverride = createUserOverride(index, projectId);
  const explicitlyExcluded = userOverride === 'exclude';
  const isDevelopment = !explicitlyExcluded && (ownership === 'managed' || index % 3 === 0);
  const startedAt = new Date(MOCK_NOW_MS - (index + 1) * 73_000).toISOString();

  return {
    instanceKey,
    parentInstanceKey: mockField(index, 17, createParentKey(index)),
    ownerUser: mockField(index, 19, index % 2 === 0 ? 'developer' : '本地开发用户'),
    executableName: mockExecutableName(index),
    executablePath: mockField(index, 23, createExecutablePath(index)),
    commandLine: mockField(index, 29, createCommandLine(index)),
    workingDirectory: mockField(index, 31, createWorkingDirectory(index)),
    cpuPercent: mockField(index, 37, ((index * 37) % 1_600) / 10),
    memoryBytes: mockField(index, 41, (24 + ((index * 47) % 4_072)) * 1024 * 1024),
    startedAt: mockField(index, 43, startedAt),
    status: mockField(index, 47, PROCESS_STATUSES[index % PROCESS_STATUSES.length]!),
    accessLevel: createAccessLevel(index),
    ownership,
    managedRunId: ownership === 'managed' ? `mock-run-${index.toString(10)}` : null,
    projectAssociation,
    projectFeatures: createProjectFeatures(index),
    projectId,
    classification: {
      score: isDevelopment ? 45 + (index % 56) : index % 40,
      version: 1,
      category: explicitlyExcluded
        ? 'excluded'
        : isDevelopment
          ? 'development'
          : CLASSIFICATION_CATEGORIES[index % CLASSIFICATION_CATEGORIES.length]!,
      reasons: [
        {
          code: ownership === 'managed' ? 'managed-process' : 'mock-evidence',
          score: ownership === 'managed' ? 100 : index % 31,
          summary: ownership === 'managed' ? '由 MagicTools 托管' : '确定性压力数据',
        },
      ],
      userOverride,
      isDevelopment,
    },
    portBindings: createPortBindings(index, instanceKey),
    lastSeenRevision: index + 1,
  };
}

function createInstanceKey(index: number): ProcessInstanceKey {
  return {
    bootId: MOCK_BOOT_ID,
    pid: 1_000 + index,
    nativeStartTime: (17_000_000_000_000_000_000n + BigInt(index) * 1_000_003n).toString(),
  };
}

function createParentKey(index: number): ProcessInstanceKey | null {
  if (index === 0 || index % 11 === 0) {
    return null;
  }
  const groupRoot = Math.floor(index / 5) * 5;
  return createInstanceKey(groupRoot === index ? index - 1 : groupRoot);
}

function mockExecutableName(index: number): FieldValue<string> {
  switch (index % 113) {
    case 0:
      return 'unknown';
    case 1:
      return { accessLimited: { reason: '压力数据：进程名称读取被拒绝' } };
    case 2:
      return 'notSupported';
    default:
      return { known: createExecutableName(index) };
  }
}

function createExecutableName(index: number): string {
  if (index > 0 && index % 97 === 0) {
    return `超长中文进程名称-${'前端资源编译与热更新服务'.repeat(7)}-${index}`;
  }
  return `${PROCESS_NAMES[index % PROCESS_NAMES.length]!}-${String(index).padStart(4, '0')}`;
}

function createExecutablePath(index: number): string {
  const name = PROCESS_NAMES[index % PROCESS_NAMES.length]!;
  return index % 2 === 0
    ? `C:\\RealLab\\示例项目-${index % 23}\\node_modules\\.bin\\${name}.cmd`
    : `/Users/developer/Projects/sample-${index % 23}/bin/${name}`;
}

function createCommandLine(index: number): string {
  return `${createExecutablePath(index)} --project sample-${index % 23} --mock-index ${index}`;
}

function createWorkingDirectory(index: number): string {
  return index % 2 === 0
    ? `C:\\RealLab\\示例项目-${index % 23}`
    : `/Users/developer/Projects/sample-${index % 23}`;
}

function createAccessLevel(index: number): AccessLevel {
  if (index % 41 === 0) {
    return 'denied';
  }
  return index % 17 === 0 ? 'limited' : 'full';
}

function createProjectAssociation(index: number): ProjectEvidence<ProjectAssociationEvidence> {
  switch (index % 10) {
    case 6:
      return 'missing';
    case 7:
      return 'unknown';
    case 8:
      return { accessLimited: { reason: '压力数据：工作目录不可访问' } };
    case 9:
      return 'notSupported';
    default: {
      const projectNumber = index % 23;
      return {
        known: {
          projectId: `project-${String(projectNumber).padStart(2, '0')}`,
          registeredRoot: createWorkingDirectory(index),
        },
      };
    }
  }
}

function knownProjectId(evidence: ProjectEvidence<ProjectAssociationEvidence>): string | null {
  return typeof evidence === 'object' && 'known' in evidence ? evidence.known.projectId : null;
}

function createProjectFeatures(index: number): ProjectEvidence<Array<ProjectFeatureEvidence>> {
  switch (index % 13) {
    case 9:
      return 'missing';
    case 10:
      return 'unknown';
    case 11:
      return { accessLimited: { reason: '压力数据：特征文件扫描受限' } };
    case 12:
      return 'notSupported';
    default:
      return {
        known: [
          {
            markerId: index % 2 === 0 ? 'package-json' : 'git',
            markerPath: `${createWorkingDirectory(index)}/${index % 2 === 0 ? 'package.json' : '.git'}`,
            detectedRoot: createWorkingDirectory(index),
          },
        ],
      };
  }
}

function createUserOverride(
  index: number,
  projectId: string | null,
): UserClassificationOverride | null {
  if (index % 59 === 0) {
    return 'exclude';
  }
  if (index % 47 === 0) {
    return 'include';
  }
  if (projectId !== null && index % 43 === 0) {
    return { assignProject: projectId };
  }
  return null;
}

function createPortBindings(
  index: number,
  instanceKey: ProcessInstanceKey,
): FieldValue<Array<PortBinding>> {
  switch (index % 43) {
    case 0:
      return 'unknown';
    case 1:
      return { accessLimited: { reason: '压力数据：端口归属读取受限' } };
    case 2:
      return 'notSupported';
    default:
      return { known: createKnownPortBindings(index, instanceKey) };
  }
}

function createKnownPortBindings(index: number, instanceKey: ProcessInstanceKey): PortBinding[] {
  const count = index > 0 && index % 97 === 0 ? 14 : index % 13 === 0 ? 0 : 1 + (index % 4);
  return Array.from({ length: count }, (_, portIndex) => {
    const protocol: PortProtocol = portIndex % 4 === 3 ? 'udp' : 'tcp';
    const addressFamily: AddressFamily = portIndex % 3 === 2 ? 'ipv6' : 'ipv4';
    return {
      protocol,
      addressFamily,
      localAddress:
        addressFamily === 'ipv6' ? '::1' : portIndex % 2 === 0 ? '127.0.0.1' : '0.0.0.0',
      localPort: 3_000 + ((index * 17 + portIndex * 101) % 50_000),
      state: createPortState(index, portIndex, protocol),
      processInstanceKey: (index + portIndex) % 17 === 0 ? null : instanceKey,
      confidence: createPortConfidence(index, portIndex),
      observedAt: new Date(MOCK_NOW_MS - (index % 7) * 1_000).toISOString(),
    };
  });
}

function createPortState(
  index: number,
  portIndex: number,
  protocol: PortProtocol,
): FieldValue<PortState> {
  const discriminator = (index + portIndex) % 37;
  if (discriminator === 0) {
    return 'unknown';
  }
  if (discriminator === 1) {
    return { accessLimited: { reason: '压力数据：Socket 状态受限' } };
  }
  if (discriminator === 2) {
    return 'notSupported';
  }
  if (protocol === 'udp') {
    return { known: 'udpBound' };
  }
  return { known: portIndex % 3 === 1 ? 'tcpEstablished' : 'tcpListen' };
}

function createPortConfidence(index: number, portIndex: number): PortOwnershipConfidence {
  const confidence: readonly PortOwnershipConfidence[] = ['exact', 'shared', 'inferred', 'unknown'];
  return confidence[(index + portIndex) % confidence.length]!;
}

function mockField<T>(index: number, offset: number, value: T): FieldValue<T> {
  switch ((index + offset) % 127) {
    case 0:
      return 'unknown';
    case 1:
      return { accessLimited: { reason: '压力数据：字段读取受限' } };
    case 2:
      return 'notSupported';
    default:
      return { known: value };
  }
}
