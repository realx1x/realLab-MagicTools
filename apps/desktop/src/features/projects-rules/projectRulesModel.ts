import type {
  ClassificationRuleAction,
  ClassificationRuleMatcherKind,
  ClassificationRuleSummary,
  ProjectSummary,
  SaveClassificationRuleRequest,
  SaveProjectRequest,
} from '@dpm/generated-types';

export type CatalogTab = 'projects' | 'rules';
export type RuleActionKind = ClassificationRuleAction['kind'];

export interface ProjectDraft {
  id: string | null;
  expectedUpdatedAt: string | null;
  name: string;
  rootDirectory: string;
}

export interface RuleDraft {
  id: string | null;
  expectedUpdatedAt: string | null;
  matcherKind: ClassificationRuleMatcherKind;
  pattern: string;
  actionKind: RuleActionKind;
  projectId: string;
  priority: string;
  enabled: boolean;
}

export interface ValidationIssue {
  field: string;
  message: string;
}

export type ProjectRequestResult =
  | { ok: true; request: SaveProjectRequest }
  | { ok: false; issues: ReadonlyArray<ValidationIssue> };

export type RuleRequestResult =
  | { ok: true; request: SaveClassificationRuleRequest }
  | { ok: false; issues: ReadonlyArray<ValidationIssue> };

export const PROJECT_FIELDS = {
  name: 'project-name',
  rootDirectory: 'project-root-directory',
} as const;

export const RULE_FIELDS = {
  actionKind: 'rule-action-kind',
  enabled: 'rule-enabled',
  matcherKind: 'rule-matcher-kind',
  pattern: 'rule-pattern',
  priority: 'rule-priority',
  projectId: 'rule-project-id',
} as const;

const MAX_PROJECT_ID_BYTES = 256;
const MAX_PROJECT_NAME_BYTES = 256;
const MAX_PROJECT_ROOT_BYTES = 32 * 1_024;
const MAX_TIMESTAMP_BYTES = 128;
const MAX_RULE_ID_BYTES = 256;
const MAX_RULE_PATTERN_BYTES = 4 * 1_024;
const MAX_RULE_PRIORITY = 1_000_000;
const MAX_PROJECT_REQUEST_WIRE_BYTES = 64 * 1_024;
const MAX_RULE_REQUEST_WIRE_BYTES = 16 * 1_024;
const INTEGER = /^-?(?:0|[1-9]\d*)$/;
const DISALLOWED_TEXT = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Cs}\p{Cn}]/u;
const utf8Encoder = new TextEncoder();

export function createProjectDraft(): ProjectDraft {
  return { expectedUpdatedAt: null, id: null, name: '', rootDirectory: '' };
}

export function projectSummaryToDraft(project: ProjectSummary): ProjectDraft {
  return {
    expectedUpdatedAt: project.updatedAt,
    id: project.id,
    name: project.input.name,
    rootDirectory: project.input.rootDirectory,
  };
}

export function projectDraftFingerprint(draft: ProjectDraft) {
  return JSON.stringify({ name: draft.name, rootDirectory: draft.rootDirectory });
}

export function buildProjectSaveRequest(draft: ProjectDraft): ProjectRequestResult {
  const issues: ValidationIssue[] = [];
  validateRequiredText(
    draft.name,
    PROJECT_FIELDS.name,
    'Project name',
    MAX_PROJECT_NAME_BYTES,
    issues,
  );
  validateRequiredText(
    draft.rootDirectory,
    PROJECT_FIELDS.rootDirectory,
    'Root directory',
    MAX_PROJECT_ROOT_BYTES,
    issues,
  );
  if (draft.rootDirectory.trim() !== '' && !isAbsolutePath(draft.rootDirectory)) {
    addIssue(issues, PROJECT_FIELDS.rootDirectory, 'Root directory must be an absolute path.');
  }
  validateStoredIdentity(
    draft.id,
    draft.expectedUpdatedAt,
    MAX_PROJECT_ID_BYTES,
    'project',
    issues,
  );
  if (issues.length > 0) {
    return { issues: deduplicateIssues(issues), ok: false };
  }

  const input = { name: draft.name, rootDirectory: draft.rootDirectory };
  const request: SaveProjectRequest =
    draft.id === null
      ? { input, operation: 'create' }
      : {
          expectedUpdatedAt: draft.expectedUpdatedAt ?? '',
          input,
          operation: 'update',
          projectId: draft.id,
        };
  if (wireBytes(request) > MAX_PROJECT_REQUEST_WIRE_BYTES) {
    return {
      issues: [{ field: 'project', message: 'Encoded project exceeds the supported size.' }],
      ok: false,
    };
  }
  return { ok: true, request };
}

export function createRuleDraft(): RuleDraft {
  return {
    actionKind: 'include',
    enabled: true,
    expectedUpdatedAt: null,
    id: null,
    matcherKind: 'executableNameExact',
    pattern: '',
    priority: '0',
    projectId: '',
  };
}

export function classificationRuleSummaryToDraft(rule: ClassificationRuleSummary): RuleDraft {
  return {
    actionKind: rule.input.action.kind,
    enabled: rule.input.enabled,
    expectedUpdatedAt: rule.updatedAt,
    id: rule.id,
    matcherKind: rule.input.matcherKind,
    pattern: rule.input.pattern,
    priority: String(rule.input.priority),
    projectId: rule.input.action.kind === 'assignProject' ? rule.input.action.projectId : '',
  };
}

export function ruleDraftFingerprint(draft: RuleDraft) {
  return JSON.stringify({
    actionKind: draft.actionKind,
    enabled: draft.enabled,
    matcherKind: draft.matcherKind,
    pattern: draft.pattern,
    priority: draft.priority,
    projectId: draft.actionKind === 'assignProject' ? draft.projectId : '',
  });
}

export function buildClassificationRuleSaveRequest(
  draft: RuleDraft,
  projects: ReadonlyArray<ProjectSummary>,
): RuleRequestResult {
  const issues: ValidationIssue[] = [];
  validateRequiredText(
    draft.pattern,
    RULE_FIELDS.pattern,
    'Match pattern',
    MAX_RULE_PATTERN_BYTES,
    issues,
  );
  const priority = readPriority(draft.priority, issues);
  let action: ClassificationRuleAction;
  if (draft.actionKind === 'assignProject') {
    validateRequiredText(
      draft.projectId,
      RULE_FIELDS.projectId,
      'Assigned project',
      MAX_PROJECT_ID_BYTES,
      issues,
    );
    if (
      draft.projectId.trim() !== '' &&
      !projects.some((project) => project.id === draft.projectId)
    ) {
      addIssue(issues, RULE_FIELDS.projectId, 'Choose a project from the current catalog.');
    }
    action = { kind: 'assignProject', projectId: draft.projectId };
  } else {
    action = { kind: draft.actionKind };
  }
  validateStoredIdentity(
    draft.id,
    draft.expectedUpdatedAt,
    MAX_RULE_ID_BYTES,
    'classification rule',
    issues,
  );
  if (issues.length > 0 || priority === null) {
    return { issues: deduplicateIssues(issues), ok: false };
  }

  const input = {
    action,
    enabled: draft.enabled,
    matcherKind: draft.matcherKind,
    pattern: draft.pattern,
    priority,
  };
  const request: SaveClassificationRuleRequest =
    draft.id === null
      ? { input, operation: 'create' }
      : {
          expectedUpdatedAt: draft.expectedUpdatedAt ?? '',
          input,
          operation: 'update',
          ruleId: draft.id,
        };
  if (wireBytes(request) > MAX_RULE_REQUEST_WIRE_BYTES) {
    return {
      issues: [
        { field: 'classification-rule', message: 'Encoded rule exceeds the supported size.' },
      ],
      ok: false,
    };
  }
  return { ok: true, request };
}

export function upsertProject(projects: ReadonlyArray<ProjectSummary>, saved: ProjectSummary) {
  const next = projects.filter((project) => project.id !== saved.id);
  next.push(saved);
  return sortProjects(next);
}

export function upsertClassificationRule(
  rules: ReadonlyArray<ClassificationRuleSummary>,
  saved: ClassificationRuleSummary,
) {
  const next = rules.filter((rule) => rule.id !== saved.id);
  next.push(saved);
  return sortClassificationRules(next);
}

export function sortProjects(projects: ReadonlyArray<ProjectSummary>) {
  return [...projects].sort((left, right) => {
    const byName = compareUtf8Binary(left.input.name, right.input.name);
    return byName === 0 ? compareUtf8Binary(left.id, right.id) : byName;
  });
}

export function sortClassificationRules(rules: ReadonlyArray<ClassificationRuleSummary>) {
  return [...rules].sort((left, right) => {
    const byPriority = right.input.priority - left.input.priority;
    return byPriority === 0 ? compareUtf8Binary(left.id, right.id) : byPriority;
  });
}

export function presentMatcherKind(kind: ClassificationRuleMatcherKind) {
  switch (kind) {
    case 'executableNameExact':
      return 'Executable name equals';
    case 'executablePathExact':
      return 'Executable path equals';
    case 'commandLineContains':
      return 'Command line contains';
    case 'workingDirectoryPrefix':
      return 'Working directory starts with';
  }
}

export function presentRuleAction(action: ClassificationRuleAction) {
  switch (action.kind) {
    case 'include':
      return 'Include';
    case 'exclude':
      return 'Exclude';
    case 'assignProject':
      return 'Assign project';
  }
}

export function isCatalogTab(value: string): value is CatalogTab {
  return value === 'projects' || value === 'rules';
}

function readPriority(value: string, issues: ValidationIssue[]) {
  if (!INTEGER.test(value)) {
    addIssue(issues, RULE_FIELDS.priority, 'Priority must be a whole number.');
    return null;
  }
  const priority = Number(value);
  if (
    !Number.isSafeInteger(priority) ||
    priority < -MAX_RULE_PRIORITY ||
    priority > MAX_RULE_PRIORITY
  ) {
    addIssue(issues, RULE_FIELDS.priority, 'Priority must be between -1000000 and 1000000.');
    return null;
  }
  return priority;
}

function validateStoredIdentity(
  id: string | null,
  expectedUpdatedAt: string | null,
  maximumIdBytes: number,
  entity: string,
  issues: ValidationIssue[],
) {
  if (id === null) {
    if (expectedUpdatedAt !== null) {
      addIssue(issues, entity, `A new ${entity} cannot carry an update timestamp.`);
    }
    return;
  }
  validateRequiredText(id, entity, `${entity} ID`, maximumIdBytes, issues);
  validateRequiredText(
    expectedUpdatedAt ?? '',
    entity,
    `${entity} update timestamp`,
    MAX_TIMESTAMP_BYTES,
    issues,
  );
}

function validateRequiredText(
  value: string,
  field: string,
  label: string,
  maximumBytes: number,
  issues: ValidationIssue[],
) {
  if (value.trim() === '') {
    addIssue(issues, field, `${label} is required.`);
  }
  if (utf8Bytes(value) > maximumBytes) {
    addIssue(issues, field, `${label} must not exceed ${maximumBytes} UTF-8 bytes.`);
  }
  if (DISALLOWED_TEXT.test(value)) {
    addIssue(issues, field, `${label} must not contain control characters.`);
  }
}

function isAbsolutePath(value: string) {
  if (value.startsWith('/')) {
    return true;
  }
  const windowsPath = value.replaceAll('/', '\\');
  if (/^[A-Za-z]:\\/.test(windowsPath)) {
    return true;
  }
  if (!windowsPath.startsWith('\\\\')) {
    return false;
  }
  const [server, share] = windowsPath.slice(2).split('\\');
  return server !== undefined && share !== undefined && server !== '' && share !== '';
}

function wireBytes(value: unknown) {
  return utf8Bytes(JSON.stringify(value));
}

function utf8Bytes(value: string) {
  return utf8Encoder.encode(value).length;
}

function compareUtf8Binary(left: string, right: string) {
  const leftBytes = utf8Encoder.encode(left);
  const rightBytes = utf8Encoder.encode(right);
  const length = Math.min(leftBytes.length, rightBytes.length);
  for (let index = 0; index < length; index += 1) {
    const difference = (leftBytes[index] ?? 0) - (rightBytes[index] ?? 0);
    if (difference !== 0) {
      return difference;
    }
  }
  return leftBytes.length - rightBytes.length;
}

function addIssue(issues: ValidationIssue[], field: string, message: string) {
  issues.push({ field, message });
}

function deduplicateIssues(issues: ReadonlyArray<ValidationIssue>) {
  const keys = new Set<string>();
  return issues.filter((issue) => {
    const key = `${issue.field}\0${issue.message}`;
    if (keys.has(key)) {
      return false;
    }
    keys.add(key);
    return true;
  });
}
