import type {
  ExecutionPreviewRequest,
  LaunchEnvironmentEntry,
  LaunchProfile,
  LaunchProfileInput,
  SaveLaunchProfileWithSecretsRequest,
  ShellKind,
} from '@dpm/generated-types';

export type LaunchProfileMode = 'direct' | 'shell';
export type EnvironmentValueKind = 'plain' | 'storedCredential' | 'newSecret';

export interface StoredCredentialMetadata {
  credentialReference: string;
  name: string;
}

export interface EnvironmentDraft {
  /** Stable React/form identity. It is never sent to the Supervisor. */
  rowId: string;
  name: string;
  plainValue: string;
  /** Explicit rotation intent; secret text itself remains only in the DOM. */
  replaceStoredSecret: boolean;
  storedCredential: StoredCredentialMetadata | null;
  valueKind: EnvironmentValueKind;
}

export interface DirectLaunchDraft {
  argv: ReadonlyArray<string>;
  executable: string;
}

export interface ShellLaunchDraft {
  command: string;
  shell: ShellKind;
}

export interface LaunchProfileDraft {
  direct: DirectLaunchDraft;
  environment: ReadonlyArray<EnvironmentDraft>;
  expectedUpdatedAt: string | null;
  interactive: boolean;
  mode: LaunchProfileMode;
  name: string;
  profileId: string | null;
  projectId: string;
  shell: ShellLaunchDraft;
  stopTimeoutMs: number;
  workingDirectory: string;
}

export interface LaunchProfileValidationIssue {
  field: string;
  message: string;
  rowId?: string;
}

export type BuildSaveRequestResult =
  | {
      ok: true;
      request: SaveLaunchProfileWithSecretsRequest;
    }
  | {
      issues: ReadonlyArray<LaunchProfileValidationIssue>;
      ok: false;
    };

export type BuildExecutionPreviewResult =
  | {
      ok: true;
      pendingSecretNames: ReadonlyArray<string>;
      request: ExecutionPreviewRequest;
    }
  | {
      issues: ReadonlyArray<LaunchProfileValidationIssue>;
      ok: false;
    };

export const LAUNCH_PROFILE_FORM_FIELDS = Object.freeze({
  directExecutable: 'launchProfile.direct.executable',
  interactive: 'launchProfile.interactive',
  mode: 'launchProfile.mode',
  name: 'launchProfile.name',
  projectId: 'launchProfile.projectId',
  shellCommand: 'launchProfile.shell.command',
  shellKind: 'launchProfile.shell.kind',
  stopTimeoutMs: 'launchProfile.stopTimeoutMs',
  workingDirectory: 'launchProfile.workingDirectory',
});

const MAX_PROFILE_ID_BYTES = 256;
const MAX_PROFILE_NAME_BYTES = 256;
const MAX_PROJECT_ID_BYTES = 256;
const MAX_EXECUTABLE_BYTES = 32 * 1_024;
const MAX_ARGUMENTS = 256;
const MAX_ARGUMENT_BYTES = 32 * 1_024;
const MAX_ARGUMENT_TOTAL_BYTES = 64 * 1_024;
const MAX_SHELL_COMMAND_BYTES = 64 * 1_024;
const MAX_WORKING_DIRECTORY_BYTES = 32 * 1_024;
const MAX_ENVIRONMENT_ENTRIES = 256;
const MAX_ENVIRONMENT_NAME_BYTES = 256;
const MAX_ENVIRONMENT_VALUE_BYTES = 32 * 1_024;
const MAX_ENVIRONMENT_TOTAL_BYTES = 64 * 1_024;
const MAX_CREDENTIAL_REFERENCE_BYTES = 4 * 1_024;
const MAX_CREDENTIAL_SECRET_BYTES = 2_560;
const MAX_TIMESTAMP_BYTES = 128;
const MAX_STOP_TIMEOUT_MS = 300_000;
const MAX_PROFILE_INPUT_WIRE_BYTES = 192 * 1_024;
const MAX_SECRET_REQUEST_WIRE_BYTES = 256 * 1_024;
const PORTABLE_ENVIRONMENT_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;
const utf8Encoder = new TextEncoder();

let fallbackRowSequence = 0;

interface CurrentEnvironment {
  draft: EnvironmentDraft;
  name: string;
  plainValue: string;
  secret: string | null;
  valueKind: EnvironmentValueKind;
}

interface CurrentDraft {
  argv: ReadonlyArray<string>;
  directExecutable: string;
  environment: ReadonlyArray<CurrentEnvironment>;
  interactive: boolean;
  mode: LaunchProfileMode;
  name: string;
  projectId: string;
  shellCommand: string;
  shellKind: ShellKind;
  stopTimeoutMs: number;
  workingDirectory: string;
}

interface RequestMaterialization {
  input: LaunchProfileInput;
  issues: ReadonlyArray<LaunchProfileValidationIssue>;
  pendingSecretNames: ReadonlyArray<string>;
  secretEnvironment: ReadonlyArray<{ name: string; secret: string }>;
}

export function environmentFormFields(rowId: string) {
  const prefix = `launchProfile.environment.${rowId}`;
  return Object.freeze({
    name: `${prefix}.name`,
    plainValue: `${prefix}.plainValue`,
    secret: `${prefix}.secret`,
    valueKind: `${prefix}.valueKind`,
  });
}

export function argumentFormField(index: number) {
  return `launchProfile.direct.argv.${index}`;
}

export function createLaunchProfileDraft(
  defaultShell: ShellKind = 'powerShell',
): LaunchProfileDraft {
  return {
    direct: { argv: [], executable: '' },
    environment: [],
    expectedUpdatedAt: null,
    interactive: false,
    mode: 'direct',
    name: '',
    profileId: null,
    projectId: '',
    shell: { command: '', shell: defaultShell },
    stopTimeoutMs: 10_000,
    workingDirectory: '',
  };
}

export function launchProfileToDraft(
  profile: LaunchProfile,
  defaultShell: ShellKind = 'powerShell',
): LaunchProfileDraft {
  const execution = profile.input.execution;
  return {
    direct:
      execution.mode === 'direct'
        ? { argv: [...execution.argv], executable: execution.executable }
        : { argv: [], executable: '' },
    environment: profile.input.environment.map((entry) => environmentEntryToDraft(entry)),
    expectedUpdatedAt: profile.updatedAt,
    interactive: profile.input.interactive,
    mode: execution.mode,
    name: profile.input.name,
    profileId: profile.id,
    projectId: profile.input.projectId ?? '',
    shell:
      execution.mode === 'shell'
        ? { command: execution.command, shell: execution.shell }
        : { command: '', shell: defaultShell },
    stopTimeoutMs: profile.input.stopTimeoutMs,
    workingDirectory: profile.input.workingDirectory,
  };
}

export function switchLaunchProfileMode(
  draft: LaunchProfileDraft,
  mode: LaunchProfileMode,
): LaunchProfileDraft {
  return draft.mode === mode ? draft : { ...draft, mode };
}

export function createEnvironmentDraft(
  valueKind: Exclude<EnvironmentValueKind, 'storedCredential'> = 'plain',
): EnvironmentDraft {
  return {
    rowId: createRowId(),
    name: '',
    plainValue: '',
    replaceStoredSecret: false,
    storedCredential: null,
    valueKind,
  };
}

export function switchEnvironmentValueKind(
  draft: EnvironmentDraft,
  valueKind: EnvironmentValueKind,
): EnvironmentDraft {
  const nextKind =
    valueKind === 'storedCredential' && draft.storedCredential === null ? 'newSecret' : valueKind;
  return draft.valueKind === nextKind
    ? draft
    : { ...draft, replaceStoredSecret: false, valueKind: nextKind };
}

export function validateLaunchProfileDraft(
  draft: LaunchProfileDraft,
  formData: FormData,
): ReadonlyArray<LaunchProfileValidationIssue> {
  const readIssues: LaunchProfileValidationIssue[] = [];
  const current = readCurrentDraft(draft, formData, readIssues);
  const materialized = materializeRequest(draft, current, true);
  return deduplicateIssues([
    ...readIssues,
    ...validateCurrentDraft(draft, current, true),
    ...materialized.issues,
  ]);
}

export function buildSaveLaunchProfileRequest(
  draft: LaunchProfileDraft,
  formData: FormData,
): BuildSaveRequestResult {
  const readIssues: LaunchProfileValidationIssue[] = [];
  const current = readCurrentDraft(draft, formData, readIssues);
  const materialized = materializeRequest(draft, current, true);
  const issues = deduplicateIssues([
    ...readIssues,
    ...validateCurrentDraft(draft, current, true),
    ...materialized.issues,
  ]);
  if (issues.length > 0) {
    return { issues, ok: false };
  }

  const request: SaveLaunchProfileWithSecretsRequest = {
    request:
      draft.profileId === null
        ? { input: materialized.input, operation: 'create' }
        : {
            expectedUpdatedAt: draft.expectedUpdatedAt ?? '',
            input: materialized.input,
            operation: 'update',
            profileId: draft.profileId,
          },
    secretEnvironment: [...materialized.secretEnvironment],
  };
  if (wireBytes(request) > MAX_SECRET_REQUEST_WIRE_BYTES) {
    return {
      issues: [
        {
          field: 'launchProfile',
          message: 'The encoded launch profile exceeds the supported request size.',
        },
      ],
      ok: false,
    };
  }
  return { ok: true, request };
}

export function buildExecutionPreviewRequest(
  draft: LaunchProfileDraft,
): BuildExecutionPreviewResult {
  const readIssues: LaunchProfileValidationIssue[] = [];
  const current = readCurrentDraft(draft, null, readIssues, false);
  const materialized = materializeRequest(draft, current, false);
  const issues = deduplicateIssues([
    ...readIssues,
    ...validateCurrentDraft(draft, current, false),
    ...materialized.issues,
  ]);
  if (issues.length > 0) {
    return { issues, ok: false };
  }
  return {
    ok: true,
    pendingSecretNames: materialized.pendingSecretNames,
    request: { profile: materialized.input },
  };
}

/**
 * Returns a stable semantic fingerprint. Secret text, credential references,
 * row IDs, and timestamps are intentionally excluded.
 */
export function launchProfileDirtyFingerprint(draft: LaunchProfileDraft): string {
  const current = readCurrentDraft(draft, null, [], false);
  return JSON.stringify({
    environment: current.environment.map((entry) => ({
      credentialAction: credentialAction(entry),
      hadStoredCredential: entry.draft.storedCredential !== null,
      name: entry.name,
      plainValue: entry.valueKind === 'plain' ? entry.plainValue : null,
      storedName: entry.draft.storedCredential?.name ?? null,
      valueKind: entry.valueKind,
    })),
    interactive: current.interactive,
    execution:
      current.mode === 'direct'
        ? {
            argv: current.argv,
            executable: current.directExecutable,
            mode: 'direct',
          }
        : {
            command: current.shellCommand,
            mode: 'shell',
            shell: current.shellKind,
          },
    name: current.name,
    profileId: draft.profileId,
    projectId: current.projectId.trim() === '' ? null : current.projectId,
    stopTimeoutMs: current.stopTimeoutMs,
    workingDirectory: current.workingDirectory,
  });
}

/** Mirrors platform_common::is_sensitive_field_name. */
export function isSensitiveEnvironmentName(name: string): boolean {
  let canonical = '';
  let token = '';
  let previousLowerOrDigit = false;

  for (const character of name) {
    if (!isAsciiAlphaNumeric(character)) {
      if (isSensitiveToken(token)) {
        return true;
      }
      token = '';
      previousLowerOrDigit = false;
      continue;
    }

    if (isAsciiUppercase(character) && previousLowerOrDigit) {
      if (isSensitiveToken(token)) {
        return true;
      }
      token = '';
    }
    const lower = character.toLowerCase();
    canonical += lower;
    token += lower;
    previousLowerOrDigit = isAsciiLowercase(character) || isAsciiDigit(character);
  }

  return (
    isSensitiveToken(token) ||
    ['apikey', 'accesskey', 'privatekey', 'clientsecret', 'sessiontoken', 'authtoken'].some(
      (pattern) => canonical.includes(pattern),
    )
  );
}

function environmentEntryToDraft(entry: LaunchEnvironmentEntry): EnvironmentDraft {
  if (entry.value.kind === 'plain') {
    return {
      rowId: createRowId(),
      name: entry.name,
      plainValue: entry.value.value,
      replaceStoredSecret: false,
      storedCredential: null,
      valueKind: 'plain',
    };
  }
  return {
    rowId: createRowId(),
    name: entry.name,
    plainValue: '',
    replaceStoredSecret: false,
    storedCredential: {
      credentialReference: entry.value.credentialReference,
      name: entry.name,
    },
    valueKind: 'storedCredential',
  };
}

function createRowId() {
  if (typeof globalThis.crypto?.randomUUID === 'function') {
    return `environment-${globalThis.crypto.randomUUID()}`;
  }
  fallbackRowSequence += 1;
  return `environment-${Date.now().toString(36)}-${fallbackRowSequence.toString(36)}`;
}

function readCurrentDraft(
  draft: LaunchProfileDraft,
  formData: FormData | null,
  issues: LaunchProfileValidationIssue[],
  readSecretValues = true,
): CurrentDraft {
  const mode = readMode(formData, draft.mode, issues);
  const shellKind = readShellKind(formData, draft.shell.shell, issues);
  const stopTimeoutMs = readStopTimeout(formData, draft.stopTimeoutMs, issues);
  return {
    argv: draft.direct.argv.map((argument, index) =>
      readText(formData, argumentFormField(index), argument, issues),
    ),
    directExecutable: readText(
      formData,
      LAUNCH_PROFILE_FORM_FIELDS.directExecutable,
      draft.direct.executable,
      issues,
    ),
    environment: draft.environment.map((environment) => {
      const fields = environmentFormFields(environment.rowId);
      return {
        draft: environment,
        name: readText(formData, fields.name, environment.name, issues, environment.rowId),
        plainValue: readText(
          formData,
          fields.plainValue,
          environment.plainValue,
          issues,
          environment.rowId,
        ),
        secret: readSecretValues
          ? readSecret(formData, fields.secret, issues, environment.rowId)
          : null,
        valueKind: readEnvironmentValueKind(formData, fields.valueKind, environment, issues),
      };
    }),
    interactive: readCheckbox(formData, LAUNCH_PROFILE_FORM_FIELDS.interactive, draft.interactive),
    mode,
    name: readText(formData, LAUNCH_PROFILE_FORM_FIELDS.name, draft.name, issues),
    projectId: readText(formData, LAUNCH_PROFILE_FORM_FIELDS.projectId, draft.projectId, issues),
    shellCommand: readText(
      formData,
      LAUNCH_PROFILE_FORM_FIELDS.shellCommand,
      draft.shell.command,
      issues,
    ),
    shellKind,
    stopTimeoutMs,
    workingDirectory: readText(
      formData,
      LAUNCH_PROFILE_FORM_FIELDS.workingDirectory,
      draft.workingDirectory,
      issues,
    ),
  };
}

function readText(
  formData: FormData | null,
  field: string,
  fallback: string,
  issues: LaunchProfileValidationIssue[],
  rowId?: string,
) {
  if (formData === null) {
    return fallback;
  }
  const raw = formData.get(field);
  if (raw === null) {
    return fallback;
  }
  if (typeof raw === 'string') {
    return raw;
  }
  pushIssue(issues, field, 'Must be a text value.', rowId);
  return fallback;
}

function readSecret(
  formData: FormData | null,
  field: string,
  issues: LaunchProfileValidationIssue[],
  rowId: string,
): string | null {
  if (formData === null) {
    return null;
  }
  const raw = formData.get(field);
  if (raw === null) {
    return null;
  }
  if (typeof raw === 'string') {
    return raw;
  }
  pushIssue(issues, field, 'Secret input must be text.', rowId);
  return null;
}

function readCheckbox(formData: FormData | null, field: string, fallback: boolean) {
  if (formData === null) {
    return fallback;
  }
  const raw = formData.get(field);
  if (raw === null) {
    return false;
  }
  return typeof raw !== 'string' || !['false', '0', 'off'].includes(raw.toLowerCase());
}

function readMode(
  formData: FormData | null,
  fallback: LaunchProfileMode,
  issues: LaunchProfileValidationIssue[],
): LaunchProfileMode {
  const raw = formData?.get(LAUNCH_PROFILE_FORM_FIELDS.mode);
  if (raw === null || raw === undefined) {
    return fallback;
  }
  if (raw === 'direct' || raw === 'shell') {
    return raw;
  }
  pushIssue(issues, LAUNCH_PROFILE_FORM_FIELDS.mode, 'Choose Direct or Shell execution.');
  return fallback;
}

function readShellKind(
  formData: FormData | null,
  fallback: ShellKind,
  issues: LaunchProfileValidationIssue[],
): ShellKind {
  const raw = formData?.get(LAUNCH_PROFILE_FORM_FIELDS.shellKind);
  if (raw === null || raw === undefined) {
    return fallback;
  }
  if (raw === 'powerShell' || raw === 'cmd' || raw === 'zsh') {
    return raw;
  }
  pushIssue(issues, LAUNCH_PROFILE_FORM_FIELDS.shellKind, 'Choose a supported shell.');
  return fallback;
}

function readStopTimeout(
  formData: FormData | null,
  fallback: number,
  issues: LaunchProfileValidationIssue[],
) {
  const raw = formData?.get(LAUNCH_PROFILE_FORM_FIELDS.stopTimeoutMs);
  if (raw === null || raw === undefined) {
    return fallback;
  }
  if (typeof raw !== 'string' || !/^(0|[1-9][0-9]*)$/.test(raw)) {
    pushIssue(
      issues,
      LAUNCH_PROFILE_FORM_FIELDS.stopTimeoutMs,
      'Stop timeout must be a whole number of milliseconds.',
    );
    return 0;
  }
  const parsed = Number(raw);
  if (!Number.isSafeInteger(parsed)) {
    pushIssue(
      issues,
      LAUNCH_PROFILE_FORM_FIELDS.stopTimeoutMs,
      'Stop timeout is outside the supported range.',
    );
    return 0;
  }
  return parsed;
}

function readEnvironmentValueKind(
  formData: FormData | null,
  field: string,
  environment: EnvironmentDraft,
  issues: LaunchProfileValidationIssue[],
): EnvironmentValueKind {
  const raw = formData?.get(field);
  if (raw === null || raw === undefined) {
    return environment.valueKind;
  }
  if (raw === 'plain' || raw === 'storedCredential' || raw === 'newSecret') {
    if (raw === 'storedCredential' && environment.storedCredential === null) {
      pushIssue(
        issues,
        field,
        'No stored credential is available for this variable.',
        environment.rowId,
      );
      return 'newSecret';
    }
    return raw;
  }
  pushIssue(issues, field, 'Choose Plain or Secret.', environment.rowId);
  return environment.valueKind;
}

function validateCurrentDraft(
  draft: LaunchProfileDraft,
  current: CurrentDraft,
  requireSecretValues: boolean,
): ReadonlyArray<LaunchProfileValidationIssue> {
  const issues: LaunchProfileValidationIssue[] = [];
  validateRequiredText(
    current.name,
    LAUNCH_PROFILE_FORM_FIELDS.name,
    'Profile name',
    MAX_PROFILE_NAME_BYTES,
    issues,
  );
  validateOptionalText(
    current.projectId,
    LAUNCH_PROFILE_FORM_FIELDS.projectId,
    MAX_PROJECT_ID_BYTES,
    issues,
  );
  if (current.projectId !== '' && current.projectId.trim() === '') {
    pushIssue(
      issues,
      LAUNCH_PROFILE_FORM_FIELDS.projectId,
      'Project ID cannot be only whitespace.',
    );
  }
  validateRequiredText(
    current.workingDirectory,
    LAUNCH_PROFILE_FORM_FIELDS.workingDirectory,
    'Working directory',
    MAX_WORKING_DIRECTORY_BYTES,
    issues,
  );
  if (
    current.workingDirectory.trim() !== '' &&
    !isSafeAbsoluteWorkingDirectory(current.workingDirectory)
  ) {
    pushIssue(
      issues,
      LAUNCH_PROFILE_FORM_FIELDS.workingDirectory,
      'Working directory must be an absolute path without dot or empty components.',
    );
  }
  if (!Number.isInteger(current.stopTimeoutMs) || current.stopTimeoutMs < 0) {
    pushIssue(
      issues,
      LAUNCH_PROFILE_FORM_FIELDS.stopTimeoutMs,
      'Stop timeout must be a non-negative whole number.',
    );
  } else if (current.stopTimeoutMs > MAX_STOP_TIMEOUT_MS) {
    pushIssue(
      issues,
      LAUNCH_PROFILE_FORM_FIELDS.stopTimeoutMs,
      'Stop timeout must not exceed 300000 milliseconds.',
    );
  }

  if (current.mode === 'direct') {
    validateRequiredText(
      current.directExecutable,
      LAUNCH_PROFILE_FORM_FIELDS.directExecutable,
      'Executable',
      MAX_EXECUTABLE_BYTES,
      issues,
    );
    if (current.argv.length > MAX_ARGUMENTS) {
      pushIssue(
        issues,
        'launchProfile.direct.argv',
        'Direct execution supports at most 256 arguments.',
      );
    }
    let totalArgumentBytes = 0;
    current.argv.forEach((argument, index) => {
      const field = argumentFormField(index);
      validateOptionalText(argument, field, MAX_ARGUMENT_BYTES, issues);
      totalArgumentBytes += utf8Bytes(argument);
    });
    if (totalArgumentBytes > MAX_ARGUMENT_TOTAL_BYTES) {
      pushIssue(
        issues,
        'launchProfile.direct.argv',
        'Arguments exceed the supported combined length.',
      );
    }
  } else {
    validateRequiredText(
      current.shellCommand,
      LAUNCH_PROFILE_FORM_FIELDS.shellCommand,
      'Shell command',
      MAX_SHELL_COMMAND_BYTES,
      issues,
    );
  }

  if (draft.profileId === null) {
    if (draft.expectedUpdatedAt !== null) {
      pushIssue(issues, 'launchProfile', 'A new profile cannot carry an update timestamp.');
    }
  } else {
    validateRequiredText(
      draft.profileId,
      'launchProfile.profileId',
      'Profile ID',
      MAX_PROFILE_ID_BYTES,
      issues,
    );
    validateRequiredText(
      draft.expectedUpdatedAt ?? '',
      'launchProfile.expectedUpdatedAt',
      'Profile update timestamp',
      MAX_TIMESTAMP_BYTES,
      issues,
    );
  }

  validateEnvironment(draft, current.environment, requireSecretValues, issues);
  return issues;
}

function validateEnvironment(
  draft: LaunchProfileDraft,
  environment: ReadonlyArray<CurrentEnvironment>,
  requireSecretValues: boolean,
  issues: LaunchProfileValidationIssue[],
) {
  if (environment.length > MAX_ENVIRONMENT_ENTRIES) {
    pushIssue(issues, 'launchProfile.environment', 'A profile supports at most 256 variables.');
  }
  const names = new Set<string>();
  const rowIds = new Set<string>();
  let materializedCount = 0;
  let storedEnvironmentBytes = 0;
  let pendingSecretBytes = 0;

  for (const entry of environment) {
    const fields = environmentFormFields(entry.draft.rowId);
    if (entry.draft.rowId === '' || rowIds.has(entry.draft.rowId)) {
      pushIssue(
        issues,
        'launchProfile.environment',
        'Environment rows must have unique stable identifiers.',
        entry.draft.rowId,
      );
    }
    rowIds.add(entry.draft.rowId);
    validateRequiredText(
      entry.name,
      fields.name,
      'Environment variable name',
      MAX_ENVIRONMENT_NAME_BYTES,
      issues,
      entry.draft.rowId,
    );
    if (entry.name !== '' && !PORTABLE_ENVIRONMENT_NAME.test(entry.name)) {
      pushIssue(
        issues,
        fields.name,
        'Variable name must match [A-Za-z_][A-Za-z0-9_]*.',
        entry.draft.rowId,
      );
    }
    const comparisonName = entry.name.toUpperCase();
    if (names.has(comparisonName)) {
      pushIssue(issues, fields.name, 'Variable names must be unique.', entry.draft.rowId);
    }
    names.add(comparisonName);
    materializedCount += 1;

    if (entry.valueKind === 'plain') {
      validateOptionalText(
        entry.plainValue,
        fields.plainValue,
        MAX_ENVIRONMENT_VALUE_BYTES,
        issues,
        entry.draft.rowId,
      );
      if (isSensitiveEnvironmentName(entry.name)) {
        pushIssue(
          issues,
          fields.valueKind,
          'Sensitive variable names must use a stored secret.',
          entry.draft.rowId,
        );
      }
      storedEnvironmentBytes += utf8Bytes(entry.name) + utf8Bytes(entry.plainValue);
      continue;
    }

    const stored = entry.draft.storedCredential;
    const renamed = stored !== null && stored.name !== entry.name;
    const needsNewSecret = entry.valueKind === 'newSecret' || renamed || stored === null;
    if (draft.profileId === null && entry.valueKind === 'storedCredential') {
      pushIssue(
        issues,
        fields.valueKind,
        'A new profile cannot reuse a stored credential reference.',
        entry.draft.rowId,
      );
    }
    if (entry.valueKind === 'storedCredential' && stored === null) {
      pushIssue(
        issues,
        fields.valueKind,
        'No stored credential is available for this variable.',
        entry.draft.rowId,
      );
    }
    if (stored !== null) {
      validateRequiredText(
        stored.credentialReference,
        fields.valueKind,
        'Credential reference',
        MAX_CREDENTIAL_REFERENCE_BYTES,
        issues,
        entry.draft.rowId,
      );
      if (!renamed && entry.valueKind === 'storedCredential') {
        storedEnvironmentBytes += utf8Bytes(entry.name) + utf8Bytes(stored.credentialReference);
      }
    }
    const rotatesStoredSecret =
      entry.valueKind === 'storedCredential' &&
      stored !== null &&
      !renamed &&
      entry.draft.replaceStoredSecret;
    if (requireSecretValues && (needsNewSecret || rotatesStoredSecret) && entry.secret === null) {
      pushIssue(
        issues,
        fields.secret,
        renamed
          ? 'A secret field is required after renaming a credential-backed variable.'
          : 'The secret field is unavailable.',
        entry.draft.rowId,
      );
    }
    if (entry.secret !== null) {
      validateOptionalText(
        entry.secret,
        fields.secret,
        MAX_CREDENTIAL_SECRET_BYTES,
        issues,
        entry.draft.rowId,
      );
      pendingSecretBytes += utf8Bytes(entry.name) + utf8Bytes(entry.secret);
    }
  }

  if (materializedCount > MAX_ENVIRONMENT_ENTRIES) {
    pushIssue(
      issues,
      'launchProfile.environment',
      'Materialized variables exceed the supported count.',
    );
  }
  if (storedEnvironmentBytes > MAX_ENVIRONMENT_TOTAL_BYTES) {
    pushIssue(
      issues,
      'launchProfile.environment',
      'Variables exceed the supported combined length.',
    );
  }
  if (pendingSecretBytes > MAX_ENVIRONMENT_TOTAL_BYTES) {
    pushIssue(
      issues,
      'launchProfile.environment',
      'Secret variables exceed the supported combined length.',
    );
  }
}

function materializeRequest(
  draft: LaunchProfileDraft,
  current: CurrentDraft,
  requireSecretValues: boolean,
): RequestMaterialization {
  const environment: LaunchEnvironmentEntry[] = [];
  const secretEnvironment: Array<{ name: string; secret: string }> = [];
  const pendingSecretNames: string[] = [];
  const issues: LaunchProfileValidationIssue[] = [];

  for (const entry of current.environment) {
    const fields = environmentFormFields(entry.draft.rowId);
    if (entry.valueKind === 'plain') {
      environment.push({ name: entry.name, value: { kind: 'plain', value: entry.plainValue } });
      continue;
    }

    const stored = entry.draft.storedCredential;
    const renamed = stored !== null && stored.name !== entry.name;
    const keepStoredReference =
      draft.profileId !== null &&
      entry.valueKind === 'storedCredential' &&
      stored !== null &&
      !renamed;
    if (keepStoredReference) {
      environment.push({
        name: entry.name,
        value: {
          credentialReference: stored.credentialReference,
          kind: 'credentialReference',
        },
      });
    }

    const requiresNewSecret = entry.valueKind === 'newSecret' || renamed || stored === null;
    const rotatesStoredSecret = keepStoredReference && entry.draft.replaceStoredSecret;
    if (requiresNewSecret || rotatesStoredSecret) {
      pendingSecretNames.push(entry.name);
      if (entry.secret !== null) {
        secretEnvironment.push({ name: entry.name, secret: entry.secret });
      } else if (requireSecretValues) {
        pushIssue(
          issues,
          fields.secret,
          renamed
            ? 'A secret field is required after renaming a credential-backed variable.'
            : 'The secret field is unavailable.',
          entry.draft.rowId,
        );
      }
    }
  }

  const input: LaunchProfileInput = {
    environment,
    execution:
      current.mode === 'direct'
        ? {
            argv: [...current.argv],
            executable: current.directExecutable,
            mode: 'direct',
          }
        : {
            command: current.shellCommand,
            mode: 'shell',
            shell: current.shellKind,
          },
    interactive: current.interactive,
    name: current.name,
    projectId: current.projectId.trim() === '' ? null : current.projectId,
    stopTimeoutMs: current.stopTimeoutMs,
    workingDirectory: current.workingDirectory,
  };
  if (wireBytes(input) > MAX_PROFILE_INPUT_WIRE_BYTES) {
    pushIssue(issues, 'launchProfile', 'The encoded launch profile exceeds the supported size.');
  }
  return { input, issues, pendingSecretNames, secretEnvironment };
}

function credentialAction(entry: CurrentEnvironment) {
  if (entry.valueKind === 'plain') {
    return 'none';
  }
  const stored = entry.draft.storedCredential;
  if (entry.valueKind === 'newSecret' || stored === null || stored.name !== entry.name) {
    return 'replace';
  }
  return entry.draft.replaceStoredSecret ? 'rotate' : 'keep';
}

function validateRequiredText(
  value: string,
  field: string,
  label: string,
  maximumBytes: number,
  issues: LaunchProfileValidationIssue[],
  rowId?: string,
) {
  validateOptionalText(value, field, maximumBytes, issues, rowId);
  if (value.trim() === '') {
    pushIssue(issues, field, `${label} is required.`, rowId);
  }
}

function validateOptionalText(
  value: string,
  field: string,
  maximumBytes: number,
  issues: LaunchProfileValidationIssue[],
  rowId?: string,
) {
  if (utf8Bytes(value) > maximumBytes) {
    pushIssue(issues, field, `Must not exceed ${maximumBytes} UTF-8 bytes.`, rowId);
  }
  if (value.includes('\0')) {
    pushIssue(issues, field, 'Must not contain NUL.', rowId);
  }
}

function isSafeAbsoluteWorkingDirectory(value: string) {
  const normalizedWindows = value.replaceAll('/', '\\');
  if (/^(\\\\\?\\|\\\\\.\\|\\\?\?\\|\\Device\\)/i.test(normalizedWindows)) {
    return false;
  }
  if (/^[A-Za-z]:\\/.test(normalizedWindows)) {
    const tail = normalizedWindows.length === 3 ? [] : normalizedWindows.slice(3).split('\\');
    return tail.every(isNormalPathComponent);
  }
  if (normalizedWindows.startsWith('\\\\')) {
    const parts = normalizedWindows.slice(2).split('\\');
    const server = parts[0];
    const share = parts[1];
    return (
      server !== undefined &&
      share !== undefined &&
      server !== '' &&
      share !== '' &&
      !['.', '?', 'GLOBALROOT'].includes(server.toUpperCase()) &&
      parts.slice(2).every(isNormalPathComponent)
    );
  }
  if (value === '/') {
    return true;
  }
  if (value.startsWith('/')) {
    return value.slice(1).split('/').every(isNormalPathComponent);
  }
  return false;
}

function isNormalPathComponent(component: string) {
  return component !== '' && component !== '.' && component !== '..';
}

function isSensitiveToken(token: string) {
  return [
    'password',
    'passwd',
    'pwd',
    'secret',
    'token',
    'authorization',
    'credential',
    'cookie',
    'session',
  ].includes(token);
}

function isAsciiAlphaNumeric(value: string) {
  return /^[A-Za-z0-9]$/.test(value);
}

function isAsciiUppercase(value: string) {
  return /^[A-Z]$/.test(value);
}

function isAsciiLowercase(value: string) {
  return /^[a-z]$/.test(value);
}

function isAsciiDigit(value: string) {
  return /^[0-9]$/.test(value);
}

function utf8Bytes(value: string) {
  return utf8Encoder.encode(value).length;
}

function wireBytes(value: unknown) {
  return utf8Bytes(JSON.stringify(value));
}

function pushIssue(
  issues: LaunchProfileValidationIssue[],
  field: string,
  message: string,
  rowId?: string,
) {
  issues.push(rowId === undefined ? { field, message } : { field, message, rowId });
}

function deduplicateIssues(issues: ReadonlyArray<LaunchProfileValidationIssue>) {
  const seen = new Set<string>();
  return issues.filter((issue) => {
    const key = `${issue.field}\0${issue.message}\0${issue.rowId ?? ''}`;
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
    return true;
  });
}
