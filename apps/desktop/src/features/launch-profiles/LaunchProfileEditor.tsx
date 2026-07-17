import { type ReactNode, useEffect, useId, useRef } from 'react';
import { Button, IconButton, SegmentedControl, TextInput } from '@dpm/ui';
import { KeyRound, Plus, Save, ShieldCheck, Trash2, X } from 'lucide-react';

import {
  argumentFormField,
  createEnvironmentDraft,
  environmentFormFields,
  isSensitiveEnvironmentName,
  LAUNCH_PROFILE_FORM_FIELDS,
  switchEnvironmentValueKind,
  switchLaunchProfileMode,
  type EnvironmentDraft,
  type LaunchProfileDraft,
  type LaunchProfileValidationIssue,
} from './launchProfileModel';

interface LaunchProfileEditorProps {
  busy: boolean;
  dirty: boolean;
  draft: LaunchProfileDraft;
  feedback: { message: string; tone: 'error' | 'success' } | null;
  focusOnMount: LaunchProfileEditorFocusTarget | null;
  issues: ReadonlyArray<LaunchProfileValidationIssue>;
  onDelete: () => void;
  onDraftChange: (draft: LaunchProfileDraft) => void;
  onMountFocusRestored: () => void;
  onSave: (formData: FormData) => void;
}

export type LaunchProfileEditorFocusTarget = 'name' | 'title';

const executionModes = [
  { label: 'Direct', value: 'direct' },
  { label: 'Shell', value: 'shell' },
] as const;

const shellKinds = [
  { label: 'PowerShell', value: 'powerShell' },
  { label: 'Command Prompt', value: 'cmd' },
  { label: 'Z shell', value: 'zsh' },
] as const;

const environmentKinds = [
  { label: 'Plain', value: 'plain' },
  { label: 'Secret', value: 'secret' },
] as const;

export function LaunchProfileEditor({
  busy,
  dirty,
  draft,
  feedback,
  focusOnMount,
  issues,
  onDelete,
  onDraftChange,
  onMountFocusRestored,
  onSave,
}: LaunchProfileEditorProps) {
  const formId = useId();
  const editorTitleRef = useRef<HTMLHeadingElement>(null);
  const environmentAddButtonRef = useRef<HTMLButtonElement>(null);
  const environmentFocusFrameRef = useRef<number | null>(null);
  const environmentNameInputsRef = useRef(new Map<string, HTMLInputElement>());
  const nameInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (busy || focusOnMount === null) {
      return;
    }
    const frame = globalThis.requestAnimationFrame(() => {
      const preferredTarget =
        focusOnMount === 'name' ? nameInputRef.current : editorTitleRef.current;
      (preferredTarget ?? editorTitleRef.current)?.focus({ preventScroll: false });
      onMountFocusRestored();
    });
    return () => globalThis.cancelAnimationFrame(frame);
  }, [busy, focusOnMount, onMountFocusRestored]);

  useEffect(
    () => () => {
      if (environmentFocusFrameRef.current !== null) {
        globalThis.cancelAnimationFrame(environmentFocusFrameRef.current);
      }
    },
    [],
  );

  const focusEnvironmentInput = (rowId: string | null) => {
    if (environmentFocusFrameRef.current !== null) {
      globalThis.cancelAnimationFrame(environmentFocusFrameRef.current);
    }
    environmentFocusFrameRef.current = globalThis.requestAnimationFrame(() => {
      environmentFocusFrameRef.current = null;
      const adjacentInput =
        rowId === null ? null : (environmentNameInputsRef.current.get(rowId) ?? null);
      (adjacentInput ?? environmentAddButtonRef.current)?.focus({ preventScroll: false });
    });
  };

  const updateEnvironment = (
    rowId: string,
    update: (environment: EnvironmentDraft) => EnvironmentDraft,
  ) => {
    onDraftChange({
      ...draft,
      environment: draft.environment.map((environment) =>
        environment.rowId === rowId ? update(environment) : environment,
      ),
    });
  };

  const removeEnvironment = (rowId: string) => {
    const removedIndex = draft.environment.findIndex((environment) => environment.rowId === rowId);
    const nextEnvironment = draft.environment.filter((environment) => environment.rowId !== rowId);
    const adjacentRow =
      removedIndex < 0
        ? null
        : (nextEnvironment[Math.min(removedIndex, nextEnvironment.length - 1)] ?? null);
    onDraftChange({
      ...draft,
      environment: nextEnvironment,
    });
    focusEnvironmentInput(adjacentRow?.rowId ?? null);
  };

  return (
    <section aria-label="Launch profile editor" className="launch-profile-editor-panel">
      <header className="launch-panel-header launch-editor-header">
        <div className="launch-editor-title">
          <h2 ref={editorTitleRef} tabIndex={-1}>
            {draft.profileId === null ? 'New profile' : draft.name || 'Untitled profile'}
          </h2>
          <span>
            {dirty ? 'Unsaved changes' : draft.profileId === null ? 'Not saved' : 'Saved'}
          </span>
        </div>
        <div className="launch-panel-actions">
          {draft.profileId !== null ? (
            <IconButton
              disabled={busy}
              icon={<Trash2 aria-hidden="true" size={15} strokeWidth={1.8} />}
              label="Delete profile"
              onClick={onDelete}
              variant="danger"
            />
          ) : null}
          <Button
            disabled={busy}
            form={formId}
            leadingIcon={<Save aria-hidden="true" size={15} strokeWidth={1.8} />}
            size="compact"
            type="submit"
            variant="primary"
          >
            {busy ? 'Saving' : 'Save'}
          </Button>
        </div>
      </header>

      <form
        className="launch-profile-form"
        id={formId}
        onSubmit={(event) => {
          event.preventDefault();
          onSave(new FormData(event.currentTarget));
        }}
      >
        <fieldset className="launch-profile-fieldset" disabled={busy}>
          {feedback ? (
            <div className="launch-form-feedback" data-tone={feedback.tone} role="status">
              {feedback.message}
            </div>
          ) : null}
          {issues.length > 0 ? (
            <div className="launch-form-feedback" data-tone="error" role="alert">
              {issues.length === 1
                ? issues[0]?.message
                : `${issues.length} fields need attention before this profile can be saved.`}
            </div>
          ) : null}

          <section aria-labelledby={`${formId}-identity`} className="launch-form-section">
            <SectionHeading id={`${formId}-identity`} title="Profile" />
            <div className="launch-form-grid launch-form-grid--two">
              <Field field={LAUNCH_PROFILE_FORM_FIELDS.name} issues={issues} label="Name">
                <TextInput
                  aria-describedby={issueDescription(issues, LAUNCH_PROFILE_FORM_FIELDS.name)}
                  autoComplete="off"
                  invalid={hasIssue(issues, LAUNCH_PROFILE_FORM_FIELDS.name)}
                  name={LAUNCH_PROFILE_FORM_FIELDS.name}
                  onChange={(event) => onDraftChange({ ...draft, name: event.target.value })}
                  ref={nameInputRef}
                  value={draft.name}
                />
              </Field>
              <Field
                field={LAUNCH_PROFILE_FORM_FIELDS.projectId}
                issues={issues}
                label="Project ID"
                optional
              >
                <TextInput
                  aria-describedby={issueDescription(issues, LAUNCH_PROFILE_FORM_FIELDS.projectId)}
                  autoComplete="off"
                  invalid={hasIssue(issues, LAUNCH_PROFILE_FORM_FIELDS.projectId)}
                  name={LAUNCH_PROFILE_FORM_FIELDS.projectId}
                  onChange={(event) => onDraftChange({ ...draft, projectId: event.target.value })}
                  value={draft.projectId}
                />
              </Field>
            </div>
          </section>

          <section aria-labelledby={`${formId}-execution`} className="launch-form-section">
            <SectionHeading id={`${formId}-execution`} title="Execution" />
            <input name={LAUNCH_PROFILE_FORM_FIELDS.mode} type="hidden" value={draft.mode} />
            <SegmentedControl
              ariaLabel="Execution mode"
              items={executionModes}
              onValueChange={(value) => {
                if (value === 'direct' || value === 'shell') {
                  onDraftChange(switchLaunchProfileMode(draft, value));
                }
              }}
              value={draft.mode}
            />
            <div className="launch-mode-summary" data-mode={draft.mode}>
              <strong>{draft.mode === 'direct' ? 'Direct process' : 'Explicit shell'}</strong>
              <span>
                {draft.mode === 'direct'
                  ? 'Executable and arguments stay separate.'
                  : 'The command is interpreted by the selected shell.'}
              </span>
            </div>
            {draft.mode === 'direct' ? (
              <DirectEditor draft={draft} issues={issues} onDraftChange={onDraftChange} />
            ) : (
              <ShellEditor draft={draft} issues={issues} onDraftChange={onDraftChange} />
            )}
          </section>

          <section aria-labelledby={`${formId}-context`} className="launch-form-section">
            <SectionHeading id={`${formId}-context`} title="Run context" />
            <Field
              field={LAUNCH_PROFILE_FORM_FIELDS.workingDirectory}
              issues={issues}
              label="Working directory"
            >
              <TextInput
                aria-describedby={issueDescription(
                  issues,
                  LAUNCH_PROFILE_FORM_FIELDS.workingDirectory,
                )}
                autoCapitalize="off"
                autoComplete="off"
                className="launch-mono-input"
                invalid={hasIssue(issues, LAUNCH_PROFILE_FORM_FIELDS.workingDirectory)}
                name={LAUNCH_PROFILE_FORM_FIELDS.workingDirectory}
                onChange={(event) =>
                  onDraftChange({ ...draft, workingDirectory: event.target.value })
                }
                spellCheck={false}
                value={draft.workingDirectory}
              />
            </Field>
            <div className="launch-form-grid launch-form-grid--two">
              <Field
                field={LAUNCH_PROFILE_FORM_FIELDS.stopTimeoutMs}
                issues={issues}
                label="Stop timeout (ms)"
              >
                <TextInput
                  aria-describedby={issueDescription(
                    issues,
                    LAUNCH_PROFILE_FORM_FIELDS.stopTimeoutMs,
                  )}
                  inputMode="numeric"
                  invalid={hasIssue(issues, LAUNCH_PROFILE_FORM_FIELDS.stopTimeoutMs)}
                  max={300000}
                  min={0}
                  name={LAUNCH_PROFILE_FORM_FIELDS.stopTimeoutMs}
                  onChange={(event) => {
                    const value = Number(event.target.value);
                    onDraftChange({
                      ...draft,
                      stopTimeoutMs: Number.isSafeInteger(value) ? value : 0,
                    });
                  }}
                  step={100}
                  type="number"
                  value={draft.stopTimeoutMs}
                />
              </Field>
              <label className="launch-checkbox-field">
                <input
                  checked={draft.interactive}
                  name={LAUNCH_PROFILE_FORM_FIELDS.interactive}
                  onChange={(event) =>
                    onDraftChange({ ...draft, interactive: event.target.checked })
                  }
                  type="checkbox"
                />
                <span>
                  <strong>Interactive terminal</strong>
                  <small>Allocate PTY / ConPTY</small>
                </span>
              </label>
            </div>
          </section>

          <section aria-labelledby={`${formId}-environment`} className="launch-form-section">
            <div className="launch-section-heading launch-section-heading--actions">
              <div>
                <h3 id={`${formId}-environment`}>Environment</h3>
                <span>{draft.environment.length} profile variables</span>
              </div>
              <Button
                disabled={draft.environment.length >= 256}
                leadingIcon={<Plus aria-hidden="true" size={14} strokeWidth={1.8} />}
                onClick={() =>
                  onDraftChange({
                    ...draft,
                    environment: [...draft.environment, createEnvironmentDraft()],
                  })
                }
                ref={environmentAddButtonRef}
                size="compact"
                variant="secondary"
              >
                Variable
              </Button>
            </div>
            <div className="launch-environment-list">
              {draft.environment.map((environment) => (
                <EnvironmentRow
                  environment={environment}
                  issues={issues}
                  key={environment.rowId}
                  onChange={(update) => updateEnvironment(environment.rowId, update)}
                  onNameInputMount={(element) => {
                    if (element === null) {
                      environmentNameInputsRef.current.delete(environment.rowId);
                    } else {
                      environmentNameInputsRef.current.set(environment.rowId, element);
                    }
                  }}
                  onRemove={() => removeEnvironment(environment.rowId)}
                />
              ))}
              {draft.environment.length === 0 ? (
                <div className="launch-environment-empty">No profile-level variables</div>
              ) : null}
            </div>
          </section>
        </fieldset>
      </form>
    </section>
  );
}

function DirectEditor({
  draft,
  issues,
  onDraftChange,
}: {
  draft: LaunchProfileDraft;
  issues: ReadonlyArray<LaunchProfileValidationIssue>;
  onDraftChange: (draft: LaunchProfileDraft) => void;
}) {
  const argumentAddButtonRef = useRef<HTMLButtonElement>(null);
  const argumentFocusFrameRef = useRef<number | null>(null);
  const argumentInputsRef = useRef(new Map<number, HTMLInputElement>());

  useEffect(
    () => () => {
      if (argumentFocusFrameRef.current !== null) {
        globalThis.cancelAnimationFrame(argumentFocusFrameRef.current);
      }
    },
    [],
  );

  const removeArgument = (removedIndex: number) => {
    const argv = draft.direct.argv.filter((_, index) => index !== removedIndex);
    const adjacentIndex = argv.length === 0 ? null : Math.min(removedIndex, argv.length - 1);
    onDraftChange({ ...draft, direct: { ...draft.direct, argv } });

    if (argumentFocusFrameRef.current !== null) {
      globalThis.cancelAnimationFrame(argumentFocusFrameRef.current);
    }
    argumentFocusFrameRef.current = globalThis.requestAnimationFrame(() => {
      argumentFocusFrameRef.current = null;
      const adjacentInput =
        adjacentIndex === null ? null : (argumentInputsRef.current.get(adjacentIndex) ?? null);
      (adjacentInput ?? argumentAddButtonRef.current)?.focus({ preventScroll: false });
    });
  };

  return (
    <div className="launch-execution-fields">
      <Field field={LAUNCH_PROFILE_FORM_FIELDS.directExecutable} issues={issues} label="Executable">
        <TextInput
          aria-describedby={issueDescription(issues, LAUNCH_PROFILE_FORM_FIELDS.directExecutable)}
          autoCapitalize="off"
          autoComplete="off"
          className="launch-mono-input"
          invalid={hasIssue(issues, LAUNCH_PROFILE_FORM_FIELDS.directExecutable)}
          name={LAUNCH_PROFILE_FORM_FIELDS.directExecutable}
          onChange={(event) =>
            onDraftChange({
              ...draft,
              direct: { ...draft.direct, executable: event.target.value },
            })
          }
          spellCheck={false}
          value={draft.direct.executable}
        />
      </Field>
      <div className="launch-argument-heading">
        <span>Arguments</span>
        <IconButton
          disabled={draft.direct.argv.length >= 256}
          icon={<Plus aria-hidden="true" size={15} strokeWidth={1.8} />}
          label="Add argument"
          onClick={() =>
            onDraftChange({
              ...draft,
              direct: { ...draft.direct, argv: [...draft.direct.argv, ''] },
            })
          }
          ref={argumentAddButtonRef}
          variant="ghost"
        />
      </div>
      <div className="launch-argument-list">
        {draft.direct.argv.map((argument, index) => {
          const field = argumentFormField(index);
          const issue = issueForField(issues, field);
          return (
            <div className="launch-argument-item" key={`${index}:${draft.direct.argv.length}`}>
              <div className="launch-argument-row">
                <span aria-hidden="true" className="launch-argument-index">
                  {index + 1}
                </span>
                <TextInput
                  aria-describedby={issue ? fieldErrorId(field) : undefined}
                  aria-label={`Argument ${index + 1}`}
                  autoCapitalize="off"
                  autoComplete="off"
                  className="launch-mono-input"
                  invalid={issue !== undefined}
                  name={field}
                  onChange={(event) => {
                    const argv = [...draft.direct.argv];
                    argv[index] = event.target.value;
                    onDraftChange({ ...draft, direct: { ...draft.direct, argv } });
                  }}
                  ref={(element) => {
                    if (element === null) {
                      argumentInputsRef.current.delete(index);
                    } else {
                      argumentInputsRef.current.set(index, element);
                    }
                  }}
                  spellCheck={false}
                  value={argument}
                />
                <IconButton
                  icon={<X aria-hidden="true" size={14} strokeWidth={1.8} />}
                  label={`Remove argument ${index + 1}`}
                  onClick={() => removeArgument(index)}
                  variant="ghost"
                />
              </div>
              {issue ? (
                <span className="launch-field-error" id={fieldErrorId(field)}>
                  {issue.message}
                </span>
              ) : null}
            </div>
          );
        })}
        {draft.direct.argv.length === 0 ? (
          <div className="launch-argument-empty">No arguments</div>
        ) : null}
      </div>
    </div>
  );
}

function ShellEditor({
  draft,
  issues,
  onDraftChange,
}: {
  draft: LaunchProfileDraft;
  issues: ReadonlyArray<LaunchProfileValidationIssue>;
  onDraftChange: (draft: LaunchProfileDraft) => void;
}) {
  return (
    <div className="launch-execution-fields">
      <input name={LAUNCH_PROFILE_FORM_FIELDS.shellKind} type="hidden" value={draft.shell.shell} />
      <div className="launch-field">
        <span className="launch-field-label">Shell</span>
        <SegmentedControl
          ariaLabel="Shell"
          items={shellKinds}
          onValueChange={(value) => {
            if (value === 'powerShell' || value === 'cmd' || value === 'zsh') {
              onDraftChange({ ...draft, shell: { ...draft.shell, shell: value } });
            }
          }}
          value={draft.shell.shell}
        />
      </div>
      <Field field={LAUNCH_PROFILE_FORM_FIELDS.shellCommand} issues={issues} label="Command">
        <textarea
          aria-describedby={issueDescription(issues, LAUNCH_PROFILE_FORM_FIELDS.shellCommand)}
          aria-invalid={hasIssue(issues, LAUNCH_PROFILE_FORM_FIELDS.shellCommand) || undefined}
          className="launch-textarea launch-mono-input"
          name={LAUNCH_PROFILE_FORM_FIELDS.shellCommand}
          onChange={(event) =>
            onDraftChange({ ...draft, shell: { ...draft.shell, command: event.target.value } })
          }
          rows={5}
          spellCheck={false}
          value={draft.shell.command}
        />
      </Field>
    </div>
  );
}

function EnvironmentRow({
  environment,
  issues,
  onChange,
  onNameInputMount,
  onRemove,
}: {
  environment: EnvironmentDraft;
  issues: ReadonlyArray<LaunchProfileValidationIssue>;
  onChange: (update: (environment: EnvironmentDraft) => EnvironmentDraft) => void;
  onNameInputMount: (element: HTMLInputElement | null) => void;
  onRemove: () => void;
}) {
  const fields = environmentFormFields(environment.rowId);
  const secret = environment.valueKind !== 'plain';
  const stored = environment.storedCredential !== null;
  const renamed = stored && environment.storedCredential?.name !== environment.name;
  const showSecretInput =
    secret &&
    (!stored ||
      renamed ||
      environment.valueKind === 'newSecret' ||
      environment.replaceStoredSecret);
  const sensitiveName = isSensitiveEnvironmentName(environment.name);
  const rowIssues = uniqueFieldIssues(issues.filter((issue) => issue.rowId === environment.rowId));

  return (
    <div className="launch-environment-row" data-secret={secret || undefined}>
      <div className="launch-environment-row-main">
        <TextInput
          aria-describedby={issueDescription(issues, fields.name)}
          aria-label="Variable name"
          autoCapitalize="off"
          autoComplete="off"
          className="launch-mono-input"
          invalid={hasIssue(issues, fields.name)}
          name={fields.name}
          onChange={(event) => onChange((current) => ({ ...current, name: event.target.value }))}
          placeholder="VARIABLE_NAME"
          ref={onNameInputMount}
          spellCheck={false}
          value={environment.name}
        />
        <input name={fields.valueKind} type="hidden" value={environment.valueKind} />
        <SegmentedControl
          ariaDescribedBy={issueDescription(issues, fields.valueKind)}
          ariaLabel={`Value type for ${environment.name || 'variable'}`}
          items={environmentKinds}
          onValueChange={(value) =>
            onChange((current) =>
              switchEnvironmentValueKind(
                current,
                value === 'plain'
                  ? 'plain'
                  : current.storedCredential === null
                    ? 'newSecret'
                    : 'storedCredential',
              ),
            )
          }
          value={secret ? 'secret' : 'plain'}
        />
        {showSecretInput ? (
          <div className="launch-secret-edit-wrap">
            <div className="launch-secret-input-wrap">
              <KeyRound aria-hidden="true" size={14} strokeWidth={1.7} />
              <TextInput
                aria-describedby={issueDescription(issues, fields.secret)}
                aria-label={stored ? 'Replacement secret value' : 'Secret value'}
                autoComplete="new-password"
                className="launch-secret-input"
                defaultValue=""
                invalid={hasIssue(issues, fields.secret)}
                key={`${environment.rowId}:${environment.valueKind}:${environment.replaceStoredSecret}`}
                name={fields.secret}
                placeholder={stored ? 'Replacement secret' : 'Secret value'}
                spellCheck={false}
                type="password"
              />
            </div>
            {stored && !renamed && environment.replaceStoredSecret ? (
              <IconButton
                icon={<X aria-hidden="true" size={14} strokeWidth={1.8} />}
                label="Keep stored secret"
                onClick={() => onChange((current) => ({ ...current, replaceStoredSecret: false }))}
                variant="ghost"
              />
            ) : null}
          </div>
        ) : secret ? (
          <div className="launch-stored-secret-control">
            <span aria-label="Stored secret value">********</span>
            <Button
              leadingIcon={<KeyRound aria-hidden="true" size={13} strokeWidth={1.8} />}
              onClick={() => onChange((current) => ({ ...current, replaceStoredSecret: true }))}
              size="compact"
              variant="secondary"
            >
              Replace
            </Button>
          </div>
        ) : (
          <TextInput
            aria-describedby={issueDescription(issues, fields.plainValue)}
            aria-label={`Value for ${environment.name || 'variable'}`}
            autoComplete="off"
            className="launch-mono-input"
            invalid={hasIssue(issues, fields.plainValue)}
            name={fields.plainValue}
            onChange={(event) =>
              onChange((current) => ({ ...current, plainValue: event.target.value }))
            }
            spellCheck={false}
            value={environment.plainValue}
          />
        )}
        <IconButton
          icon={<Trash2 aria-hidden="true" size={14} strokeWidth={1.8} />}
          label={`Remove ${environment.name || 'environment variable'}`}
          onClick={onRemove}
          variant="ghost"
        />
      </div>
      <div className="launch-environment-meta">
        {secret ? (
          <span className="launch-secret-state">
            <ShieldCheck aria-hidden="true" size={13} strokeWidth={1.8} />
            {stored && !renamed && !environment.replaceStoredSecret
              ? 'Stored credential'
              : stored
                ? 'Replacement pending'
                : 'New secret'}
          </span>
        ) : null}
        {sensitiveName && !secret ? (
          <span className="launch-sensitive-warning">Sensitive name requires Secret</span>
        ) : null}
        {rowIssues.map((issue) => (
          <span className="launch-field-error" id={fieldErrorId(issue.field)} key={issue.field}>
            {issue.message}
          </span>
        ))}
      </div>
    </div>
  );
}

function SectionHeading({ id, title }: { id: string; title: string }) {
  return (
    <div className="launch-section-heading">
      <h3 id={id}>{title}</h3>
    </div>
  );
}

function Field({
  children,
  field,
  issues,
  label,
  optional = false,
}: {
  children: ReactNode;
  field: string;
  issues: ReadonlyArray<LaunchProfileValidationIssue>;
  label: string;
  optional?: boolean;
}) {
  const issue = issues.find((candidate) => candidate.field === field);
  return (
    <label className="launch-field">
      <span className="launch-field-label">
        {label}
        {optional ? <small>Optional</small> : null}
      </span>
      {children}
      {issue ? (
        <span className="launch-field-error" id={fieldErrorId(field)}>
          {issue.message}
        </span>
      ) : null}
    </label>
  );
}

function hasIssue(issues: ReadonlyArray<LaunchProfileValidationIssue>, field: string) {
  return issues.some((issue) => issue.field === field);
}

function issueForField(issues: ReadonlyArray<LaunchProfileValidationIssue>, field: string) {
  return issues.find((issue) => issue.field === field);
}

function issueDescription(issues: ReadonlyArray<LaunchProfileValidationIssue>, field: string) {
  return hasIssue(issues, field) ? fieldErrorId(field) : undefined;
}

function fieldErrorId(field: string) {
  return `launch-error-${field.replace(/[^A-Za-z0-9_-]/g, '-')}`;
}

function uniqueFieldIssues(issues: ReadonlyArray<LaunchProfileValidationIssue>) {
  const fields = new Set<string>();
  return issues.filter((issue) => {
    if (fields.has(issue.field)) {
      return false;
    }
    fields.add(issue.field);
    return true;
  });
}
