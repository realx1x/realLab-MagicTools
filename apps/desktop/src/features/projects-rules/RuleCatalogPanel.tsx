import type {
  ClassificationRuleMatcherKind,
  ClassificationRuleSummary,
  ProjectSummary,
} from '@dpm/generated-types';
import { Button, IconButton, TextInput } from '@dpm/ui';
import { ListFilter, LoaderCircle, Plus, RefreshCw, Save, Trash2 } from 'lucide-react';
import type { ReactNode } from 'react';

import {
  RULE_FIELDS,
  type RuleActionKind,
  type RuleDraft,
  type ValidationIssue,
  presentMatcherKind,
  presentRuleAction,
} from './projectRulesModel';

interface RuleCatalogPanelProps {
  busy: boolean;
  dirty: boolean;
  draft: RuleDraft;
  error: string | null;
  feedback: { message: string; tone: 'error' | 'success' } | null;
  issues: ReadonlyArray<ValidationIssue>;
  loading: boolean;
  onCreate: () => void;
  onDelete: () => void;
  onDraftChange: (draft: RuleDraft) => void;
  onRefresh: () => void;
  onSave: () => void;
  onSelect: (rule: ClassificationRuleSummary) => void;
  projects: ReadonlyArray<ProjectSummary>;
  rules: ReadonlyArray<ClassificationRuleSummary>;
}

const MATCHER_OPTIONS: ReadonlyArray<{
  label: string;
  value: ClassificationRuleMatcherKind;
}> = [
  { label: 'Executable name equals', value: 'executableNameExact' },
  { label: 'Executable path equals', value: 'executablePathExact' },
  { label: 'Command line contains', value: 'commandLineContains' },
  { label: 'Working directory starts with', value: 'workingDirectoryPrefix' },
];

const ACTION_OPTIONS: ReadonlyArray<{ label: string; value: RuleActionKind }> = [
  { label: 'Include', value: 'include' },
  { label: 'Exclude', value: 'exclude' },
  { label: 'Assign project', value: 'assignProject' },
];

export function RuleCatalogPanel({
  busy,
  dirty,
  draft,
  error,
  feedback,
  issues,
  loading,
  onCreate,
  onDelete,
  onDraftChange,
  onRefresh,
  onSave,
  onSelect,
  projects,
  rules,
}: RuleCatalogPanelProps) {
  const selectedProjectAvailable = projects.some((project) => project.id === draft.projectId);

  return (
    <div className="catalog-workspace">
      <aside aria-label="Classification rules" className="catalog-list-panel">
        <header className="catalog-panel-header">
          <div className="catalog-panel-title">
            <h2>Rules</h2>
            <span>{loading ? 'Loading' : `${rules.length.toLocaleString()} saved`}</span>
          </div>
          <div className="catalog-panel-actions">
            <IconButton
              disabled={busy || loading}
              icon={
                <RefreshCw
                  aria-hidden="true"
                  className={loading ? 'catalog-spin' : undefined}
                  size={15}
                  strokeWidth={1.8}
                />
              }
              label="Refresh rules"
              onClick={onRefresh}
              variant="ghost"
            />
            <IconButton
              disabled={busy}
              icon={<Plus aria-hidden="true" size={16} strokeWidth={1.8} />}
              label="New rule"
              onClick={onCreate}
              variant="secondary"
            />
          </div>
        </header>
        {error ? (
          <div className="catalog-inline-alert" role="alert">
            <span>{error}</span>
            <Button
              disabled={busy || loading}
              onClick={onRefresh}
              size="compact"
              variant="secondary"
            >
              Retry
            </Button>
          </div>
        ) : null}
        <div className="catalog-list" role="list">
          {rules.map((rule) => {
            const selected = rule.id === draft.id;
            return (
              <div key={rule.id} role="listitem">
                <button
                  aria-current={selected ? 'page' : undefined}
                  className="catalog-list-item catalog-list-item--rule"
                  data-enabled={rule.input.enabled || undefined}
                  data-selected={selected || undefined}
                  disabled={busy}
                  onClick={() => onSelect(rule)}
                  type="button"
                >
                  <ListFilter aria-hidden="true" size={16} strokeWidth={1.7} />
                  <span className="catalog-list-copy">
                    <strong title={rule.input.pattern}>{rule.input.pattern}</strong>
                    <span>
                      {presentMatcherKind(rule.input.matcherKind)}
                      <span aria-hidden="true"> / </span>
                      {presentRuleAction(rule.input.action)}
                    </span>
                    <span>
                      Priority {rule.input.priority.toLocaleString()}
                      <span aria-hidden="true"> / </span>
                      {rule.input.enabled ? 'Enabled' : 'Disabled'}
                    </span>
                  </span>
                </button>
              </div>
            );
          })}
          {loading && rules.length === 0 ? (
            <CatalogListState
              icon={<LoaderCircle aria-hidden="true" className="catalog-spin" size={18} />}
              label="Loading rules"
            />
          ) : null}
          {!loading && rules.length === 0 && error === null ? (
            <CatalogListState
              icon={<ListFilter aria-hidden="true" size={18} strokeWidth={1.6} />}
              label="No classification rules"
            />
          ) : null}
        </div>
      </aside>

      <form
        className="catalog-editor-panel"
        onSubmit={(event) => {
          event.preventDefault();
          onSave();
        }}
      >
        <header className="catalog-editor-header">
          <div className="catalog-editor-heading">
            <h2>{draft.id === null ? 'New rule' : draft.pattern || 'Classification rule'}</h2>
            <span>
              {dirty
                ? 'Unsaved changes'
                : draft.expectedUpdatedAt === null
                  ? 'Not saved'
                  : `Updated ${formatUpdatedAt(draft.expectedUpdatedAt)}`}
            </span>
          </div>
          <div className="catalog-editor-actions">
            {draft.id !== null ? (
              <Button
                disabled={busy}
                leadingIcon={<Trash2 aria-hidden="true" size={14} strokeWidth={1.8} />}
                onClick={onDelete}
                size="compact"
                variant="danger"
              >
                Delete
              </Button>
            ) : null}
            <Button
              disabled={busy || !dirty}
              leadingIcon={<Save aria-hidden="true" size={14} strokeWidth={1.8} />}
              size="compact"
              type="submit"
              variant="primary"
            >
              {busy ? 'Working' : 'Save'}
            </Button>
          </div>
        </header>
        {feedback ? (
          <div
            aria-live="polite"
            className="catalog-form-feedback"
            data-tone={feedback.tone}
            role={feedback.tone === 'error' ? 'alert' : 'status'}
          >
            {feedback.message}
          </div>
        ) : null}
        <fieldset className="catalog-fieldset" disabled={busy}>
          <div className="catalog-form-section catalog-form-grid">
            <CatalogSelectField
              issue={findIssue(issues, RULE_FIELDS.matcherKind)}
              label="Matcher"
              labelFor={RULE_FIELDS.matcherKind}
            >
              <select
                className="catalog-select"
                id={RULE_FIELDS.matcherKind}
                onChange={(event) =>
                  onDraftChange({
                    ...draft,
                    matcherKind: event.target.value as ClassificationRuleMatcherKind,
                  })
                }
                value={draft.matcherKind}
              >
                {MATCHER_OPTIONS.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
            </CatalogSelectField>

            <CatalogField
              issue={findIssue(issues, RULE_FIELDS.pattern)}
              label="Pattern"
              labelFor={RULE_FIELDS.pattern}
            >
              <TextInput
                aria-describedby={issueDescriptionId(issues, RULE_FIELDS.pattern)}
                autoCapitalize="off"
                autoComplete="off"
                className="catalog-mono"
                id={RULE_FIELDS.pattern}
                invalid={findIssue(issues, RULE_FIELDS.pattern) !== null}
                onChange={(event) => onDraftChange({ ...draft, pattern: event.target.value })}
                spellCheck={false}
                value={draft.pattern}
              />
            </CatalogField>

            <div className="catalog-form-grid catalog-form-grid--two">
              <CatalogSelectField
                issue={findIssue(issues, RULE_FIELDS.actionKind)}
                label="Action"
                labelFor={RULE_FIELDS.actionKind}
              >
                <select
                  className="catalog-select"
                  id={RULE_FIELDS.actionKind}
                  onChange={(event) =>
                    onDraftChange({
                      ...draft,
                      actionKind: event.target.value as RuleActionKind,
                    })
                  }
                  value={draft.actionKind}
                >
                  {ACTION_OPTIONS.map((option) => (
                    <option key={option.value} value={option.value}>
                      {option.label}
                    </option>
                  ))}
                </select>
              </CatalogSelectField>

              <CatalogField
                issue={findIssue(issues, RULE_FIELDS.priority)}
                label="Priority"
                labelFor={RULE_FIELDS.priority}
              >
                <TextInput
                  aria-describedby={issueDescriptionId(issues, RULE_FIELDS.priority)}
                  id={RULE_FIELDS.priority}
                  invalid={findIssue(issues, RULE_FIELDS.priority) !== null}
                  max={1_000_000}
                  min={-1_000_000}
                  onChange={(event) => onDraftChange({ ...draft, priority: event.target.value })}
                  step={1}
                  type="number"
                  value={draft.priority}
                />
              </CatalogField>
            </div>

            {draft.actionKind === 'assignProject' ? (
              <CatalogSelectField
                issue={findIssue(issues, RULE_FIELDS.projectId)}
                label="Project"
                labelFor={RULE_FIELDS.projectId}
              >
                <select
                  aria-describedby={issueDescriptionId(issues, RULE_FIELDS.projectId)}
                  aria-invalid={findIssue(issues, RULE_FIELDS.projectId) !== null || undefined}
                  className="catalog-select"
                  id={RULE_FIELDS.projectId}
                  onChange={(event) => onDraftChange({ ...draft, projectId: event.target.value })}
                  value={draft.projectId}
                >
                  <option value="">Select project</option>
                  {!selectedProjectAvailable && draft.projectId !== '' ? (
                    <option value={draft.projectId}>Unavailable project ({draft.projectId})</option>
                  ) : null}
                  {projects.map((project) => (
                    <option key={project.id} value={project.id}>
                      {project.input.name} ({shortIdentity(project.id)})
                    </option>
                  ))}
                </select>
              </CatalogSelectField>
            ) : null}

            <label className="catalog-checkbox" htmlFor={RULE_FIELDS.enabled}>
              <input
                checked={draft.enabled}
                id={RULE_FIELDS.enabled}
                onChange={(event) => onDraftChange({ ...draft, enabled: event.target.checked })}
                type="checkbox"
              />
              <span>Enabled</span>
            </label>
          </div>
        </fieldset>
      </form>
    </div>
  );
}

function CatalogField({
  children,
  issue,
  label,
  labelFor,
}: {
  children: ReactNode;
  issue: ValidationIssue | null;
  label: string;
  labelFor: string;
}) {
  return (
    <label className="catalog-field" htmlFor={labelFor}>
      <span className="catalog-field-label">{label}</span>
      {children}
      {issue ? (
        <span className="catalog-field-error" id={`${labelFor}-error`}>
          {issue.message}
        </span>
      ) : null}
    </label>
  );
}

function CatalogSelectField(props: {
  children: ReactNode;
  issue: ValidationIssue | null;
  label: string;
  labelFor: string;
}) {
  return <CatalogField {...props} />;
}

function CatalogListState({ icon, label }: { icon: ReactNode; label: string }) {
  return (
    <div className="catalog-list-state">
      {icon}
      <span>{label}</span>
    </div>
  );
}

function findIssue(issues: ReadonlyArray<ValidationIssue>, field: string) {
  return issues.find((issue) => issue.field === field) ?? null;
}

function issueDescriptionId(issues: ReadonlyArray<ValidationIssue>, field: string) {
  return findIssue(issues, field) === null ? undefined : `${field}-error`;
}

function shortIdentity(value: string) {
  return value.length <= 10 ? value : `${value.slice(0, 8)}...`;
}

function formatUpdatedAt(value: string) {
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) {
    return 'recently';
  }
  return new Intl.DateTimeFormat(undefined, {
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    month: 'short',
  }).format(date);
}
