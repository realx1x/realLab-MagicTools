import type { ProjectSummary } from '@dpm/generated-types';
import { Button, IconButton, TextInput } from '@dpm/ui';
import { Folder, LoaderCircle, Plus, RefreshCw, Save, Trash2 } from 'lucide-react';
import type { ReactNode } from 'react';

import { PROJECT_FIELDS, type ProjectDraft, type ValidationIssue } from './projectRulesModel';

interface ProjectCatalogPanelProps {
  busy: boolean;
  dirty: boolean;
  draft: ProjectDraft;
  error: string | null;
  feedback: { message: string; tone: 'error' | 'success' } | null;
  issues: ReadonlyArray<ValidationIssue>;
  loading: boolean;
  onCreate: () => void;
  onDelete: () => void;
  onDraftChange: (draft: ProjectDraft) => void;
  onRefresh: () => void;
  onSave: () => void;
  onSelect: (project: ProjectSummary) => void;
  projects: ReadonlyArray<ProjectSummary>;
}

export function ProjectCatalogPanel({
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
}: ProjectCatalogPanelProps) {
  return (
    <div className="catalog-workspace">
      <aside aria-label="Projects" className="catalog-list-panel">
        <header className="catalog-panel-header">
          <div className="catalog-panel-title">
            <h2>Projects</h2>
            <span>{loading ? 'Loading' : `${projects.length.toLocaleString()} saved`}</span>
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
              label="Refresh projects"
              onClick={onRefresh}
              variant="ghost"
            />
            <IconButton
              disabled={busy}
              icon={<Plus aria-hidden="true" size={16} strokeWidth={1.8} />}
              label="New project"
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
          {projects.map((project) => {
            const selected = project.id === draft.id;
            return (
              <div key={project.id} role="listitem">
                <button
                  aria-current={selected ? 'page' : undefined}
                  className="catalog-list-item catalog-list-item--project"
                  data-selected={selected || undefined}
                  disabled={busy}
                  onClick={() => onSelect(project)}
                  type="button"
                >
                  <Folder aria-hidden="true" size={16} strokeWidth={1.7} />
                  <span className="catalog-list-copy">
                    <strong>{project.input.name}</strong>
                    <span className="catalog-mono" title={project.input.rootDirectory}>
                      {project.input.rootDirectory}
                    </span>
                  </span>
                </button>
              </div>
            );
          })}
          {loading && projects.length === 0 ? (
            <CatalogListState
              icon={<LoaderCircle aria-hidden="true" className="catalog-spin" size={18} />}
              label="Loading projects"
            />
          ) : null}
          {!loading && projects.length === 0 && error === null ? (
            <CatalogListState
              icon={<Folder aria-hidden="true" size={18} strokeWidth={1.6} />}
              label="No saved projects"
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
            <h2>{draft.id === null ? 'New project' : draft.name || 'Project'}</h2>
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
          <div className="catalog-form-section">
            <CatalogField
              issue={findIssue(issues, PROJECT_FIELDS.name)}
              label="Name"
              labelFor={PROJECT_FIELDS.name}
            >
              <TextInput
                aria-describedby={issueDescriptionId(issues, PROJECT_FIELDS.name)}
                autoComplete="off"
                id={PROJECT_FIELDS.name}
                invalid={findIssue(issues, PROJECT_FIELDS.name) !== null}
                maxLength={256}
                onChange={(event) => onDraftChange({ ...draft, name: event.target.value })}
                value={draft.name}
              />
            </CatalogField>
            <CatalogField
              issue={findIssue(issues, PROJECT_FIELDS.rootDirectory)}
              label="Root directory"
              labelFor={PROJECT_FIELDS.rootDirectory}
            >
              <TextInput
                aria-describedby={issueDescriptionId(issues, PROJECT_FIELDS.rootDirectory)}
                autoCapitalize="off"
                autoComplete="off"
                className="catalog-mono"
                id={PROJECT_FIELDS.rootDirectory}
                invalid={findIssue(issues, PROJECT_FIELDS.rootDirectory) !== null}
                onChange={(event) => onDraftChange({ ...draft, rootDirectory: event.target.value })}
                spellCheck={false}
                value={draft.rootDirectory}
              />
            </CatalogField>
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
  const errorId = `${labelFor}-error`;
  return (
    <label className="catalog-field" htmlFor={labelFor}>
      <span className="catalog-field-label">{label}</span>
      {children}
      {issue ? (
        <span className="catalog-field-error" id={errorId}>
          {issue.message}
        </span>
      ) : null}
    </label>
  );
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
