import type { ClassificationRuleSummary, ProjectSummary } from '@dpm/generated-types';
import {
  Button,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogOverlay,
  DialogPortal,
  DialogRoot,
  DialogTitle,
  TabsContent,
  TabsList,
  TabsRoot,
  TabsTrigger,
} from '@dpm/ui';
import {
  CircleOff,
  Folder,
  FolderCog,
  ListFilter,
  LoaderCircle,
  Trash2,
  TriangleAlert,
  type LucideIcon,
} from 'lucide-react';
import { useCallback, useEffect, useRef, useState } from 'react';

import { useSupervisorSnapshot } from '../../app/SupervisorProvider';
import {
  deleteClassificationRule,
  deleteProject,
  listClassificationRules,
  listProjects,
  saveClassificationRule,
  saveProject,
} from '../../lib/projectRules';
import type { SupervisorConnectionState } from '../../lib/supervisor';
import { ProjectCatalogPanel } from './ProjectCatalogPanel';
import { RuleCatalogPanel } from './RuleCatalogPanel';
import {
  buildClassificationRuleSaveRequest,
  buildProjectSaveRequest,
  classificationRuleSummaryToDraft,
  createProjectDraft,
  createRuleDraft,
  isCatalogTab,
  projectDraftFingerprint,
  projectSummaryToDraft,
  PROJECT_FIELDS,
  RULE_FIELDS,
  ruleDraftFingerprint,
  sortClassificationRules,
  sortProjects,
  upsertClassificationRule,
  upsertProject,
  type CatalogTab,
  type ProjectDraft,
  type RuleDraft,
  type ValidationIssue,
} from './projectRulesModel';

import './projectsRules.css';

interface CollectionState<T> {
  error: string | null;
  items: ReadonlyArray<T>;
  loading: boolean;
}

interface Feedback {
  message: string;
  tone: 'error' | 'success';
}

type MutationState = { action: 'delete' | 'save'; entity: 'project' | 'rule' } | null;

type DeleteTarget =
  | {
      dirty: boolean;
      expectedUpdatedAt: string;
      id: string;
      kind: 'project';
      label: string;
    }
  | {
      dirty: boolean;
      expectedUpdatedAt: string;
      id: string;
      kind: 'rule';
      label: string;
    };

interface AvailabilityPresentation {
  busy: boolean;
  detail: string;
  Icon: LucideIcon;
  title: string;
}

const initialProjectDraft = createProjectDraft();
const initialRuleDraft = createRuleDraft();

let draftCache = {
  projectBaseline: projectDraftFingerprint(initialProjectDraft),
  projectDraft: initialProjectDraft,
  ruleBaseline: ruleDraftFingerprint(initialRuleDraft),
  ruleDraft: initialRuleDraft,
  tab: 'projects' as CatalogTab,
};

export function ProjectsRulesPage() {
  const snapshot = useSupervisorSnapshot();
  const ready =
    snapshot.connectionState.kind === 'connected' &&
    snapshot.synchronized &&
    snapshot.generation !== null;
  const generation = ready ? snapshot.generation : null;

  const [tab, setTab] = useState<CatalogTab>(draftCache.tab);
  const [projectsState, setProjectsState] = useState<CollectionState<ProjectSummary>>({
    error: null,
    items: [],
    loading: false,
  });
  const [rulesState, setRulesState] = useState<CollectionState<ClassificationRuleSummary>>({
    error: null,
    items: [],
    loading: false,
  });
  const [projectDraft, setProjectDraft] = useState<ProjectDraft>(draftCache.projectDraft);
  const [projectBaseline, setProjectBaseline] = useState(draftCache.projectBaseline);
  const [projectIssues, setProjectIssues] = useState<ReadonlyArray<ValidationIssue>>([]);
  const [projectFeedback, setProjectFeedback] = useState<Feedback | null>(null);
  const [ruleDraft, setRuleDraft] = useState<RuleDraft>(draftCache.ruleDraft);
  const [ruleBaseline, setRuleBaseline] = useState(draftCache.ruleBaseline);
  const [ruleIssues, setRuleIssues] = useState<ReadonlyArray<ValidationIssue>>([]);
  const [ruleFeedback, setRuleFeedback] = useState<Feedback | null>(null);
  const [mutation, setMutation] = useState<MutationState>(null);
  const [deleteTarget, setDeleteTarget] = useState<DeleteTarget | null>(null);
  const [deleteError, setDeleteError] = useState<string | null>(null);

  const scopeRef = useRef({ generation, ready });
  const readSequenceRef = useRef(0);
  const mutationSequenceRef = useRef(0);
  const projectDraftRef = useRef(projectDraft);
  const projectDirtyRef = useRef(false);
  const ruleDraftRef = useRef(ruleDraft);
  const ruleDirtyRef = useRef(false);

  const projectDirty = projectDraftFingerprint(projectDraft) !== projectBaseline;
  const ruleDirty = ruleDraftFingerprint(ruleDraft) !== ruleBaseline;
  const busy = mutation !== null || projectsState.loading || rulesState.loading;
  scopeRef.current = { generation, ready };
  projectDraftRef.current = projectDraft;
  projectDirtyRef.current = projectDirty;
  ruleDraftRef.current = ruleDraft;
  ruleDirtyRef.current = ruleDirty;

  useEffect(() => {
    draftCache = { projectBaseline, projectDraft, ruleBaseline, ruleDraft, tab };
  }, [projectBaseline, projectDraft, ruleBaseline, ruleDraft, tab]);

  const replaceProjectDraft = useCallback(
    (draft: ProjectDraft, feedback: Feedback | null = null) => {
      projectDraftRef.current = draft;
      projectDirtyRef.current = false;
      setProjectDraft(draft);
      setProjectBaseline(projectDraftFingerprint(draft));
      setProjectIssues([]);
      setProjectFeedback(feedback);
    },
    [],
  );

  const replaceRuleDraft = useCallback((draft: RuleDraft, feedback: Feedback | null = null) => {
    ruleDraftRef.current = draft;
    ruleDirtyRef.current = false;
    setRuleDraft(draft);
    setRuleBaseline(ruleDraftFingerprint(draft));
    setRuleIssues([]);
    setRuleFeedback(feedback);
  }, []);

  const refreshCatalog = useCallback(
    async (expectedGeneration: number) => {
      const sequence = readSequenceRef.current + 1;
      readSequenceRef.current = sequence;
      setProjectsState((current) => ({ ...current, error: null, loading: true }));
      setRulesState((current) => ({ ...current, error: null, loading: true }));

      const [projectsResult, rulesResult] = await Promise.allSettled([
        listProjects(),
        listClassificationRules(),
      ]);
      if (
        !readRequestIsCurrent(
          scopeRef.current,
          readSequenceRef.current,
          expectedGeneration,
          sequence,
        )
      ) {
        return;
      }

      if (projectsResult.status === 'fulfilled') {
        const projects = sortProjects(projectsResult.value);
        setProjectsState({ error: null, items: projects, loading: false });
        const selectedId = projectDraftRef.current.id;
        if (!projectDirtyRef.current && selectedId !== null) {
          const refreshed = projects.find((project) => project.id === selectedId);
          replaceProjectDraft(
            refreshed === undefined ? createProjectDraft() : projectSummaryToDraft(refreshed),
          );
        }
      } else {
        setProjectsState((current) => ({
          ...current,
          error: 'Projects could not be read from the Supervisor.',
          loading: false,
        }));
      }

      if (rulesResult.status === 'fulfilled') {
        const rules = sortClassificationRules(rulesResult.value);
        setRulesState({ error: null, items: rules, loading: false });
        const selectedId = ruleDraftRef.current.id;
        if (!ruleDirtyRef.current && selectedId !== null) {
          const refreshed = rules.find((rule) => rule.id === selectedId);
          replaceRuleDraft(
            refreshed === undefined
              ? createRuleDraft()
              : classificationRuleSummaryToDraft(refreshed),
          );
        }
      } else {
        setRulesState((current) => ({
          ...current,
          error: 'Classification rules could not be read from the Supervisor.',
          loading: false,
        }));
      }
    },
    [replaceProjectDraft, replaceRuleDraft],
  );

  useEffect(() => {
    readSequenceRef.current += 1;
    mutationSequenceRef.current += 1;
    setMutation(null);
    setDeleteTarget(null);
    setDeleteError(null);
    if (!ready || generation === null) {
      setProjectsState({ error: null, items: [], loading: false });
      setRulesState({ error: null, items: [], loading: false });
      return;
    }
    setProjectsState({ error: null, items: [], loading: true });
    setRulesState({ error: null, items: [], loading: true });
    void refreshCatalog(generation);
  }, [generation, ready, refreshCatalog]);

  useEffect(
    () => () => {
      scopeRef.current = { generation: null, ready: false };
      readSequenceRef.current += 1;
      mutationSequenceRef.current += 1;
    },
    [],
  );

  const handleProjectDraftChange = (draft: ProjectDraft) => {
    projectDraftRef.current = draft;
    projectDirtyRef.current = projectDraftFingerprint(draft) !== projectBaseline;
    setProjectDraft(draft);
    setProjectIssues([]);
    setProjectFeedback(null);
  };

  const handleRuleDraftChange = (draft: RuleDraft) => {
    ruleDraftRef.current = draft;
    ruleDirtyRef.current = ruleDraftFingerprint(draft) !== ruleBaseline;
    setRuleDraft(draft);
    setRuleIssues([]);
    setRuleFeedback(null);
  };

  const selectProject = (project: ProjectSummary) => {
    if (busy || project.id === projectDraft.id || !confirmDiscard(projectDirty, 'project')) {
      return;
    }
    replaceProjectDraft(projectSummaryToDraft(project));
  };

  const selectRule = (rule: ClassificationRuleSummary) => {
    if (busy || rule.id === ruleDraft.id || !confirmDiscard(ruleDirty, 'classification rule')) {
      return;
    }
    replaceRuleDraft(classificationRuleSummaryToDraft(rule));
  };

  const createProject = () => {
    if (!busy && confirmDiscard(projectDirty, 'project')) {
      replaceProjectDraft(createProjectDraft());
    }
  };

  const createRule = () => {
    if (!busy && confirmDiscard(ruleDirty, 'classification rule')) {
      replaceRuleDraft(createRuleDraft());
    }
  };

  const handleRefresh = () => {
    if (!busy && generation !== null && ready) {
      void refreshCatalog(generation);
    }
  };

  const handleProjectSave = async () => {
    const built = buildProjectSaveRequest(projectDraft);
    if (!built.ok) {
      setProjectIssues(built.issues);
      setProjectFeedback(null);
      focusFirstIssue(built.issues);
      return;
    }
    if (generation === null || !ready || busy) {
      return;
    }

    const expectedGeneration = generation;
    const sequence = mutationSequenceRef.current + 1;
    mutationSequenceRef.current = sequence;
    setMutation({ action: 'save', entity: 'project' });
    setProjectIssues([]);
    setProjectFeedback(null);
    try {
      const saved = await saveProject(built.request);
      if (
        !mutationIsCurrent(
          scopeRef.current,
          mutationSequenceRef.current,
          expectedGeneration,
          sequence,
        )
      ) {
        return;
      }
      setProjectsState((current) => ({
        error: null,
        items: upsertProject(current.items, saved),
        loading: false,
      }));
      replaceProjectDraft(projectSummaryToDraft(saved), {
        message: 'Project saved.',
        tone: 'success',
      });
    } catch {
      if (
        mutationIsCurrent(
          scopeRef.current,
          mutationSequenceRef.current,
          expectedGeneration,
          sequence,
        )
      ) {
        setProjectFeedback({
          message: 'The project was not saved. It may have changed; your draft was kept.',
          tone: 'error',
        });
      }
    } finally {
      if (
        mutationIsCurrent(
          scopeRef.current,
          mutationSequenceRef.current,
          expectedGeneration,
          sequence,
        )
      ) {
        setMutation(null);
      }
    }
  };

  const handleRuleSave = async () => {
    const built = buildClassificationRuleSaveRequest(ruleDraft, projectsState.items);
    if (!built.ok) {
      setRuleIssues(built.issues);
      setRuleFeedback(null);
      focusFirstIssue(built.issues);
      return;
    }
    if (generation === null || !ready || busy) {
      return;
    }

    const expectedGeneration = generation;
    const sequence = mutationSequenceRef.current + 1;
    mutationSequenceRef.current = sequence;
    setMutation({ action: 'save', entity: 'rule' });
    setRuleIssues([]);
    setRuleFeedback(null);
    try {
      const saved = await saveClassificationRule(built.request);
      if (
        !mutationIsCurrent(
          scopeRef.current,
          mutationSequenceRef.current,
          expectedGeneration,
          sequence,
        )
      ) {
        return;
      }
      setRulesState((current) => ({
        error: null,
        items: upsertClassificationRule(current.items, saved),
        loading: false,
      }));
      replaceRuleDraft(classificationRuleSummaryToDraft(saved), {
        message: 'Classification rule saved.',
        tone: 'success',
      });
    } catch {
      if (
        mutationIsCurrent(
          scopeRef.current,
          mutationSequenceRef.current,
          expectedGeneration,
          sequence,
        )
      ) {
        setRuleFeedback({
          message: 'The rule was not saved. It may have changed; your draft was kept.',
          tone: 'error',
        });
      }
    } finally {
      if (
        mutationIsCurrent(
          scopeRef.current,
          mutationSequenceRef.current,
          expectedGeneration,
          sequence,
        )
      ) {
        setMutation(null);
      }
    }
  };

  const openProjectDelete = () => {
    const saved = projectsState.items.find((project) => project.id === projectDraft.id);
    if (saved !== undefined && projectDraft.expectedUpdatedAt !== null && !busy) {
      setDeleteError(null);
      setDeleteTarget({
        dirty: projectDirty,
        expectedUpdatedAt: projectDraft.expectedUpdatedAt,
        id: saved.id,
        kind: 'project',
        label: saved.input.name,
      });
    }
  };

  const openRuleDelete = () => {
    const saved = rulesState.items.find((rule) => rule.id === ruleDraft.id);
    if (saved !== undefined && ruleDraft.expectedUpdatedAt !== null && !busy) {
      setDeleteError(null);
      setDeleteTarget({
        dirty: ruleDirty,
        expectedUpdatedAt: ruleDraft.expectedUpdatedAt,
        id: saved.id,
        kind: 'rule',
        label: saved.input.pattern,
      });
    }
  };

  const confirmDelete = async () => {
    const target = deleteTarget;
    if (target === null || generation === null || !ready || busy) {
      return;
    }

    const expectedGeneration = generation;
    const sequence = mutationSequenceRef.current + 1;
    mutationSequenceRef.current = sequence;
    setMutation({ action: 'delete', entity: target.kind });
    setDeleteError(null);
    if (target.kind === 'project') {
      setProjectFeedback(null);
    } else {
      setRuleFeedback(null);
    }
    try {
      if (target.kind === 'project') {
        await deleteProject({
          expectedUpdatedAt: target.expectedUpdatedAt,
          projectId: target.id,
        });
      } else {
        await deleteClassificationRule({
          expectedUpdatedAt: target.expectedUpdatedAt,
          ruleId: target.id,
        });
      }
      if (
        !mutationIsCurrent(
          scopeRef.current,
          mutationSequenceRef.current,
          expectedGeneration,
          sequence,
        )
      ) {
        return;
      }
      if (target.kind === 'project') {
        setProjectsState((current) => ({
          ...current,
          error: null,
          items: current.items.filter((project) => project.id !== target.id),
        }));
        replaceProjectDraft(createProjectDraft(), {
          message: 'Project deleted.',
          tone: 'success',
        });
        setDeleteTarget(null);
        focusCatalogField(PROJECT_FIELDS.name);
      } else {
        setRulesState((current) => ({
          ...current,
          error: null,
          items: current.items.filter((rule) => rule.id !== target.id),
        }));
        replaceRuleDraft(createRuleDraft(), {
          message: 'Classification rule deleted.',
          tone: 'success',
        });
        setDeleteTarget(null);
        focusCatalogField(RULE_FIELDS.pattern);
      }
    } catch {
      if (
        !mutationIsCurrent(
          scopeRef.current,
          mutationSequenceRef.current,
          expectedGeneration,
          sequence,
        )
      ) {
        return;
      }
      if (target.kind === 'project') {
        setDeleteError('The project was not deleted. It may have changed or still be referenced.');
        setProjectFeedback({
          message:
            'The project was not deleted. It may have changed or still be referenced by a launch profile or rule. Your draft was kept.',
          tone: 'error',
        });
      } else {
        setDeleteError('The classification rule was not deleted. It may have changed.');
        setRuleFeedback({
          message: 'The classification rule was not deleted. Your draft was kept.',
          tone: 'error',
        });
      }
    } finally {
      if (
        mutationIsCurrent(
          scopeRef.current,
          mutationSequenceRef.current,
          expectedGeneration,
          sequence,
        )
      ) {
        setMutation(null);
      }
    }
  };

  const availability = ready ? null : presentAvailability(snapshot.connectionState);

  return (
    <main className="projects-rules-page" id="main-content" tabIndex={-1}>
      <header className="page-header projects-rules-page-header">
        <div className="page-title">
          <FolderCog aria-hidden="true" size={18} strokeWidth={1.8} />
          <div>
            <h1>Projects &amp; rules</h1>
            <p>Registered roots and process classification</p>
          </div>
        </div>
      </header>
      <TabsRoot
        className="projects-rules-tabs"
        onValueChange={(value) => {
          if (isCatalogTab(value)) {
            setTab(value);
          }
        }}
        value={tab}
      >
        <TabsList aria-label="Project and rule views" className="projects-rules-tab-list">
          <TabsTrigger disabled={busy} value="projects">
            <Folder aria-hidden="true" size={14} strokeWidth={1.8} />
            <span>Projects</span>
          </TabsTrigger>
          <TabsTrigger disabled={busy} value="rules">
            <ListFilter aria-hidden="true" size={14} strokeWidth={1.8} />
            <span>Rules</span>
          </TabsTrigger>
        </TabsList>
        {availability ? (
          <CatalogAvailability presentation={availability} />
        ) : (
          <>
            <TabsContent className="projects-rules-tab-content" value="projects">
              <ProjectCatalogPanel
                busy={busy}
                dirty={projectDirty}
                draft={projectDraft}
                error={projectsState.error}
                feedback={projectFeedback}
                issues={projectIssues}
                loading={projectsState.loading}
                onCreate={createProject}
                onDelete={openProjectDelete}
                onDraftChange={handleProjectDraftChange}
                onRefresh={handleRefresh}
                onSave={() => void handleProjectSave()}
                onSelect={selectProject}
                projects={projectsState.items}
              />
            </TabsContent>
            <TabsContent className="projects-rules-tab-content" value="rules">
              <RuleCatalogPanel
                busy={busy}
                dirty={ruleDirty}
                draft={ruleDraft}
                error={rulesState.error}
                feedback={ruleFeedback}
                issues={ruleIssues}
                loading={rulesState.loading}
                onCreate={createRule}
                onDelete={openRuleDelete}
                onDraftChange={handleRuleDraftChange}
                onRefresh={handleRefresh}
                onSave={() => void handleRuleSave()}
                onSelect={selectRule}
                projects={projectsState.items}
                rules={rulesState.items}
              />
            </TabsContent>
          </>
        )}
      </TabsRoot>
      <DeleteConfirmation
        busy={busy}
        error={deleteError}
        onCancel={() => {
          setDeleteTarget(null);
          setDeleteError(null);
        }}
        onConfirm={() => void confirmDelete()}
        target={deleteTarget}
      />
    </main>
  );
}

function DeleteConfirmation({
  busy,
  error,
  onCancel,
  onConfirm,
  target,
}: {
  busy: boolean;
  error: string | null;
  onCancel: () => void;
  onConfirm: () => void;
  target: DeleteTarget | null;
}) {
  const entity = target?.kind === 'project' ? 'project' : 'classification rule';
  return (
    <DialogRoot
      onOpenChange={(open) => {
        if (!open && !busy) {
          onCancel();
        }
      }}
      open={target !== null}
    >
      <DialogPortal>
        <DialogOverlay className="catalog-dialog-overlay" />
        <DialogContent className="catalog-dialog-content">
          <div className="catalog-dialog-heading">
            <Trash2 aria-hidden="true" size={18} strokeWidth={1.8} />
            <DialogTitle>Delete {entity}</DialogTitle>
          </div>
          <DialogDescription>
            Delete <strong>{target?.label ?? ''}</strong>? This cannot be undone.
          </DialogDescription>
          {target?.kind === 'project' ? (
            <p className="catalog-dialog-note">
              A project referenced by a launch profile or classification rule will not be deleted.
            </p>
          ) : null}
          {target?.dirty ? (
            <p className="catalog-dialog-note">Unsaved editor changes will be discarded.</p>
          ) : null}
          {error ? (
            <p className="catalog-dialog-error" role="alert">
              {error}
            </p>
          ) : null}
          <div className="catalog-dialog-actions">
            <DialogClose asChild>
              <Button disabled={busy} variant="secondary">
                Cancel
              </Button>
            </DialogClose>
            <Button
              disabled={busy}
              leadingIcon={<Trash2 aria-hidden="true" size={14} strokeWidth={1.8} />}
              onClick={onConfirm}
              variant="danger"
            >
              {busy ? 'Deleting' : 'Delete'}
            </Button>
          </div>
        </DialogContent>
      </DialogPortal>
    </DialogRoot>
  );
}

function focusCatalogField(id: string) {
  globalThis.requestAnimationFrame(() => {
    document.getElementById(id)?.focus({ preventScroll: false });
  });
}

function CatalogAvailability({ presentation }: { presentation: AvailabilityPresentation }) {
  const { busy, detail, Icon, title } = presentation;
  return (
    <div aria-live="polite" className="catalog-availability" role="status">
      <Icon
        aria-hidden="true"
        className={busy ? 'catalog-spin' : undefined}
        size={20}
        strokeWidth={1.8}
      />
      <strong>{title}</strong>
      <span>{detail}</span>
    </div>
  );
}

function presentAvailability(state: SupervisorConnectionState): AvailabilityPresentation {
  switch (state.kind) {
    case 'connected':
      return {
        busy: true,
        detail: 'Waiting for a consistent Supervisor snapshot.',
        Icon: LoaderCircle,
        title: 'Synchronizing catalogs',
      };
    case 'connecting':
    case 'authenticating':
    case 'backoff':
      return {
        busy: true,
        detail: 'Catalogs will load after the local Supervisor reconnects.',
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
        detail: 'Reconnect to manage registered projects and classification rules.',
        Icon: CircleOff,
        title: 'Projects and rules unavailable',
      };
  }
}

function confirmDiscard(dirty: boolean, entity: string) {
  return !dirty || globalThis.confirm(`Discard the unsaved changes to this ${entity}?`);
}

function focusFirstIssue(issues: ReadonlyArray<ValidationIssue>) {
  const first = issues[0];
  if (first === undefined) {
    return;
  }
  globalThis.requestAnimationFrame(() => {
    document.getElementById(first.field)?.focus({ preventScroll: false });
  });
}

function readRequestIsCurrent(
  scope: { generation: number | null; ready: boolean },
  currentSequence: number,
  expectedGeneration: number,
  expectedSequence: number,
) {
  return (
    scope.ready && scope.generation === expectedGeneration && currentSequence === expectedSequence
  );
}

function mutationIsCurrent(
  scope: { generation: number | null; ready: boolean },
  currentSequence: number,
  expectedGeneration: number,
  expectedSequence: number,
) {
  return readRequestIsCurrent(scope, currentSequence, expectedGeneration, expectedSequence);
}
