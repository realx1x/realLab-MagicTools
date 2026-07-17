import { useCallback, useEffect, useRef, useState } from 'react';
import type { FinalExecutionPreview, LaunchProfile } from '@dpm/generated-types';
import { Play } from 'lucide-react';

import {
  createProfileMutationOperationId,
  deleteLaunchProfile,
  listLaunchProfiles,
  previewLaunchProfile,
  profileMutationRequestSha256,
  saveLaunchProfile,
} from '../../lib/launchProfiles';
import { ExecutionPreviewPanel } from './ExecutionPreviewPanel';
import { LaunchProfileEditor, type LaunchProfileEditorFocusTarget } from './LaunchProfileEditor';
import { LaunchProfileList } from './LaunchProfileList';
import {
  buildExecutionPreviewRequest,
  buildSaveLaunchProfileRequest,
  createLaunchProfileDraft,
  launchProfileDirtyFingerprint,
  launchProfileToDraft,
  type LaunchProfileDraft,
  type LaunchProfileValidationIssue,
} from './launchProfileModel';

interface PreviewState {
  emptyState: 'invalidDraft' | 'notRequested';
  error: string | null;
  loading: boolean;
  pendingSecretNames: ReadonlyArray<string>;
  preview: FinalExecutionPreview | null;
  stale: boolean;
}

interface ProfileMutationIntent {
  operationId: string;
  requestSha256: string;
}

const initialDraft = createLaunchProfileDraft();
const utf8Encoder = new TextEncoder();
const initialPreviewState: PreviewState = {
  emptyState: 'notRequested',
  error: null,
  loading: false,
  pendingSecretNames: [],
  preview: null,
  stale: false,
};

export function LaunchProfilesPage() {
  const [profiles, setProfiles] = useState<ReadonlyArray<LaunchProfile>>([]);
  const [listLoading, setListLoading] = useState(true);
  const [listError, setListError] = useState<string | null>(null);
  const [draft, setDraft] = useState<LaunchProfileDraft>(initialDraft);
  const [baselineFingerprint, setBaselineFingerprint] = useState(() =>
    launchProfileDirtyFingerprint(initialDraft),
  );
  const [dirty, setDirty] = useState(false);
  const [issues, setIssues] = useState<ReadonlyArray<LaunchProfileValidationIssue>>([]);
  const [feedback, setFeedback] = useState<{
    message: string;
    tone: 'error' | 'success';
  } | null>(null);
  const [busy, setBusy] = useState(false);
  const [editorEpoch, setEditorEpoch] = useState(0);
  const [previewState, setPreviewState] = useState<PreviewState>(initialPreviewState);
  const dirtyRef = useRef(dirty);
  const draftRef = useRef(draft);
  const editorFocusAfterRemountRef = useRef<LaunchProfileEditorFocusTarget | null>(null);
  const listSequenceRef = useRef(0);
  const previewSequenceRef = useRef(0);
  const saveIntentRef = useRef<ProfileMutationIntent | null>(null);
  const deleteIntentRef = useRef<ProfileMutationIntent | null>(null);

  const handleEditorFocusRestored = useCallback(() => {
    editorFocusAfterRemountRef.current = null;
  }, []);

  const replaceDraft = useCallback(
    (
      nextDraft: LaunchProfileDraft,
      nextFeedback: { message: string; tone: 'error' | 'success' } | null,
    ) => {
      const nextBaseline = launchProfileDirtyFingerprint(nextDraft);
      draftRef.current = nextDraft;
      dirtyRef.current = false;
      setDraft(nextDraft);
      setBaselineFingerprint(nextBaseline);
      setDirty(false);
      setIssues([]);
      setFeedback(nextFeedback);
      setEditorEpoch((current) => current + 1);
    },
    [],
  );

  const refreshProfiles = useCallback(async () => {
    const sequence = listSequenceRef.current + 1;
    listSequenceRef.current = sequence;
    setListLoading(true);
    setListError(null);
    try {
      const listedProfiles = await listLaunchProfiles();
      if (listSequenceRef.current === sequence) {
        setProfiles(listedProfiles);
        const selectedProfileId = draftRef.current.profileId;
        if (!dirtyRef.current && selectedProfileId !== null) {
          const refreshedProfile = listedProfiles.find(
            (profile) => profile.id === selectedProfileId,
          );
          replaceDraft(
            refreshedProfile === undefined
              ? createLaunchProfileDraft()
              : launchProfileToDraft(refreshedProfile),
            null,
          );
        }
      }
    } catch {
      if (listSequenceRef.current === sequence) {
        setListError('Profiles are unavailable while the Supervisor is offline.');
      }
    } finally {
      if (listSequenceRef.current === sequence) {
        setListLoading(false);
      }
    }
  }, [replaceDraft]);

  useEffect(() => {
    void refreshProfiles();
  }, [refreshProfiles]);

  useEffect(() => {
    const nextDirty = launchProfileDirtyFingerprint(draft) !== baselineFingerprint;
    draftRef.current = draft;
    dirtyRef.current = nextDirty;
    setDirty(nextDirty);
  }, [baselineFingerprint, draft]);

  useEffect(() => {
    const sequence = previewSequenceRef.current + 1;
    previewSequenceRef.current = sequence;
    setPreviewState((current) => ({ ...current, error: null, stale: current.preview !== null }));

    const timer = globalThis.setTimeout(() => {
      const built = buildExecutionPreviewRequest(draft);
      if (!built.ok) {
        if (previewSequenceRef.current === sequence) {
          setPreviewState({
            emptyState: 'invalidDraft',
            error: null,
            loading: false,
            pendingSecretNames: [],
            preview: null,
            stale: false,
          });
        }
        return;
      }

      setPreviewState((current) => ({
        ...current,
        emptyState: 'notRequested',
        error: null,
        loading: true,
        pendingSecretNames: built.pendingSecretNames,
      }));
      void previewLaunchProfile(built.request)
        .then((preview) => {
          if (previewSequenceRef.current === sequence) {
            setPreviewState({
              emptyState: 'notRequested',
              error: null,
              loading: false,
              pendingSecretNames: built.pendingSecretNames,
              preview,
              stale: false,
            });
          }
        })
        .catch(() => {
          if (previewSequenceRef.current === sequence) {
            setPreviewState((current) => ({
              ...current,
              error: 'Final preview is unavailable from the Supervisor.',
              loading: false,
              stale: current.preview !== null,
            }));
          }
        });
    }, 350);

    return () => globalThis.clearTimeout(timer);
  }, [draft]);

  const confirmDiscard = () =>
    !dirty || globalThis.confirm('Discard the unsaved changes to this launch profile?');

  const selectProfile = (profile: LaunchProfile) => {
    if (busy || !confirmDiscard()) {
      return;
    }
    replaceDraft(launchProfileToDraft(profile), null);
  };

  const createProfile = () => {
    if (busy || !confirmDiscard()) {
      return;
    }
    replaceDraft(createLaunchProfileDraft(), null);
  };

  const handleDraftChange = (nextDraft: LaunchProfileDraft) => {
    const nextDirty = launchProfileDirtyFingerprint(nextDraft) !== baselineFingerprint;
    draftRef.current = nextDraft;
    dirtyRef.current = nextDirty;
    setDraft(nextDraft);
    setDirty(nextDirty);
    setIssues([]);
    setFeedback(null);
  };

  const handleSave = async (formData: FormData) => {
    const built = buildSaveLaunchProfileRequest(draft, formData);
    if (!built.ok) {
      setIssues(built.issues);
      setFeedback(null);
      return;
    }

    setBusy(true);
    setIssues([]);
    setFeedback(null);
    try {
      const requestSha256 = await profileMutationRequestSha256(built.request);
      const intent = mutationIntent(saveIntentRef.current, requestSha256, 'save');
      saveIntentRef.current = intent;
      const saved = await saveLaunchProfile(built.request, intent.operationId);
      saveIntentRef.current = null;
      listSequenceRef.current += 1;
      setListLoading(false);
      setListError(null);
      setProfiles((current) => upsertProfile(current, saved));
      editorFocusAfterRemountRef.current = 'title';
      replaceDraft(launchProfileToDraft(saved), {
        message: 'Profile saved.',
        tone: 'success',
      });
    } catch {
      setFeedback({
        message: 'The Supervisor could not save this profile.',
        tone: 'error',
      });
    } finally {
      setBusy(false);
    }
  };

  const handleDelete = async () => {
    if (draft.profileId === null || draft.expectedUpdatedAt === null) {
      return;
    }
    if (!globalThis.confirm(`Delete the launch profile "${draft.name}"?`)) {
      return;
    }

    setBusy(true);
    setFeedback(null);
    const profileId = draft.profileId;
    const request = {
      expectedUpdatedAt: draft.expectedUpdatedAt,
      profileId,
    };
    try {
      const requestSha256 = await profileMutationRequestSha256(request);
      const intent = mutationIntent(deleteIntentRef.current, requestSha256, 'delete');
      deleteIntentRef.current = intent;
      await deleteLaunchProfile(request, intent.operationId);
      deleteIntentRef.current = null;
      listSequenceRef.current += 1;
      setListLoading(false);
      setListError(null);
      setProfiles((current) => current.filter((profile) => profile.id !== profileId));
      editorFocusAfterRemountRef.current = 'name';
      replaceDraft(createLaunchProfileDraft(), {
        message: 'Profile deleted.',
        tone: 'success',
      });
    } catch {
      setFeedback({
        message: 'The Supervisor could not delete this profile.',
        tone: 'error',
      });
    } finally {
      setBusy(false);
    }
  };

  const handleRefresh = () => {
    if (busy) {
      return;
    }
    void refreshProfiles();
  };

  return (
    <main className="launch-profiles-page" id="main-content" tabIndex={-1}>
      <header className="page-header launch-profiles-page-header">
        <div className="page-title">
          <Play aria-hidden="true" size={18} strokeWidth={1.8} />
          <div>
            <h1>Launch profiles</h1>
            <p>Direct and explicit shell execution</p>
          </div>
        </div>
      </header>
      <div className="launch-profiles-workspace">
        <LaunchProfileList
          disabled={busy}
          error={listError}
          loading={listLoading}
          onCreate={createProfile}
          onRefresh={handleRefresh}
          onSelect={selectProfile}
          profiles={profiles}
          selectedProfileId={draft.profileId}
        />
        <LaunchProfileEditor
          busy={busy}
          dirty={dirty}
          draft={draft}
          feedback={feedback}
          focusOnMount={editorFocusAfterRemountRef.current}
          issues={issues}
          key={editorEpoch}
          onDelete={() => void handleDelete()}
          onDraftChange={handleDraftChange}
          onMountFocusRestored={handleEditorFocusRestored}
          onSave={(formData) => void handleSave(formData)}
        />
        <ExecutionPreviewPanel
          emptyState={previewState.emptyState}
          error={previewState.error}
          loading={previewState.loading}
          pendingSecretNames={previewState.pendingSecretNames}
          preview={previewState.preview}
          stale={previewState.stale}
        />
      </div>
    </main>
  );
}

function upsertProfile(
  profiles: ReadonlyArray<LaunchProfile>,
  saved: LaunchProfile,
): ReadonlyArray<LaunchProfile> {
  const existing = profiles.findIndex((profile) => profile.id === saved.id);
  if (existing === -1) {
    return sortProfiles([saved, ...profiles]);
  }
  const next = [...profiles];
  next[existing] = saved;
  return sortProfiles(next);
}

function sortProfiles(profiles: ReadonlyArray<LaunchProfile>) {
  return [...profiles].sort((left, right) => {
    const byName = compareUtf8Binary(left.input.name, right.input.name);
    return byName === 0 ? compareUtf8Binary(left.id, right.id) : byName;
  });
}

function compareUtf8Binary(left: string, right: string) {
  const leftBytes = utf8Encoder.encode(left);
  const rightBytes = utf8Encoder.encode(right);
  const sharedLength = Math.min(leftBytes.length, rightBytes.length);
  for (let index = 0; index < sharedLength; index += 1) {
    const difference = (leftBytes[index] ?? 0) - (rightBytes[index] ?? 0);
    if (difference !== 0) {
      return difference;
    }
  }
  return leftBytes.length - rightBytes.length;
}

function mutationIntent(
  current: ProfileMutationIntent | null,
  requestSha256: string,
  kind: 'delete' | 'save',
): ProfileMutationIntent {
  if (current?.requestSha256 === requestSha256) {
    return current;
  }
  return {
    operationId: createProfileMutationOperationId(kind),
    requestSha256,
  };
}
