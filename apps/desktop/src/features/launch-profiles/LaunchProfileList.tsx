import type { LaunchProfile } from '@dpm/generated-types';
import { IconButton } from '@dpm/ui';
import { Plus, RefreshCw, TerminalSquare } from 'lucide-react';

interface LaunchProfileListProps {
  disabled: boolean;
  error: string | null;
  loading: boolean;
  onCreate: () => void;
  onRefresh: () => void;
  onSelect: (profile: LaunchProfile) => void;
  profiles: ReadonlyArray<LaunchProfile>;
  selectedProfileId: string | null;
}

export function LaunchProfileList({
  disabled,
  error,
  loading,
  onCreate,
  onRefresh,
  onSelect,
  profiles,
  selectedProfileId,
}: LaunchProfileListProps) {
  return (
    <aside aria-label="Launch profiles" className="launch-profile-list-panel">
      <header className="launch-panel-header">
        <div>
          <h2>Profiles</h2>
          <span>{loading ? 'Loading' : `${profiles.length} saved`}</span>
        </div>
        <div className="launch-panel-actions">
          <IconButton
            disabled={disabled || loading}
            icon={<RefreshCw aria-hidden="true" size={15} strokeWidth={1.8} />}
            label="Refresh profiles"
            onClick={onRefresh}
            variant="ghost"
          />
          <IconButton
            disabled={disabled}
            icon={<Plus aria-hidden="true" size={16} strokeWidth={1.8} />}
            label="New profile"
            onClick={onCreate}
            variant="secondary"
          />
        </div>
      </header>
      {error ? (
        <div className="launch-inline-alert" role="alert">
          {error}
        </div>
      ) : null}
      <div className="launch-profile-list" role="list">
        {profiles.map((profile) => {
          const selected = profile.id === selectedProfileId;
          return (
            <div key={profile.id} role="listitem">
              <button
                aria-current={selected ? 'page' : undefined}
                className="launch-profile-list-item"
                data-selected={selected || undefined}
                disabled={disabled}
                onClick={() => onSelect(profile)}
                type="button"
              >
                <TerminalSquare aria-hidden="true" size={16} strokeWidth={1.7} />
                <span className="launch-profile-list-copy">
                  <strong>{profile.input.name}</strong>
                  <span>
                    {profile.input.execution.mode === 'direct' ? 'Direct' : 'Shell'}
                    <span aria-hidden="true"> / </span>
                    {formatUpdatedAt(profile.updatedAt)}
                  </span>
                </span>
              </button>
            </div>
          );
        })}
        {!loading && profiles.length === 0 ? (
          <div className="launch-profile-list-empty">
            <TerminalSquare aria-hidden="true" size={18} strokeWidth={1.6} />
            <span>No saved profiles</span>
          </div>
        ) : null}
      </div>
    </aside>
  );
}

function formatUpdatedAt(value: string) {
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) {
    return 'Updated';
  }
  return new Intl.DateTimeFormat(undefined, {
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    month: 'short',
  }).format(date);
}
